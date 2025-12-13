"""
Simple Tkinter GUI for the Hybrid Cryptography System.

- Location: crypto_engine/gui_app.py
- Uses only the required functions from hybrid_crypto.py:
  generate_rsa_keypair, load_private_key, encrypt_file, decrypt_file, save_encrypted_file, load_encrypted_file

Tabs:
- Login / Register
- Encrypt & Share
- Receive & Decrypt

Security/UI details followed:
- Passphrases obtained via tkinter.simpledialog.askstring(..., show='*')
- File selections via tkinter.filedialog
- Decrypt action shows a "TAMPERING DETECTED" alert on ValueError

Run:
    python -m crypto_engine.gui_app
or
    python crypto_engine/gui_app.py

"""

import os
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import base64

# Import hybrid_crypto functions. Try package-relative import first, then fallback.
try:
    from .hybrid_crypto import (
        generate_rsa_keypair,
        load_private_key,
        encrypt_file,
        decrypt_file,
        save_encrypted_file,
        load_encrypted_file,
    )
except Exception:
    # Running as script directly from project root may require absolute import
    from hybrid_crypto import (
        generate_rsa_keypair,
        load_private_key,
        encrypt_file,
        decrypt_file,
        save_encrypted_file,
        load_encrypted_file,
    )

# Import DBManager for user auth and key lookup
try:
    from .db_manager import DBManager
except Exception:
    from db_manager import DBManager

class HybridCryptoGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Hybrid Cryptography System - GUI")
        self.geometry("820x520")

        # In-memory loaded keys
        self.loaded_private_key_pem = None  # bytes
        self.loaded_private_key_path = None
        self.loaded_public_key_pem = None  # bytes (if loaded)
        self.loaded_public_key_path = None

        # Database manager for multi-user key lookup and authentication
        os.makedirs(os.path.join(os.getcwd(), 'user_data'), exist_ok=True)
        self.db = DBManager(db_path=os.path.join('user_data', 'app.db'))

        # Current logged-in user state: dict with keys: username, private_key_path, public_key_path, passphrase
        self.current_user = None

        self._build_ui()

    def _build_ui(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True, padx=8, pady=8)

        # Tabs: Login/Register must be first
        tab_login = ttk.Frame(self.notebook)
        tab_encrypt = ttk.Frame(self.notebook)
        tab_decrypt = ttk.Frame(self.notebook)

        self.notebook.add(tab_login, text='Login / Register')
        self.notebook.add(tab_encrypt, text='Encrypt & Share')
        self.notebook.add(tab_decrypt, text='Receive & Decrypt')

        # Build tabs
        self._build_login_tab(tab_login)
        self._build_encrypt_tab(tab_encrypt)
        self._build_decrypt_tab(tab_decrypt)

        # Encrypt/Decrypt tabs disabled until login
        self.notebook.tab(tab_encrypt, state='disabled')
        self.notebook.tab(tab_decrypt, state='disabled')

    # ------------------------------
    # Login / Register Tab
    # ------------------------------
    def _build_login_tab(self, parent):
        frm = ttk.Frame(parent, padding=12)
        frm.pack(fill='both', expand=True)

        ttk.Label(frm, text='Username:').grid(row=0, column=0, sticky='w')
        self.login_username_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.login_username_var, width=40).grid(row=0, column=1, sticky='w')

        ttk.Label(frm, text='Passphrase:').grid(row=1, column=0, sticky='w', pady=(8,0))
        self.login_pass_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.login_pass_var, show='*', width=40).grid(row=1, column=1, sticky='w')

        ttk.Label(frm, text='Confirm Passphrase (for registration):').grid(row=2, column=0, sticky='w', pady=(8,0))
        self.login_pass_confirm_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.login_pass_confirm_var, show='*', width=40).grid(row=2, column=1, sticky='w')

        ttk.Button(frm, text='Register', command=self._on_register_user).grid(row=3, column=0, pady=12, sticky='w')
        ttk.Button(frm, text='Login', command=self._on_login_user).grid(row=3, column=1, pady=12, sticky='w')

        ttk.Label(frm, text='Note: Registration will generate RSA-4096 keys for the user and store key paths in the DB.').grid(row=4, column=0, columnspan=2, sticky='w')
        # Current user display
        self.lbl_current_user = ttk.Label(frm, text='Logged in as: None')
        self.lbl_current_user.grid(row=5, column=0, columnspan=2, sticky='w', pady=(12,0))

    def _on_register_user(self):
        username = self.login_username_var.get().strip()
        passphrase = self.login_pass_var.get()
        pass_confirm = self.login_pass_confirm_var.get()
        if not username:
            messagebox.showerror('Error', 'Enter a username to register.')
            return
        if not passphrase:
            messagebox.showerror('Error', 'Enter a passphrase.')
            return
        if passphrase != pass_confirm:
            messagebox.showerror('Error', 'Passphrases do not match.')
            return

        # Generate keys under ./keys/<username>/
        output_dir = os.path.join(os.getcwd(), 'keys', username)
        try:
            os.makedirs(output_dir, exist_ok=True)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to create keys directory:\n{e}')
            return

        try:
            result = generate_rsa_keypair(passphrase=passphrase, output_dir=output_dir)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to generate key pair:\n{e}')
            return

        priv = result.get('private_key_file')
        pub = result.get('public_key_file')
        if not priv or not pub:
            messagebox.showerror('Error', 'Key generation did not return expected file paths.')
            return

        # Register user in DB (store passphrase securely handled by DBManager)
        try:
            # Expected signature: register_user(username, passphrase, private_key_path, public_key_path)
            self.db.register_user(username, passphrase, priv, pub)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to register user in DB:\n{e}')
            return

        # Auto-login the new user
        self.current_user = {'username': username, 'private_key_path': priv, 'public_key_path': pub, 'passphrase': passphrase}
        try:
            self.loaded_private_key_pem = load_private_key(priv, passphrase)
            self.loaded_private_key_path = priv
        except Exception:
            # Non-fatal; still allow login
            self.loaded_private_key_pem = None
            self.loaded_private_key_path = None

        messagebox.showinfo('Success', f'User "{username}" registered and logged in.')
        # Enable Encrypt and Decrypt tabs and switch to Encrypt tab
        try:
            self.notebook.tab(1, state='normal')
            self.notebook.tab(2, state='normal')
            self.notebook.select(1)
        except Exception:
            pass
        # update UI labels
        try:
            self.lbl_current_user.config(text=f'Logged in as: {username}')
            self.lbl_receiver_info.config(text=f'{username} (private key loaded)')
        except Exception:
            pass
        self._refresh_user_lists()

    def _on_login_user(self):
        username = self.login_username_var.get().strip()
        passphrase = self.login_pass_var.get()
        if not username or not passphrase:
            messagebox.showerror('Error', 'Enter username and passphrase to login.')
            return

        try:
            user_data = self.db.get_user_data(username)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to query DB for user:\n{e}')
            return
        if not user_data:
            messagebox.showerror('Error', 'User not found.')
            return

        try:
            if not self.db.verify_passphrase(username, passphrase):
                messagebox.showerror('Error', 'Invalid passphrase.')
                return
        except Exception as e:
            messagebox.showerror('Error', f'Failed to verify passphrase:\n{e}')
            return

        # Login successful
        priv_path = user_data.get('private_key_path') or user_data.get('private_key')
        pub_path = user_data.get('public_key_path') or user_data.get('public_key')
        self.current_user = {'username': username, 'private_key_path': priv_path, 'public_key_path': pub_path, 'passphrase': passphrase}

        # Attempt to load private key into memory
        try:
            if priv_path:
                self.loaded_private_key_pem = load_private_key(priv_path, passphrase)
                self.loaded_private_key_path = priv_path
        except Exception:
            self.loaded_private_key_pem = None
            self.loaded_private_key_path = None

        messagebox.showinfo('Success', f'Logged in as {username}')
        try:
            self.notebook.tab(1, state='normal')
            self.notebook.tab(2, state='normal')
            self.notebook.select(1)
        except Exception:
            pass
        try:
            self.lbl_current_user.config(text=f'Logged in as: {username}')
            self.lbl_receiver_info.config(text=f'{username} (private key loaded)')
        except Exception:
            pass
        self._refresh_user_lists()

    def _refresh_user_lists(self):
        """Refresh usernames lists in comboboxes from DB."""
        try:
            names = self.db.get_all_usernames() or []
        except Exception:
            names = []
        # update comboboxes if present
        try:
            if hasattr(self, 'receiver_username_cb'):
                self.receiver_username_cb['values'] = names
        except Exception:
            pass
        try:
            if hasattr(self, 'sender_username_cb'):
                self.sender_username_cb['values'] = names
        except Exception:
            pass

    # ------------------------------
    # (Key management is handled via the Login / Register tab and DB)
    # ------------------------------
    # Encrypt & Share Tab
    # ------------------------------
    def _build_encrypt_tab(self, parent):
        frm = ttk.Frame(parent, padding=12)
        frm.pack(fill='both', expand=True)

        # File to encrypt
        ttk.Label(frm, text='File to encrypt:').grid(row=0, column=0, sticky='w')
        self.encrypt_input_path_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.encrypt_input_path_var, width=70).grid(row=1, column=0, columnspan=2, sticky='w')
        ttk.Button(frm, text='Browse...', command=self._on_browse_encrypt_input).grid(row=1, column=2, sticky='w')

        # Receiver selection from DB
        ttk.Label(frm, text='Select receiver (username):').grid(row=2, column=0, sticky='w', pady=(12,0))
        self.receiver_username_var = tk.StringVar()
        self.receiver_username_cb = ttk.Combobox(frm, textvariable=self.receiver_username_var, width=67, state='readonly')
        self.receiver_username_cb.grid(row=3, column=0, columnspan=2, sticky='w')
        ttk.Button(frm, text='Refresh', command=self._refresh_user_lists).grid(row=3, column=2, sticky='w')

        # Sender private key is derived from logged-in user; show path (disabled)
        ttk.Label(frm, text='Sender private key (logged-in user):').grid(row=4, column=0, sticky='w', pady=(12,0))
        self.sender_priv_path_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.sender_priv_path_var, width=70, state='disabled').grid(row=5, column=0, columnspan=2, sticky='w')
        ttk.Button(frm, text='Use Logged-in Key', command=self._on_use_logged_in_key).grid(row=5, column=2, sticky='w')

        # Output encrypted package path
        ttk.Label(frm, text='Save encrypted package to (JSON):').grid(row=6, column=0, sticky='w', pady=(12,0))
        self.encrypted_output_path_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.encrypted_output_path_var, width=70).grid(row=7, column=0, columnspan=2, sticky='w')
        ttk.Button(frm, text='Browse...', command=self._on_browse_encrypted_output).grid(row=7, column=2, sticky='w')

        ttk.Button(frm, text='Encrypt & Save', command=self._on_encrypt_and_save).grid(row=8, column=0, pady=18, sticky='w')

    def _on_browse_encrypt_input(self):
        path = filedialog.askopenfilename(title='Select file to encrypt', filetypes=[('All files','*.*')])
        if path:
            self.encrypt_input_path_var.set(path)

    def _on_browse_receiver_pub(self):
        # legacy/manual: allow selecting a PEM directly
        path = filedialog.askopenfilename(title='Select receiver public key PEM', filetypes=[('PEM','*.pem'), ('All','*.*')])
        if path:
            # set combobox to empty and store manual path
            self.receiver_username_var.set('')
            self.receiver_pub_path_manual = path

    def _on_browse_sender_priv(self):
        # legacy/manual: allow selecting a sender private key JSON
        path = filedialog.askopenfilename(title='Select sender encrypted private key JSON', filetypes=[('JSON','*.json'), ('All','*.*')])
        if path:
            self.sender_priv_path_var.set(path)

    def _on_use_logged_in_key(self):
        """Populate the sender private key field with the logged-in user's private key path."""
        if self.current_user and self.current_user.get('private_key_path'):
            self.sender_priv_path_var.set(self.current_user.get('private_key_path'))
        else:
            messagebox.showerror('Error', 'No logged-in user or private key path available.')

    def _on_browse_encrypted_output(self):
        path = filedialog.asksaveasfilename(title='Save encrypted package as', defaultextension='.json', filetypes=[('JSON','*.json'), ('All','*.*')])
        if path:
            self.encrypted_output_path_var.set(path)

    def _on_encrypt_and_save(self):
        input_path = self.encrypt_input_path_var.get().strip()
        receiver_username = getattr(self, 'receiver_username_var', tk.StringVar()).get().strip()
        receiver_pub_manual = getattr(self, 'receiver_pub_path_manual', None)
        output_path = self.encrypted_output_path_var.get().strip()

        if not input_path or not os.path.exists(input_path):
            messagebox.showerror('Error', 'Select a valid input file to encrypt.')
            return
        if not output_path:
            messagebox.showerror('Error', 'Select a path to save the encrypted JSON package.')
            return

        # Resolve receiver public key
        receiver_pub_pem = None
        if receiver_username:
            try:
                receiver_pub_pem = self.db.get_public_key_by_username(receiver_username)
            except Exception as e:
                messagebox.showerror('Error', f'Failed to retrieve receiver public key from DB:\n{e}')
                return
            if isinstance(receiver_pub_pem, str):
                receiver_pub_pem = receiver_pub_pem.encode()
        elif receiver_pub_manual:
            try:
                with open(receiver_pub_manual, 'rb') as f:
                    receiver_pub_pem = f.read()
            except Exception as e:
                messagebox.showerror('Error', f'Failed to read receiver public key:\n{e}')
                return
        else:
            messagebox.showerror('Error', 'Select a receiver username or provide a public key PEM file.')
            return

        # Determine sender private key path from logged-in user
        sender_priv_path = None
        if self.current_user:
            sender_priv_path = self.current_user.get('private_key_path')

        # Prompt for passphrase to decrypt sender private key (require unlocking each time)
        passphrase = simpledialog.askstring('Passphrase', 'Enter your passphrase to unlock your private key for signing:', show='*', parent=self)
        if passphrase is None:
            return
        try:
            if sender_priv_path and os.path.exists(sender_priv_path):
                sender_priv_pem = load_private_key(sender_priv_path, passphrase)
            elif self.loaded_private_key_pem:
                sender_priv_pem = self.loaded_private_key_pem
            else:
                raise FileNotFoundError('Sender private key not available for logged-in user')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to load sender private key:\n{e}')
            return

        try:
            encrypted_pkg = encrypt_file(input_path, receiver_pub_pem, sender_priv_pem)
        except Exception as e:
            messagebox.showerror('Error', f'Encryption failed:\n{e}')
            return

        try:
            save_encrypted_file(encrypted_pkg, output_path)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to save encrypted package:\n{e}')
            return

        messagebox.showinfo('Success', f'Encrypted package saved to:\n{output_path}')
        self._refresh_user_lists()

    # ------------------------------
    # Receive & Decrypt Tab
    # ------------------------------
    def _build_decrypt_tab(self, parent):
        frm = ttk.Frame(parent, padding=12)
        frm.pack(fill='both', expand=True)

        ttk.Label(frm, text='Encrypted package (JSON):').grid(row=0, column=0, sticky='w')
        self.encrypted_input_path_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.encrypted_input_path_var, width=70).grid(row=1, column=0, columnspan=2, sticky='w')
        ttk.Button(frm, text='Browse...', command=self._on_browse_encrypted_input).grid(row=1, column=2, sticky='w')

        # Receiver private key info comes from logged-in user
        ttk.Label(frm, text='Receiver (logged-in user):').grid(row=2, column=0, sticky='w', pady=(12,0))
        self.lbl_receiver_info = ttk.Label(frm, text='Not logged in')
        self.lbl_receiver_info.grid(row=3, column=0, columnspan=2, sticky='w')

        # Sender username (to fetch sender public key from DB)
        ttk.Label(frm, text='Sender username (for public key lookup):').grid(row=4, column=0, sticky='w', pady=(12,0))
        self.sender_username_var = tk.StringVar()
        self.sender_username_cb = ttk.Combobox(frm, textvariable=self.sender_username_var, width=67, state='readonly')
        self.sender_username_cb.grid(row=5, column=0, columnspan=2, sticky='w')
        ttk.Button(frm, text='Refresh', command=self._refresh_user_lists).grid(row=5, column=2, sticky='w')

        ttk.Button(frm, text='Load & Decrypt', command=self._on_load_and_decrypt).grid(row=6, column=0, pady=18, sticky='w')

    def _on_browse_encrypted_input(self):
        path = filedialog.askopenfilename(title='Select encrypted JSON package', filetypes=[('JSON','*.json'), ('All','*.*')])
        if path:
            self.encrypted_input_path_var.set(path)

    def _on_browse_receiver_priv(self):
        # legacy/manual
        path = filedialog.askopenfilename(title='Select encrypted private key JSON file', filetypes=[('JSON','*.json'), ('All','*.*')])
        if path:
            self.receiver_priv_path_var.set(path)

    def _on_load_and_decrypt(self):
        encrypted_pkg_path = self.encrypted_input_path_var.get().strip()

        if not encrypted_pkg_path or not os.path.exists(encrypted_pkg_path):
            messagebox.showerror('Error', 'Select a valid encrypted JSON package to load.')
            return

        # Load encrypted package
        try:
            encrypted_pkg = load_encrypted_file(encrypted_pkg_path)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to load encrypted package:\n{e}')
            return

        # Determine receiver private key PEM bytes: use logged-in user state if present
        receiver_priv_pem = None
        if self.current_user:
            try:
                priv_path = self.current_user.get('private_key_path')
                priv_pass = self.current_user.get('passphrase')
                receiver_priv_pem = load_private_key(priv_path, priv_pass)
            except Exception as e:
                messagebox.showerror('Error', f'Failed to load receiver private key from logged-in user:\n{e}')
                return
        elif self.loaded_private_key_pem:
            receiver_priv_pem = self.loaded_private_key_pem
        else:
            messagebox.showerror('Error', 'No receiver private key available. Log in or load a private key first.')
            return

        # Determine sender public key via DB lookup using sender username field
        sender_pub_pem = None
        sender_username = self.sender_username_var.get().strip() if hasattr(self, 'sender_username_var') else ''
        if sender_username:
            try:
                sender_pub_pem = self.db.get_public_key_by_username(sender_username)
            except Exception as e:
                messagebox.showerror('Error', f'Failed to retrieve sender public key from DB:\n{e}')
                return
            if isinstance(sender_pub_pem, str):
                sender_pub_pem = sender_pub_pem.encode()
        else:
            # try to read from package if present (public_key_pem stored as Base64)
            pkg_pub_b64 = encrypted_pkg.get('public_key_pem')
            if pkg_pub_b64:
                try:
                    sender_pub_pem = base64.b64decode(pkg_pub_b64)
                except Exception:
                    sender_pub_pem = None

        if sender_pub_pem is None:
            messagebox.showerror('Error', 'Sender public key required for signature verification. Provide sender username or ensure package contains embedded public key.')
            return

        try:
            plaintext_bytes = decrypt_file(encrypted_pkg, receiver_priv_pem, sender_pub_pem)
        except ValueError:
            messagebox.showerror('TAMPERING DETECTED', 'TAMPERING DETECTED: Signature or authentication tag verification failed.')
            return
        except Exception as e:
            messagebox.showerror('Error', f'Decryption failed:\n{e}')
            return

        # Save decrypted data to disk (user chooses location)
        suggested_name = encrypted_pkg.get('metadata', {}).get('original_filename', 'decrypted_output')
        save_path = filedialog.asksaveasfilename(title='Save decrypted file as', initialfile=suggested_name, defaultextension='', filetypes=[('All','*.*')])
        if not save_path:
            return
        try:
            with open(save_path, 'wb') as f:
                f.write(plaintext_bytes)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to save decrypted file:\n{e}')
            return

        messagebox.showinfo('Success', f'Decrypted file saved to:\n{save_path}')


if __name__ == '__main__':
    app = HybridCryptoGUI()
    app.mainloop()
