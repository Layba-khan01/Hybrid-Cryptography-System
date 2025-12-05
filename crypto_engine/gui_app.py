"""
Simple Tkinter GUI for the Hybrid Cryptography System.

- Location: crypto_engine/gui_app.py
- Uses only the required functions from hybrid_crypto.py:
  generate_rsa_keypair, load_private_key, encrypt_file, decrypt_file, save_encrypted_file, load_encrypted_file

Tabs:
- Key Management
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

        self._build_ui()

    def _build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill='both', expand=True, padx=8, pady=8)

        # Tabs
        tab_keys = ttk.Frame(notebook)
        tab_encrypt = ttk.Frame(notebook)
        tab_decrypt = ttk.Frame(notebook)

        notebook.add(tab_keys, text='Key Management')
        notebook.add(tab_encrypt, text='Encrypt & Share')
        notebook.add(tab_decrypt, text='Receive & Decrypt')

        self._build_key_management_tab(tab_keys)
        self._build_encrypt_tab(tab_encrypt)
        self._build_decrypt_tab(tab_decrypt)

    # ------------------------------
    # Key Management Tab
    # ------------------------------
    def _build_key_management_tab(self, parent):
        frm = ttk.Frame(parent, padding=12)
        frm.pack(fill='both', expand=True)

        # Generate Keypair
        lbl_gen = ttk.Label(frm, text='Generate RSA-4096 Key Pair (encrypted private key on disk)')
        lbl_gen.grid(row=0, column=0, columnspan=3, sticky='w')

        btn_generate = ttk.Button(frm, text='Generate Key Pair', command=self._on_generate_keypair)
        btn_generate.grid(row=1, column=0, sticky='w', pady=8)

        self.lbl_pub_path = ttk.Label(frm, text='Public key file: -')
        self.lbl_pub_path.grid(row=2, column=0, columnspan=3, sticky='w')

        self.lbl_priv_path = ttk.Label(frm, text='Encrypted private key file: -')
        self.lbl_priv_path.grid(row=3, column=0, columnspan=3, sticky='w')

        # Load existing private key (decrypt)
        sep = ttk.Separator(frm, orient='horizontal')
        sep.grid(row=4, column=0, columnspan=3, sticky='ew', pady=12)

        btn_load_priv = ttk.Button(frm, text='Load Encrypted Private Key...', command=self._on_load_private_key)
        btn_load_priv.grid(row=5, column=0, sticky='w')

        self.lbl_loaded_priv = ttk.Label(frm, text='Loaded private key: None')
        self.lbl_loaded_priv.grid(row=6, column=0, columnspan=3, sticky='w', pady=(6,0))

        # Load public key
        btn_load_pub = ttk.Button(frm, text='Load Public Key...', command=self._on_load_public_key)
        btn_load_pub.grid(row=7, column=0, sticky='w', pady=8)

        self.lbl_loaded_pub = ttk.Label(frm, text='Loaded public key: None')
        self.lbl_loaded_pub.grid(row=8, column=0, columnspan=3, sticky='w')

    def _on_generate_keypair(self):
        # Ask for passphrase (masked)
        passphrase = simpledialog.askstring("Passphrase", "Enter passphrase to protect private key:", show='*', parent=self)
        if passphrase is None:
            return
        # Ask role (sender/receiver) and validate
        while True:
            role = simpledialog.askstring("Role", "Enter role for the key pair ('sender' or 'receiver'):", parent=self)
            if role is None:
                return
            role = role.strip().lower()
            if role in ("sender", "receiver"):
                break
            messagebox.showerror("Invalid role", "Please enter either 'sender' or 'receiver'.")

        # Destination directory (base); keys will be saved under <output_dir>/<role>/
        base_output_dir = filedialog.askdirectory(title='Select directory to save keys (will create files)')
        if not base_output_dir:
            return
        output_dir = os.path.join(base_output_dir, role)

        try:
            result = generate_rsa_keypair(passphrase=passphrase, output_dir=output_dir)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key pair:\n{e}")
            return

        # result contains 'private_key_file' and 'public_key_file'
        priv = result.get('private_key_file')
        pub = result.get('public_key_file')
        self.lbl_pub_path.config(text=f'Public key file ({role}): {pub or "-"}')
        self.lbl_priv_path.config(text=f'Encrypted private key file ({role}): {priv or "-"}')

        messagebox.showinfo("Success", f"Key pair for role '{role}' generated and saved to:\n{output_dir}")

    def _on_load_private_key(self):
        # Choose encrypted private key JSON file
        path = filedialog.askopenfilename(title='Select encrypted private key JSON file', filetypes=[('JSON', '*.json'), ('All', '*.*')])
        if not path:
            return

        passphrase = simpledialog.askstring("Passphrase", "Enter passphrase to decrypt private key:", show='*', parent=self)
        if passphrase is None:
            return

        try:
            priv_pem = load_private_key(path, passphrase)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load private key:\n{e}")
            return

        # store in memory
        self.loaded_private_key_pem = priv_pem
        self.loaded_private_key_path = path
        self.lbl_loaded_priv.config(text=f'Loaded private key: {os.path.basename(path)}')
        messagebox.showinfo("Success", "Private key loaded into memory")

    def _on_load_public_key(self):
        path = filedialog.askopenfilename(title='Select public key PEM file', filetypes=[('PEM', '*.pem'), ('All', '*.*')])
        if not path:
            return
        try:
            with open(path, 'rb') as f:
                pub = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read public key file:\n{e}")
            return

        self.loaded_public_key_pem = pub
        self.loaded_public_key_path = path
        self.lbl_loaded_pub.config(text=f'Loaded public key: {os.path.basename(path)}')
        messagebox.showinfo("Success", "Public key loaded into memory")

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

        # Receiver public key
        ttk.Label(frm, text='Receiver public key (PEM file):').grid(row=2, column=0, sticky='w', pady=(12,0))
        self.receiver_pub_path_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.receiver_pub_path_var, width=70).grid(row=3, column=0, columnspan=2, sticky='w')
        ttk.Button(frm, text='Browse...', command=self._on_browse_receiver_pub).grid(row=3, column=2, sticky='w')

        # Sender private key (choose file or use loaded)
        ttk.Label(frm, text='Sender private key (use loaded or browse encrypted file):').grid(row=4, column=0, sticky='w', pady=(12,0))
        self.sender_priv_path_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.sender_priv_path_var, width=70).grid(row=5, column=0, columnspan=2, sticky='w')
        ttk.Button(frm, text='Browse...', command=self._on_browse_sender_priv).grid(row=5, column=2, sticky='w')

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
        path = filedialog.askopenfilename(title='Select receiver public key PEM', filetypes=[('PEM','*.pem'), ('All','*.*')])
        if path:
            self.receiver_pub_path_var.set(path)

    def _on_browse_sender_priv(self):
        path = filedialog.askopenfilename(title='Select sender encrypted private key JSON', filetypes=[('JSON','*.json'), ('All','*.*')])
        if path:
            self.sender_priv_path_var.set(path)

    def _on_browse_encrypted_output(self):
        path = filedialog.asksaveasfilename(title='Save encrypted package as', defaultextension='.json', filetypes=[('JSON','*.json'), ('All','*.*')])
        if path:
            self.encrypted_output_path_var.set(path)

    def _on_encrypt_and_save(self):
        input_path = self.encrypt_input_path_var.get().strip()
        receiver_pub_path = self.receiver_pub_path_var.get().strip()
        sender_priv_path = self.sender_priv_path_var.get().strip()
        output_path = self.encrypted_output_path_var.get().strip()

        if not input_path or not os.path.exists(input_path):
            messagebox.showerror('Error', 'Select a valid input file to encrypt.')
            return
        if not receiver_pub_path or not os.path.exists(receiver_pub_path):
            messagebox.showerror('Error', 'Select a valid receiver public key PEM file.')
            return
        if not output_path:
            messagebox.showerror('Error', 'Select a path to save the encrypted JSON package.')
            return

        # Read receiver public key PEM bytes
        try:
            with open(receiver_pub_path, 'rb') as f:
                receiver_pub_pem = f.read()
        except Exception as e:
            messagebox.showerror('Error', f'Failed to read receiver public key:\n{e}')
            return

        # Determine sender private key PEM bytes: prefer loaded in-memory, else decrypt from chosen file
        sender_priv_pem = None
        if self.loaded_private_key_pem:
            sender_priv_pem = self.loaded_private_key_pem
        elif sender_priv_path:
            # need passphrase to decrypt the selected private key
            passphrase = simpledialog.askstring('Passphrase', 'Enter passphrase to decrypt sender private key:', show='*', parent=self)
            if passphrase is None:
                return
            try:
                sender_priv_pem = load_private_key(sender_priv_path, passphrase)
            except Exception as e:
                messagebox.showerror('Error', f'Failed to load sender private key:\n{e}')
                return
        else:
            messagebox.showerror('Error', 'No sender private key provided. Either load it in Key Management or select the encrypted private key file here.')
            return

        # All good: call encrypt_file (it accepts a path or raw bytes)
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

        ttk.Label(frm, text='Receiver private key (decrypt from encrypted key file):').grid(row=2, column=0, sticky='w', pady=(12,0))
        self.receiver_priv_path_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.receiver_priv_path_var, width=70).grid(row=3, column=0, columnspan=2, sticky='w')
        ttk.Button(frm, text='Browse...', command=self._on_browse_receiver_priv).grid(row=3, column=2, sticky='w')

        ttk.Button(frm, text='Load & Decrypt', command=self._on_load_and_decrypt).grid(row=4, column=0, pady=18, sticky='w')

    def _on_browse_encrypted_input(self):
        path = filedialog.askopenfilename(title='Select encrypted JSON package', filetypes=[('JSON','*.json'), ('All','*.*')])
        if path:
            self.encrypted_input_path_var.set(path)

    def _on_browse_receiver_priv(self):
        path = filedialog.askopenfilename(title='Select encrypted private key JSON file', filetypes=[('JSON','*.json'), ('All','*.*')])
        if path:
            self.receiver_priv_path_var.set(path)

    def _on_load_and_decrypt(self):
        encrypted_pkg_path = self.encrypted_input_path_var.get().strip()
        receiver_priv_path = self.receiver_priv_path_var.get().strip()

        if not encrypted_pkg_path or not os.path.exists(encrypted_pkg_path):
            messagebox.showerror('Error', 'Select a valid encrypted JSON package to load.')
            return

        if not receiver_priv_path and not self.loaded_private_key_pem:
            messagebox.showerror('Error', 'No receiver private key provided. Load one in Key Management or select encrypted private key JSON here.')
            return

        # Load encrypted package
        try:
            encrypted_pkg = load_encrypted_file(encrypted_pkg_path)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to load encrypted package:\n{e}')
            return

        # Determine receiver private key PEM bytes
        receiver_priv_pem = None
        if self.loaded_private_key_pem:
            # prefer in-memory loaded key
            receiver_priv_pem = self.loaded_private_key_pem
        else:
            passphrase = simpledialog.askstring('Passphrase', 'Enter passphrase to decrypt your private key:', show='*', parent=self)
            if passphrase is None:
                return
            try:
                receiver_priv_pem = load_private_key(receiver_priv_path, passphrase)
            except Exception as e:
                messagebox.showerror('Error', f'Failed to load receiver private key:\n{e}')
                return

        # Try to decrypt. On ValueError we must show TAMPERING DETECTED as required.
        # Determine sender public key to use for verification
        sender_pub_pem = None
        if self.loaded_public_key_pem:
            sender_pub_pem = self.loaded_public_key_pem
        else:
            # try to read from package if present (public_key_pem stored as Base64)
            pkg_pub_b64 = encrypted_pkg.get('public_key_pem')
            if pkg_pub_b64:
                try:
                    sender_pub_pem = base64.b64decode(pkg_pub_b64)
                except Exception:
                    sender_pub_pem = None

        # If still missing, prompt user to select sender public key PEM file
        if sender_pub_pem is None:
            choose_path = filedialog.askopenfilename(title='Select sender public key PEM (or Cancel to abort)', filetypes=[('PEM','*.pem'), ('All','*.*')])
            if not choose_path:
                messagebox.showerror('Error', 'Sender public key required for signature verification. Aborting.')
                return
            try:
                with open(choose_path, 'rb') as f:
                    sender_pub_pem = f.read()
            except Exception as e:
                messagebox.showerror('Error', f'Failed to read sender public key:\n{e}')
                return

        try:
            plaintext_bytes = decrypt_file(encrypted_pkg, receiver_priv_pem, sender_pub_pem)
        except ValueError as e:
            # Signature or GCM tag verification failure or other value errors
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
