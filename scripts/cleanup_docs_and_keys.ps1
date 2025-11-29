# Cleanup redundant docs and untrack keys
# Run this locally in PowerShell from the repo root.

param(
    [string]$BackupDir = "$env:USERPROFILE\Desktop\hybrid_crypto_backup_$((Get-Date).ToString('yyyyMMdd_HHmmss'))"
)

Write-Host "Creating backup directory: $BackupDir"
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

# Backup keys if directory exists
if (Test-Path -Path .\keys) {
    Write-Host "Backing up keys/ to $BackupDir"
    Copy-Item -Path .\keys -Destination $BackupDir -Recurse -Force
} else {
    Write-Host "No keys/ directory found to backup."
}

# Files to remove
$files = @('PROJECT_SUMMARY.md','INDEX.md','IMPLEMENTATION_SUMMARY.md')

foreach ($f in $files) {
    if (Test-Path -Path $f) {
        Write-Host "Deleting file: $f"
        Remove-Item -Path $f -Force
    } else {
        Write-Host "File not found (skipping): $f"
    }
}

# Ensure keys/ is ignored by .gitignore
if (Test-Path -Path .gitignore) {
    $gitignore = Get-Content .gitignore -Raw
    if ($gitignore -notmatch "^keys/" ) {
        Write-Host "Adding keys/ to .gitignore"
        Add-Content -Path .gitignore -Value "`n# Ignore generated keys\nkeys/"
    } else {
        Write-Host "keys/ already present in .gitignore"
    }
} else {
    Write-Host ".gitignore not found — creating and adding keys/"
    Set-Content -Path .gitignore -Value "# Ignore generated keys`nkeys/"
}

# Attempt git operations (if git is available locally)
if (Get-Command git -ErrorAction SilentlyContinue) {
    Write-Host "Running git commands to stop tracking keys and removed files"
    git rm --cached -r keys 2>$null || Write-Host "keys/ not tracked or already removed from index"
    git rm --cached @($files | Where-Object { Test-Path $_ }) 2>$null || Write-Host "Docs not tracked or already removed from index"
    git add .gitignore
    git commit -m "Remove redundant docs and stop tracking generated keys/ (cleanup)" || Write-Host "Nothing to commit or commit failed"
    Write-Host "If you use a remote, push with: git push origin main"
} else {
    Write-Host "git not found in PATH — please run the following commands locally after verifying backups:"
    Write-Host "  git rm --cached -r keys"
    Write-Host "  git rm --cached PROJECT_SUMMARY.md INDEX.md IMPLEMENTATION_SUMMARY.md"
    Write-Host "  git add .gitignore"
    Write-Host "  git commit -m 'Remove redundant docs and stop tracking generated keys/'"
    Write-Host "  git push origin main"
}

Write-Host "Cleanup script finished. Verify repository status with 'git status' locally."