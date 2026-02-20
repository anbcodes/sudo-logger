# Sudo Audit Logger

Single-file encrypted sudo command logger that logs to GitHub BEFORE execution.

## Features

- ✅ Single file - pure Node.js (no bash)
- 🔐 AES-256-GCM encryption
- ⚠️ Confirms command before execution
- 📤 **Logs BEFORE running sudo** (ensures audit trail even if command fails/crashes)
- 🔍 Beautiful web viewer with decryption

## Installation

1. Install dependencies:
```bash
npm install
```

2. Create `config.json`:
```json
{
  "ENCRYPTION_PASSWORD": "your-secret-password",
  "GITHUB_REPO": "username/repo-name",
  "GITHUB_USER": "username",
  "GITHUB_TOKEN": "ghp_xxxxxxxxxxxxx"
}
```

Get GitHub token: Settings → Developer settings → Personal access tokens → Generate new token
- Required permission: `repo`

3. Create an alias:
```bash
echo 'alias s="node /path/to/sudo-logger.js"' >> ~/.bashrc
source ~/.bashrc
```

## Usage

```bash
s apt update
```

Flow:
1. Confirms command
2. **Encrypts and logs to GitHub**
3. Executes sudo command

## View Logs

To decrypt and view your logs locally:
```bash
node decrypt-viewer.js
```

## Security Notes

⚠️ **Important Security Considerations:**

1. **Password Storage**: The encryption password is stored in `config.json` (NOT in the scripts). Keep this file secure!
2. **GitHub Token**: Your GitHub token is also in `config.json` - never commit this file (it's in .gitignore)
3. **Public Repo**: The scripts can be public, but `config.json` must stay private. Logs are encrypted - only someone with your password can read them
4. **Node.js Security**: This uses native Node.js crypto (no external crypto libraries needed)
5. **Sudo Access**: This script still uses real sudo - it's a wrapper, not a replacement

## How Encryption Works

- **Algorithm**: AES-256-GCM (Galois/Counter Mode for authenticated encryption)
- **Key Derivation**: scrypt with random salt
- **Authentication**: Built-in authentication tag prevents tampering
- **Each entry**: Independently encrypted with unique IV and salt

## Files

- `sudo-logger.js` - Main wrapper script
- `setup.js` - Configuration setup
- `decrypt-viewer.js` - View decrypted logs locally
- `config.json` - Your configuration (created by setup, DO NOT COMMIT)
- `~/.sudo-audit-logs/` - Local log storage and git repo

## Troubleshooting

**"GitHub not configured"**: Run `npm run setup` first

**"Failed to push to GitHub"**: 
- Check your GitHub token has `repo` permissions
- Ensure the repository exists
- Try creating the repo first on GitHub

**"Failed to decrypt"**: Wrong password or corrupted data

## Viewing Logs in Browser (GitHub Pages)

Since logs are pushed to GitHub, you can view them in a web browser:

1. **Enable GitHub Pages**:
   - Go to your repo Settings → Pages
   - Source: Deploy from a branch
   - Branch: main, folder: / (root)
   - Save

2. **Copy `index.html` to your logs repo**:
   ```bash
   cp index.html ~/.sudo-audit-logs/
   cd ~/.sudo-audit-logs
   git add index.html
   git commit -m "Add web viewer"
   git push
   ```

3. **Access your logs**:
   - Visit: `https://yourusername.github.io/your-repo-name/`
   - Enter your encryption password
   - View decrypted logs with beautiful formatting

4. **Share with others**:
   - The repo can be public (logs are encrypted)
   - Share the GitHub Pages URL and password securely
   - Decryption happens entirely in the browser (client-side)

The web viewer shows:
- Command history with timestamps
- User and hostname information
- Exit codes (success/failure)
- Working directory
- Statistics (total commands, success rate)
