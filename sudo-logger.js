#!/usr/bin/env node
import { spawn } from 'child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync } from 'fs';
import { createCipheriv, createDecipheriv, randomBytes, pbkdf2 } from 'crypto';
import { promisify } from 'util';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createInterface } from 'readline';
import { hostname } from 'os';
import simpleGit from 'simple-git';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load config from file (required)
const CONFIG_FILE = join(__dirname, 'config.json');
if (!existsSync(CONFIG_FILE)) {
  console.error('❌ Configuration not found.');
  console.error('Create config.json with:');
  console.error(JSON.stringify({
    ENCRYPTION_PASSWORD: 'your-secret-password',
    GITHUB_REPO: 'username/repo-name',
    GITHUB_USER: 'username',
    GITHUB_TOKEN: 'ghp_xxxxx'
  }, null, 2));
  process.exit(1);
}

const CONFIG = {
  REPO_PATH: join(process.env.HOME, '.sudo-audit-logs'),
  LOG_FILE: 'audit-log.json',
  ...JSON.parse(readFileSync(CONFIG_FILE, 'utf8'))
};

const pbkdf2Async = promisify(pbkdf2);

async function encrypt(text) {
  const salt = randomBytes(16);
  const key = await pbkdf2Async(CONFIG.ENCRYPTION_PASSWORD, salt, 100000, 32, 'sha256');
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([
    cipher.update(text, 'utf8'),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();
  const result = Buffer.concat([salt, iv, authTag, encrypted]);
  return result.toString('base64');
}

async function createLogEntry(command) {
  const entry = {
    timestamp: new Date().toISOString(),
    user: process.env.USER || process.env.USERNAME,
    hostname: hostname(),
    command: command,
    exitCode: null, // Unknown before execution
    output: '',
    cwd: process.cwd()
  };

  return await encrypt(JSON.stringify(entry));
}

async function saveToRepo(encryptedEntry) {
  if (!existsSync(CONFIG.REPO_PATH)) {
    mkdirSync(CONFIG.REPO_PATH, { recursive: true });
  }

  const logFilePath = join(CONFIG.REPO_PATH, CONFIG.LOG_FILE);

  let logs = [];
  if (existsSync(logFilePath)) {
    try {
      logs = JSON.parse(readFileSync(logFilePath, 'utf8'));
    } catch (e) {
      logs = [];
    }
  }

  logs.push({
    id: logs.length + 1,
    encrypted: encryptedEntry
  });

  writeFileSync(logFilePath, JSON.stringify(logs, null, 2));
}

async function copyHtmlViewer() {
  const htmlSource = join(__dirname, 'index.html');
  const htmlDest = join(CONFIG.REPO_PATH, 'index.html');
  const nojekyll = join(CONFIG.REPO_PATH, '.nojekyll');
  
  if (existsSync(htmlSource)) {
    copyFileSync(htmlSource, htmlDest);
  }
  
  // Create .nojekyll for GitHub Pages
  if (!existsSync(nojekyll)) {
    writeFileSync(nojekyll, '');
  }
}

async function pullFromGitHub() {
  const git = simpleGit(CONFIG.REPO_PATH);
  
  try {
    // Clone if repo doesn't exist locally
    if (!existsSync(join(CONFIG.REPO_PATH, '.git'))) {
      console.log('📦 Cloning repository...');
      const remoteUrl = `https://${CONFIG.GITHUB_TOKEN}@github.com/${CONFIG.GITHUB_REPO}.git`;
      await simpleGit().clone(remoteUrl, CONFIG.REPO_PATH);
      
      // Set git config after cloning
      await git.addConfig('user.name', CONFIG.GITHUB_USER || 'Sudo Logger');
      await git.addConfig('user.email', `${CONFIG.GITHUB_USER}@users.noreply.github.com`);
      
      console.log('✅ Repository cloned');
      return true;
    }
    
    // Pull latest changes
    await git.pull('origin', 'main', ['--rebase']);
    console.log('✅ Pulled latest changes');
    return true;
  } catch (error) {
    console.error('❌ GitHub pull failed:', error.message);
    return false;
  }
}

async function checkForTampering() {
  const git = simpleGit(CONFIG.REPO_PATH);
  
  try {
    if (!existsSync(join(CONFIG.REPO_PATH, '.git'))) {
      return [];
    }
    
    // Get all commits that modified audit-log.json
    const log = await git.log(['--all', '--', CONFIG.LOG_FILE]);
    
    const tamperedCommits = [];
    
    for (const commit of log.all) {
      try {
        const diff = await git.show([commit.hash, '--', CONFIG.LOG_FILE]);
        
        // Count deletions (lines starting with -)
        const lines = diff.split('\n');
        let deletions = 0;
        let additions = 0;
        
        for (const line of lines) {
          if (line.startsWith('-') && !line.startsWith('---')) {
            deletions++;
          }
          if (line.startsWith('+') && !line.startsWith('+++')) {
            additions++;
          }
        }
        
        // If there are deletions without equivalent additions, this is tampering
        if (deletions > additions + 2) { // +2 for json formatting tolerance
          tamperedCommits.push({
            hash: commit.hash,
            author: commit.author_name,
            date: commit.date,
            deletions: deletions - 2,
            message: commit.message
          });
        }
      } catch (error) {
        // Skip commits we can't analyze
        console.error(`⚠️  Could not check commit ${commit.hash.substring(0, 7)}:`, error.message);
      }
    }
    
    return tamperedCommits;
  } catch (error) {
    console.error('⚠️  Tamper check warning:', error.message);
    return [];
  }
}

async function logTamperingWarning(tamperInfo) {
  const entry = {
    timestamp: new Date().toISOString(),
    user: process.env.USER || process.env.USERNAME,
    hostname: hostname(),
    command: `[TAMPERING DETECTED] ${tamperInfo.deletions} log entries deleted in commit ${tamperInfo.hash.substring(0, 7)} by ${tamperInfo.author}`,
    exitCode: -1,
    output: `WARNING: Audit log tampering detected!\nCommit: ${tamperInfo.hash}\nAuthor: ${tamperInfo.author}\nDate: ${tamperInfo.date}\nMessage: ${tamperInfo.message}\nDeletions: ${tamperInfo.deletions} entries`,
    cwd: process.cwd()
  };
  
  return await encrypt(JSON.stringify(entry));
}

async function getLoggedTamperCommits() {
  const logFilePath = join(CONFIG.REPO_PATH, CONFIG.LOG_FILE);
  
  if (!existsSync(logFilePath)) {
    return new Set();
  }
  
  try {
    const logs = JSON.parse(readFileSync(logFilePath, 'utf8'));
    const commitHashes = new Set();
    
    for (const log of logs) {
      try {
        const decrypted = JSON.parse(await decrypt(log.encrypted));
        if (decrypted.command && decrypted.command.includes('[TAMPERING DETECTED]')) {
          // Extract commit hash from command
          const match = decrypted.command.match(/commit ([a-f0-9]{7})/);
          if (match) {
            commitHashes.add(match[1]);
          }
        }
      } catch (e) {
        // Skip entries we can't decrypt
      }
    }
    
    return commitHashes;
  } catch (e) {
    return new Set();
  }
}

async function decrypt(encryptedText) {
  const buffer = Buffer.from(encryptedText, 'base64');
  
  const salt = buffer.subarray(0, 16);
  const iv = buffer.subarray(16, 32);
  const authTag = buffer.subarray(32, 48);
  const encrypted = buffer.subarray(48);
  
  const key = await pbkdf2Async(CONFIG.ENCRYPTION_PASSWORD, salt, 100000, 32, 'sha256');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);
  
  return decrypted.toString('utf8');
}

async function pushToGitHub() {
  const git = simpleGit(CONFIG.REPO_PATH);

  try {
    await git.add([CONFIG.LOG_FILE, 'index.html', '.nojekyll']);
    
    // Check if there are changes to commit
    const status = await git.status();
    if (status.files.length === 0) {
      console.log('✅ No changes to push');
      return true;
    }
    
    await git.commit(`Log entry: ${new Date().toISOString()}`);
    await git.push('origin', 'main');

    console.log('✅ Logged to GitHub');
    return true;
  } catch (error) {
    console.error('❌ GitHub push failed:', error.message);
    return false;
  }
}

async function confirmCommand(command) {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    console.log('\n📋 Command: sudo ' + command);
    rl.question('Execute? (y/N): ', (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
    });
  });
}

function execSudo(args) {
  // Replace current process with sudo (similar to bash exec)
  spawn('sudo', args, {
    stdio: 'inherit',
    detached: false
  }).on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exit(code);
    }
  });
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log('Usage: node sudo-logger.js <command> [args...]');
    console.log('Example: node sudo-logger.js apt update');
    process.exit(1);
  }

  const command = args.join(' ');

  // Confirm
  if (!await confirmCommand(command)) {
    console.log('❌ Cancelled');
    process.exit(0);
  }

  // Pull first BEFORE making any changes
  console.log('📥 Pulling from GitHub...');
  const pullSuccess = await pullFromGitHub();
  if (!pullSuccess) {
    console.error('❌ Cannot proceed - GitHub pull failed');
    process.exit(1);
  }

  // Check for tampering after pull
  console.log('🔍 Checking for tampering...');
  const tamperedCommits = await checkForTampering();
  const alreadyLogged = await getLoggedTamperCommits();
  
  if (tamperedCommits.length > 0) {
    console.warn(`⚠️  TAMPERING DETECTED: ${tamperedCommits.length} commit(s) with deletions found!`);
    
    // Log any new tampering we haven't seen before
    for (const tamperInfo of tamperedCommits) {
      const shortHash = tamperInfo.hash.substring(0, 7);
      if (!alreadyLogged.has(shortHash)) {
        console.warn(`   New tampering: Commit ${shortHash} by ${tamperInfo.author}`);
        console.warn(`   ${tamperInfo.deletions} entries deleted`);
        
        const warningEntry = await logTamperingWarning(tamperInfo);
        await saveToRepo(warningEntry);
      }
    }
  }

  // Log BEFORE execution
  console.log('🔐 Encrypting and logging...');
  const encryptedEntry = await createLogEntry(command);
  await saveToRepo(encryptedEntry);

  console.log('📄 Copying HTML viewer...');
  await copyHtmlViewer();

  console.log('📤 Pushing to GitHub...');
  const pushSuccess = await pushToGitHub();
  
  if (!pushSuccess) {
    console.error('❌ Cannot execute sudo - GitHub push failed');
    process.exit(1);
  }

  console.log('🔄 Executing sudo...\n');

  // Replace process with sudo (like bash exec)
  execSudo(args);
}

main().catch(console.error);
