// Security-critical primitives, isolated for direct unit testing:
// git URL allowlisting (SSRF guard) and zip extraction (zip-slip / zip-bomb /
// symlink guards). Mirrors web-integration/scan_service.py's design 1:1.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const AdmZip = require('adm-zip');

class RejectedInput extends Error {}

const ALLOWED_GIT_HOSTS = new Set(['github.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org', 'sr.ht']);

const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;        // 20 MB compressed upload cap
const MAX_UNCOMPRESSED_BYTES = 150 * 1024 * 1024; // 150 MB extracted cap (zip-bomb guard)
const MAX_ZIP_FILES = 5000;
const MAX_CLONE_BYTES = 200 * 1024 * 1024;        // 200 MB cloned-repo cap
const CLONE_TIMEOUT_MS = 60_000;

function validateGitUrl(urlStr) {
  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch (e) {
    throw new RejectedInput('invalid URL');
  }
  if (parsed.protocol !== 'https:') {
    throw new RejectedInput('only https:// URLs are allowed');
  }
  const host = parsed.hostname.toLowerCase();
  if (!ALLOWED_GIT_HOSTS.has(host)) {
    throw new RejectedInput(`host not allowed: ${host || '(none)'}`);
  }
  if (parsed.username || parsed.password) {
    throw new RejectedInput('URLs with embedded credentials are not allowed');
  }
  return urlStr;
}

function safeExtractZip(buffer, destDir, limits = {}) {
  const maxFiles = limits.maxFiles ?? MAX_ZIP_FILES;
  const maxUncompressed = limits.maxUncompressed ?? MAX_UNCOMPRESSED_BYTES;

  let zip;
  try {
    zip = new AdmZip(buffer);
  } catch (e) {
    throw new RejectedInput('not a valid zip file');
  }
  const entries = zip.getEntries();
  if (entries.length > maxFiles) {
    throw new RejectedInput(`zip contains too many entries (> ${maxFiles})`);
  }

  let totalUncompressed = 0;
  for (const entry of entries) totalUncompressed += entry.header.size;
  if (totalUncompressed > maxUncompressed) {
    throw new RejectedInput('zip would extract to more than the allowed size limit');
  }

  const destResolved = path.resolve(destDir);
  const validated = [];
  for (const entry of entries) {
    const targetPath = path.resolve(destDir, entry.entryName);
    const rel = path.relative(destResolved, targetPath);
    if (rel.startsWith('..') || path.isAbsolute(rel)) {
      throw new RejectedInput(`unsafe path in zip entry: ${entry.entryName}`);
    }
    const mode = (entry.header.attr >>> 16) & 0xffff;
    if (mode && (mode & 0xf000) === 0xa000) {
      throw new RejectedInput(`symlink entries are not allowed: ${entry.entryName}`);
    }
    validated.push({ entry, targetPath });
  }

  for (const { entry, targetPath } of validated) {
    if (entry.isDirectory) {
      fs.mkdirSync(targetPath, { recursive: true });
    } else {
      fs.mkdirSync(path.dirname(targetPath), { recursive: true });
      fs.writeFileSync(targetPath, entry.getData());
    }
  }
}

function dirSizeBytes(root) {
  let total = 0;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile()) total += fs.statSync(full).size;
    }
  }
  return total;
}

function cloneUrlToTemp(url) {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-url-'));
  const cloneDir = path.join(tmpRoot, 'repo');
  try {
    execFileSync('git', ['clone', '--depth', '1', '--', url, cloneDir], {
      timeout: CLONE_TIMEOUT_MS,
      stdio: ['ignore', 'ignore', 'ignore'],
    });
  } catch (e) {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
    throw new RejectedInput('clone failed');
  }
  return { tmpRoot, cloneDir };
}

module.exports = {
  RejectedInput,
  ALLOWED_GIT_HOSTS,
  MAX_UPLOAD_BYTES,
  MAX_UNCOMPRESSED_BYTES,
  MAX_ZIP_FILES,
  MAX_CLONE_BYTES,
  CLONE_TIMEOUT_MS,
  validateGitUrl,
  safeExtractZip,
  dirSizeBytes,
  cloneUrlToTemp,
};
