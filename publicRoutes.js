// Public-facing scan routes — pure Node port, no Python/Docker/sidecar needed.
// Mount directly in server.js: app.use(require('./scanner/publicRoutes'));
//
// Same security model as the original Python design:
//   - Report-only: no local-path scanning, no save-to-disk endpoint.
//   - Git URLs restricted to an allowlist of hosts, https:// only (SSRF guard).
//   - Uploaded zips: zip-slip + zip-bomb protected, size/file-count capped.
//   - Every scan runs in a fresh temp dir, deleted before the response returns.
//   - A concurrency cap bounds resource usage regardless of the rate limiter.
//
// Requires: npm install adm-zip   (express, express-rate-limit already used
// elsewhere in this project)
const express = require('express');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const { scanPath } = require('./engine');
const {
  RejectedInput,
  MAX_UPLOAD_BYTES,
  MAX_CLONE_BYTES,
  validateGitUrl,
  safeExtractZip,
  dirSizeBytes,
  cloneUrlToTemp,
} = require('./security');
const fsPath = require('path');
const os = require('os');

const MAX_CONCURRENT_SCANS = 2;
let activeScans = 0;

const router = express.Router();

const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,                  // 20 scans per IP per window — tune to your traffic
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many scan requests. Please try again later.' },
});

router.use('/api/scan', scanLimiter);

router.post('/api/scan/url', express.json({ limit: '10kb' }), (req, res) => {
  const url = req.body && req.body.url;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'url is required' });
  }
  try {
    validateGitUrl(url);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  if (activeScans >= MAX_CONCURRENT_SCANS) {
    return res.status(429).json({ error: 'scanner is busy, try again shortly' });
  }
  activeScans++;
  let tmpRoot;
  try {
    const cloned = cloneUrlToTemp(url);
    tmpRoot = cloned.tmpRoot;
    if (dirSizeBytes(cloned.cloneDir) > MAX_CLONE_BYTES) {
      return res.status(400).json({ error: 'repository exceeds size limit' });
    }
    const { findings, fileCount } = scanPath(cloned.cloneDir);
    return res.json({ findings, file_count: fileCount });
  } catch (e) {
    if (e instanceof RejectedInput) return res.status(400).json({ error: e.message });
    console.error(e);
    return res.status(500).json({ error: 'internal error' });
  } finally {
    activeScans--;
    if (tmpRoot) fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

router.post('/api/scan/zip', express.raw({ type: () => true, limit: MAX_UPLOAD_BYTES }), (req, res) => {
  if (!req.body || !req.body.length) {
    return res.status(400).json({ error: 'empty upload' });
  }
  if (activeScans >= MAX_CONCURRENT_SCANS) {
    return res.status(429).json({ error: 'scanner is busy, try again shortly' });
  }
  activeScans++;
  let tmpRoot;
  try {
    tmpRoot = fs.mkdtempSync(fsPath.join(os.tmpdir(), 'scan-zip-'));
    const extractDir = fsPath.join(tmpRoot, 'extracted');
    fs.mkdirSync(extractDir);
    safeExtractZip(req.body, extractDir);
    const { findings, fileCount } = scanPath(extractDir);
    return res.json({ findings, file_count: fileCount });
  } catch (e) {
    if (e instanceof RejectedInput) return res.status(400).json({ error: e.message });
    console.error(e);
    return res.status(500).json({ error: 'internal error' });
  } finally {
    activeScans--;
    if (tmpRoot) fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

module.exports = router;
