// Core scan engine — pure JS port of the Python repo_scanner package.
//
// Same design as the Python version's composite check: individual regex
// rule hits (rules.js) are informational; the strong signal is a file that
// both collects recon-style data AND ships it out over the network in the
// same file. This port has no AST — everything is regex/text based, same
// approach already used (and tested) for JS/TS in the Python version.
const fs = require('fs');
const path = require('path');
const { RULES, SEVERITY_ORDER } = require('./rules');

const EXCLUDED_DIRS = new Set(['.git', 'venv', '.venv', 'node_modules', '__pycache__', 'dist', 'build', '.tox']);
const SCAN_EXTENSIONS = new Set(['.py', '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx']);
const JS_TS_EXTENSIONS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx']);

const EXFIL_HOST_HINTS = [
  'api.telegram.org',
  'discord.com/api/webhooks',
  'discordapp.com/api/webhooks',
  'httpdebugger.com',
  'webhook.site',
  'requestbin',
  'ngrok.io',
  'pipedream.net',
];

// Python composite: recon + a `requests.*`/urllib call in the same file.
// Kept at a single "critical" tier (matching the original AST-based Python
// version) since "requests.get/post(" combined with recon is still a fairly
// narrow, uncommon combination even via text search — unlike bare fetch()
// in JS, which is used in nearly every web app.
const PY_RECON_PATTERNS = [
  /socket\.gethostname\(\)/i,
  /platform\.uname\(\)/i,
  /os\.getlogin\(\)/i,
  /getpass\.getuser\(\)/i,
  /["'](?:systeminfo|whoami)["']/i,
];
const PY_EXFIL_PATTERNS = [
  /requests\.(?:post|get|put|request)\(/i,
  /urllib\.request\.urlopen\(/i,
  /http\.client\./i,
];

// JS/TS composite: three tiers, same as the tested Python version —
// known exfil host = critical, beacon/pixel = high, generic fetch/XHR = medium
// (generic network calls alone are too common in legitimate code to treat
// as critical).
const JS_RECON_PATTERNS = [
  /os\.hostname\(\)/i,
  /os\.userInfo\(\)/i,
  /os\.networkInterfaces\(\)/i,
  /navigator\.userAgent/i,
  /document\.cookie/i,
  /process\.env/i,
  /(?:localStorage|sessionStorage)\.getItem\(/i,
];
const JS_STRONG_EXFIL_PATTERNS = [
  /navigator\.sendBeacon\(/i,
  /new Image\(\)[\s\S]{0,80}?\.src\s*=/i,
];
const JS_GENERIC_NETWORK_PATTERNS = [
  /fetch\(/i,
  /axios\.(?:post|get|put)\(/i,
  /XMLHttpRequest/i,
];

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

function firstMatchLine(text, patterns) {
  let best = null;
  for (const p of patterns) {
    const m = p.exec(text);
    if (m) {
      const line = lineOf(text, m.index);
      if (best === null || line < best) best = line;
    }
  }
  return best || 1;
}

function regexScan(filePath, text) {
  const findings = [];
  for (const rule of RULES) {
    const re = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g');
    let m;
    while ((m = re.exec(text)) !== null) {
      const line = lineOf(text, m.index);
      const lineText = text.split('\n')[line - 1] || '';
      findings.push({
        rule_id: rule.id,
        severity: rule.severity,
        category: rule.category,
        description: rule.description,
        file: filePath,
        line,
        snippet: lineText.trim().slice(0, 160),
      });
      if (m.index === re.lastIndex) re.lastIndex++; // guard against zero-width matches
    }
  }
  return findings;
}

function pyCompositeScan(filePath, text) {
  const reconHit = PY_RECON_PATTERNS.some(p => p.test(text));
  if (!reconHit) return [];
  const exfilHit = PY_EXFIL_PATTERNS.some(p => p.test(text));
  if (!exfilHit) return [];
  const line = firstMatchLine(text, PY_RECON_PATTERNS);
  return [{
    rule_id: 'composite-recon-plus-exfil-py',
    severity: 'critical',
    category: 'infostealer',
    description: 'File both collects system/user information AND makes an outbound HTTP request ' +
      '(requests/urllib) in the same file. This is the core pattern of an infostealer that phones ' +
      'home with harvested data.',
    file: filePath,
    line,
    snippet: '(recon pattern + requests/urllib call in same file)',
  }];
}

function jsCompositeScan(filePath, text) {
  const reconHit = JS_RECON_PATTERNS.some(p => p.test(text));
  if (!reconHit) return [];

  const hasExfilHost = EXFIL_HOST_HINTS.some(h => text.includes(h));
  const strongExfil = JS_STRONG_EXFIL_PATTERNS.some(p => p.test(text));
  const genericNetwork = JS_GENERIC_NETWORK_PATTERNS.some(p => p.test(text));

  if (hasExfilHost) {
    const line = firstMatchLine(text, JS_RECON_PATTERNS);
    return [{
      rule_id: 'composite-recon-plus-exfil-js',
      severity: 'critical',
      category: 'infostealer',
      description: 'File collects recon-style data (cookies/localStorage/user-agent/os info/env vars) ' +
        'AND references a known exfil-style endpoint (bot API, webhook, relay service) in the same file.',
      file: filePath,
      line,
      snippet: '(recon pattern + known exfil host in same file)',
    }];
  }
  if (strongExfil) {
    const line = firstMatchLine(text, JS_RECON_PATTERNS);
    return [{
      rule_id: 'composite-recon-plus-beacon-js',
      severity: 'high',
      category: 'infostealer',
      description: 'File collects recon-style data AND uses a beacon-style call (sendBeacon / ' +
        'tracking-pixel Image().src) to send it out. Common in legitimate analytics too — verify the destination.',
      file: filePath,
      line,
      snippet: '(recon pattern + sendBeacon/Image beacon in same file)',
    }];
  }
  if (genericNetwork) {
    const line = firstMatchLine(text, JS_RECON_PATTERNS);
    return [{
      rule_id: 'composite-recon-plus-network-js',
      severity: 'medium',
      category: 'infostealer',
      description: 'File collects recon-style data AND makes a generic network call (fetch/axios/XHR) ' +
        'in the same file. May be entirely legitimate (e.g. reporting client info to your own API) — ' +
        "verify the destination and what's actually sent.",
      file: filePath,
      line,
      snippet: '(recon pattern + fetch/axios/XHR in same file)',
    }];
  }
  return [];
}

function scanText(filePath, text) {
  const findings = regexScan(filePath, text);
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.py') {
    findings.push(...pyCompositeScan(filePath, text));
  } else if (JS_TS_EXTENSIONS.has(ext)) {
    findings.push(...jsCompositeScan(filePath, text));
  }
  return findings;
}

function scanFile(filePath) {
  let text;
  try {
    text = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    return [];
  }
  return scanText(filePath, text);
}

function walkFiles(root) {
  const out = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      continue;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (EXCLUDED_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        stack.push(path.join(dir, entry.name));
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SCAN_EXTENSIONS.has(ext)) out.push(path.join(dir, entry.name));
      }
    }
  }
  return out;
}

function countAllFiles(root) {
  let count = 0;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      continue;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (EXCLUDED_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        stack.push(path.join(dir, entry.name));
      } else if (entry.isFile()) {
        count++;
      }
    }
  }
  return count;
}

function relativizeFindings(findings, base) {
  return findings.map(f => ({ ...f, file: path.relative(base, f.file) || path.basename(f.file) }));
}

function scanPath(targetPath) {
  const stat = fs.statSync(targetPath);
  if (stat.isFile()) {
    return { findings: scanFile(targetPath), fileCount: 1 };
  }
  const files = walkFiles(targetPath);
  const findings = files.flatMap(scanFile);
  return { findings: relativizeFindings(findings, targetPath), fileCount: countAllFiles(targetPath) };
}

module.exports = { scanPath, scanFile, scanText, SEVERITY_ORDER, EXFIL_HOST_HINTS };
