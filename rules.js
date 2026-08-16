// Regex signatures for common infostealer / exfiltration patterns.
// Ported from the Python repo-scanner project (repo_scanner/rules.py there).
// Individual hits are informational — the real signal is the composite
// check in engine.js that looks for *combinations* (recon + outbound call
// in the same file), which is what actually distinguishes malicious code
// from a normal diagnostics/analytics script.

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

const RULES = [
  // --- Exfiltration channels ---
  {
    id: 'telegram-bot-exfil',
    severity: 'critical',
    category: 'exfiltration',
    pattern: /api\.telegram\.org\/bot/i,
    description: 'Sends data directly to a hardcoded Telegram bot API endpoint',
  },
  {
    id: 'discord-webhook-exfil',
    severity: 'high',
    category: 'exfiltration',
    pattern: /discord(?:app)?\.com\/api\/webhooks/i,
    description: 'Sends data to a Discord webhook URL',
  },
  {
    id: 'disguised-exfil-service',
    severity: 'high',
    category: 'exfiltration',
    pattern: /httpdebugger\.com|webhook\.site|requestbin\.(?:com|net)|ngrok\.io|pipedream\.net/i,
    description: 'Uses a 3rd-party request-inspection/relay service, a common way to disguise ' +
      'data exfiltration as a legitimate HTTP debugging call',
  },
  {
    id: 'hardcoded-bot-token',
    severity: 'critical',
    category: 'exfiltration',
    pattern: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/,
    description: 'Hardcoded Telegram bot token pattern',
  },
  // --- Recon / system fingerprinting ---
  {
    id: 'systeminfo-harvest',
    severity: 'medium',
    category: 'recon',
    pattern: /(?:subprocess\.(?:getoutput|check_output|run|Popen)|os\.system)\([^)]*["']systeminfo["']/i,
    description: 'Runs Windows `systeminfo` to dump full system details',
  },
  {
    id: 'whoami-harvest',
    severity: 'low',
    category: 'recon',
    pattern: /["']whoami["']/i,
    description: 'Runs `whoami` to identify the current user',
  },
  {
    id: 'public-ip-lookup',
    severity: 'low',
    category: 'recon',
    pattern: /api\.ipify\.org|ipinfo\.io|ip-api\.com|checkip\.amazonaws\.com/i,
    description: "Looks up the machine's public IP via a 3rd-party service",
  },
  {
    id: 'hostname-collect',
    severity: 'low',
    category: 'recon',
    pattern: /socket\.gethostname\(\)/i,
    description: 'Collects the local hostname (Python)',
  },
  {
    id: 'uname-collect',
    severity: 'low',
    category: 'recon',
    pattern: /platform\.uname\(\)/i,
    description: 'Collects detailed OS/platform fingerprint (Python)',
  },
  {
    id: 'getlogin-collect',
    severity: 'low',
    category: 'recon',
    pattern: /os\.getlogin\(\)|getpass\.getuser\(\)/i,
    description: 'Collects the logged-in username (Python)',
  },
  // --- Credential / browser data theft ---
  {
    id: 'browser-credential-path',
    severity: 'critical',
    category: 'credential-theft',
    pattern: /(User Data|Login Data|Local State)["'\\/].*?(Chrome|Edge|Opera|Brave)/i,
    description: 'References browser credential-store files (saved passwords/cookies)',
  },
  {
    id: 'firefox-profile-path',
    severity: 'high',
    category: 'credential-theft',
    pattern: /Mozilla[\\/]Firefox[\\/]Profiles/i,
    description: 'References Firefox profile directory (often used to steal saved logins)',
  },
  {
    id: 'win32crypt-decrypt',
    severity: 'critical',
    category: 'credential-theft',
    pattern: /win32crypt\.CryptUnprotectData/i,
    description: 'Uses Windows DPAPI decryption, the standard technique for decrypting Chrome-saved passwords',
  },
  // --- Keylogging / clipboard theft ---
  {
    id: 'keylogger-api',
    severity: 'critical',
    category: 'keylogging',
    pattern: /pynput\.keyboard|keyboard\.hook\(|GetAsyncKeyState|SetWindowsHookEx/i,
    description: 'Uses a keyboard-hooking API characteristic of keyloggers',
  },
  {
    id: 'clipboard-read',
    severity: 'medium',
    category: 'credential-theft',
    pattern: /pyperclip\.paste\(\)/i,
    description: 'Reads clipboard contents (often used to steal crypto wallet addresses/passwords)',
  },
  // --- Persistence ---
  {
    id: 'registry-run-key',
    severity: 'high',
    category: 'persistence',
    pattern: /CurrentVersion\\\\Run/i,
    description: 'Writes to the Windows Run registry key for persistence on boot',
  },
  {
    id: 'cron-persistence',
    severity: 'medium',
    category: 'persistence',
    pattern: /crontab -e|\/etc\/cron\./i,
    description: 'Modifies crontab / cron.d for persistence',
  },
  {
    id: 'startup-folder-persistence',
    severity: 'medium',
    category: 'persistence',
    pattern: /Startup[\\/]Microsoft|\.config[\\/]autostart/i,
    description: 'Drops a file into an OS autostart location',
  },
  // --- Obfuscation / droppers ---
  {
    id: 'obfuscated-exec',
    severity: 'high',
    category: 'obfuscation',
    pattern: /(?:exec|eval)\(\s*(?:base64\.b64decode|marshal\.loads|zlib\.decompress|codecs\.decode)/i,
    description: 'Decodes and executes an obfuscated/encoded payload at runtime (Python)',
  },
  {
    id: 'self-writing-script',
    severity: 'medium',
    category: 'dropper',
    pattern: /open\([^)]*\.py["'][^)]*["']w["']\)/i,
    description: 'Writes out a new .py file at runtime (dropper behavior); check what it writes',
  },
  // --- JS/TS recon ---
  {
    id: 'node-os-hostname',
    severity: 'low',
    category: 'recon',
    pattern: /os\.hostname\(\)/i,
    description: 'Collects the local hostname (Node `os` module)',
  },
  {
    id: 'node-os-userinfo',
    severity: 'low',
    category: 'recon',
    pattern: /os\.userInfo\(\)/i,
    description: 'Collects OS user info (username, home dir, shell) via Node `os` module',
  },
  {
    id: 'node-os-netifaces',
    severity: 'low',
    category: 'recon',
    pattern: /os\.networkInterfaces\(\)/i,
    description: 'Enumerates local network interfaces via Node `os` module',
  },
  {
    id: 'node-exec-recon-cmd',
    severity: 'medium',
    category: 'recon',
    pattern: /(?:execSync|exec|spawnSync)\([^)]*["'](?:systeminfo|whoami|ipconfig|ifconfig|uname -a)["']/i,
    description: 'Shells out to a system-fingerprinting command (systeminfo/whoami/ipconfig/...)',
  },
  {
    id: 'browser-useragent-collect',
    severity: 'low',
    category: 'recon',
    pattern: /navigator\.userAgent/i,
    description: 'Collects browser user-agent string',
  },
  {
    id: 'browser-cookie-read',
    severity: 'low',
    category: 'credential-theft',
    pattern: /document\.cookie/i,
    description: 'Reads document.cookie (session/auth cookies). Low on its own; escalates when ' +
      'paired with an outbound network call in the same file (see composite-recon-plus-* findings)',
  },
  {
    id: 'browser-storage-read',
    severity: 'low',
    category: 'credential-theft',
    pattern: /(?:localStorage|sessionStorage)\.getItem\(/i,
    description: 'Reads localStorage/sessionStorage (often holds auth tokens). Low on its own; ' +
      'escalates when paired with an outbound network call in the same file (see composite-recon-plus-* findings)',
  },
  // --- JS/TS exfiltration primitives ---
  {
    id: 'sendbeacon-call',
    severity: 'low',
    category: 'exfiltration',
    pattern: /navigator\.sendBeacon\(/i,
    description: 'Uses navigator.sendBeacon — legitimate for analytics, but also a common covert-exfil ' +
      'channel since it survives page unload and is rarely inspected',
  },
  {
    id: 'image-pixel-beacon',
    severity: 'medium',
    category: 'exfiltration',
    pattern: /new Image\(\)[\s\S]{0,80}?\.src\s*=/i,
    description: 'Builds a tracking-pixel style beacon (new Image(), then .src = ...) — a classic ' +
      'way to exfiltrate data via a GET request that looks like an image load',
  },
  // --- JS/TS obfuscation ---
  {
    id: 'obfuscated-eval-js',
    severity: 'high',
    category: 'obfuscation',
    pattern: /(?:eval|Function)\(\s*(?:atob|unescape|decodeURIComponent)\(/i,
    description: 'Decodes and executes an obfuscated/encoded payload at runtime (JS)',
  },
];

module.exports = { RULES, SEVERITY_ORDER };
