// Truth Button — Reviews API
// A small, self-contained Express backend. Data persists to a local JSON file
// (data/reviews.json). No external database required to get started.
//
// Run locally:   npm install && npm start
// Env vars:
//   PORT                — port to listen on (default 3000)
//   ALLOWED_ORIGIN       — set to your site's origin to lock down CORS in production
//                          (comma-separated for multiple). Defaults to "*" (open) for easy setup.
//   ADMIN_SECRET         — required to view /api/stats (the visitor dashboard). Unset = dashboard disabled.

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'reviews.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const QOTD_FILE = path.join(DATA_DIR, 'qotd.json');
const VISITS_FILE = path.join(DATA_DIR, 'visits.json');

const ALLOWED_CATEGORIES = ['work', 'sports', 'restaurants', 'prices', 'economy'];
const MAX_TEXT_LEN = 2000;
const MAX_SUBJECT_LEN = 140;
const MAX_REPLY_LEN = 500;
const MAX_QUESTION_LEN = 300;
const MAX_PATH_LEN = 200;
const VISIT_DAYS_KEPT = 90; // trim daily counters older than this so the file doesn't grow forever

// ---------- storage: JSON file with a simple write queue to avoid concurrent-write corruption ----------
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify({ reviews: [] }, null, 2));
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [] }, null, 2));
if (!fs.existsSync(QOTD_FILE)) fs.writeFileSync(QOTD_FILE, JSON.stringify({ qotd: null }, null, 2));
if (!fs.existsSync(VISITS_FILE)) fs.writeFileSync(VISITS_FILE, JSON.stringify({ totalViews: 0, byDay: {}, byPath: {}, byReferrer: {}, firstSeen: null, lastSeen: null }, null, 2));

let writeQueue = Promise.resolve();

function readJsonFile(file, fallback){
  try {
    const raw = fs.readFileSync(file, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    return fallback;
  }
}

function writeJsonFile(file, data){
  writeQueue = writeQueue.then(() => {
    return new Promise((resolve, reject) => {
      fs.writeFile(file, JSON.stringify(data, null, 2), err => {
        if (err) reject(err); else resolve();
      });
    });
  });
  return writeQueue;
}

function readData(){ return readJsonFile(DATA_FILE, { reviews: [] }); }
function writeData(data){ return writeJsonFile(DATA_FILE, data); }
function readUsers(){ return readJsonFile(USERS_FILE, { users: [] }); }
function writeUsers(data){ return writeJsonFile(USERS_FILE, data); }
function readQotd(){ return readJsonFile(QOTD_FILE, { qotd: null }); }
function writeQotd(data){ return writeJsonFile(QOTD_FILE, data); }
function readVisits(){ return readJsonFile(VISITS_FILE, { totalViews: 0, byDay: {}, byPath: {}, byReferrer: {}, firstSeen: null, lastSeen: null }); }
function writeVisits(data){ return writeJsonFile(VISITS_FILE, data); }

// ---------- helpers ----------
function makeId(){
  return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
}

function clip(str, max){
  if (typeof str !== 'string') return '';
  return str.slice(0, max).trim();
}

function isValidCategory(c){ return ALLOWED_CATEGORIES.includes(c); }

// ---------- auth: password hashing (scrypt, no extra dependency) + bearer-token sessions ----------
// Sessions live in memory only — they reset if the server restarts (e.g. Render's
// free tier spinning down), same tradeoff as everything else on the free JSON-file setup.
const sessions = new Map(); // token -> userId

function hashPassword(password){
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored){
  const [salt, hash] = String(stored || '').split(':');
  if (!salt || !hash) return false;
  const candidate = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(candidate, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function isValidEmail(email){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }

function publicUser(user){
  return { id: user.id, username: user.username, contributionScore: user.contributionScore || 0 };
}

function requireAuth(req, res, next){
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const userId = token && sessions.get(token);
  if (!userId) return res.status(401).json({ error: 'Sign in required.' });
  const data = readUsers();
  const user = data.users.find(u => u.id === userId);
  if (!user) return res.status(401).json({ error: 'Sign in required.' });
  req.user = user;
  req.token = token;
  next();
}

// ---------- admin: shared-secret gate for the visitor dashboard (not a user account) ----------
const ADMIN_SECRET = process.env.ADMIN_SECRET;
function requireAdmin(req, res, next){
  if (!ADMIN_SECRET) return res.status(503).json({ error: 'Admin dashboard not configured on this server.' });
  const provided = Buffer.from(String(req.headers['x-admin-secret'] || ''));
  const expected = Buffer.from(ADMIN_SECRET);
  const match = provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
  if (!match) return res.status(401).json({ error: 'Unauthorized.' });
  next();
}

function referrerHost(referrer){
  if (!referrer) return 'direct';
  try {
    const host = new URL(referrer).hostname.replace(/^www\./, '');
    return host || 'direct';
  } catch (e) {
    return 'direct';
  }
}

function dayKey(timestamp){
  return new Date(timestamp).toISOString().slice(0, 10); // YYYY-MM-DD, UTC
}

// ---------- app ----------
const app = express();
app.set('trust proxy', 1); // Render sits behind a reverse proxy — without this, req.ip is the proxy's IP for every request, making rate limiting apply to all visitors combined instead of per-visitor
app.disable('x-powered-by');

app.use(helmet());

app.use(express.json({ limit: '100kb' }));

const allowedOrigin = process.env.ALLOWED_ORIGIN;
if (allowedOrigin) {
  const origins = allowedOrigin.split(',').map(o => o.trim());
  app.use(cors({ origin: origins }));
} else {
  app.use(cors()); // open for easy first-time setup; lock down with ALLOWED_ORIGIN in production
}

// global floor: blunts broad floods before they even reach route-specific limits below
app.use(perMinute(300));

// per-route rate limiting (express-rate-limit: bounded memory, auto-expiring buckets —
// unlike a hand-rolled version, old IPs don't linger forever and leak memory)
function perMinute(max){
  return rateLimit({
    windowMs: 60000,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Slow down a bit.' }
  });
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

// ---------- visitor tracking ----------

// POST /api/visit — fired once per page load from the frontend. Stores aggregated
// counters only (no per-visit log, no IPs) to keep the file small and visitors anonymous.
// Named deliberately generic (not "/track") since ad-blockers and privacy extensions
// (uBlock's EasyPrivacy, Brave Shields, Firefox ETP) filter requests by URL patterns
// containing "track" — a plain analytics-sounding path avoids that silently eating hits.
app.post('/api/visit', perMinute(30), (req, res) => {
  const body = req.body || {};
  const visitPath = clip(body.path, MAX_PATH_LEN) || '/';
  const host = referrerHost(body.referrer);
  const now = Date.now();
  const today = dayKey(now);

  const visits = readVisits();
  visits.totalViews = (visits.totalViews || 0) + 1;
  visits.byDay[today] = (visits.byDay[today] || 0) + 1;
  visits.byPath[visitPath] = (visits.byPath[visitPath] || 0) + 1;
  visits.byReferrer[host] = (visits.byReferrer[host] || 0) + 1;
  visits.firstSeen = visits.firstSeen || now;
  visits.lastSeen = now;

  const cutoff = new Date(now - VISIT_DAYS_KEPT * 86400000).toISOString().slice(0, 10);
  for (const day of Object.keys(visits.byDay)) {
    if (day < cutoff) delete visits.byDay[day];
  }

  writeVisits(visits)
    .then(() => res.status(201).json({ ok: true }))
    .catch(() => res.status(500).json({ error: 'Could not record visit.' }));
});

// GET /api/stats — the private dashboard's data source. Requires the ADMIN_SECRET
// header, not a user login (this isn't tied to the reviews accounts system).
app.get('/api/stats', requireAdmin, (req, res) => {
  const visits = readVisits();
  const topN = (obj, n) => Object.entries(obj)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([key, count]) => ({ key, count }));

  res.json({
    totalViews: visits.totalViews || 0,
    firstSeen: visits.firstSeen,
    lastSeen: visits.lastSeen,
    byDay: visits.byDay,
    topPaths: topN(visits.byPath, 15),
    topReferrers: topN(visits.byReferrer, 15)
  });
});

// ---------- auth ----------

// POST /api/auth/signup — free, plain accounts, no roles.
app.post('/api/auth/signup', perMinute(10), (req, res) => {
  const body = req.body || {};
  const username = clip(body.username, 30);
  const email = clip(body.email, 200).toLowerCase();
  const password = String(body.password || '');

  if (username.length < 2) return res.status(400).json({ error: 'Username must be at least 2 characters.' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const data = readUsers();
  if (data.users.some(u => u.email === email)) return res.status(400).json({ error: 'An account with that email already exists.' });
  if (data.users.some(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(400).json({ error: 'That username is taken.' });

  const user = {
    id: makeId(),
    username, email,
    passwordHash: hashPassword(password),
    contributionScore: 0,
    createdAt: Date.now()
  };
  data.users.push(user);
  writeUsers(data)
    .then(() => {
      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, user.id);
      res.status(201).json({ token, user: publicUser(user) });
    })
    .catch(() => res.status(500).json({ error: 'Could not create account.' }));
});

// POST /api/auth/login
app.post('/api/auth/login', perMinute(20), (req, res) => {
  const body = req.body || {};
  const email = clip(body.email, 200).toLowerCase();
  const password = String(body.password || '');

  const data = readUsers();
  const user = data.users.find(u => u.email === email);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, user.id);
  res.json({ token, user: publicUser(user) });
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

// ---------- QOTD + leaderboard ----------

app.get('/api/qotd', (req, res) => {
  res.json({ qotd: readQotd().qotd });
});

app.get('/api/leaderboard', (req, res) => {
  const data = readUsers();
  const leaderboard = data.users
    .map(u => ({ username: u.username, contributionScore: u.contributionScore || 0 }))
    .filter(u => u.contributionScore > 0)
    .sort((a, b) => b.contributionScore - a.contributionScore);
  res.json({ leaderboard });
});

// POST /api/qotd — only the current top contributor can set it
app.post('/api/qotd', requireAuth, perMinute(10), (req, res) => {
  const question = clip((req.body || {}).question, MAX_QUESTION_LEN);
  if (!question) return res.status(400).json({ error: 'Question is required.' });

  const usersData = readUsers();
  const leaderboard = usersData.users
    .map(u => ({ id: u.id, contributionScore: u.contributionScore || 0 }))
    .sort((a, b) => b.contributionScore - a.contributionScore);
  const isTop = leaderboard.length > 0 && leaderboard[0].id === req.user.id && leaderboard[0].contributionScore > 0;
  if (!isTop) return res.status(403).json({ error: 'Only the top contributor can set the question of the day.' });

  const qotd = { question, setBy: req.user.username, setAt: Date.now() };
  writeQotd({ qotd })
    .then(() => res.json({ qotd }))
    .catch(() => res.status(500).json({ error: 'Could not save the question.' }));
});

// GET /api/reviews?category=work&state=texas
app.get('/api/reviews', (req, res) => {
  const { category, state } = req.query;
  if (category && !isValidCategory(category)) {
    return res.status(400).json({ error: 'Unknown category.' });
  }
  const data = readData();
  let results = data.reviews;
  if (category) results = results.filter(r => r.category === category);
  if (state) results = results.filter(r => r.state.toLowerCase() === String(state).toLowerCase());
  results = results.slice().sort((a, b) => b.timestamp - a.timestamp);
  res.json({ reviews: results });
});

// POST /api/reviews
app.post('/api/reviews', requireAuth, perMinute(12), (req, res) => {
  const body = req.body || {};
  const category = body.category;
  const state = clip(body.state, 40);
  const subject = clip(body.subject, MAX_SUBJECT_LEN);
  const text = clip(body.text, MAX_TEXT_LEN);
  const rating = parseInt(body.rating, 10);
  const priceThen = clip(body.priceThen, 20);
  const priceNow = clip(body.priceNow, 20);
  const sportType = clip(body.sportType, 40);

  if (!isValidCategory(category)) return res.status(400).json({ error: 'Unknown or missing category.' });
  if (!state) return res.status(400).json({ error: 'State is required.' });
  if (!subject) return res.status(400).json({ error: 'Subject is required.' });
  if (!text) return res.status(400).json({ error: 'Review text is required.' });
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'Rating must be an integer 1-5.' });
  }

  const review = {
    id: makeId(),
    category, state, subject, text, name: req.user.username, rating,
    priceThen, priceNow, sportType,
    likes: 0,
    timestamp: Date.now(),
    replies: []
  };

  const data = readData();
  data.reviews.unshift(review);

  const usersData = readUsers();
  const user = usersData.users.find(u => u.id === req.user.id);
  if (user) user.contributionScore = (user.contributionScore || 0) + 3;

  Promise.all([writeData(data), writeUsers(usersData)])
    .then(() => res.status(201).json({ review }))
    .catch(() => res.status(500).json({ error: 'Could not save review.' }));
});

// POST /api/reviews/:id/like
app.post('/api/reviews/:id/like', perMinute(60), (req, res) => {
  const data = readData();
  const review = data.reviews.find(r => r.id === req.params.id);
  if (!review) return res.status(404).json({ error: 'Review not found.' });
  review.likes = (review.likes || 0) + 1;
  writeData(data)
    .then(() => res.json({ review }))
    .catch(() => res.status(500).json({ error: 'Could not save like.' }));
});

// POST /api/reviews/:id/reply
app.post('/api/reviews/:id/reply', requireAuth, perMinute(20), (req, res) => {
  const data = readData();
  const review = data.reviews.find(r => r.id === req.params.id);
  if (!review) return res.status(404).json({ error: 'Review not found.' });

  const text = clip((req.body || {}).text, MAX_REPLY_LEN);
  if (!text) return res.status(400).json({ error: 'Reply text is required.' });

  if (!review.replies) review.replies = [];
  review.replies.push({ id: makeId(), name: req.user.username, text, timestamp: Date.now() });

  const usersData = readUsers();
  const user = usersData.users.find(u => u.id === req.user.id);
  if (user) user.contributionScore = (user.contributionScore || 0) + 1;

  Promise.all([writeData(data), writeUsers(usersData)])
    .then(() => res.json({ review }))
    .catch(() => res.status(500).json({ error: 'Could not save reply.' }));
});

// ---------- fallbacks: never leak a stack trace or Express's default HTML error page ----------
app.use((req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request too large.' });
  }
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Malformed request body.' });
  }
  console.error(err);
  res.status(500).json({ error: 'Something went wrong.' });
});

app.listen(PORT, () => {
  console.log('Truth Button Reviews API listening on port ' + PORT);
});
