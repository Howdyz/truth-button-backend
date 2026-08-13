// Truth Button — Reviews API
// A small, self-contained Express backend. Data persists to a local JSON file
// (data/reviews.json). No external database required to get started.
//
// Run locally:   npm install && npm start
// Env vars:
//   PORT              — port to listen on (default 3000)
//   ALLOWED_ORIGIN     — set to your site's origin to lock down CORS in production
//                        (comma-separated for multiple). Defaults to "*" (open) for easy setup.

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const stripe = process.env.STRIPE_SECRET_KEY ? require('stripe')(process.env.STRIPE_SECRET_KEY) : null;

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'reviews.json');
const LICENSES_FILE = path.join(DATA_DIR, 'licenses.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const QOTD_FILE = path.join(DATA_DIR, 'qotd.json');
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

const ALLOWED_CATEGORIES = ['work', 'sports', 'restaurants', 'prices', 'economy'];
const MAX_TEXT_LEN = 2000;
const MAX_SUBJECT_LEN = 140;
const MAX_NAME_LEN = 60;
const MAX_REPLY_LEN = 500;
const MAX_QUESTION_LEN = 300;

// ---------- storage: JSON file with a simple write queue to avoid concurrent-write corruption ----------
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify({ reviews: [] }, null, 2));
if (!fs.existsSync(LICENSES_FILE)) fs.writeFileSync(LICENSES_FILE, JSON.stringify({ licenses: [] }, null, 2));
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [] }, null, 2));
if (!fs.existsSync(QOTD_FILE)) fs.writeFileSync(QOTD_FILE, JSON.stringify({ qotd: null }, null, 2));

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
function readLicenses(){ return readJsonFile(LICENSES_FILE, { licenses: [] }); }
function writeLicenses(data){ return writeJsonFile(LICENSES_FILE, data); }
function readUsers(){ return readJsonFile(USERS_FILE, { users: [] }); }
function writeUsers(data){ return writeJsonFile(USERS_FILE, data); }
function readQotd(){ return readJsonFile(QOTD_FILE, { qotd: null }); }
function writeQotd(data){ return writeJsonFile(QOTD_FILE, data); }

function makeLicenseKey(){
  const part = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `TB-${part()}-${part()}-${part()}`;
}

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
  return { id: user.id, username: user.username, role: user.role, contributionScore: user.contributionScore || 0 };
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

function requireAdmin(req, res, next){
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
    next();
  });
}

// ---------- app ----------
const app = express();

// Stripe webhook needs the raw request body to verify the signature, so this
// route is registered before the global express.json() body parser below.
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(503).send('Stripe not configured.');
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send('Webhook signature verification failed.');
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const license = {
      key: makeLicenseKey(),
      sessionId: session.id,
      email: (session.customer_details && session.customer_details.email) || session.customer_email || '',
      createdAt: Date.now(),
      active: true
    };
    const data = readLicenses();
    data.licenses.push(license);
    writeLicenses(data).catch(() => {});
  }

  res.json({ received: true });
});

app.use(express.json({ limit: '100kb' }));

const allowedOrigin = process.env.ALLOWED_ORIGIN;
if (allowedOrigin) {
  const origins = allowedOrigin.split(',').map(o => o.trim());
  app.use(cors({ origin: origins }));
} else {
  app.use(cors()); // open for easy first-time setup; lock down with ALLOWED_ORIGIN in production
}

// very light rate limiting per IP (in-memory, resets on restart — fine for a small community feature)
const rateBuckets = new Map();
function rateLimit(maxPerMinute){
  return (req, res, next) => {
    const ip = req.ip || 'unknown';
    const now = Date.now();
    const bucket = rateBuckets.get(ip) || [];
    const recent = bucket.filter(t => now - t < 60000);
    if (recent.length >= maxPerMinute) {
      return res.status(429).json({ error: 'Too many requests. Slow down a bit.' });
    }
    recent.push(now);
    rateBuckets.set(ip, recent);
    next();
  };
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

// ---------- auth ----------

// POST /api/auth/signup — the very first account ever created becomes admin automatically,
// so the site owner just has to sign up first on a fresh deploy.
app.post('/api/auth/signup', rateLimit(10), (req, res) => {
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
    role: data.users.length === 0 ? 'admin' : 'member',
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
app.post('/api/auth/login', rateLimit(20), (req, res) => {
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

// POST /api/qotd — only the current top contributor or an admin can set it
app.post('/api/qotd', requireAuth, rateLimit(10), (req, res) => {
  const question = clip((req.body || {}).question, MAX_QUESTION_LEN);
  if (!question) return res.status(400).json({ error: 'Question is required.' });

  const usersData = readUsers();
  const leaderboard = usersData.users
    .map(u => ({ id: u.id, contributionScore: u.contributionScore || 0 }))
    .sort((a, b) => b.contributionScore - a.contributionScore);
  const isTop = leaderboard.length > 0 && leaderboard[0].id === req.user.id && leaderboard[0].contributionScore > 0;
  const isAdmin = req.user.role === 'admin';
  if (!isTop && !isAdmin) return res.status(403).json({ error: 'Only the top contributor or an admin can set the question of the day.' });

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
app.post('/api/reviews', requireAuth, rateLimit(12), (req, res) => {
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
app.post('/api/reviews/:id/like', rateLimit(60), (req, res) => {
  const data = readData();
  const review = data.reviews.find(r => r.id === req.params.id);
  if (!review) return res.status(404).json({ error: 'Review not found.' });
  review.likes = (review.likes || 0) + 1;
  writeData(data)
    .then(() => res.json({ review }))
    .catch(() => res.status(500).json({ error: 'Could not save like.' }));
});

// POST /api/reviews/:id/reply
app.post('/api/reviews/:id/reply', requireAuth, rateLimit(20), (req, res) => {
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

// ---------- admin ----------

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const users = readUsers().users;
  const reviews = readData().reviews;
  res.json({
    totalUsers: users.length,
    totalAdmins: users.filter(u => u.role === 'admin').length,
    totalReviews: reviews.length,
    totalReplies: reviews.reduce((sum, r) => sum + (r.replies ? r.replies.length : 0), 0)
  });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = readUsers().users.slice().sort((a, b) => (b.contributionScore || 0) - (a.contributionScore || 0));
  res.json({ users: users.map(publicUser) });
});

app.post('/api/admin/users/:id/role', requireAdmin, (req, res) => {
  const role = (req.body || {}).role;
  if (role !== 'admin' && role !== 'member') return res.status(400).json({ error: 'Role must be "admin" or "member".' });
  const data = readUsers();
  const user = data.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  user.role = role;
  writeUsers(data)
    .then(() => res.json({ user: publicUser(user) }))
    .catch(() => res.status(500).json({ error: 'Could not update role.' }));
});

app.delete('/api/admin/reviews/:id', requireAdmin, (req, res) => {
  const data = readData();
  const before = data.reviews.length;
  data.reviews = data.reviews.filter(r => r.id !== req.params.id);
  if (data.reviews.length === before) return res.status(404).json({ error: 'Review not found.' });
  writeData(data)
    .then(() => res.json({ ok: true }))
    .catch(() => res.status(500).json({ error: 'Could not delete review.' }));
});

// POST /api/admin/license/backfill — manually create a license for a completed Checkout
// Session that the webhook never received (e.g. the destination didn't exist yet, or
// was misconfigured at the time of purchase). body: { sessionId, email }
app.post('/api/admin/license/backfill', requireAdmin, (req, res) => {
  const sessionId = clip((req.body || {}).sessionId, 200);
  const email = clip((req.body || {}).email, 200);
  if (!sessionId) return res.status(400).json({ error: 'sessionId is required.' });

  const data = readLicenses();
  const existing = data.licenses.find(l => l.sessionId === sessionId);
  if (existing) return res.json({ key: existing.key, alreadyExisted: true });

  const license = { key: makeLicenseKey(), sessionId, email, createdAt: Date.now(), active: true };
  data.licenses.push(license);
  writeLicenses(data)
    .then(() => res.status(201).json({ key: license.key }))
    .catch(() => res.status(500).json({ error: 'Could not create license.' }));
});

// GET /api/license/for-session?session_id=cs_xxx
// Used by the post-checkout success page to display the key. The webhook usually
// beats the redirect, but if the key isn't there yet this returns 202 so the
// page can retry briefly instead of treating it as a hard failure.
app.get('/api/license/for-session', rateLimit(30), (req, res) => {
  const sessionId = req.query.session_id;
  if (!sessionId) return res.status(400).json({ error: 'session_id is required.' });
  const data = readLicenses();
  const license = data.licenses.find(l => l.sessionId === sessionId);
  if (!license) return res.status(202).json({ pending: true });
  res.json({ key: license.key });
});

// POST /api/license/verify — body: { key }
app.post('/api/license/verify', rateLimit(20), (req, res) => {
  const key = clip((req.body || {}).key, 40).toUpperCase();
  if (!key) return res.status(400).json({ error: 'License key is required.' });
  const data = readLicenses();
  const license = data.licenses.find(l => l.key === key);
  res.json({ valid: !!(license && license.active) });
});

app.listen(PORT, () => {
  console.log('Truth Button Reviews API listening on port ' + PORT);
});
