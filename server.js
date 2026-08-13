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
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

const ALLOWED_CATEGORIES = ['work', 'sports', 'restaurants', 'prices', 'economy'];
const MAX_TEXT_LEN = 2000;
const MAX_SUBJECT_LEN = 140;
const MAX_NAME_LEN = 60;
const MAX_REPLY_LEN = 500;

// ---------- storage: JSON file with a simple write queue to avoid concurrent-write corruption ----------
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify({ reviews: [] }, null, 2));
if (!fs.existsSync(LICENSES_FILE)) fs.writeFileSync(LICENSES_FILE, JSON.stringify({ licenses: [] }, null, 2));

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
app.post('/api/reviews', rateLimit(12), (req, res) => {
  const body = req.body || {};
  const category = body.category;
  const state = clip(body.state, 40);
  const subject = clip(body.subject, MAX_SUBJECT_LEN);
  const text = clip(body.text, MAX_TEXT_LEN);
  const name = clip(body.name, MAX_NAME_LEN) || 'Anonymous';
  const rating = parseInt(body.rating, 10);
  const priceThen = clip(body.priceThen, 20);
  const priceNow = clip(body.priceNow, 20);

  if (!isValidCategory(category)) return res.status(400).json({ error: 'Unknown or missing category.' });
  if (!state) return res.status(400).json({ error: 'State is required.' });
  if (!subject) return res.status(400).json({ error: 'Subject is required.' });
  if (!text) return res.status(400).json({ error: 'Review text is required.' });
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'Rating must be an integer 1-5.' });
  }

  const review = {
    id: makeId(),
    category, state, subject, text, name, rating,
    priceThen, priceNow,
    likes: 0,
    timestamp: Date.now(),
    replies: []
  };

  const data = readData();
  data.reviews.unshift(review);
  writeData(data)
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
app.post('/api/reviews/:id/reply', rateLimit(20), (req, res) => {
  const data = readData();
  const review = data.reviews.find(r => r.id === req.params.id);
  if (!review) return res.status(404).json({ error: 'Review not found.' });

  const name = clip((req.body || {}).name, MAX_NAME_LEN) || 'Anonymous';
  const text = clip((req.body || {}).text, MAX_REPLY_LEN);
  if (!text) return res.status(400).json({ error: 'Reply text is required.' });

  if (!review.replies) review.replies = [];
  review.replies.push({ id: makeId(), name, text, timestamp: Date.now() });

  writeData(data)
    .then(() => res.json({ review }))
    .catch(() => res.status(500).json({ error: 'Could not save reply.' }));
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
