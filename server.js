// Truth Button — Reviews API
// A small, self-contained Express backend. Data persists to Upstash Redis
// (REST API, no extra client library needed — just fetch). Render's free
// tier has no persistent disk, so local JSON files get wiped on every
// restart; Redis is what actually survives across deploys/restarts.
//
// Run locally:   npm install && npm start
// Env vars:
//   PORT                     — port to listen on (default 3000)
//   ALLOWED_ORIGIN            — set to your site's origin to lock down CORS in production
//                               (comma-separated for multiple). Defaults to "*" (open) for easy setup.
//   ADMIN_SECRET              — required to view /api/stats (the visitor dashboard). Unset = dashboard disabled.
//   UPSTASH_REDIS_REST_URL    — Upstash Redis REST endpoint (e.g. https://xxx.upstash.io).
//   UPSTASH_REDIS_REST_TOKEN  — Upstash Redis REST token.
//   Without the two Upstash vars set, storage falls back to an in-memory store
//   (fine for local dev/testing — NOT persistent, resets on every restart).
//   STRIPE_DOWNLOADER_SECRET_KEY — Stripe secret key (sk_live_... or sk_test_...) for the Lightning
//                               Downloader unlock specifically. Deliberately separate from any other
//                               Stripe key already in use elsewhere (e.g. donations) — a Stripe secret
//                               key is account-wide, but keeping this one distinctly named means it can
//                               never be accidentally overwritten by or collide with another feature's
//                               credentials. Unset = checkout disabled (trial still works, unlock button
//                               errors).
//   STRIPE_DOWNLOADER_WEBHOOK_SECRET — signing secret for the /api/downloader/webhook endpoint, from
//                               the Stripe Dashboard webhook you point at that URL. Each Stripe webhook
//                               endpoint has its own unique secret, so this must stay separate from any
//                               other webhook's secret too. Required to actually mark an account
//                               unlocked after payment — without it, paid sessions are never confirmed.
//   FRONTEND_URL              — where Stripe Checkout redirects after payment (default: the live site).

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const Stripe = require('stripe');
const scannerRoutes = require('./scanner/publicRoutes');

// Express 4 does NOT catch a rejected promise from an async handler — it becomes an
// unhandled rejection, which crashes the whole process on modern Node (terminates by
// default since Node 15). Every async route/middleware below is wrapped in this so a
// transient Redis hiccup returns a clean 500 to one request instead of killing the
// server for every visitor.
function asyncHandler(fn){
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

const PORT = process.env.PORT || 3000;

// ---------- Lightning Downloader unlock: Stripe (one-time payment, no pre-created Price needed —
// the amount is defined inline in the Checkout Session below) ----------
const STRIPE_DOWNLOADER_SECRET_KEY = process.env.STRIPE_DOWNLOADER_SECRET_KEY;
const STRIPE_DOWNLOADER_WEBHOOK_SECRET = process.env.STRIPE_DOWNLOADER_WEBHOOK_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://projectsilverbeam.com';
const DOWNLOADER_UNLOCK_PRICE_USD = 1000; // $10.00, in cents
const stripe = STRIPE_DOWNLOADER_SECRET_KEY ? new Stripe(STRIPE_DOWNLOADER_SECRET_KEY) : null;
if (!STRIPE_DOWNLOADER_SECRET_KEY) {
  console.warn('STRIPE_DOWNLOADER_SECRET_KEY not set — Lightning Downloader unlock checkout is disabled.');
}

const ALLOWED_CATEGORIES = ['work', 'sports', 'restaurants', 'prices', 'economy'];
const MAX_TEXT_LEN = 2000;
const MAX_SUBJECT_LEN = 140;
const MAX_REPLY_LEN = 500;
const MAX_QUESTION_LEN = 300;
const MAX_PATH_LEN = 200;
const VISIT_DAYS_KEPT = 90; // trim daily counters older than this so the record doesn't grow forever
const MAX_ADVERTISER_LEN = 60;
const MAX_HEADLINE_LEN = 100;
const MAX_AD_BODY_LEN = 200;
const MAX_URL_LEN = 500;
const MAX_QR_LABEL_LEN = 80;
const MAX_PHOTO_BASE64_LEN = 1500000; // ~1.5MB of base64 text (~1.1MB binary) — plenty for a client-compressed JPEG
const PHOTO_TTL_SECONDS = 60 * 60 * 24 * 90; // hosted photos auto-expire after 90 days

// ---------- storage: Upstash Redis REST API, with an in-memory fallback for local dev ----------
const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const memoryStore = new Map();

if (!REDIS_URL || !REDIS_TOKEN) {
  console.warn('UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN not set — using in-memory storage. ' +
    'Data will NOT persist across restarts. Set both env vars in production.');
}

async function storeGet(key, fallback){
  if (!REDIS_URL || !REDIS_TOKEN) {
    return memoryStore.has(key) ? memoryStore.get(key) : fallback;
  }
  const res = await fetch(`${REDIS_URL}/get/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${REDIS_TOKEN}` }
  });
  if (!res.ok) throw new Error('Redis GET failed: ' + res.status);
  const data = await res.json();
  if (data.result == null) return fallback;
  try { return JSON.parse(data.result); } catch (e) { return fallback; }
}

async function storeSet(key, value){
  if (!REDIS_URL || !REDIS_TOKEN) {
    memoryStore.set(key, value);
    return;
  }
  const res = await fetch(`${REDIS_URL}/set/${encodeURIComponent(key)}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${REDIS_TOKEN}`, 'Content-Type': 'text/plain' },
    body: JSON.stringify(value)
  });
  if (!res.ok) throw new Error('Redis SET failed: ' + res.status);
}

async function storeSetWithTTL(key, value, ttlSeconds){
  if (!REDIS_URL || !REDIS_TOKEN) {
    memoryStore.set(key, value);
    // setTimeout's delay is a 32-bit signed int internally — anything longer (90 days in ms
    // overflows it) silently clamps to ~1ms instead of throwing, deleting the entry almost
    // immediately. Cap at the max safe delay; this is the dev-only fallback anyway (data
    // doesn't survive a restart regardless), so an eventual-but-not-exact expiry is fine.
    if (ttlSeconds) setTimeout(() => memoryStore.delete(key), Math.min(ttlSeconds * 1000, 2147483647)).unref();
    return;
  }
  const res = await fetch(`${REDIS_URL}/set/${encodeURIComponent(key)}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${REDIS_TOKEN}`, 'Content-Type': 'text/plain' },
    body: JSON.stringify(value)
  });
  if (!res.ok) throw new Error('Redis SET failed: ' + res.status);
  const exRes = await fetch(`${REDIS_URL}/expire/${encodeURIComponent(key)}/${ttlSeconds}`, {
    headers: { Authorization: `Bearer ${REDIS_TOKEN}` }
  });
  if (!exRes.ok) throw new Error('Redis EXPIRE failed: ' + exRes.status);
}

function readData(){ return storeGet('tb:reviews', { reviews: [] }); }
function writeData(data){ return storeSet('tb:reviews', data); }
function readUsers(){ return storeGet('tb:users', { users: [] }); }
function writeUsers(data){ return storeSet('tb:users', data); }
function readQotd(){ return storeGet('tb:qotd', { qotd: null }); }
function writeQotd(data){ return storeSet('tb:qotd', data); }
function readVisits(){ return storeGet('tb:visits', { totalViews: 0, byDay: {}, byPath: {}, byReferrer: {}, firstSeen: null, lastSeen: null }); }
function writeVisits(data){ return storeSet('tb:visits', data); }
function readAds(){ return storeGet('tb:ads', { ads: [] }); }
function writeAds(data){ return storeSet('tb:ads', data); }
function readQrLinks(){ return storeGet('tb:qrlinks', { links: [] }); }
function writeQrLinks(data){ return storeSet('tb:qrlinks', data); }

// ---------- helpers ----------
function makeId(){
  return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
}

function clip(str, max){
  if (typeof str !== 'string') return '';
  return str.slice(0, max).trim();
}

// Proper HTML escaping — safe for BOTH text-content and attribute-value
// contexts (unlike the frontend's textContent/innerHTML round-trip, which
// only escapes for text content and was the root of an XSS found in an
// earlier audit). Used for the server-rendered /go/:id interstitial page.
function escapeHtmlServer(str){
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function isValidCategory(c){ return ALLOWED_CATEGORIES.includes(c); }

// ---------- auth: password hashing (scrypt, no extra dependency) + bearer-token sessions ----------
// Sessions live in memory only — they reset if the server restarts (e.g. Render's
// free tier spinning down). Reviews/users/ads/visits now survive that via Redis;
// being logged out on restart is a much smaller tradeoff than losing data outright.
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
  return { id: user.id, username: user.username, contributionScore: user.contributionScore || 0, downloaderUnlocked: !!user.downloaderUnlocked };
}

const requireAuth = asyncHandler(async (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const userId = token && sessions.get(token);
  if (!userId) return res.status(401).json({ error: 'Sign in required.' });
  const data = await readUsers();
  const user = data.users.find(u => u.id === userId);
  if (!user) return res.status(401).json({ error: 'Sign in required.' });
  req.user = user;
  req.token = token;
  next();
});

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

function isValidHttpUrl(str){
  try {
    const u = new URL(str);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch (e) {
    return false;
  }
}

function publicAd(ad){
  return { id: ad.id, advertiser: ad.advertiser, headline: ad.headline, body: ad.body, imageUrl: ad.imageUrl || null };
}

// ---------- app ----------
const app = express();
app.set('trust proxy', 1); // Render sits behind a reverse proxy — without this, req.ip is the proxy's IP for every request, making rate limiting apply to all visitors combined instead of per-visitor
app.disable('x-powered-by');

app.use(helmet());

// CORS needs to be mounted before ANY route (not just before the global express.json()
// below) — a route registered earlier than this in the stack (like the Stripe webhook,
// or /api/photos, both special-cased to run before the global json() body-size limit)
// would otherwise send its real response with no CORS headers at all. The browser's
// preflight OPTIONS request wouldn't catch this, since OPTIONS doesn't match a
// method-specific app.post() route and falls through to here regardless — only the
// actual POST/GET response would silently fail client-side. Found via a real browser
// test on /api/photos: preflight succeeded, the real POST failed with net::ERR_FAILED.
const allowedOrigin = process.env.ALLOWED_ORIGIN;
if (allowedOrigin) {
  const origins = allowedOrigin.split(',').map(o => o.trim());
  app.use(cors({ origin: origins }));
} else {
  app.use(cors()); // open for easy first-time setup; lock down with ALLOWED_ORIGIN in production
}

// Stripe webhook needs the raw, unparsed request body to verify the signature —
// it MUST be registered before the global express.json() below, or that middleware
// would consume/transform the body first and signature verification would fail.
app.post('/api/downloader/webhook', express.raw({ type: 'application/json' }), asyncHandler(async (req, res) => {
  if (!stripe || !STRIPE_DOWNLOADER_WEBHOOK_SECRET) return res.status(503).send('Webhook not configured.');

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_DOWNLOADER_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send('Webhook signature verification failed.');
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    // This webhook is account-wide in Stripe — it would also fire for ANY other
    // Checkout session ever created on this account (e.g. if donations moves off
    // the static Payment Link to real Checkout someday). The metadata tag is what
    // actually scopes this to "the downloader was paid for," not just the presence
    // of a client_reference_id. Also require payment_status === 'paid' rather than
    // trusting "completed" alone — completed can fire before an async payment
    // method (bank debit, etc.) actually clears, though card payments (the only
    // method offered here) are always synchronous so this is defense-in-depth.
    const isDownloaderUnlock = session.metadata && session.metadata.product === 'downloader-unlock';
    const userId = session.client_reference_id;
    if (isDownloaderUnlock && session.payment_status === 'paid' && userId) {
      const data = await readUsers();
      const user = data.users.find(u => u.id === userId);
      if (user && !user.downloaderUnlocked) {
        user.downloaderUnlocked = true;
        user.downloaderUnlockedAt = Date.now();
        await writeUsers(data);
      }
    }
  }

  res.json({ received: true });
}));

// POST /api/photos — signed-in only. Lets a user host a single photo (already
// compressed client-side to a data URL) to get a public URL — built for the Share
// Page tool, since Facebook/etc. need a real https og:image URL and most people
// don't have one handy. Reuses the existing Upstash Redis storage, no new
// credentials needed. Registered here, with its own json() limit, and BEFORE the
// global 100kb one below — same reason as the Stripe webhook above: a compressed
// photo is bigger than this site's normal JSON payloads, so it needs its own parser
// ahead of the stricter global default. Sign-in is required for the same reason QR
// trackable links require it: an open, anyone-can-host-anything endpoint on a
// trusted domain is a real abuse vector (illegal/abusive content, bandwidth theft),
// and tying every upload to an account makes it accountable/revocable.
app.post('/api/photos', express.json({ limit: '2mb' }), requireAuth, perMinute(10), asyncHandler(async (req, res) => {
  const dataUrl = (req.body || {}).dataUrl;
  const match = typeof dataUrl === 'string' && dataUrl.match(/^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/);
  if (!match) return res.status(400).json({ error: 'Expected a JPEG, PNG, or WebP image.' });
  const mime = 'image/' + match[1];
  const base64 = match[2];
  if (base64.length > MAX_PHOTO_BASE64_LEN) return res.status(413).json({ error: 'Photo is too large — try a smaller or more compressed image.' });

  let id, exists;
  do {
    id = makeShortId();
    exists = await storeGet('tb:photo:' + id, null);
  } while (exists);

  await storeSetWithTTL('tb:photo:' + id, { id, userId: req.user.id, mime, base64, createdAt: Date.now() }, PHOTO_TTL_SECONDS);
  res.status(201).json({ id, url: `${req.protocol}://${req.get('host')}/photos/${id}`, expiresInDays: PHOTO_TTL_SECONDS / 86400 });
}));

app.use(express.json({ limit: '100kb' }));

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

// global floor: blunts broad floods before they even reach route-specific limits below
app.use(perMinute(300));

app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

// ---------- visitor tracking ----------

// POST /api/visit — fired once per page load from the frontend. Stores aggregated
// counters only (no per-visit log, no IPs) to keep the record small and visitors anonymous.
// Named deliberately generic (not "/track") since ad-blockers and privacy extensions
// (uBlock's EasyPrivacy, Brave Shields, Firefox ETP) filter requests by URL patterns
// containing "track" — a plain analytics-sounding path avoids that silently eating hits.
app.post('/api/visit', perMinute(30), asyncHandler(async (req, res) => {
  const body = req.body || {};
  const visitPath = clip(body.path, MAX_PATH_LEN) || '/';
  const host = referrerHost(body.referrer);
  const now = Date.now();
  const today = dayKey(now);

  const visits = await readVisits();
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

  await writeVisits(visits);
  res.status(201).json({ ok: true });
}));

// GET /api/stats — the private dashboard's data source. Requires the ADMIN_SECRET
// header, not a user login (this isn't tied to the reviews accounts system).
app.get('/api/stats', requireAdmin, asyncHandler(async (req, res) => {
  const visits = await readVisits();
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
}));

// ---------- ads ----------

// GET /api/ads/active — public. Returns active ads (no impression/click counts —
// those are only exposed to the admin) so the frontend can pick one to display.
app.get('/api/ads/active', asyncHandler(async (req, res) => {
  const data = await readAds();
  const active = data.ads.filter(a => a.active).map(publicAd);
  res.json({ ads: active });
}));

// GET /api/ads/:id/click — records the click, then redirects to the advertiser's URL.
// A plain link (not a JS fetch) so it works reliably in new tabs / with JS disabled.
app.get('/api/ads/:id/click', perMinute(120), asyncHandler(async (req, res) => {
  const data = await readAds();
  const ad = data.ads.find(a => a.id === req.params.id);
  if (!ad || !ad.active) return res.status(404).json({ error: 'Ad not found.' });
  ad.clicks = (ad.clicks || 0) + 1;
  writeAds(data).catch(() => {});
  res.redirect(302, ad.linkUrl);
}));

// POST /api/ads/:id/impression — fired once when an ad is actually shown.
app.post('/api/ads/:id/impression', perMinute(120), asyncHandler(async (req, res) => {
  const data = await readAds();
  const ad = data.ads.find(a => a.id === req.params.id);
  if (!ad) return res.status(404).json({ error: 'Ad not found.' });
  ad.impressions = (ad.impressions || 0) + 1;
  writeAds(data)
    .then(() => res.json({ ok: true }))
    .catch(() => res.status(500).json({ error: 'Could not record impression.' }));
}));

// GET /api/ads — admin: full list including stats, active or not.
app.get('/api/ads', requireAdmin, asyncHandler(async (req, res) => {
  const data = await readAds();
  res.json({ ads: data.ads });
}));

// POST /api/ads — admin: create a new ad.
app.post('/api/ads', requireAdmin, asyncHandler(async (req, res) => {
  const body = req.body || {};
  const advertiser = clip(body.advertiser, MAX_ADVERTISER_LEN);
  const headline = clip(body.headline, MAX_HEADLINE_LEN);
  const adBody = clip(body.body, MAX_AD_BODY_LEN);
  const linkUrl = clip(body.linkUrl, MAX_URL_LEN);
  const imageUrl = clip(body.imageUrl, MAX_URL_LEN);

  if (!advertiser) return res.status(400).json({ error: 'Advertiser name is required.' });
  if (!headline) return res.status(400).json({ error: 'Headline is required.' });
  if (!isValidHttpUrl(linkUrl)) return res.status(400).json({ error: 'A valid http(s) link URL is required.' });
  if (imageUrl && !isValidHttpUrl(imageUrl)) return res.status(400).json({ error: 'Image URL must be a valid http(s) link.' });

  const ad = {
    id: makeId(),
    advertiser, headline, body: adBody, linkUrl,
    imageUrl: imageUrl || null,
    active: body.active !== false,
    impressions: 0,
    clicks: 0,
    createdAt: Date.now()
  };
  const data = await readAds();
  data.ads.unshift(ad);
  writeAds(data)
    .then(() => res.status(201).json({ ad }))
    .catch(() => res.status(500).json({ error: 'Could not save ad.' }));
}));

// PATCH /api/ads/:id — admin: edit fields or toggle active.
app.patch('/api/ads/:id', requireAdmin, asyncHandler(async (req, res) => {
  const data = await readAds();
  const ad = data.ads.find(a => a.id === req.params.id);
  if (!ad) return res.status(404).json({ error: 'Ad not found.' });

  const body = req.body || {};
  if (body.advertiser !== undefined) ad.advertiser = clip(body.advertiser, MAX_ADVERTISER_LEN);
  if (body.headline !== undefined) ad.headline = clip(body.headline, MAX_HEADLINE_LEN);
  if (body.body !== undefined) ad.body = clip(body.body, MAX_AD_BODY_LEN);
  if (body.linkUrl !== undefined) {
    if (!isValidHttpUrl(body.linkUrl)) return res.status(400).json({ error: 'A valid http(s) link URL is required.' });
    ad.linkUrl = clip(body.linkUrl, MAX_URL_LEN);
  }
  if (body.imageUrl !== undefined) {
    const img = clip(body.imageUrl, MAX_URL_LEN);
    if (img && !isValidHttpUrl(img)) return res.status(400).json({ error: 'Image URL must be a valid http(s) link.' });
    ad.imageUrl = img || null;
  }
  if (body.active !== undefined) ad.active = !!body.active;

  writeAds(data)
    .then(() => res.json({ ad }))
    .catch(() => res.status(500).json({ error: 'Could not update ad.' }));
}));

// DELETE /api/ads/:id — admin: remove an ad entirely.
app.delete('/api/ads/:id', requireAdmin, asyncHandler(async (req, res) => {
  const data = await readAds();
  const before = data.ads.length;
  data.ads = data.ads.filter(a => a.id !== req.params.id);
  if (data.ads.length === before) return res.status(404).json({ error: 'Ad not found.' });
  writeAds(data)
    .then(() => res.json({ ok: true }))
    .catch(() => res.status(500).json({ error: 'Could not delete ad.' }));
}));

// ---------- auth ----------

// POST /api/auth/signup — free, plain accounts, no roles.
app.post('/api/auth/signup', perMinute(10), asyncHandler(async (req, res) => {
  const body = req.body || {};
  const username = clip(body.username, 30);
  const email = clip(body.email, 200).toLowerCase();
  const password = String(body.password || '');

  if (username.length < 2) return res.status(400).json({ error: 'Username must be at least 2 characters.' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const data = await readUsers();
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
}));

// POST /api/auth/login
app.post('/api/auth/login', perMinute(20), asyncHandler(async (req, res) => {
  const body = req.body || {};
  const email = clip(body.email, 200).toLowerCase();
  const password = String(body.password || '');

  const data = await readUsers();
  const user = data.users.find(u => u.email === email);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, user.id);
  res.json({ token, user: publicUser(user) });
}));

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

// DELETE /api/auth/account — signed-in only, self-service. Permanently removes the
// caller's own account and invalidates their session. Doesn't touch reviews/replies
// they've posted (those keep their username as free text, same as if any other
// historical author record disappeared) — just the account + login credentials.
app.delete('/api/auth/account', requireAuth, asyncHandler(async (req, res) => {
  const data = await readUsers();
  data.users = data.users.filter(u => u.id !== req.user.id);
  await writeUsers(data);
  sessions.delete(req.token);
  res.json({ ok: true });
}));

// ---------- Lightning Downloader unlock ----------

// POST /api/downloader/checkout — signed-in only. Creates a Stripe Checkout session for
// the one-time unlock and returns its URL; the frontend opens it in a new tab so the
// original tab's in-memory session survives (this site doesn't persist auth across reloads).
app.post('/api/downloader/checkout', requireAuth, perMinute(10), asyncHandler(async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Payments are not configured on this server yet.' });
  if (req.user.downloaderUnlocked) return res.status(400).json({ error: 'Already unlocked.' });

  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    payment_method_types: ['card'],
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: 'Lightning Downloader — Lifetime Unlock' },
        unit_amount: DOWNLOADER_UNLOCK_PRICE_USD
      },
      quantity: 1
    }],
    client_reference_id: req.user.id,
    metadata: { product: 'downloader-unlock' }, // scopes the webhook to only this checkout flow — see the webhook handler
    success_url: `${FRONTEND_URL}/index.html?mode=downloader&paid=1`,
    cancel_url: `${FRONTEND_URL}/index.html?mode=downloader`
  });

  res.json({ url: session.url });
}));

// GET /api/downloader/status — signed-in only. Lets the frontend re-check unlock status
// on demand (e.g. after returning from Stripe) without requiring a fresh login.
app.get('/api/downloader/status', requireAuth, asyncHandler(async (req, res) => {
  res.json({ unlocked: !!req.user.downloaderUnlocked });
}));

// ---------- QR trackable landing pages ----------
// Signed-in only to create (see comment on the route below for why an open
// URL-redirect creator on this domain would be a real abuse risk). Public to
// visit — that's the whole point, someone scans a QR code and lands here.

function makeShortId(){
  return Math.random().toString(36).slice(2, 8) + Math.random().toString(36).slice(2, 4);
}

function qrLandingPageHtml({ destinationUrl, label, ownerName }){
  const safeUrl = escapeHtmlServer(destinationUrl);
  const safeLabel = label ? escapeHtmlServer(label) : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex">
<title>${safeLabel ? safeLabel + ' — ' : ''}Continue via The Truth Button</title>
<style>
  body{margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#14110F; color:#F2EDE1; font-family:system-ui,-apple-system,sans-serif;}
  .card{max-width:440px; margin:24px; padding:32px; background:#1C1814; border:1px solid rgba(242,237,225,0.14); border-radius:12px; text-align:center;}
  .kicker{font-size:11px; letter-spacing:0.14em; text-transform:uppercase; color:#E8C23C; margin-bottom:14px;}
  h1{font-size:20px; margin:0 0 10px;}
  .dest{font-size:13px; color:#8C8377; word-break:break-all; margin-bottom:24px;}
  a.go{display:inline-block; background:#2F8F7A; color:#14110F; text-decoration:none; padding:14px 28px; border-radius:6px; font-weight:700; font-size:14px;}
  a.go:hover{opacity:0.9;}
  .offramp{margin-top:28px; padding-top:20px; border-top:1px solid rgba(242,237,225,0.14); font-size:12px; color:#8C8377;}
  .offramp a{color:#2F8F7A; text-decoration:none;}
</style>
</head>
<body>
  <div class="card">
    <div class="kicker">Shared via The Truth Button</div>
    <h1>${safeLabel || 'This link is ready for you'}</h1>
    <div class="dest">${safeUrl}</div>
    <a class="go" href="${safeUrl}" target="_blank" rel="noopener">Continue →</a>
    <div class="offramp">🔍 Also on <a href="/">The Truth Button</a> — free tools to check if photos/video are AI-generated, look up surveillance cameras, scan code for malware, and more.</div>
  </div>
</body>
</html>`;
}

function qrNotFoundHtml(){
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="robots" content="noindex">
<title>Link not found — The Truth Button</title>
<style>body{margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#14110F; color:#F2EDE1; font-family:system-ui,-apple-system,sans-serif;}
.card{max-width:400px; margin:24px; padding:32px; background:#1C1814; border:1px solid rgba(242,237,225,0.14); border-radius:12px; text-align:center;}
a{color:#2F8F7A;}</style></head>
<body><div class="card"><h1>Link not found</h1><p>This QR code link doesn't exist or was removed.</p><a href="/">Go to The Truth Button →</a></div></body></html>`;
}

// POST /api/qrlinks — signed-in only. An open, unauthenticated URL-redirect
// creator on a trusted domain is a well-known phishing/spam vector (the
// domain's reputation gets borrowed for whatever the redirect actually points
// at). Requiring sign-in ties every link to an accountable identity.
app.post('/api/qrlinks', requireAuth, perMinute(20), asyncHandler(async (req, res) => {
  const body = req.body || {};
  const rawUrl = clip(body.url, MAX_URL_LEN);
  const label = clip(body.label, MAX_QR_LABEL_LEN);

  if (!isValidHttpUrl(rawUrl)) return res.status(400).json({ error: 'A valid http(s) URL is required.' });
  const normalizedUrl = new URL(rawUrl).href; // normalizes + percent-encodes, avoids storing a raw/malformed string

  const data = await readQrLinks();
  let id;
  do { id = makeShortId(); } while (data.links.some(l => l.id === id));

  const link = {
    id, userId: req.user.id, destinationUrl: normalizedUrl, label: label || null,
    clicks: 0, createdAt: Date.now()
  };
  data.links.push(link);
  writeQrLinks(data)
    .then(() => res.status(201).json({ id, shortUrl: `${req.protocol}://${req.get('host')}/go/${id}` }))
    .catch(() => res.status(500).json({ error: 'Could not save the link.' }));
}));

// GET /go/:id — public. Serves the branded interstitial (or a friendly 404),
// then the visitor clicks through to the actual destination themselves —
// deliberately not an instant redirect, since the whole point is the
// off-ramp content actually gets seen.
app.get('/go/:id', perMinute(120), asyncHandler(async (req, res) => {
  const data = await readQrLinks();
  const link = data.links.find(l => l.id === req.params.id);
  res.set('Content-Type', 'text/html; charset=utf-8');
  if (!link) return res.status(404).send(qrNotFoundHtml());

  link.clicks = (link.clicks || 0) + 1;
  writeQrLinks(data).catch(() => {}); // best-effort; don't block the page on this
  res.send(qrLandingPageHtml({ destinationUrl: link.destinationUrl, label: link.label }));
}));

// GET /photos/:id — public. Serves the actual image bytes for a photo hosted via
// POST /api/photos (see that route, registered early, for why/how). Not
// found/expired just 404s with plain text — fine for an <img src>, it shows as a
// broken image rather than needing special handling.
app.get('/photos/:id', perMinute(300), asyncHandler(async (req, res) => {
  // helmet's default Cross-Origin-Resource-Policy is "same-origin", which blocks
  // browsers (not bots like Facebook's crawler, which ignores it) from loading this
  // as a cross-origin <img>. The entire point of this route is to be embedded
  // elsewhere, so it needs the permissive value — found via a real browser test
  // where the URL worked fine via curl/a scraper but silently failed as an <img src>.
  // Set unconditionally (before the not-found check too) so a stale/broken <img src>
  // fails as a normal broken image rather than an inconsistent CORP-blocked one.
  res.set('Cross-Origin-Resource-Policy', 'cross-origin');
  const photo = await storeGet('tb:photo:' + req.params.id, null);
  if (!photo) return res.status(404).type('text/plain').send('Not found or expired.');
  res.set('Content-Type', photo.mime);
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  res.send(Buffer.from(photo.base64, 'base64'));
}));

// GET /api/qrlinks — signed-in only. Lets a user see their own links + click counts.
app.get('/api/qrlinks', requireAuth, asyncHandler(async (req, res) => {
  const data = await readQrLinks();
  const mine = data.links
    .filter(l => l.userId === req.user.id)
    .map(l => ({ id: l.id, destinationUrl: l.destinationUrl, label: l.label, clicks: l.clicks || 0, createdAt: l.createdAt }))
    .sort((a, b) => b.createdAt - a.createdAt);
  res.json({ links: mine });
}));

// DELETE /api/qrlinks/:id — signed-in only, owner-only.
app.delete('/api/qrlinks/:id', requireAuth, asyncHandler(async (req, res) => {
  const data = await readQrLinks();
  const link = data.links.find(l => l.id === req.params.id);
  if (!link) return res.status(404).json({ error: 'Link not found.' });
  if (link.userId !== req.user.id) return res.status(403).json({ error: 'Not your link.' });
  data.links = data.links.filter(l => l.id !== req.params.id);
  writeQrLinks(data)
    .then(() => res.json({ ok: true }))
    .catch(() => res.status(500).json({ error: 'Could not delete the link.' }));
}));

// ---------- QOTD + leaderboard ----------

app.get('/api/qotd', asyncHandler(async (req, res) => {
  const data = await readQotd();
  res.json({ qotd: data.qotd });
}));

app.get('/api/leaderboard', asyncHandler(async (req, res) => {
  const data = await readUsers();
  const leaderboard = data.users
    .map(u => ({ username: u.username, contributionScore: u.contributionScore || 0 }))
    .filter(u => u.contributionScore > 0)
    .sort((a, b) => b.contributionScore - a.contributionScore);
  res.json({ leaderboard });
}));

// POST /api/qotd — only the current top contributor can set it
app.post('/api/qotd', requireAuth, perMinute(10), asyncHandler(async (req, res) => {
  const question = clip((req.body || {}).question, MAX_QUESTION_LEN);
  if (!question) return res.status(400).json({ error: 'Question is required.' });

  const usersData = await readUsers();
  const leaderboard = usersData.users
    .map(u => ({ id: u.id, contributionScore: u.contributionScore || 0 }))
    .sort((a, b) => b.contributionScore - a.contributionScore);
  const isTop = leaderboard.length > 0 && leaderboard[0].id === req.user.id && leaderboard[0].contributionScore > 0;
  if (!isTop) return res.status(403).json({ error: 'Only the top contributor can set the question of the day.' });

  const qotd = { question, setBy: req.user.username, setAt: Date.now() };
  writeQotd({ qotd })
    .then(() => res.json({ qotd }))
    .catch(() => res.status(500).json({ error: 'Could not save the question.' }));
}));

// GET /api/reviews?category=work&state=texas
app.get('/api/reviews', asyncHandler(async (req, res) => {
  const { category, state } = req.query;
  if (category && !isValidCategory(category)) {
    return res.status(400).json({ error: 'Unknown category.' });
  }
  const data = await readData();
  let results = data.reviews;
  if (category) results = results.filter(r => r.category === category);
  if (state) results = results.filter(r => r.state.toLowerCase() === String(state).toLowerCase());
  results = results.slice().sort((a, b) => b.timestamp - a.timestamp);
  res.json({ reviews: results });
}));

// POST /api/reviews
app.post('/api/reviews', requireAuth, perMinute(12), asyncHandler(async (req, res) => {
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

  const data = await readData();
  data.reviews.unshift(review);

  const usersData = await readUsers();
  const user = usersData.users.find(u => u.id === req.user.id);
  if (user) user.contributionScore = (user.contributionScore || 0) + 3;

  Promise.all([writeData(data), writeUsers(usersData)])
    .then(() => res.status(201).json({ review }))
    .catch(() => res.status(500).json({ error: 'Could not save review.' }));
}));

// POST /api/reviews/:id/like
app.post('/api/reviews/:id/like', perMinute(60), asyncHandler(async (req, res) => {
  const data = await readData();
  const review = data.reviews.find(r => r.id === req.params.id);
  if (!review) return res.status(404).json({ error: 'Review not found.' });
  review.likes = (review.likes || 0) + 1;
  writeData(data)
    .then(() => res.json({ review }))
    .catch(() => res.status(500).json({ error: 'Could not save like.' }));
}));

// POST /api/reviews/:id/reply
app.post('/api/reviews/:id/reply', requireAuth, perMinute(20), asyncHandler(async (req, res) => {
  const data = await readData();
  const review = data.reviews.find(r => r.id === req.params.id);
  if (!review) return res.status(404).json({ error: 'Review not found.' });

  const text = clip((req.body || {}).text, MAX_REPLY_LEN);
  if (!text) return res.status(400).json({ error: 'Reply text is required.' });

  if (!review.replies) review.replies = [];
  review.replies.push({ id: makeId(), name: req.user.username, text, timestamp: Date.now() });

  const usersData = await readUsers();
  const user = usersData.users.find(u => u.id === req.user.id);
  if (user) user.contributionScore = (user.contributionScore || 0) + 1;

  Promise.all([writeData(data), writeUsers(usersData)])
    .then(() => res.json({ review }))
    .catch(() => res.status(500).json({ error: 'Could not save reply.' }));
}));

// ---------- code scanner (public, report-only) ----------
app.use(scannerRoutes);

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

// Defense-in-depth: every async route above is wrapped in asyncHandler, so this
// should never fire in practice — but if a future route ever misses the wrapper,
// log it instead of letting Node terminate the whole process (default since Node 15).
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection (should not happen — check asyncHandler coverage):', reason);
});

app.listen(PORT, () => {
  console.log('Truth Button Reviews API listening on port ' + PORT);
});
