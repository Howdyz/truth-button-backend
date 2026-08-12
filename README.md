# Truth Button — Reviews API

A small, self-contained backend for the Reviews section (Work, Sports,
Restaurants, Price Watch, Economy). Data is stored in a local JSON file
(`data/reviews.json`) — no external database needed to get started.

This has been tested locally: health check, posting a review, filtering by
category/state, liking, replying, and input validation all work as expected.

## Run it locally

```bash
npm install
npm start
```

Server listens on `http://localhost:3000` by default (override with `PORT`).

## Endpoints

- `GET /api/health` — returns `{ ok: true }`
- `GET /api/reviews?category=work&state=Texas` — `state` is optional (omit for all states)
- `POST /api/reviews` — body: `{ category, state, subject, text, name, rating, priceThen, priceNow }`
- `POST /api/reviews/:id/like` — increments the like count
- `POST /api/reviews/:id/reply` — body: `{ name, text }`

`category` must be one of: `work`, `sports`, `restaurants`, `prices`, `economy`.

## Deploying it for real (so it's reachable from your live site)

You need somewhere that keeps a Node process running continuously — this
can't run on Claude, and it can't run purely as static files. Cheapest/simplest
free options, roughly in order of ease:

### Option A — Render.com (recommended starting point)
1. Push this folder to a GitHub repo (or use Render's "public git repo" import).
2. On Render: **New → Web Service**, connect the repo.
3. Build command: `npm install`. Start command: `npm start`.
4. Once deployed, Render gives you a URL like `https://your-app.onrender.com`.
5. **Important caveat:** Render's free tier disk is *not* guaranteed to persist
   across deploys/restarts. Fine for testing and low-stakes use; for real
   long-term durability, add Render's persistent disk add-on (small paid
   tier) or migrate to a hosted database (see Option C).

### Option B — Railway or Fly.io
Similar flow to Render — connect a repo, it detects Node, deploys. Both have
small free/trial tiers and slightly better persistent-volume support than
Render's free tier. Worth comparing current pricing since free-tier terms
change often.

### Option C — Swap the JSON file for a real hosted database
For anything beyond casual/testing use, the JSON file approach isn't built
for high write concurrency or guaranteed durability. The natural upgrade is
swapping `readData()`/`writeData()` in `server.js` for calls to a hosted
Postgres (Supabase, Neon, Railway Postgres) — the rest of the API surface
(routes, validation) stays the same. Happy to help make that swap when you're
ready to go that route.

## Locking down CORS

By default this allows requests from any origin, which is fine for getting
things working. Before going live, set the `ALLOWED_ORIGIN` environment
variable to your actual site's origin (e.g. `https://yoursite.com`) so random
other sites can't hit your API from a browser.

## Connecting the frontend

In `truth-button_9.html`, set:

```js
const REVIEWS_API_BASE = 'https://your-app.onrender.com';
```

Leave it as `null` to keep the page running in local-only fallback mode
(reviews only visible in that one browser tab — useful for testing the UI
before your backend is deployed).
