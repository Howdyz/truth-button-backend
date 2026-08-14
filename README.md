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

**Accounts** — free, no roles. Anyone can sign up; every account can post reviews/replies and, if they're the top contributor on the leaderboard, set the question of the day.
- `POST /api/auth/signup` — body: `{ username, email, password }` → `{ token, user }`
- `POST /api/auth/login` — body: `{ email, password }` → `{ token, user }`
- `POST /api/auth/logout` — requires `Authorization: Bearer <token>`

**Reviews**
- `GET /api/reviews?category=work&state=Texas` — `state` is optional (omit for all states)
- `POST /api/reviews` — requires auth — body: `{ category, state, subject, text, rating, priceThen, priceNow, sportType }`
- `POST /api/reviews/:id/like` — increments the like count
- `POST /api/reviews/:id/reply` — requires auth — body: `{ text }`

`category` must be one of: `work`, `sports`, `restaurants`, `prices`, `economy`.

**Question of the day / leaderboard**
- `GET /api/qotd` — current question
- `GET /api/leaderboard` — top contributors by score
- `POST /api/qotd` — requires auth, and only works if you're the current top contributor — body: `{ question }`

**Mobile Share licenses** (Stripe-purchased add-on)
- `POST /api/stripe-webhook` — Stripe calls this directly; not for manual use
- `GET /api/license/for-session?session_id=cs_xxx` — used by `unlock.html` to show the key after checkout
- `POST /api/license/verify` — body: `{ key }` → `{ valid }`
- `POST /api/license/backfill` — maintenance tool for a purchase the webhook missed. Requires header `X-Maintenance-Secret: <MAINTENANCE_SECRET>` — body: `{ sessionId, email }`

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

## Environment variables

- `PORT` — port to listen on (default 3000)
- `ALLOWED_ORIGIN` — locks down CORS (see above), comma-separated for multiple origins
- `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` — needed for the Mobile Share license flow
- `MAINTENANCE_SECRET` — any random string you pick. Required to call `/api/license/backfill`. Set it once in Render's Environment tab, then pass it as the `X-Maintenance-Secret` header when you need to run that tool.

## Connecting the frontend

In `truth-button_9.html`, set:

```js
const REVIEWS_API_BASE = 'https://your-app.onrender.com';
```

Leave it as `null` to keep the page running in local-only fallback mode
(reviews only visible in that one browser tab — useful for testing the UI
before your backend is deployed).
