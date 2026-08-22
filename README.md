# FreePay

One Cloudflare Worker, one `wrangler deploy` — no separate frontend/backend.
Multi-brand bKash/Nagad/Upay/Rocket/Cellfin gateway where every brand's
invoices pay straight into that brand's own wallet number. FreePay never
custodies customer funds, so there's no withdraw flow.

## Project layout

```
src/
  index.js              — the actual Worker entry (routes /api/* + static pages)
  api.js                — all JSON API logic (auth, brands, invoices, SMS, admin)
  pages/
    raw/                 — source HTML/JS for every page (edit these)
    style.css            — the FreePay design system (emerald/indigo/ink)
  pages.generated.js     — AUTO-GENERATED bundle of the above (do not hand-edit)
build-pages.js           — rebuilds pages.generated.js from src/pages/raw + style.css
schema.sql                — D1 schema
wrangler.toml
```

## Editing a page

1. Edit the relevant file under `src/pages/raw/` (or `src/pages/style.css`
   for global styling).
2. Run `npm run build:pages` (re-runs `build-pages.js`) to regenerate
   `src/pages.generated.js`.
3. `npm run deploy`.

## Deploy

```bash
npm install -g wrangler
wrangler d1 create freepay-db
# paste the returned database_id into wrangler.toml
npm run db:migrate:remote
npm run build:pages
npm run deploy
```

Before going live, in `src/api.js`:
- Change `CONFIG.SESSION_SECRET` to a long random string (or move it to
  `wrangler secret put SESSION_SECRET` + read `env.SESSION_SECRET`).
- `CONFIG.ADMIN_EMAILS` — emails that get Admin Panel access after a normal
  password login (`devugly@login.com` is preset). No passwordless bypass —
  a real password login is always required.

## Pages

- `/` — landing
- `/pay?id=INV-XXXX` — customer payment flow (brand header, method select,
  5-second verify loading ring, toast on no-match, auto-poll in background)
- `/app/login.html`, `/app/signup.html`
- `/app/dashboard.html` — stats + recent transactions
- `/app/brand.html` — create brands (domain locked after creation), logo,
  per-method numbers + enable/disable, API key + regenerate
- `/app/transactions.html` — full history
- `/app/download.html` — FreePay Sync app + brand API key for setup
- `/app/docs.html` — Node.js integration examples
- `/app/settings.html` — account + all brands' API keys
- `/app/donate.html` — admin-configured donation numbers
- `/app/admin/index.html` — suspend users, enable/disable any brand or any
  single payment method on any brand, view every transaction platform-wide,
  set the APK download link + donate numbers

## Design

Violet-to-blue gradient system (`src/pages/style.css`) matching the provided
landing page reference — `--accent:#6a5cf5` (violet) to `--blue:#4f7cff` as
the primary gradient, near-black `--ink:#14152b` for dark surfaces (nav
active state, balance card, buttons). Real original-artwork SVG logos live
under `src/pages/raw/assets/logos/`: `freepay.svg` plus one badge per wallet
method (`bkash.svg`, `nagad.svg`, `upay.svg`, `rocket.svg`, `cellfin.svg`) —
these are FreePay's own stylized badges, not reproductions of the actual
trademarked wallet logos. They're used consistently across the landing page,
nav bar, pay page, brand management, download, donate, and admin panel.

The dashboard nav collapses to a hamburger + slide-down panel under 760px,
matching the landing page's own mobile menu pattern.

## Admin Panel features

- **Analytics** — 7-day daily verified-volume bar chart, top brands by
  volume, recent signups, per-method revenue breakdown
- **Users** — suspend/unsuspend any account
- **Brands** — enable/disable any brand or any single payment method on it,
  and regenerate any brand's API key directly (support/security tool)
- **Transactions** — every invoice platform-wide, with CSV export
- **Site Settings** — site name, support email, APK download URL, donate
  numbers — all admin-editable at runtime (no redeploy needed)

## Docs page

`/app/docs.html` now has language-tabbed code examples (cURL / Node.js /
Python / PHP) for both invoice creation and webhook verification.

## Not included yet

- Real file upload for brand logos (currently a URL field — add R2 later)
- Actual custom-domain hosting for a brand's `domain` field (informational
  only right now)
- Binance Pay / TON automatic crypto rail (different settlement mechanism,
  not SMS-based — separate integration)
- The Android SMS-forwarder app still targets the older single-user API;
  it hasn't been reworked for the brand/multi-method model yet.
