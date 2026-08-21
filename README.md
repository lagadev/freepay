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

New palette (`src/pages/style.css`): emerald green (`--accent:#059669`) as
the primary action color, indigo (`--indigo:#4F46E5`) as the secondary
accent, and a near-black ink (`--ink:#0B1120`) for dark UI surfaces —
replacing the old pink/navy PayLink look. Wallet-brand chip colors (bKash
pink, Nagad orange, etc.) are left as their real-world colors since those
identify the payment method, not FreePay's own branding.

## Not included yet

- Real file upload for brand logos (currently a URL field — add R2 later)
- Actual custom-domain hosting for a brand's `domain` field (informational
  only right now)
- Binance Pay / TON automatic crypto rail (different settlement mechanism,
  not SMS-based — separate integration)
- The Android SMS-forwarder app still targets the older single-user API;
  it hasn't been reworked for the brand/multi-method model yet.
