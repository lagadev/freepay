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

**Navigation**: every dashboard page's nav is a single elegant "Menu"
dropdown button (`PL.renderNav`) — no separate desktop-links-row +
mobile-hamburger split. One consistent pattern at every screen size, closes
on outside-click/Escape/link-click.

v3 polish pass: refined shadow depth (`--shadow-sm/--shadow/--shadow-lg`),
consistent `--ease` cubic-bezier transitions on every interactive element
(cards, buttons, switches, table rows), sharper focus rings on inputs,
button press feedback, and a proper modal/dialog system for admin actions.

## Security (v3)

- **Login lockout**: 5 wrong passwords locks that account for 15 minutes —
  even the correct password won't work until it clears. Independent of IP,
  so a distributed attack against one account still gets stopped.
- **Rate limiting**: signup, login (per-IP), and TrxID verification
  (per-invoice) are all rate-limited against brute-force/spam via a D1-backed
  sliding window (`rate_limits` table).
- **Session invalidation**: every user has a `token_version`. Admin can force
  someone's active sessions to die instantly (Admin Panel → Users → Force
  Logout / Reset Password) without needing a server-side session store.
- **XSS hardening**: every place user-controlled text (brand names, invoice
  references, TrxIDs, user names/emails) gets inserted into the page now
  goes through `PL.esc()` before hitting `innerHTML`. This closes a real
  stored-XSS gap that existed before — a brand name like
  `<img src=x onerror=...>` would previously have executed in anyone
  viewing that data (dashboard, admin panel, or the public pay page).
- **Response security headers** on every request: CSP (scripts/styles/fonts
  locked to this origin + Google Fonts), `X-Frame-Options: DENY`
  (clickjacking), `X-Content-Type-Options: nosniff`, HSTS, and a locked-down
  `Permissions-Policy`.
- **Timing-safe login**: a login attempt for a nonexistent email still pays
  the same password-hashing cost as a real one, so response time can't be
  used to enumerate which emails have accounts.
- **Audit log**: every admin mutation (suspend, delete, edit, config change,
  force-logout, password reset, key regeneration...) is recorded with who,
  what, when, and from which IP — visible in Admin Panel → Audit Log.
- Passwords already use PBKDF2 (120k iterations) + per-user salt; SQL is
  100% parameterized (D1 `.bind()`) everywhere, so there's no SQL injection
  surface to begin with.

If you deployed FreePay **before** this update, run the migration once:
```bash
wrangler d1 execute freepay-db --remote --file=./migrations/001_security_hardening.sql
```

## Admin Panel features

- **Analytics** — 7-day daily verified-volume bar chart, top brands by
  volume, recent signups, per-method revenue breakdown
- **Users** — search + pagination, click into any user to see their brands
  and stats, **edit** name/email, **suspend/unsuspend**, **force logout**
  (kills all their sessions instantly), **reset password** (issues a new
  temp password), and **permanently delete** an account (cascades to their
  brands/invoices/SMS logs)
- **Brands** — enable/disable any brand or any single payment method on it,
  regenerate any brand's API key, and **delete** a brand outright
  (cascades to its invoices/SMS logs)
- **Transactions** — search across invoice ID/TrxID/brand/owner, filter by
  status, paginated, **delete** any transaction, CSV export
- **Audit Log** — full history of every admin action taken on the site
- **Site Settings** — site name, support email, APK download URL, donate
  numbers — all admin-editable at runtime (no redeploy needed)

Every list/detail view uses the same danger-aware confirmation modal before
anything destructive happens (delete, suspend, reset password, etc).

## Docs page

`/app/docs.html` has language-tabbed code examples (cURL / Node.js /
Python / PHP) for both invoice creation and webhook verification — and every
code block now has a one-click **Copy** button (`PL.attachCopyButtons()`).

## Android app (FreePay Sync)

`android/` has the full source for the SMS-forwarding companion app —
login with a Brand API Key, live list of every captured SMS with its sync
status, and a persistent Telegram support banner (**@devugly**).

It's built entirely by CI (`.github/workflows/release.yml`) — push a tag like
`android-v1.0.0` or run the workflow manually from the Actions tab, and a
debug-signed `freepay-sync.apk` gets attached to a new GitHub Release. See
`android/README.md` for full details.

## Not included yet

- Real file upload for brand logos (currently a URL field — add R2 later)
- Actual custom-domain hosting for a brand's `domain` field (informational
  only right now)
- Binance Pay / TON automatic crypto rail (different settlement mechanism,
  not SMS-based — separate integration)
