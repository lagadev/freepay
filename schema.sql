-- FreePay v3 schema — multi-brand, multi-method, security hardening, admin audit trail
-- Run with: wrangler d1 execute freepay-db --file=./schema.sql
-- (Safe to re-run: every statement is IF NOT EXISTS / idempotent.)

CREATE TABLE IF NOT EXISTS users (
  id                     TEXT PRIMARY KEY,
  email                  TEXT UNIQUE NOT NULL,
  password_hash          TEXT NOT NULL,
  name                   TEXT,
  suspended              INTEGER NOT NULL DEFAULT 0,   -- admin can suspend an account
  failed_login_attempts  INTEGER NOT NULL DEFAULT 0,   -- resets on successful login
  lockout_until          INTEGER,                      -- unix ms; login blocked until this passes
  token_version          INTEGER NOT NULL DEFAULT 0,   -- bump to invalidate ALL existing sessions
  created_at             INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- A "brand" is one storefront/site. A user can own several. Each brand has
-- its OWN mobile-wallet numbers and its OWN API key — money for a brand's
-- invoices always goes straight to that brand's own numbers.
CREATE TABLE IF NOT EXISTS brands (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL,
  name            TEXT NOT NULL,
  logo_url        TEXT,
  domain          TEXT,                        -- informational, locked after creation
  api_key         TEXT UNIQUE NOT NULL,
  enabled         INTEGER NOT NULL DEFAULT 1,   -- admin kill-switch for the whole brand
  bkash_number    TEXT,
  nagad_number    TEXT,
  upay_number     TEXT,
  rocket_number   TEXT,
  cellfin_number  TEXT,
  bkash_enabled   INTEGER NOT NULL DEFAULT 0,
  nagad_enabled   INTEGER NOT NULL DEFAULT 0,
  upay_enabled    INTEGER NOT NULL DEFAULT 0,
  rocket_enabled  INTEGER NOT NULL DEFAULT 0,
  cellfin_enabled INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_brands_user ON brands(user_id);
CREATE INDEX IF NOT EXISTS idx_brands_api_key ON brands(api_key);

CREATE TABLE IF NOT EXISTS invoices (
  id              TEXT PRIMARY KEY,             -- INV-XXXXXXXX
  brand_id        TEXT NOT NULL,
  reference       TEXT,
  amount          REAL NOT NULL,
  method          TEXT,                         -- bkash|nagad|upay|rocket|cellfin, NULL until chosen
  merchant_number TEXT,
  status          TEXT NOT NULL DEFAULT 'pending', -- pending | verified | expired
  callback_url    TEXT,
  redirect_url    TEXT,
  trx_id          TEXT,
  sender_number   TEXT,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,              -- created_at + 15 minutes
  verified_at     INTEGER,
  FOREIGN KEY (brand_id) REFERENCES brands(id)
);
CREATE INDEX IF NOT EXISTS idx_invoices_brand ON invoices(brand_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_invoices_trx ON invoices(trx_id);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(brand_id, status);

CREATE TABLE IF NOT EXISTS sms_transactions (
  id                 TEXT PRIMARY KEY,
  brand_id           TEXT NOT NULL,
  trx_id             TEXT NOT NULL,
  amount             REAL NOT NULL,
  sender_number      TEXT,
  method             TEXT NOT NULL,
  raw_sms            TEXT,
  received_at        INTEGER NOT NULL,
  matched_invoice_id TEXT,
  created_at         INTEGER NOT NULL,
  UNIQUE(brand_id, trx_id),
  FOREIGN KEY (brand_id) REFERENCES brands(id)
);
CREATE INDEX IF NOT EXISTS idx_sms_brand_trx ON sms_transactions(brand_id, trx_id);
CREATE INDEX IF NOT EXISTS idx_sms_brand_pending ON sms_transactions(brand_id, method, matched_invoice_id);

-- Small admin-editable key/value store: APK download URL, donate numbers, site name, etc.
CREATE TABLE IF NOT EXISTS app_config (
  key   TEXT PRIMARY KEY,
  value TEXT
);

-- Every admin action (suspend, delete, edit, config change, force-logout...)
-- gets recorded here — visible in Admin Panel → Audit Log.
CREATE TABLE IF NOT EXISTS admin_audit_log (
  id           TEXT PRIMARY KEY,
  admin_email  TEXT NOT NULL,
  action       TEXT NOT NULL,       -- e.g. "user.suspend", "brand.delete"
  target_type  TEXT,                -- "user" | "brand" | "invoice" | "config"
  target_id    TEXT,
  detail       TEXT,                -- short human-readable description
  ip           TEXT,
  created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON admin_audit_log(created_at DESC);

-- Generic sliding-window rate limiter used for login/signup/verify endpoints.
CREATE TABLE IF NOT EXISTS rate_limits (
  key          TEXT PRIMARY KEY,   -- e.g. "login:1.2.3.4" or "verify:INV-XXXX"
  count        INTEGER NOT NULL DEFAULT 0,
  window_start INTEGER NOT NULL
);

-- ---------------------------------------------------------------------
-- MIGRATION for existing deployments (created before this schema version):
-- D1/SQLite doesn't support "ADD COLUMN IF NOT EXISTS", so if you deployed
-- FreePay before and these columns don't exist yet on your `users` table,
-- run these three lines by hand (they'll error harmlessly if already applied):
--
--   ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
--   ALTER TABLE users ADD COLUMN lockout_until INTEGER;
--   ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;
-- ---------------------------------------------------------------------

