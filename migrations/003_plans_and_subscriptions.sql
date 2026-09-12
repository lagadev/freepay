-- Run this ONCE against an existing FreePay database that predates the
-- Buy Plans / subscription-billing update:
--   wrangler d1 execute freepay-db --remote --file=./migrations/003_plans_and_subscriptions.sql
--
-- Fresh installs don't need this — schema.sql already includes it.

ALTER TABLE invoices ADD COLUMN purpose TEXT NOT NULL DEFAULT 'customer';
ALTER TABLE invoices ADD COLUMN plan_id TEXT;
ALTER TABLE invoices ADD COLUMN subscribing_brand_id TEXT;

CREATE TABLE IF NOT EXISTS plans (
  id               TEXT PRIMARY KEY,
  name             TEXT NOT NULL,
  days             INTEGER NOT NULL,
  price            REAL NOT NULL,
  original_price   REAL,
  badge_text       TEXT,
  features         TEXT NOT NULL DEFAULT '[]',
  is_trial         INTEGER NOT NULL DEFAULT 0,
  enabled          INTEGER NOT NULL DEFAULT 1,
  sort_order       INTEGER NOT NULL DEFAULT 0,
  created_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_plans_enabled ON plans(enabled, sort_order);

CREATE TABLE IF NOT EXISTS subscriptions (
  id          TEXT PRIMARY KEY,
  brand_id    TEXT NOT NULL UNIQUE,
  plan_id     TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'active',
  started_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  FOREIGN KEY (brand_id) REFERENCES brands(id),
  FOREIGN KEY (plan_id) REFERENCES plans(id)
);
CREATE INDEX IF NOT EXISTS idx_subscriptions_brand ON subscriptions(brand_id);
