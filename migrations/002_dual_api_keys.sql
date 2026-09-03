-- Run this ONCE against an existing FreePay database that predates the
-- dual-API-key update (invoice key vs SMS/App key):
--   wrangler d1 execute freepay-db --remote --file=./migrations/002_dual_api_keys.sql
--
-- Fresh installs don't need this — schema.sql already includes it.

ALTER TABLE brands ADD COLUMN ingest_key TEXT;

-- Every existing brand gets a fresh, unique placeholder ingest key so the
-- UNIQUE index below can be created; each brand owner should then hit
-- Dashboard -> Brand -> "SMS/App Key" -> Regenerate once to get a real one.
UPDATE brands SET ingest_key = 'APP_' || substr(id, 1, 8) || substr(hex(randomblob(8)), 1, 16)
WHERE ingest_key IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_brands_ingest_key ON brands(ingest_key);
