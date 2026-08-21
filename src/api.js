/**
 * FreePay — single Cloudflare Worker. One deploy, serves the JSON API
 * (under /api/*) AND every HTML/CSS/JS page (see pages.generated.js) from
 * the same origin. No separate frontend deploy, no cross-origin proxy
 * needed — the browser always talks to one URL.
 *
 * Ownership model: every invoice pays into the BRAND's OWN mobile-wallet
 * number. FreePay never custodies customer funds — it only verifies (via
 * SMS) and reports. No withdraw endpoint exists because there's nothing
 * held to withdraw.
 */

// ---- server config ---------------------------------------------------
// Move SESSION_SECRET to `wrangler secret put SESSION_SECRET` in production.
const CONFIG = {
  SITE_NAME: "FreePay",
  SESSION_SECRET: "A7xK9mQ2vL8pR4tN6zY1cW5hJ3sF0dG8bU2nI7eX4qP9rT6yM3kV1aZ8wC5",
  INVOICE_TTL_MINUTES: 15,
  SESSION_TTL_DAYS: 30,
  // Emails in this list get admin access automatically after a normal
  // email+password login. No passwordless bypass — a real account with a
  // real password must exist and log in normally.
  ADMIN_EMAILS: ["devugly@login.com"],
  CORS_ORIGIN: "*",
};
// -------------------------------------------------------------------------

const METHODS = [
  { id: "bkash", label: "bKash", color: "#E2136E" },
  { id: "nagad", label: "Nagad", color: "#F0561F" },
  { id: "upay", label: "Upay", color: "#7A1FA2" },
  { id: "rocket", label: "Rocket", color: "#8C1AF6" },
  { id: "cellfin", label: "Cellfin", color: "#0A6E4E" },
];
const METHOD_IDS = METHODS.map((m) => m.id);

const AMOUNT_TOLERANCE = 0.5;
const PBKDF2_ITERATIONS = 100000;

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": CONFIG.CORS_ORIGIN,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}
function json(data, status, extraHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(), ...(extraHeaders || {}) },
  });
}
async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}
function ttlMs() {
  return CONFIG.INVOICE_TTL_MINUTES * 60 * 1000;
}
function normalizeTrx(trx) {
  return String(trx || "").trim().toUpperCase();
}
function normalizeMethod(method) {
  const m = String(method || "").trim().toLowerCase();
  return METHOD_IDS.includes(m) ? m : null;
}
function genId(prefix, len) {
  return prefix + crypto.randomUUID().replace(/-/g, "").slice(0, len).toUpperCase();
}
function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// ---- password hashing ---------------------------------------------------
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, keyMaterial, 256);
  return `${toHex(salt)}:${toHex(new Uint8Array(bits))}`;
}
async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = String(stored || "").split(":");
  if (!saltHex || !hashHex) return false;
  const salt = fromHex(saltHex);
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, keyMaterial, 256);
  return toHex(new Uint8Array(bits)) === hashHex;
}

// ---- sessions -------------------------------------------------------------
async function hmacHex(message) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(CONFIG.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return toHex(new Uint8Array(sig));
}
function b64urlEncode(str) {
  return btoa(unescape(encodeURIComponent(str))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str) {
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  return decodeURIComponent(escape(atob(str.replace(/-/g, "+").replace(/_/g, "/") + pad)));
}
async function createSessionToken(userId) {
  const payload = JSON.stringify({ uid: userId, exp: Date.now() + CONFIG.SESSION_TTL_DAYS * 86400000 });
  const p = b64urlEncode(payload);
  return `${p}.${await hmacHex(p)}`;
}
async function verifySessionToken(token) {
  if (!token || !token.includes(".")) return null;
  const [p, sig] = token.split(".");
  if ((await hmacHex(p)) !== sig) return null;
  try {
    const payload = JSON.parse(b64urlDecode(p));
    if (!payload.uid || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}
function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}
function sessionCookieHeader(token) {
  const maxAge = CONFIG.SESSION_TTL_DAYS * 86400;
  // Single-Worker deploy: frontend and API are the same origin, so
  // SameSite=Lax is enough.
  return { "Set-Cookie": `session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}` };
}
function clearSessionCookieHeader() {
  return { "Set-Cookie": "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0" };
}
async function getSessionUser(request, env) {
  const token = getCookie(request, "session");
  if (!token) return null;
  const payload = await verifySessionToken(token);
  if (!payload) return null;
  const user = await env.DB.prepare(`SELECT * FROM users WHERE id = ?`).bind(payload.uid).first();
  if (!user || user.suspended) return null;
  return user;
}
function isAdmin(user) {
  return !!user && CONFIG.ADMIN_EMAILS.includes(user.email);
}
async function requireAdmin(request, env) {
  const user = await getSessionUser(request, env);
  if (!user || !isAdmin(user)) return null;
  return user;
}
async function getBrandByApiKey(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  return await env.DB.prepare(`SELECT * FROM brands WHERE api_key = ?`).bind(m[1].trim()).first();
}

function userPublic(u) {
  return { id: u.id, email: u.email, name: u.name, createdAt: u.created_at, isAdmin: isAdmin(u) };
}
function brandPublic(b) {
  return {
    id: b.id,
    name: b.name,
    logoUrl: b.logo_url,
    domain: b.domain,
    apiKey: b.api_key,
    enabled: !!b.enabled,
    createdAt: b.created_at,
    numbers: {
      bkash: b.bkash_number, nagad: b.nagad_number, upay: b.upay_number, rocket: b.rocket_number, cellfin: b.cellfin_number,
    },
    methodsEnabled: {
      bkash: !!b.bkash_enabled, nagad: !!b.nagad_enabled, upay: !!b.upay_enabled, rocket: !!b.rocket_enabled, cellfin: !!b.cellfin_enabled,
    },
  };
}
function invoicePublic(inv, brand) {
  return {
    id: inv.id,
    reference: inv.reference,
    amount: inv.amount,
    method: inv.method,
    merchantNumber: inv.merchant_number,
    status: inv.status,
    trxId: inv.trx_id,
    createdAt: inv.created_at,
    expiresAt: inv.expires_at,
    verifiedAt: inv.verified_at,
    redirectUrl: inv.redirect_url,
    brand: brand ? { name: brand.name, logoUrl: brand.logo_url } : null,
  };
}

// ---- auth handlers ------------------------------------------------------

async function handleSignup(request, env) {
  const body = await readJson(request);
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const name = body.name ? String(body.name).slice(0, 80) : null;

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "সঠিক ইমেইল দিন।" }, 400);
  if (password.length < 8) return json({ error: "পাসওয়ার্ড কমপক্ষে ৮ ক্যারেক্টার হতে হবে।" }, 400);

  const existing = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
  if (existing) return json({ error: "এই ইমেইল দিয়ে আগে থেকেই অ্যাকাউন্ট আছে।" }, 409);

  const id = crypto.randomUUID();
  const now = Date.now();
  await env.DB.prepare(`INSERT INTO users (id, email, password_hash, name, suspended, created_at) VALUES (?, ?, ?, ?, 0, ?)`)
    .bind(id, email, await hashPassword(password), name, now)
    .run();

  const token = await createSessionToken(id);
  const user = await env.DB.prepare(`SELECT * FROM users WHERE id = ?`).bind(id).first();
  return json({ user: userPublic(user) }, 201, sessionCookieHeader(token));
}

async function handleLogin(request, env) {
  const body = await readJson(request);
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const user = await env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
  if (!user || !(await verifyPassword(password, user.password_hash))) return json({ error: "ইমেইল অথবা পাসওয়ার্ড ভুল।" }, 401);
  if (user.suspended) return json({ error: "এই অ্যাকাউন্ট সাসপেন্ড করা হয়েছে। এডমিনের সাথে যোগাযোগ করুন।" }, 403);
  const token = await createSessionToken(user.id);
  return json({ user: userPublic(user) }, 200, sessionCookieHeader(token));
}

function handleLogout() {
  return json({ ok: true }, 200, clearSessionCookieHeader());
}

async function handleMe(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not logged in." }, 401);
  return json({ user: userPublic(user) }, 200);
}

// ---- brand handlers (session-auth, scoped to caller) ---------------------

async function ownBrandOr404(brandId, user, env) {
  const brand = await env.DB.prepare(`SELECT * FROM brands WHERE id = ?`).bind(brandId).first();
  if (!brand) return null;
  if (brand.user_id !== user.id && !isAdmin(user)) return "forbidden";
  return brand;
}

async function listBrands(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not logged in." }, 401);
  const rows = await env.DB.prepare(`SELECT * FROM brands WHERE user_id = ? ORDER BY created_at DESC`).bind(user.id).all();
  return json({ brands: (rows.results || []).map(brandPublic) }, 200);
}

async function createBrand(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not logged in." }, 401);
  const body = await readJson(request);
  const name = String(body.name || "").trim().slice(0, 80);
  const domain = body.domain ? String(body.domain).trim().toLowerCase().slice(0, 200) : null;
  if (!name) return json({ error: "Brand নাম দিন।" }, 400);
  if (domain && !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) return json({ error: "সঠিক ডোমেইন দিন (যেমন mysite.com)।" }, 400);

  const id = crypto.randomUUID();
  const now = Date.now();
  const apiKey = genId("BR", 32);
  await env.DB.prepare(
    `INSERT INTO brands (id, user_id, name, domain, api_key, enabled, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)`
  ).bind(id, user.id, name, domain, apiKey, now).run();

  const brand = await env.DB.prepare(`SELECT * FROM brands WHERE id = ?`).bind(id).first();
  return json({ brand: brandPublic(brand) }, 201);
}

async function updateBrandProfile(brandId, request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not logged in." }, 401);
  const brand = await ownBrandOr404(brandId, user, env);
  if (!brand) return json({ error: "Brand পাওয়া যায়নি।" }, 404);
  if (brand === "forbidden") return json({ error: "Forbidden." }, 403);

  const body = await readJson(request);
  const name = body.name !== undefined ? String(body.name).trim().slice(0, 80) : brand.name;
  const logoUrl = body.logoUrl !== undefined ? String(body.logoUrl).trim().slice(0, 500) : brand.logo_url;
  // domain is intentionally NOT editable here — locked after creation.
  if (!name) return json({ error: "Brand নাম খালি রাখা যাবে না।" }, 400);

  await env.DB.prepare(`UPDATE brands SET name = ?, logo_url = ? WHERE id = ?`).bind(name, logoUrl, brandId).run();
  const updated = await env.DB.prepare(`SELECT * FROM brands WHERE id = ?`).bind(brandId).first();
  return json({ brand: brandPublic(updated) }, 200);
}

async function updateBrandMethods(brandId, request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not logged in." }, 401);
  const brand = await ownBrandOr404(brandId, user, env);
  if (!brand) return json({ error: "Brand পাওয়া যায়নি।" }, 404);
  if (brand === "forbidden") return json({ error: "Forbidden." }, 403);

  const body = await readJson(request);
  const numRe = /^01[0-9]{9}$/;
  const updates = {};
  for (const m of METHOD_IDS) {
    if (body.numbers && body.numbers[m] !== undefined) {
      const val = String(body.numbers[m]).trim();
      if (val && !numRe.test(val)) return json({ error: `${m} নাম্বার সঠিক ফরম্যাটে দিন (01XXXXXXXXX)।` }, 400);
      updates[`${m}_number`] = val || null;
    }
    if (body.enabled && body.enabled[m] !== undefined) {
      updates[`${m}_enabled`] = body.enabled[m] ? 1 : 0;
    }
  }

  const setClauses = Object.keys(updates);
  if (setClauses.length) {
    const sql = `UPDATE brands SET ${setClauses.map((c) => `${c} = ?`).join(", ")} WHERE id = ?`;
    await env.DB.prepare(sql).bind(...setClauses.map((c) => updates[c]), brandId).run();
  }
  const updated = await env.DB.prepare(`SELECT * FROM brands WHERE id = ?`).bind(brandId).first();
  return json({ brand: brandPublic(updated) }, 200);
}

async function regenerateBrandKey(brandId, request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not logged in." }, 401);
  const brand = await ownBrandOr404(brandId, user, env);
  if (!brand) return json({ error: "Brand পাওয়া যায়নি।" }, 404);
  if (brand === "forbidden") return json({ error: "Forbidden." }, 403);
  const newKey = genId("BR", 32);
  await env.DB.prepare(`UPDATE brands SET api_key = ? WHERE id = ?`).bind(newKey, brandId).run();
  return json({ apiKey: newKey }, 200);
}

async function myStats(request, env) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not logged in." }, 401);
  const brandIds = (await env.DB.prepare(`SELECT id FROM brands WHERE user_id = ?`).bind(user.id).all()).results || [];
  if (!brandIds.length) return json({ totalReceived: 0, today: 0, month: 0, totalVolume: 0, transactionCount: 0 }, 200);
  const ids = brandIds.map((b) => b.id);
  const placeholders = ids.map(() => "?").join(",");

  const startOfToday = new Date(); startOfToday.setHours(0, 0, 0, 0);
  const startOfMonth = new Date(); startOfMonth.setDate(1); startOfMonth.setHours(0, 0, 0, 0);

  const [totalRow, todayRow, monthRow, countRow] = await Promise.all([
    env.DB.prepare(`SELECT COALESCE(SUM(amount),0) AS s FROM invoices WHERE brand_id IN (${placeholders}) AND status='verified'`).bind(...ids).first(),
    env.DB.prepare(`SELECT COALESCE(SUM(amount),0) AS s FROM invoices WHERE brand_id IN (${placeholders}) AND status='verified' AND verified_at>=?`).bind(...ids, startOfToday.getTime()).first(),
    env.DB.prepare(`SELECT COALESCE(SUM(amount),0) AS s FROM invoices WHERE brand_id IN (${placeholders}) AND status='verified' AND verified_at>=?`).bind(...ids, startOfMonth.getTime()).first(),
    env.DB.prepare(`SELECT COUNT(*) AS c FROM invoices WHERE brand_id IN (${placeholders})`).bind(...ids).first(),
  ]);
  return json({ totalReceived: totalRow.s, today: todayRow.s, month: monthRow.s, totalVolume: totalRow.s, transactionCount: countRow.c }, 200);
}

async function myTransactions(request, env, url) {
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Not logged in." }, 401);
  const limit = Math.min(Number(url.searchParams.get("limit")) || 20, 200);
  const rows = await env.DB.prepare(
    `SELECT i.id, i.reference, i.amount, i.method, i.status, i.trx_id, i.created_at, i.verified_at, b.name AS brand_name
     FROM invoices i JOIN brands b ON b.id = i.brand_id
     WHERE b.user_id = ? ORDER BY i.created_at DESC LIMIT ?`
  ).bind(user.id, limit).all();
  return json({ transactions: rows.results || [] }, 200);
}

// ---- invoice + sms handlers (brand API key auth) --------------------------

async function createInvoice(request, env, url) {
  const brand = await getBrandByApiKey(request, env);
  if (!brand) return json({ error: "Unauthorized. Send Authorization: Bearer <YOUR_BRAND_API_KEY>." }, 401);
  if (!brand.enabled) return json({ error: "এই Brand বর্তমানে ডিজেবল করা আছে।" }, 403);

  const body = await readJson(request);
  const amount = Number(body.amount);
  const reference = body.reference ? String(body.reference).slice(0, 128) : null;
  const callbackUrl = body.callbackUrl ? String(body.callbackUrl).slice(0, 500) : null;
  const redirectUrl = body.redirectUrl ? String(body.redirectUrl).slice(0, 500) : null;
  const method = body.method ? normalizeMethod(body.method) : null;
  if (!amount || amount <= 0) return json({ error: "A positive 'amount' is required." }, 400);

  let merchantNumber = null;
  if (method) {
    if (!brand[`${method}_enabled`]) return json({ error: `এই Brand-এ ${method} মেথডটি এনেবল করা নেই।` }, 400);
    merchantNumber = brand[`${method}_number`];
    if (!merchantNumber) return json({ error: `${method} নাম্বার সেট করা নেই।` }, 400);
  }

  const id = genId("INV-", 8);
  const now = Date.now();
  const expiresAt = now + ttlMs();

  await env.DB.prepare(
    `INSERT INTO invoices (id, brand_id, reference, amount, method, merchant_number, status, callback_url, redirect_url, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)`
  ).bind(id, brand.id, reference, amount, method, merchantNumber, callbackUrl, redirectUrl, now, expiresAt).run();

  const payUrl = `${url.origin}/pay?id=${id}`;
  return json({ id, reference, amount, method, merchantNumber, status: "pending", createdAt: now, expiresAt, payUrl }, 201);
}

async function getInvoiceRaw(id, env) {
  const invoice = await env.DB.prepare(`SELECT * FROM invoices WHERE id = ?`).bind(id).first();
  if (!invoice) return null;
  if (invoice.status === "pending" && Date.now() > invoice.expires_at) {
    await env.DB.prepare(`UPDATE invoices SET status = 'expired' WHERE id = ?`).bind(id).run();
    invoice.status = "expired";
  }
  return invoice;
}

async function getInvoiceRoute(id, env) {
  const invoice = await getInvoiceRaw(id, env);
  if (!invoice) return json({ error: "Invoice not found." }, 404);
  const brand = await env.DB.prepare(`SELECT * FROM brands WHERE id = ?`).bind(invoice.brand_id).first();
  const availableMethods = brand
    ? METHODS.filter((m) => brand[`${m.id}_enabled`] && brand[`${m.id}_number`]).map((m) => ({ id: m.id, label: m.label, color: m.color }))
    : [];
  return json({ ...invoicePublic(invoice, brand), availableMethods }, 200);
}

async function selectMethod(id, request, env) {
  const invoice = await getInvoiceRaw(id, env);
  if (!invoice) return json({ error: "Invoice not found." }, 404);
  if (invoice.status !== "pending") return json({ ...invoicePublic(invoice), error: "This invoice is no longer pending." }, 409);

  const body = await readJson(request);
  const method = normalizeMethod(body.method);
  if (!method) return json({ error: "সঠিক মেথড দিন।" }, 400);

  const brand = await env.DB.prepare(`SELECT * FROM brands WHERE id = ?`).bind(invoice.brand_id).first();
  if (!brand || !brand.enabled || !brand[`${method}_enabled`] || !brand[`${method}_number`]) {
    return json({ error: "এই মেথডটি এই মুহূর্তে উপলব্ধ নয়।" }, 409);
  }

  await env.DB.prepare(`UPDATE invoices SET method = ?, merchant_number = ? WHERE id = ?`)
    .bind(method, brand[`${method}_number`], id).run();

  const updated = await getInvoiceRaw(id, env);
  return json(invoicePublic(updated, brand), 200);
}

async function signPayload(payload, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return toHex(new Uint8Array(sig));
}
async function fireWebhook(invoice, env, ctx) {
  if (!invoice.callback_url) return;
  const brand = await env.DB.prepare(`SELECT api_key FROM brands WHERE id = ?`).bind(invoice.brand_id).first();
  const payload = JSON.stringify({
    event: "invoice.verified", id: invoice.id, reference: invoice.reference, amount: invoice.amount,
    method: invoice.method, trxId: invoice.trx_id, senderNumber: invoice.sender_number, verifiedAt: invoice.verified_at,
  });
  const secret = brand ? brand.api_key : CONFIG.SESSION_SECRET;
  const send = signPayload(payload, secret).then((signature) =>
    fetch(invoice.callback_url, { method: "POST", headers: { "Content-Type": "application/json", "X-Signature": signature }, body: payload }).catch(() => {})
  );
  if (ctx && ctx.waitUntil) ctx.waitUntil(send);
  else await send;
}

// Enforces: TrxID must correspond to an SMS that matches this invoice's
// amount/method AND arrived within the invoice's own 15-minute window
// (created_at..expires_at) — i.e. "was this verified in the last 15 min?".
async function verifyInvoice(id, request, env, ctx) {
  const invoice = await getInvoiceRaw(id, env);
  if (!invoice) return json({ error: "Invoice not found." }, 404);
  if (invoice.status === "verified") return json({ ...invoicePublic(invoice), message: "Already verified." }, 200);
  if (invoice.status === "expired") return json({ ...invoicePublic(invoice), message: "This invoice has expired." }, 409);
  if (!invoice.method) return json({ error: "আগে পেমেন্ট মেথড সিলেক্ট করুন।" }, 400);

  const body = await readJson(request);
  const trxId = normalizeTrx(body.trxId);
  const senderNumber = body.senderNumber ? String(body.senderNumber).trim() : null;
  if (!trxId || trxId.length < 5) return json({ error: "সঠিক Transaction ID দিন।" }, 400);

  const reused = await env.DB.prepare(`SELECT id FROM invoices WHERE trx_id = ? AND status = 'verified' AND id != ? AND brand_id = ?`)
    .bind(trxId, id, invoice.brand_id).first();
  if (reused) return json({ error: "এই Transaction ID ইতিমধ্যে অন্য একটি পেমেন্ট ভেরিফাই করতে ব্যবহৃত হয়েছে।" }, 409);

  await env.DB.prepare(`UPDATE invoices SET trx_id = ?, sender_number = ? WHERE id = ?`).bind(trxId, senderNumber, id).run();

  const match = await env.DB.prepare(
    `SELECT * FROM sms_transactions WHERE brand_id = ? AND trx_id = ? AND method = ? AND matched_invoice_id IS NULL
       AND received_at BETWEEN ? AND ? AND ABS(amount - ?) <= ? LIMIT 1`
  ).bind(invoice.brand_id, trxId, invoice.method, invoice.created_at, invoice.expires_at, invoice.amount, AMOUNT_TOLERANCE).first();

  if (!match) {
    return json({ ...invoicePublic(invoice), trxId, senderNumber, status: "pending", message: "TrxID পাওয়া যায়নি।" }, 202);
  }

  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare(`UPDATE invoices SET status = 'verified', verified_at = ? WHERE id = ?`).bind(now, id),
    env.DB.prepare(`UPDATE sms_transactions SET matched_invoice_id = ? WHERE id = ?`).bind(id, match.id),
  ]);
  const updated = await getInvoiceRaw(id, env);
  await fireWebhook(updated, env, ctx);
  return json({ ...invoicePublic(updated), message: "Payment verified." }, 200);
}

async function ingestSms(request, env, ctx) {
  const brand = await getBrandByApiKey(request, env);
  if (!brand) return json({ error: "Unauthorized." }, 401);

  const body = await readJson(request);
  const trxId = normalizeTrx(body.trxId);
  const amount = Number(body.amount);
  const method = normalizeMethod(body.method) || "bkash";
  const senderNumber = body.senderNumber ? String(body.senderNumber).trim() : null;
  const receivedAt = Number(body.receivedAt) || Date.now();
  const rawSms = body.rawSms ? String(body.rawSms).slice(0, 1000) : null;
  if (!trxId || !amount || amount <= 0) return json({ error: "trxId and a positive amount are required." }, 400);

  const smsId = crypto.randomUUID();
  const now = Date.now();
  try {
    await env.DB.prepare(
      `INSERT INTO sms_transactions (id, brand_id, trx_id, amount, sender_number, method, raw_sms, received_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(smsId, brand.id, trxId, amount, senderNumber, method, rawSms, receivedAt, now).run();
  } catch {
    return json({ ok: true, message: "Already recorded (duplicate trxID)." }, 200);
  }

  let invoice = await env.DB.prepare(
    `SELECT * FROM invoices WHERE brand_id = ? AND trx_id = ? AND method = ? AND status = 'pending' AND ? BETWEEN created_at AND expires_at LIMIT 1`
  ).bind(brand.id, trxId, method, receivedAt).first();

  if (!invoice) {
    const candidates = await env.DB.prepare(
      `SELECT * FROM invoices WHERE brand_id = ? AND method = ? AND status = 'pending' AND trx_id IS NULL
         AND ? BETWEEN created_at AND expires_at AND ABS(amount - ?) <= ?`
    ).bind(brand.id, method, receivedAt, amount, AMOUNT_TOLERANCE).all();
    if (candidates.results && candidates.results.length === 1) invoice = candidates.results[0];
  }
  if (!invoice) return json({ ok: true, matched: false, message: "SMS stored, no matching invoice yet." }, 200);

  await env.DB.batch([
    env.DB.prepare(`UPDATE invoices SET status = 'verified', trx_id = ?, sender_number = COALESCE(sender_number, ?), verified_at = ? WHERE id = ?`)
      .bind(trxId, senderNumber, now, invoice.id),
    env.DB.prepare(`UPDATE sms_transactions SET matched_invoice_id = ? WHERE id = ?`).bind(invoice.id, smsId),
  ]);
  const verifiedInvoice = await getInvoiceRaw(invoice.id, env);
  await fireWebhook(verifiedInvoice, env, ctx);
  return json({ ok: true, matched: true, invoiceId: invoice.id }, 200);
}

// ---- public config (download apk url, donate numbers) --------------------

async function getConfigValue(env, key, fallback) {
  const row = await env.DB.prepare(`SELECT value FROM app_config WHERE key = ?`).bind(key).first();
  return row ? row.value : fallback;
}
async function setConfigValue(env, key, value) {
  await env.DB.prepare(`INSERT INTO app_config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
    .bind(key, value).run();
}

async function publicConfig(request, env) {
  const [apkUrl, donateBkash, donateNagad, donateNote] = await Promise.all([
    getConfigValue(env, "apk_url", ""),
    getConfigValue(env, "donate_bkash", ""),
    getConfigValue(env, "donate_nagad", ""),
    getConfigValue(env, "donate_note", ""),
  ]);
  return json({ siteName: CONFIG.SITE_NAME, methods: METHODS, apkUrl, donateBkash, donateNagad, donateNote }, 200);
}

// ---- admin handlers --------------------------------------------------

async function adminStats(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const [users, brands, invoices, verified] = await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) c FROM users`).first(),
    env.DB.prepare(`SELECT COUNT(*) c FROM brands`).first(),
    env.DB.prepare(`SELECT COUNT(*) c FROM invoices`).first(),
    env.DB.prepare(`SELECT COALESCE(SUM(amount),0) s, COUNT(*) c FROM invoices WHERE status='verified'`).first(),
  ]);
  return json({ users: users.c, brands: brands.c, invoices: invoices.c, verifiedVolume: verified.s, verifiedCount: verified.c }, 200);
}

async function adminListUsers(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const rows = await env.DB.prepare(`SELECT id, email, name, suspended, created_at FROM users ORDER BY created_at DESC LIMIT 500`).all();
  return json({ users: rows.results || [] }, 200);
}

async function adminToggleUser(userId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const body = await readJson(request);
  await env.DB.prepare(`UPDATE users SET suspended = ? WHERE id = ?`).bind(body.suspended ? 1 : 0, userId).run();
  return json({ ok: true }, 200);
}

async function adminListBrands(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const rows = await env.DB.prepare(
    `SELECT b.*, u.email AS owner_email FROM brands b JOIN users u ON u.id = b.user_id ORDER BY b.created_at DESC LIMIT 500`
  ).all();
  return json({ brands: (rows.results || []).map((b) => ({ ...brandPublic(b), ownerEmail: b.owner_email })) }, 200);
}

async function adminToggleBrand(brandId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const body = await readJson(request);
  await env.DB.prepare(`UPDATE brands SET enabled = ? WHERE id = ?`).bind(body.enabled ? 1 : 0, brandId).run();
  return json({ ok: true }, 200);
}

async function adminToggleBrandMethod(brandId, methodId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  if (!METHOD_IDS.includes(methodId)) return json({ error: "Unknown method." }, 400);
  const body = await readJson(request);
  await env.DB.prepare(`UPDATE brands SET ${methodId}_enabled = ? WHERE id = ?`).bind(body.enabled ? 1 : 0, brandId).run();
  return json({ ok: true }, 200);
}

async function adminTransactions(request, env, url) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const limit = Math.min(Number(url.searchParams.get("limit")) || 50, 500);
  const rows = await env.DB.prepare(
    `SELECT i.id, i.reference, i.amount, i.method, i.status, i.trx_id, i.created_at, i.verified_at, b.name AS brand_name, u.email AS owner_email
     FROM invoices i JOIN brands b ON b.id = i.brand_id JOIN users u ON u.id = b.user_id
     ORDER BY i.created_at DESC LIMIT ?`
  ).bind(limit).all();
  return json({ transactions: rows.results || [] }, 200);
}

async function adminUpdateConfig(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const body = await readJson(request);
  const allowed = ["apk_url", "donate_bkash", "donate_nagad", "donate_note"];
  for (const key of allowed) {
    if (body[key] !== undefined) await setConfigValue(env, key, String(body[key]).slice(0, 1000));
  }
  return json({ ok: true }, 200);
}

// ---- API router (mounted at /api/* by index.js) ---------------------------

export async function handleApi(request, env, ctx, url) {
  const { pathname } = url;
  const method = request.method;

  if (pathname === "/api/health") return json({ ok: true, time: Date.now() }, 200);

  // auth
  if (pathname === "/api/auth/signup" && method === "POST") return await handleSignup(request, env);
  if (pathname === "/api/auth/login" && method === "POST") return await handleLogin(request, env);
  if (pathname === "/api/auth/logout" && method === "POST") return handleLogout();
  if (pathname === "/api/me" && method === "GET") return await handleMe(request, env);

  // brands (session)
  if (pathname === "/api/brands" && method === "GET") return await listBrands(request, env);
  if (pathname === "/api/brands" && method === "POST") return await createBrand(request, env);
  let m;
  if ((m = pathname.match(/^\/api\/brands\/([a-zA-Z0-9-]+)$/)) && method === "POST") return await updateBrandProfile(m[1], request, env);
  if ((m = pathname.match(/^\/api\/brands\/([a-zA-Z0-9-]+)\/methods$/)) && method === "POST") return await updateBrandMethods(m[1], request, env);
  if ((m = pathname.match(/^\/api\/brands\/([a-zA-Z0-9-]+)\/regenerate-key$/)) && method === "POST") return await regenerateBrandKey(m[1], request, env);

  // my stats / transactions
  if (pathname === "/api/me/stats" && method === "GET") return await myStats(request, env);
  if (pathname === "/api/me/transactions" && method === "GET") return await myTransactions(request, env, url);

  // brand-key invoice API
  if (pathname === "/api/invoices" && method === "POST") return await createInvoice(request, env, url);
  if ((m = pathname.match(/^\/api\/invoices\/([a-zA-Z0-9-]+)$/)) && method === "GET") return await getInvoiceRoute(m[1], env);
  if ((m = pathname.match(/^\/api\/invoices\/([a-zA-Z0-9-]+)\/select-method$/)) && method === "POST") return await selectMethod(m[1], request, env);
  if ((m = pathname.match(/^\/api\/invoices\/([a-zA-Z0-9-]+)\/verify$/)) && method === "POST") return await verifyInvoice(m[1], request, env, ctx);
  if (pathname === "/api/sms/ingest" && method === "POST") return await ingestSms(request, env, ctx);

  // public config
  if (pathname === "/api/config/public" && method === "GET") return await publicConfig(request, env);

  // admin
  if (pathname === "/api/admin/stats" && method === "GET") return await adminStats(request, env);
  if (pathname === "/api/admin/users" && method === "GET") return await adminListUsers(request, env);
  if ((m = pathname.match(/^\/api\/admin\/users\/([a-zA-Z0-9-]+)\/toggle$/)) && method === "POST") return await adminToggleUser(m[1], request, env);
  if (pathname === "/api/admin/brands" && method === "GET") return await adminListBrands(request, env);
  if ((m = pathname.match(/^\/api\/admin\/brands\/([a-zA-Z0-9-]+)\/toggle$/)) && method === "POST") return await adminToggleBrand(m[1], request, env);
  if ((m = pathname.match(/^\/api\/admin\/brands\/([a-zA-Z0-9-]+)\/methods\/([a-z]+)\/toggle$/)) && method === "POST")
    return await adminToggleBrandMethod(m[1], m[2], request, env);
  if (pathname === "/api/admin/transactions" && method === "GET") return await adminTransactions(request, env, url);
  if (pathname === "/api/admin/config" && method === "POST") return await adminUpdateConfig(request, env);

  return json({ error: "Not found." }, 404);
}

export { CONFIG, corsHeaders, json };
