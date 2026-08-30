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
  SESSION_SECRET: "5b63732a0ba6258be7d1300226f2deeecfe43cfb6869efbb",
  INVOICE_TTL_MINUTES: 15,
  SESSION_TTL_DAYS: 30,
  // Emails in this list get admin access automatically after a normal
  // email+password login. No passwordless bypass — a real account with a
  // real password must exist and log in normally.
  ADMIN_EMAILS: ["devugly@login.com"],
  CORS_ORIGIN: "*",

  // ---- security tuning ----
  LOGIN_MAX_FAILED_ATTEMPTS: 5, // per-account lockout threshold
  LOGIN_LOCKOUT_MINUTES: 15,
  RATE_LIMIT_LOGIN_PER_IP: 15, // requests per window
  RATE_LIMIT_LOGIN_WINDOW_MIN: 15,
  RATE_LIMIT_SIGNUP_PER_IP: 6,
  RATE_LIMIT_SIGNUP_WINDOW_MIN: 60,
  RATE_LIMIT_VERIFY_PER_INVOICE: 30, // TrxID guesses per invoice
  RATE_LIMIT_VERIFY_WINDOW_MIN: 15,
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

// Applied to EVERY response (HTML and JSON) by index.js. Blocks clickjacking,
// MIME-sniffing, leaking referrers cross-site, and — combined with escaping
// user content client-side — limits what an XSS payload could reach even if
// one slipped through, since scripts/styles/fonts/connections are locked to
// this origin (plus Google Fonts, which the UI actually uses).
function securityHeaders() {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src 'self' https://fonts.gstatic.com; " +
      "img-src 'self' data: https:; " +
      "connect-src 'self'; " +
      "frame-ancestors 'none'; " +
      "base-uri 'self'; form-action 'self'",
  };
}

function json(data, status, extraHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(), ...securityHeaders(), ...(extraHeaders || {}) },
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

// ---- security utilities ---------------------------------------------

function getClientIp(request) {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
}

/**
 * Simple fixed-window rate limiter backed by D1. Returns true if the request
 * is allowed, false if the caller should be blocked (429). Not perfectly
 * precise under high concurrency (D1 has no atomic increment), but more
 * than sufficient to stop scripted brute-force/spam against auth endpoints.
 */
async function checkRateLimit(env, key, max, windowMinutes) {
  const now = Date.now();
  const windowMs = windowMinutes * 60000;
  const row = await env.DB.prepare(`SELECT * FROM rate_limits WHERE key = ?`).bind(key).first();

  if (!row || now - row.window_start > windowMs) {
    await env.DB.prepare(
      `INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)
       ON CONFLICT(key) DO UPDATE SET count = 1, window_start = excluded.window_start`
    ).bind(key, now).run();
    return true;
  }
  if (row.count >= max) return false;
  await env.DB.prepare(`UPDATE rate_limits SET count = count + 1 WHERE key = ?`).bind(key).run();
  return true;
}

async function logAudit(env, adminEmail, action, targetType, targetId, detail, request) {
  try {
    await env.DB.prepare(
      `INSERT INTO admin_audit_log (id, admin_email, action, target_type, target_id, detail, ip, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        crypto.randomUUID(),
        adminEmail,
        action,
        targetType || null,
        targetId || null,
        detail || null,
        request ? getClientIp(request) : null,
        Date.now()
      )
      .run();
  } catch {
    // Audit logging must never break the actual admin action.
  }
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
// A syntactically-valid but unusable hash used as the comparison target when
// no account exists, so a login attempt for a nonexistent email still pays
// the same PBKDF2 cost as a real one (constant-time-ish, defeats simple
// response-time account enumeration).
const DUMMY_HASH =
  "00000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000";

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
async function createSessionToken(userId, tokenVersion) {
  const payload = JSON.stringify({ uid: userId, tv: tokenVersion || 0, exp: Date.now() + CONFIG.SESSION_TTL_DAYS * 86400000 });
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
  // If an admin (or the user via "logout everywhere") bumped token_version
  // since this token was issued, treat the old token as dead.
  if ((payload.tv || 0) !== (user.token_version || 0)) return null;
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

// Used by the FreePay Sync mobile app to validate a Brand API key on login
// and show which brand it's connected to, without exposing anything the
// app doesn't need.
async function brandMe(request, env) {
  const brand = await getBrandByApiKey(request, env);
  if (!brand) return json({ error: "API key ভুল বা নেই।" }, 401);
  return json(
    {
      id: brand.id,
      name: brand.name,
      logoUrl: brand.logo_url,
      enabled: !!brand.enabled,
      methodsEnabled: {
        bkash: !!brand.bkash_enabled, nagad: !!brand.nagad_enabled, upay: !!brand.upay_enabled,
        rocket: !!brand.rocket_enabled, cellfin: !!brand.cellfin_enabled,
      },
    },
    200
  );
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
  const ip = getClientIp(request);
  const allowed = await checkRateLimit(env, `signup:${ip}`, CONFIG.RATE_LIMIT_SIGNUP_PER_IP, CONFIG.RATE_LIMIT_SIGNUP_WINDOW_MIN);
  if (!allowed) return json({ error: "খুব বেশি চেষ্টা হয়েছে। কিছুক্ষণ পর আবার চেষ্টা করুন।" }, 429);

  const body = await readJson(request);
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const name = body.name ? String(body.name).trim().slice(0, 80) : null;

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "সঠিক ইমেইল দিন।" }, 400);
  if (password.length < 8) return json({ error: "পাসওয়ার্ড কমপক্ষে ৮ ক্যারেক্টার হতে হবে।" }, 400);
  if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
    return json({ error: "পাসওয়ার্ডে কমপক্ষে একটি অক্ষর ও একটি সংখ্যা থাকতে হবে।" }, 400);
  }

  const existing = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
  if (existing) return json({ error: "এই ইমেইল দিয়ে আগে থেকেই অ্যাকাউন্ট আছে।" }, 409);

  const id = crypto.randomUUID();
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO users (id, email, password_hash, name, suspended, failed_login_attempts, token_version, created_at)
     VALUES (?, ?, ?, ?, 0, 0, 0, ?)`
  )
    .bind(id, email, await hashPassword(password), name, now)
    .run();

  const token = await createSessionToken(id, 0);
  const user = await env.DB.prepare(`SELECT * FROM users WHERE id = ?`).bind(id).first();
  return json({ user: userPublic(user) }, 201, sessionCookieHeader(token));
}

async function handleLogin(request, env) {
  const ip = getClientIp(request);
  const ipAllowed = await checkRateLimit(env, `login:${ip}`, CONFIG.RATE_LIMIT_LOGIN_PER_IP, CONFIG.RATE_LIMIT_LOGIN_WINDOW_MIN);
  if (!ipAllowed) return json({ error: "খুব বেশি লগইন চেষ্টা হয়েছে এই IP থেকে। কিছুক্ষণ পর আবার চেষ্টা করুন।" }, 429);

  const body = await readJson(request);
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const user = await env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();

  // Per-account lockout: independent of the IP limit above, so a distributed
  // attack against ONE account still gets stopped even from many IPs.
  if (user && user.lockout_until && Date.now() < user.lockout_until) {
    const minsLeft = Math.ceil((user.lockout_until - Date.now()) / 60000);
    return json({ error: `একাধিকবার ভুল পাসওয়ার্ড দেওয়ায় অ্যাকাউন্টটি সাময়িকভাবে লক করা হয়েছে। ${minsLeft} মিনিট পর আবার চেষ্টা করুন।` }, 423);
  }

  const validPassword = await verifyPassword(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !validPassword) {
    if (user) {
      const attempts = (user.failed_login_attempts || 0) + 1;
      const lockout = attempts >= CONFIG.LOGIN_MAX_FAILED_ATTEMPTS ? Date.now() + CONFIG.LOGIN_LOCKOUT_MINUTES * 60000 : null;
      await env.DB.prepare(`UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE id = ?`)
        .bind(attempts, lockout, user.id)
        .run();
    }
    return json({ error: "ইমেইল অথবা পাসওয়ার্ড ভুল।" }, 401);
  }
  if (user.suspended) return json({ error: "এই অ্যাকাউন্ট সাসপেন্ড করা হয়েছে। এডমিনের সাথে যোগাযোগ করুন।" }, 403);

  // Successful login clears the failure counter.
  await env.DB.prepare(`UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?`).bind(user.id).run();

  const token = await createSessionToken(user.id, user.token_version || 0);
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

  const allowed = await checkRateLimit(env, `verify:${id}`, CONFIG.RATE_LIMIT_VERIFY_PER_INVOICE, CONFIG.RATE_LIMIT_VERIFY_WINDOW_MIN);
  if (!allowed) return json({ error: "অনেকবার চেষ্টা হয়েছে। কিছুক্ষণ অপেক্ষা করুন।" }, 429);

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
  const [apkUrl, donateBkash, donateNagad, donateNote, siteName, supportEmail] = await Promise.all([
    getConfigValue(env, "apk_url", ""),
    getConfigValue(env, "donate_bkash", ""),
    getConfigValue(env, "donate_nagad", ""),
    getConfigValue(env, "donate_note", ""),
    getConfigValue(env, "site_name", CONFIG.SITE_NAME),
    getConfigValue(env, "support_email", ""),
  ]);
  return json({ siteName, methods: METHODS, apkUrl, donateBkash, donateNagad, donateNote, supportEmail }, 200);
}

// ---- admin handlers --------------------------------------------------

async function adminStats(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const [users, brands, invoices, verified, suspended, locked] = await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) c FROM users`).first(),
    env.DB.prepare(`SELECT COUNT(*) c FROM brands`).first(),
    env.DB.prepare(`SELECT COUNT(*) c FROM invoices`).first(),
    env.DB.prepare(`SELECT COALESCE(SUM(amount),0) s, COUNT(*) c FROM invoices WHERE status='verified'`).first(),
    env.DB.prepare(`SELECT COUNT(*) c FROM users WHERE suspended = 1`).first(),
    env.DB.prepare(`SELECT COUNT(*) c FROM users WHERE lockout_until IS NOT NULL AND lockout_until > ?`).bind(Date.now()).first(),
  ]);
  return json(
    {
      users: users.c, brands: brands.c, invoices: invoices.c,
      verifiedVolume: verified.s, verifiedCount: verified.c,
      suspendedUsers: suspended.c, lockedUsers: locked.c,
    },
    200
  );
}

// ---- admin: users (search, pagination, full detail, edit, delete, reset) --

async function adminListUsers(request, env, url) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const search = (url.searchParams.get("q") || "").trim();
  const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
  const limit = Math.min(Number(url.searchParams.get("limit")) || 25, 100);
  const offset = (page - 1) * limit;

  const where = search ? `WHERE email LIKE ? OR name LIKE ?` : "";
  const params = search ? [`%${search}%`, `%${search}%`] : [];

  const [rows, countRow] = await Promise.all([
    env.DB.prepare(
      `SELECT id, email, name, suspended, failed_login_attempts, lockout_until, token_version, created_at
       FROM users ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
    ).bind(...params, limit, offset).all(),
    env.DB.prepare(`SELECT COUNT(*) c FROM users ${where}`).bind(...params).first(),
  ]);
  return json({ users: rows.results || [], total: countRow.c, page, limit }, 200);
}

async function adminUserDetail(userId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const user = await env.DB.prepare(
    `SELECT id, email, name, suspended, failed_login_attempts, lockout_until, token_version, created_at FROM users WHERE id = ?`
  ).bind(userId).first();
  if (!user) return json({ error: "User পাওয়া যায়নি।" }, 404);

  const [brands, stats] = await Promise.all([
    env.DB.prepare(`SELECT * FROM brands WHERE user_id = ? ORDER BY created_at DESC`).bind(userId).all(),
    env.DB.prepare(
      `SELECT COUNT(*) txCount, COALESCE(SUM(CASE WHEN i.status='verified' THEN i.amount ELSE 0 END),0) volume
       FROM invoices i JOIN brands b ON b.id = i.brand_id WHERE b.user_id = ?`
    ).bind(userId).first(),
  ]);

  return json(
    {
      user,
      brands: (brands.results || []).map(brandPublic),
      transactionCount: stats.txCount,
      verifiedVolume: stats.volume,
    },
    200
  );
}

async function adminUpdateUser(userId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const target = await env.DB.prepare(`SELECT * FROM users WHERE id = ?`).bind(userId).first();
  if (!target) return json({ error: "User পাওয়া যায়নি।" }, 404);

  const body = await readJson(request);
  const name = body.name !== undefined ? String(body.name).trim().slice(0, 80) : target.name;
  let email = target.email;
  if (body.email !== undefined) {
    email = String(body.email).trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "সঠিক ইমেইল দিন।" }, 400);
    const clash = await env.DB.prepare(`SELECT id FROM users WHERE email = ? AND id != ?`).bind(email, userId).first();
    if (clash) return json({ error: "এই ইমেইল অন্য অ্যাকাউন্টে ব্যবহৃত হচ্ছে।" }, 409);
  }

  await env.DB.prepare(`UPDATE users SET name = ?, email = ? WHERE id = ?`).bind(name, email, userId).run();
  await logAudit(env, admin.email, "user.edit", "user", userId, `name/email updated (${target.email} -> ${email})`, request);
  return json({ ok: true }, 200);
}

async function adminToggleUser(userId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const body = await readJson(request);
  const suspended = body.suspended ? 1 : 0;
  await env.DB.prepare(`UPDATE users SET suspended = ? WHERE id = ?`).bind(suspended, userId).run();
  await logAudit(env, admin.email, suspended ? "user.suspend" : "user.unsuspend", "user", userId, null, request);
  return json({ ok: true }, 200);
}

// Forces every existing session for this account to stop working immediately
// (bumping token_version invalidates all previously-issued tokens).
async function adminForceLogout(userId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  await env.DB.prepare(`UPDATE users SET token_version = token_version + 1 WHERE id = ?`).bind(userId).run();
  await logAudit(env, admin.email, "user.force_logout", "user", userId, null, request);
  return json({ ok: true }, 200);
}

// Admin sets a new temporary password for a user (e.g. locked-out account
// recovery) and forces all their existing sessions to end.
async function adminResetPassword(userId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const user = await env.DB.prepare(`SELECT id FROM users WHERE id = ?`).bind(userId).first();
  if (!user) return json({ error: "User পাওয়া যায়নি।" }, 404);

  const tempPassword = genId("", 12).toLowerCase() + Math.floor(Math.random() * 90 + 10);
  await env.DB.prepare(
    `UPDATE users SET password_hash = ?, token_version = token_version + 1, failed_login_attempts = 0, lockout_until = NULL WHERE id = ?`
  )
    .bind(await hashPassword(tempPassword), userId)
    .run();
  await logAudit(env, admin.email, "user.reset_password", "user", userId, "temporary password issued", request);
  return json({ ok: true, tempPassword }, 200);
}

// Permanently deletes a user AND everything that belongs to them (brands,
// invoices, sms logs). Irreversible — the UI requires a typed confirmation.
async function adminDeleteUser(userId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const user = await env.DB.prepare(`SELECT email FROM users WHERE id = ?`).bind(userId).first();
  if (!user) return json({ error: "User পাওয়া যায়নি।" }, 404);
  if (isAdmin(user)) return json({ error: "Admin অ্যাকাউন্ট ডিলিট করা যাবে না।" }, 403);

  const brandIds = (await env.DB.prepare(`SELECT id FROM brands WHERE user_id = ?`).bind(userId).all()).results || [];
  for (const b of brandIds) {
    await env.DB.prepare(`DELETE FROM sms_transactions WHERE brand_id = ?`).bind(b.id).run();
    await env.DB.prepare(`DELETE FROM invoices WHERE brand_id = ?`).bind(b.id).run();
  }
  await env.DB.prepare(`DELETE FROM brands WHERE user_id = ?`).bind(userId).run();
  await env.DB.prepare(`DELETE FROM users WHERE id = ?`).bind(userId).run();

  await logAudit(env, admin.email, "user.delete", "user", userId, `deleted account ${user.email} (${brandIds.length} brands cascaded)`, request);
  return json({ ok: true }, 200);
}

// ---- admin: brands ---------------------------------------------------

async function adminListBrands(request, env, url) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const search = (url.searchParams.get("q") || "").trim();
  const where = search ? `WHERE b.name LIKE ? OR u.email LIKE ?` : "";
  const params = search ? [`%${search}%`, `%${search}%`] : [];
  const rows = await env.DB.prepare(
    `SELECT b.*, u.email AS owner_email FROM brands b JOIN users u ON u.id = b.user_id ${where} ORDER BY b.created_at DESC LIMIT 300`
  ).bind(...params).all();
  return json({ brands: (rows.results || []).map((b) => ({ ...brandPublic(b), ownerEmail: b.owner_email })) }, 200);
}

async function adminToggleBrand(brandId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const body = await readJson(request);
  const enabled = body.enabled ? 1 : 0;
  await env.DB.prepare(`UPDATE brands SET enabled = ? WHERE id = ?`).bind(enabled, brandId).run();
  await logAudit(env, admin.email, enabled ? "brand.enable" : "brand.disable", "brand", brandId, null, request);
  return json({ ok: true }, 200);
}

async function adminToggleBrandMethod(brandId, methodId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  if (!METHOD_IDS.includes(methodId)) return json({ error: "Unknown method." }, 400);
  const body = await readJson(request);
  const enabled = body.enabled ? 1 : 0;
  await env.DB.prepare(`UPDATE brands SET ${methodId}_enabled = ? WHERE id = ?`).bind(enabled, brandId).run();
  await logAudit(env, admin.email, "brand.method_toggle", "brand", brandId, `${methodId} -> ${enabled ? "on" : "off"}`, request);
  return json({ ok: true }, 200);
}

async function adminDeleteBrand(brandId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const brand = await env.DB.prepare(`SELECT name FROM brands WHERE id = ?`).bind(brandId).first();
  if (!brand) return json({ error: "Brand পাওয়া যায়নি।" }, 404);

  await env.DB.prepare(`DELETE FROM sms_transactions WHERE brand_id = ?`).bind(brandId).run();
  await env.DB.prepare(`DELETE FROM invoices WHERE brand_id = ?`).bind(brandId).run();
  await env.DB.prepare(`DELETE FROM brands WHERE id = ?`).bind(brandId).run();

  await logAudit(env, admin.email, "brand.delete", "brand", brandId, `deleted brand "${brand.name}"`, request);
  return json({ ok: true }, 200);
}

async function adminRegenerateBrandKey(brandId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const brand = await env.DB.prepare(`SELECT id FROM brands WHERE id = ?`).bind(brandId).first();
  if (!brand) return json({ error: "Brand পাওয়া যায়নি।" }, 404);
  const newKey = genId("BR", 32);
  await env.DB.prepare(`UPDATE brands SET api_key = ? WHERE id = ?`).bind(newKey, brandId).run();
  await logAudit(env, admin.email, "brand.regenerate_key", "brand", brandId, null, request);
  return json({ apiKey: newKey }, 200);
}

// ---- admin: transactions ----------------------------------------------

async function adminTransactions(request, env, url) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const search = (url.searchParams.get("q") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();
  const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
  const limit = Math.min(Number(url.searchParams.get("limit")) || 50, 200);
  const offset = (page - 1) * limit;

  const clauses = [];
  const params = [];
  if (search) {
    clauses.push(`(i.id LIKE ? OR i.trx_id LIKE ? OR i.reference LIKE ? OR b.name LIKE ? OR u.email LIKE ?)`);
    params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
  }
  if (status && ["pending", "verified", "expired"].includes(status)) {
    clauses.push(`i.status = ?`);
    params.push(status);
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";

  const [rows, countRow] = await Promise.all([
    env.DB.prepare(
      `SELECT i.id, i.reference, i.amount, i.method, i.status, i.trx_id, i.created_at, i.verified_at, b.name AS brand_name, u.email AS owner_email
       FROM invoices i JOIN brands b ON b.id = i.brand_id JOIN users u ON u.id = b.user_id
       ${where} ORDER BY i.created_at DESC LIMIT ? OFFSET ?`
    ).bind(...params, limit, offset).all(),
    env.DB.prepare(
      `SELECT COUNT(*) c FROM invoices i JOIN brands b ON b.id = i.brand_id JOIN users u ON u.id = b.user_id ${where}`
    ).bind(...params).first(),
  ]);
  return json({ transactions: rows.results || [], total: countRow.c, page, limit }, 200);
}

async function adminDeleteInvoice(invoiceId, request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const invoice = await env.DB.prepare(`SELECT id FROM invoices WHERE id = ?`).bind(invoiceId).first();
  if (!invoice) return json({ error: "Invoice পাওয়া যায়নি।" }, 404);
  await env.DB.prepare(`UPDATE sms_transactions SET matched_invoice_id = NULL WHERE matched_invoice_id = ?`).bind(invoiceId).run();
  await env.DB.prepare(`DELETE FROM invoices WHERE id = ?`).bind(invoiceId).run();
  await logAudit(env, admin.email, "invoice.delete", "invoice", invoiceId, null, request);
  return json({ ok: true }, 200);
}

// ---- admin: audit log ---------------------------------------------------

async function adminAuditLog(request, env, url) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const limit = Math.min(Number(url.searchParams.get("limit")) || 100, 500);
  const rows = await env.DB.prepare(`SELECT * FROM admin_audit_log ORDER BY created_at DESC LIMIT ?`).bind(limit).all();
  return json({ logs: rows.results || [] }, 200);
}



async function adminAnalytics(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);

  const days = 7;
  const cutoff = Date.now() - days * 86400000;

  const [dailyRows, topBrands, recentUsers, methodBreakdown] = await Promise.all([
    env.DB.prepare(
      `SELECT date(verified_at/1000, 'unixepoch') AS day, COALESCE(SUM(amount),0) AS volume, COUNT(*) AS count
       FROM invoices WHERE status='verified' AND verified_at >= ? GROUP BY day ORDER BY day ASC`
    ).bind(cutoff).all(),
    env.DB.prepare(
      `SELECT b.id, b.name, u.email AS owner_email, COALESCE(SUM(CASE WHEN i.status='verified' THEN i.amount ELSE 0 END),0) AS volume,
              COUNT(CASE WHEN i.status='verified' THEN 1 END) AS count
       FROM brands b JOIN users u ON u.id = b.user_id LEFT JOIN invoices i ON i.brand_id = b.id
       GROUP BY b.id ORDER BY volume DESC LIMIT 8`
    ).all(),
    env.DB.prepare(`SELECT email, name, created_at FROM users ORDER BY created_at DESC LIMIT 8`).all(),
    env.DB.prepare(
      `SELECT method, COALESCE(SUM(amount),0) AS volume, COUNT(*) AS count FROM invoices
       WHERE status='verified' AND method IS NOT NULL GROUP BY method ORDER BY volume DESC`
    ).all(),
  ]);

  // Fill in any missing days in the window with zeroes so the chart is continuous.
  const byDay = {};
  (dailyRows.results || []).forEach((r) => (byDay[r.day] = r));
  const daily = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000);
    const key = d.toISOString().slice(0, 10);
    daily.push(byDay[key] || { day: key, volume: 0, count: 0 });
  }

  return json(
    {
      daily,
      topBrands: (topBrands.results || []).map((b) => ({ ...b, ownerEmail: b.owner_email })),
      recentUsers: recentUsers.results || [],
      methodBreakdown: methodBreakdown.results || [],
    },
    200
  );
}

async function adminUpdateConfig(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Forbidden." }, 403);
  const body = await readJson(request);
  const allowed = ["apk_url", "donate_bkash", "donate_nagad", "donate_note", "site_name", "support_email"];
  const changed = [];
  for (const key of allowed) {
    if (body[key] !== undefined) {
      await setConfigValue(env, key, String(body[key]).slice(0, 1000));
      changed.push(key);
    }
  }
  if (changed.length) await logAudit(env, admin.email, "config.update", "config", null, changed.join(", "), request);
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
  if (pathname === "/api/brands/me" && method === "GET") return await brandMe(request, env);
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

  // admin — dashboard/stats
  if (pathname === "/api/admin/stats" && method === "GET") return await adminStats(request, env);
  if (pathname === "/api/admin/analytics" && method === "GET") return await adminAnalytics(request, env);
  if (pathname === "/api/admin/audit-log" && method === "GET") return await adminAuditLog(request, env, url);

  // admin — users
  if (pathname === "/api/admin/users" && method === "GET") return await adminListUsers(request, env, url);
  if ((m = pathname.match(/^\/api\/admin\/users\/([a-zA-Z0-9-]+)$/)) && method === "GET") return await adminUserDetail(m[1], request, env);
  if ((m = pathname.match(/^\/api\/admin\/users\/([a-zA-Z0-9-]+)$/)) && method === "POST") return await adminUpdateUser(m[1], request, env);
  if ((m = pathname.match(/^\/api\/admin\/users\/([a-zA-Z0-9-]+)\/toggle$/)) && method === "POST") return await adminToggleUser(m[1], request, env);
  if ((m = pathname.match(/^\/api\/admin\/users\/([a-zA-Z0-9-]+)\/force-logout$/)) && method === "POST") return await adminForceLogout(m[1], request, env);
  if ((m = pathname.match(/^\/api\/admin\/users\/([a-zA-Z0-9-]+)\/reset-password$/)) && method === "POST") return await adminResetPassword(m[1], request, env);
  if ((m = pathname.match(/^\/api\/admin\/users\/([a-zA-Z0-9-]+)\/delete$/)) && method === "POST") return await adminDeleteUser(m[1], request, env);

  // admin — brands
  if (pathname === "/api/admin/brands" && method === "GET") return await adminListBrands(request, env, url);
  if ((m = pathname.match(/^\/api\/admin\/brands\/([a-zA-Z0-9-]+)\/toggle$/)) && method === "POST") return await adminToggleBrand(m[1], request, env);
  if ((m = pathname.match(/^\/api\/admin\/brands\/([a-zA-Z0-9-]+)\/methods\/([a-z]+)\/toggle$/)) && method === "POST")
    return await adminToggleBrandMethod(m[1], m[2], request, env);
  if ((m = pathname.match(/^\/api\/admin\/brands\/([a-zA-Z0-9-]+)\/regenerate-key$/)) && method === "POST")
    return await adminRegenerateBrandKey(m[1], request, env);
  if ((m = pathname.match(/^\/api\/admin\/brands\/([a-zA-Z0-9-]+)\/delete$/)) && method === "POST") return await adminDeleteBrand(m[1], request, env);

  // admin — transactions
  if (pathname === "/api/admin/transactions" && method === "GET") return await adminTransactions(request, env, url);
  if ((m = pathname.match(/^\/api\/admin\/transactions\/([a-zA-Z0-9-]+)\/delete$/)) && method === "POST")
    return await adminDeleteInvoice(m[1], request, env);

  // admin — site config
  if (pathname === "/api/admin/config" && method === "POST") return await adminUpdateConfig(request, env);

  return json({ error: "Not found." }, 404);
}

export { CONFIG, corsHeaders, securityHeaders, json };
