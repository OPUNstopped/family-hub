// ============================================================================
// Milton Montessori Family Hub — entire backend in one file.
// ============================================================================

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (path.startsWith("/api/")) {
    try {
      const res = await handleApi(path, request, env, url);
      return withSecurity(res);
    } catch (err) {
      return withSecurity(json({ ok: false, error: "Server error." }, 500));
    }
  }

  const res = await next();
  return withSecurity(res);
}

async function handleApi(path, request, env, url) {
  const m = request.method;

  if (path === "/api/login") {
    if (m === "POST") return apiLogin(request, env);
    return bad("Method not allowed.", 405);
  }
  if (path === "/api/session") {
    if (m === "GET") return json({ authed: await requireAdmin(request, env) });
    if (m === "DELETE") return json({ ok: true }, 200, { "Set-Cookie": clearCookieHeader() });
    return bad("Method not allowed.", 405);
  }
  if (path === "/api/submissions") {
    if (m === "POST") return apiSubmit(request, env);
    if (m === "GET") return apiListSubmissions(request, env, url);
    if (m === "DELETE") return apiDeleteSubmission(request, env, url);
    return bad("Method not allowed.", 405);
  }
  if (path === "/api/content") {
    if (m === "GET") return apiGetContent(env);
    if (m === "PUT") return apiPutContent(request, env);
    return bad("Method not allowed.", 405);
  }
  return bad("Not found.", 404);
}

// ---- LOGIN -----------------------------------------------------------------
async function apiLogin(request, env) {
  const ip = clientIp(request);
  const burst = await rateLimit(env, `login:burst:${ip}`, 5, 60);
  if (!burst.allowed) return bad(`Too many attempts. Try again in ${burst.retryAfter}s.`, 429);
  const slow = await rateLimit(env, `login:slow:${ip}`, 30, 60 * 60);
  if (!slow.allowed) return bad("Too many attempts. Try again later.", 429);

  let body;
  try { body = await readJson(request); } catch { return bad("Invalid request."); }

  const username = String(body.username || "").trim();
  const password = String(body.password || "");

  const expectedUser = env.ADMIN_USERNAME || "admin";
  const expectedPass = env.ADMIN_PASSWORD || "miltonpta2026";

  const userOk = safeEqual(username.toLowerCase(), expectedUser.toLowerCase());
  const passOk = safeEqual(password, expectedPass);
  if (!(userOk && passOk)) return bad("Incorrect username or password.", 401);

  const ttl = 60 * 60 * 8;
  const token = await makeSession(env, ttl);
  return json({ ok: true }, 200, { "Set-Cookie": sessionCookieHeader(token, ttl) });
}

// ---- SUBMISSIONS -----------------------------------------------------------
function newId() {
  return `${Date.now()}-${crypto.getRandomValues(new Uint32Array(1))[0].toString(36)}`;
}

async function apiSubmit(request, env) {
  const ip = clientIp(request);
  const rl = await rateLimit(env, `submit:${ip}`, 8, 60 * 10);
  if (!rl.allowed) return bad("You've submitted a few times just now. Please wait a bit.", 429);
  if (!env.HUB_KV) return bad("Storage not configured.", 500);

  let body;
  try { body = await readJson(request); } catch { return bad("Invalid submission."); }

  const type = body.type === "rsvp" ? "rsvp" : "volunteer";
  const name = cleanStr(body.name, 120);
  const email = cleanStr(body.email, 254);
  if (!name) return bad("Name is required.");
  if (!isEmail(email)) return bad("A valid email is required.");

  const entry = {
    type, name, email,
    phone: cleanStr(body.phone, 40),
    event: cleanStr(body.event, 160),
    guests: cleanStr(body.guests, 10),
    message: cleanStr(body.message, 1000),
    ts: new Date().toISOString(),
    ip,
  };
  const prefix = type === "rsvp" ? "rsvp" : "vol";
  await env.HUB_KV.put(`${prefix}:${newId()}`, JSON.stringify(entry), {
    expirationTtl: 60 * 60 * 24 * 430,
  });
  return json({ ok: true });
}

async function apiListSubmissions(request, env, url) {
  if (!(await requireAdmin(request, env))) return bad("Not authorized.", 401);
  if (!env.HUB_KV) return bad("Storage not configured.", 500);

  const kind = url.searchParams.get("kind");
  async function listPrefix(prefix) {
    const out = [];
    let cursor;
    do {
      const res = await env.HUB_KV.list({ prefix: prefix + ":", cursor, limit: 1000 });
      for (const k of res.keys) {
        const v = await env.HUB_KV.get(k.name, "json");
        if (v) { delete v.ip; out.push({ id: k.name, ...v }); }
      }
      cursor = res.list_complete ? null : res.cursor;
    } while (cursor);
    out.sort((a, b) => (a.ts < b.ts ? 1 : -1));
    return out;
  }
  const result = {};
  if (!kind || kind === "vol") result.volunteers = await listPrefix("vol");
  if (!kind || kind === "rsvp") result.rsvps = await listPrefix("rsvp");
  return json({ ok: true, ...result });
}

async function apiDeleteSubmission(request, env, url) {
  if (!(await requireAdmin(request, env))) return bad("Not authorized.", 401);
  if (!env.HUB_KV) return bad("Storage not configured.", 500);

  const id = url.searchParams.get("id");
  const clear = url.searchParams.get("clear");
  if (id) {
    if (!/^(vol|rsvp):/.test(id)) return bad("Invalid id.");
    await env.HUB_KV.delete(id);
    return json({ ok: true });
  }
  if (clear === "vol" || clear === "rsvp") {
    let cursor;
    do {
      const res = await env.HUB_KV.list({ prefix: clear + ":", cursor, limit: 1000 });
      for (const k of res.keys) await env.HUB_KV.delete(k.name);
      cursor = res.list_complete ? null : res.cursor;
    } while (cursor);
    return json({ ok: true });
  }
  return bad("Nothing to delete.");
}

// ---- CONTENT ---------------------------------------------------------------
const CONTENT_KEY = "site:content";
const MAX_CONTENT_BYTES = 4.5 * 1024 * 1024;

async function apiGetContent(env) {
  if (!env.HUB_KV) return json({ ok: true, content: null });
  const content = await env.HUB_KV.get(CONTENT_KEY, "json");
  return json({ ok: true, content: content || null });
}

async function apiPutContent(request, env) {
  if (!(await requireAdmin(request, env))) return bad("Not authorized.", 401);
  if (!env.HUB_KV) return bad("Storage not configured.", 500);
  const buf = await request.arrayBuffer();
  if (buf.byteLength > MAX_CONTENT_BYTES) return bad("Content too large. Try smaller images.", 413);
  let content;
  try { content = JSON.parse(new TextDecoder().decode(buf)); }
  catch { return bad("Invalid content."); }
  if (typeof content !== "object" || content === null || Array.isArray(content)) {
    return bad("Invalid content shape.");
  }
  await env.HUB_KV.put(CONTENT_KEY, JSON.stringify(content));
  return json({ ok: true });
}

// ============================================================================
// Helpers
// ============================================================================

function withSecurity(res) {
  const h = new Headers(res.headers);
  h.set("X-Frame-Options", "DENY");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  h.set("Referrer-Policy", "strict-origin-when-cross-origin");
  h.set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=()");
  h.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; upgrade-insecure-requests"
  );
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders,
    },
  });
}
function bad(msg, status = 400) { return json({ ok: false, error: msg }, status); }

function clientIp(request) { return request.headers.get("CF-Connecting-IP") || "0.0.0.0"; }
async function readJson(request, maxBytes = 20 * 1024) {
  const buf = await request.arrayBuffer();
  if (buf.byteLength > maxBytes) throw new Error("Payload too large");
  return JSON.parse(new TextDecoder().decode(buf));
}
function cleanStr(v, max = 500) { return v == null ? "" : String(v).slice(0, max).trim(); }
function isEmail(v) { return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v) && v.length <= 254; }
function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---- Signed session cookies ------------------------------------------------
const SESSION_COOKIE = "mmfh_session";
function sessionSecret(env) {
  return (env && env.SESSION_SECRET) || "mmfh-builtin-session-key-2026-change-if-you-like";
}
async function makeSession(env, ttlSeconds = 60 * 60 * 8) {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const payload = `admin.${exp}`;
  const sig = await hmac(sessionSecret(env), payload);
  return `${payload}.${sig}`;
}
async function verifySession(env, token) {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [role, expStr, sig] = parts;
  const expected = await hmac(sessionSecret(env), `${role}.${expStr}`);
  if (!safeEqual(sig, expected)) return false;
  if (parseInt(expStr, 10) < Math.floor(Date.now() / 1000)) return false;
  return role === "admin";
}
async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret || ""), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return bytesToHex(new Uint8Array(sig));
}
function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const out = {};
  header.split(";").forEach((pair) => {
    const idx = pair.indexOf("=");
    if (idx > -1) out[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
  });
  return out;
}
function sessionCookieHeader(token, ttlSeconds = 60 * 60 * 8) {
  return `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${ttlSeconds}; HttpOnly; Secure; SameSite=Strict`;
}
function clearCookieHeader() {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}
async function requireAdmin(request, env) {
  return verifySession(env, parseCookies(request)[SESSION_COOKIE]);
}

// ---- Rate limiting ---------------------------------------------------------
async function rateLimit(env, key, limit, windowSeconds) {
  const kv = env.HUB_KV;
  if (!kv) return { allowed: true, remaining: limit };
  const now = Math.floor(Date.now() / 1000);
  const bucketKey = `rl:${key}`;
  let rec = null;
  try { rec = await kv.get(bucketKey, "json"); } catch { rec = null; }
  if (!rec || now - rec.start >= windowSeconds) rec = { start: now, count: 0 };
  rec.count += 1;
  const allowed = rec.count <= limit;
  await kv.put(bucketKey, JSON.stringify(rec), { expirationTtl: windowSeconds + 5 });
  return { allowed, remaining: Math.max(0, limit - rec.count), retryAfter: allowed ? 0 : rec.start + windowSeconds - now };
}
