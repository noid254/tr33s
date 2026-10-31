// tr33s admin + waitlist API. Zero dependencies: needs only Node 18+.
// Data lives in DATA_DIR as plain JSON files and uploaded photos in DATA_DIR/uploads.
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = +process.env.PORT || 3100;
const HOST = process.env.HOST || "127.0.0.1";
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, "data"));
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const UP = path.join(DATA_DIR, "uploads");
fs.mkdirSync(UP, { recursive: true, mode: 0o750 });

if (ADMIN_PASSWORD.length < 10) {
  console.error("Set ADMIN_PASSWORD (at least 10 characters) in the environment. Refusing to start.");
  process.exit(1);
}

/* ---------- storage ---------- */
const SIGNUPS = path.join(DATA_DIR, "signups.json");
const CONTENT = path.join(DATA_DIR, "content.json");
const SECRET_FILE = path.join(DATA_DIR, ".secret");
function readJSON(f, d) { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch (e) { return d; } }
function writeJSON(f, v) { const t = f + ".tmp"; fs.writeFileSync(t, JSON.stringify(v, null, 1), { mode: 0o640 }); fs.renameSync(t, f); }
let secret;
try { secret = fs.readFileSync(SECRET_FILE, "utf8"); } catch (e) { secret = crypto.randomBytes(32).toString("hex"); fs.writeFileSync(SECRET_FILE, secret, { mode: 0o600 }); }

const SLOTS = ["hero", "banner", "gallery1", "gallery2", "gallery3", "stagey1", "stagey2", "stagey3", "stagey4", "stagey8", "stagey30"];

/* ---------- helpers ---------- */
function send(res, code, body, headers) {
  const h = Object.assign({ "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "Cache-Control": "no-store" }, headers || {});
  if (body !== null && typeof body === "object" && !Buffer.isBuffer(body)) { h["Content-Type"] = "application/json"; body = JSON.stringify(body); }
  res.writeHead(code, h); res.end(body);
}
function body(req, max) {
  return new Promise((ok, no) => {
    const parts = []; let n = 0;
    req.on("data", c => { n += c.length; if (n > max) { no(new Error("too large")); req.destroy(); } else parts.push(c); });
    req.on("end", () => ok(Buffer.concat(parts)));
    req.on("error", no);
  });
}
const hits = new Map();
function limited(key, max, ms) {
  const now = Date.now(), a = (hits.get(key) || []).filter(t => now - t < ms);
  a.push(now); hits.set(key, a); return a.length > max;
}
setInterval(() => { const now = Date.now(); for (const [k, a] of hits) if (!a.some(t => now - t < 3600e3)) hits.delete(k); }, 600e3).unref();
function ip(req) { return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim(); }
function same(a, b) { const x = crypto.createHash("sha256").update(a).digest(), y = crypto.createHash("sha256").update(b).digest(); return crypto.timingSafeEqual(x, y); }

/* ---------- sessions: signed cookie, 12 hours ---------- */
function sign(v) { return crypto.createHmac("sha256", secret).update(v).digest("hex"); }
function makeSession() { const exp = String(Date.now() + 12 * 3600e3); return exp + "." + sign(exp); }
function isAdmin(req) {
  const m = /(?:^|;\s*)t33s=([^;]+)/.exec(req.headers.cookie || ""); if (!m) return false;
  const [exp, sig] = m[1].split("."); if (!exp || !sig || +exp < Date.now()) return false;
  return same(sig, sign(exp));
}
function secure(req) { return (req.headers["x-forwarded-proto"] || "") === "https"; }
function sameOrigin(req) { const o = req.headers.origin; if (!o) return true; try { return new URL(o).host === req.headers.host; } catch (e) { return false; } }

/* ---------- images ---------- */
function sniff(b) {
  if (b.length > 12 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "jpg";
  if (b.length > 12 && b.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "png";
  if (b.length > 12 && b.slice(0, 4).toString() === "RIFF" && b.slice(8, 12).toString() === "WEBP") return "webp";
  return null;
}
const MIME = { jpg: "image/jpeg", png: "image/png", webp: "image/webp" };

/* ---------- routes ---------- */
const clean = (v, n) => String(v == null ? "" : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "").trim().slice(0, n);

async function handle(req, res) {
  const u = new URL(req.url, "http://x"), p = u.pathname, m = req.method;

  // public: photo overrides
  if (p === "/api/content" && m === "GET") {
    const c = readJSON(CONTENT, { images: {} });
    return send(res, 200, { images: c.images || {} }, { "Cache-Control": "public, max-age=60" });
  }

  // public: waitlist sign-up
  if (p === "/api/signup" && m === "POST") {
    if (limited("s:" + ip(req), 12, 3600e3)) return send(res, 429, { error: "Too many requests" });
    let j; try { j = JSON.parse((await body(req, 20000)).toString("utf8")); } catch (e) { return send(res, 400, { error: "Bad request" }); }
    const name = clean(j.name, 120), email = clean(j.email, 160), phone = clean(j.phone, 40);
    if (!name || (!email && !phone)) return send(res, 400, { error: "Name and a contact are required" });
    const rec = {
      id: crypto.randomBytes(5).toString("hex"), at: new Date().toISOString(), status: "new", note: "",
      ref: clean(j.ref, 40), name, email, phone, qty: Math.max(1, Math.min(500, parseInt(j.qty, 10) || 1)),
      location: clean(j.location, 120), profile: clean(j.profile, 120), gift: !!j.gift, recipient: clean(j.recipient, 120),
      details: clean(typeof j.details === "string" ? j.details : JSON.stringify(j.trees || j.details || ""), 3000)
    };
    const all = readJSON(SIGNUPS, []); all.push(rec); writeJSON(SIGNUPS, all);
    return send(res, 200, { ok: true });
  }

  // admin login / logout
  if (p === "/api/login" && m === "POST") {
    if (!sameOrigin(req)) return send(res, 403, { error: "Forbidden" });
    if (limited("l:" + ip(req), 8, 15 * 60e3)) return send(res, 429, { error: "Too many attempts. Try again in 15 minutes." });
    let j; try { j = JSON.parse((await body(req, 2000)).toString("utf8")); } catch (e) { return send(res, 400, { error: "Bad request" }); }
    if (!same(String(j.password || ""), ADMIN_PASSWORD)) return send(res, 401, { error: "Wrong password" });
    return send(res, 200, { ok: true }, { "Set-Cookie": "t33s=" + makeSession() + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200" + (secure(req) ? "; Secure" : "") });
  }
  if (p === "/api/logout" && m === "POST") return send(res, 200, { ok: true }, { "Set-Cookie": "t33s=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" });

  // admin only below
  if (p.startsWith("/api/admin/")) {
    if (!isAdmin(req)) return send(res, 401, { error: "Not signed in" });
    if (m !== "GET" && !sameOrigin(req)) return send(res, 403, { error: "Forbidden" });

    if (p === "/api/admin/me") return send(res, 200, { ok: true });

    if (p === "/api/admin/signups" && m === "GET") return send(res, 200, { signups: readJSON(SIGNUPS, []).reverse() });

    if (p === "/api/admin/signups.csv" && m === "GET") {
      const cols = ["at", "ref", "name", "email", "phone", "qty", "location", "profile", "gift", "recipient", "status", "note", "details"];
      const q = v => { let t = String(v == null ? "" : v); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return '"' + t.replace(/"/g, '""') + '"'; };
      const rows = readJSON(SIGNUPS, []).map(r => cols.map(c => q(r[c])).join(","));
      return send(res, 200, cols.join(",") + "\n" + rows.join("\n"), { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": 'attachment; filename="tr33s-waitlist.csv"' });
    }

    let mm = /^\/api\/admin\/signups\/([a-f0-9]{10})$/.exec(p);
    if (mm && m === "PATCH") {
      let j; try { j = JSON.parse((await body(req, 5000)).toString("utf8")); } catch (e) { return send(res, 400, { error: "Bad request" }); }
      const all = readJSON(SIGNUPS, []), r = all.find(x => x.id === mm[1]); if (!r) return send(res, 404, { error: "Not found" });
      if (j.status !== undefined) r.status = ["new", "contacted", "interested", "not-interested"].includes(j.status) ? j.status : r.status;
      if (j.note !== undefined) r.note = clean(j.note, 1000);
      for (const k of ["name", "email", "phone", "location"]) if (j[k] !== undefined) r[k] = clean(j[k], 160);
      if (j.qty !== undefined) r.qty = Math.max(1, Math.min(500, parseInt(j.qty, 10) || r.qty));
      writeJSON(SIGNUPS, all); return send(res, 200, { ok: true, signup: r });
    }
    if (mm && m === "DELETE") {
      const all = readJSON(SIGNUPS, []), n = all.filter(x => x.id !== mm[1]); writeJSON(SIGNUPS, n); return send(res, 200, { ok: true, removed: all.length - n.length });
    }

    if (p === "/api/admin/images" && m === "GET") return send(res, 200, { slots: SLOTS, images: (readJSON(CONTENT, { images: {} }).images) || {} });

    mm = /^\/api\/admin\/images\/([a-z0-9]+)$/.exec(p);
    if (mm && SLOTS.includes(mm[1])) {
      const slot = mm[1], c = readJSON(CONTENT, { images: {} }); c.images = c.images || {};
      if (m === "PUT") {
        const buf = await body(req, 6 * 1024 * 1024).catch(() => null);
        if (!buf) return send(res, 413, { error: "Image is larger than 6 MB" });
        const kind = sniff(buf); if (!kind) return send(res, 400, { error: "Use a JPG, PNG or WebP image" });
        const name = slot + "-" + Date.now().toString(36) + "." + kind;
        fs.writeFileSync(path.join(UP, name), buf, { mode: 0o640 });
        const old = c.images[slot]; c.images[slot] = "/uploads/" + name; writeJSON(CONTENT, c);
        if (old && old.startsWith("/uploads/")) fs.unlink(path.join(UP, path.basename(old)), () => {});
        return send(res, 200, { ok: true, url: c.images[slot] });
      }
      if (m === "DELETE") {
        const old = c.images[slot]; delete c.images[slot]; writeJSON(CONTENT, c);
        if (old && old.startsWith("/uploads/")) fs.unlink(path.join(UP, path.basename(old)), () => {});
        return send(res, 200, { ok: true });
      }
    }
    return send(res, 404, { error: "Not found" });
  }

  // uploaded photos
  if (p.startsWith("/uploads/") && m === "GET") {
    const f = path.basename(p), ext = path.extname(f).slice(1);
    if (!/^[a-z0-9\-]+\.(jpg|png|webp)$/.test(f)) return send(res, 404, "Not found");
    try { return send(res, 200, fs.readFileSync(path.join(UP, f)), { "Content-Type": MIME[ext], "Cache-Control": "public, max-age=3600" }); } catch (e) { return send(res, 404, "Not found"); }
  }

  // admin page
  if ((p === "/admin" || p === "/admin/") && m === "GET") {
    return send(res, 200, fs.readFileSync(path.join(__dirname, "admin.html")), { "Content-Type": "text/html; charset=utf-8", "X-Robots-Tag": "noindex", "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'" });
  }
  return send(res, 404, "Not found");
}

http.createServer((req, res) => { handle(req, res).catch(e => { console.error(e); try { send(res, 500, { error: "Server error" }); } catch (x) {} }); })
  .listen(PORT, HOST, () => console.log("tr33s admin API on http://" + HOST + ":" + PORT + ", data in " + DATA_DIR));
