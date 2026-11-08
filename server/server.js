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

const USERS = path.join(DATA_DIR, "users.json");
const TREES = path.join(DATA_DIR, "trees.json");
const BATCHES = path.join(DATA_DIR, "batches.json");
const STATUSES = ["planned", "planted", "alive", "needs-replacing", "replaced"];
const KINDS = ["commercial", "restoration"];
const CROPS = ["avocado", "melia"];
const rid = () => crypto.randomBytes(5).toString("hex");
const normEmail = v => String(v || "").trim().toLowerCase();
function normPhone(v) { let d = String(v || "").replace(/\D/g, ""); if (d.length === 10 && d[0] === "0") d = "254" + d.slice(1); else if (d.length === 9) d = "254" + d; return d; }
function hashPw(pw) { const salt = crypto.randomBytes(16).toString("hex"); return salt + ":" + crypto.scryptSync(pw, salt, 32).toString("hex"); }
function checkPw(pw, stored) { const [salt, h] = String(stored || "").split(":"); if (!salt || !h) return false; const a = Buffer.from(h, "hex"), b = crypto.scryptSync(String(pw), salt, 32); return a.length === b.length && crypto.timingSafeEqual(a, b); }
const DUMMY_HASH = hashPw("not-a-real-password");
const okDate = v => /^\d{4}-\d{2}-\d{2}$/.test(String(v || "")) ? String(v) : "";
const pct = b => b && b.total > 0 ? Math.round(1000 * Math.min(b.alive, b.total) / b.total) / 10 : null;

const SLOTS = ["hero", "banner", "gallery1", "gallery2", "gallery3", "meliaHero", "meliaA", "meliaB", "meliaC", "stagey1", "stagey2", "stagey3", "stagey4", "stagey8", "stagey30"];

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
function makeUserSession(uid) { const exp = String(Date.now() + 30 * 24 * 3600e3), v = uid + "." + exp; return v + "." + sign("u:" + v); }
function userFrom(req) {
  const m = /(?:^|;\s*)t33u=([^;]+)/.exec(req.headers.cookie || ""); if (!m) return null;
  const [uid, exp, sig] = m[1].split("."); if (!uid || !exp || !sig || +exp < Date.now()) return null;
  if (!same(sig, sign("u:" + uid + "." + exp))) return null;
  return readJSON(USERS, []).find(u => u.id === uid) || null;
}
function ucookie(req, val, maxAge) { return "t33u=" + val + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=" + maxAge + (secure(req) ? "; Secure" : ""); }
function publicUser(u) { return { id: u.id, name: u.name, email: u.email, phone: u.phone, at: u.at }; }
function treeView(t, batches) {
  const b = t.batchId ? batches.find(x => x.id === t.batchId) : null;
  return Object.assign({}, t, { batch: b ? { id: b.id, name: b.name, location: b.location, total: b.total, alive: b.alive, pct: pct(b), checkedAt: b.checkedAt, note: b.note } : null });
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
      ref: clean(j.ref, 40), crop: CROPS.includes(j.crop) ? j.crop : "avocado", name, email, phone, qty: Math.max(1, Math.min(500, parseInt(j.qty, 10) || 1)),
      location: clean(j.location, 120), profile: clean(j.profile, 120), gift: !!j.gift, recipient: clean(j.recipient, 120),
      details: clean(typeof j.details === "string" ? j.details : JSON.stringify(j.trees || j.details || ""), 3000)
    };
    const su = userFrom(req); if (su) rec.userId = su.id;
    const all = readJSON(SIGNUPS, []); all.push(rec); writeJSON(SIGNUPS, all);
    return send(res, 200, { ok: true });
  }

  // public: live counters (real data only)
  if (p === "/api/stats" && m === "GET") {
    const trees = readJSON(TREES, []), batches = readJSON(BATCHES, []);
    const planted = trees.filter(t => t.status !== "planned").length;
    const tot = batches.reduce((a, b) => a + (b.total || 0), 0), al = batches.reduce((a, b) => a + Math.min(b.alive || 0, b.total || 0), 0);
    return send(res, 200, { members: readJSON(USERS, []).length, planted, batches: batches.length, alivePct: tot ? Math.round(1000 * al / tot) / 10 : null }, { "Cache-Control": "public, max-age=60" });
  }

  // members: sign up, log in, profile
  if (p === "/api/register" && m === "POST") {
    if (!sameOrigin(req)) return send(res, 403, { error: "Forbidden" });
    if (limited("r:" + ip(req), 10, 3600e3)) return send(res, 429, { error: "Too many sign-ups from this connection. Try again later." });
    let j; try { j = JSON.parse((await body(req, 4000)).toString("utf8")); } catch (e) { return send(res, 400, { error: "Bad request" }); }
    const name = clean(j.name, 100), email = normEmail(j.email), phone = normPhone(j.phone), pw = String(j.password || "");
    if (!name) return send(res, 400, { error: "Please enter your name" });
    if (!email && !phone) return send(res, 400, { error: "Enter an email or a phone number" });
    if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return send(res, 400, { error: "That email does not look right" });
    if (phone && (phone.length < 9 || phone.length > 15)) return send(res, 400, { error: "That phone number does not look right" });
    if (pw.length < 8 || pw.length > 200) return send(res, 400, { error: "Use a password of at least 8 characters" });
    const users = readJSON(USERS, []);
    if (users.some(u => (email && u.email === email) || (phone && u.phone === phone))) return send(res, 409, { error: "That email or phone already has an account. Please log in." });
    const u = { id: rid(), name, email, phone, hash: hashPw(pw), at: new Date().toISOString() };
    users.push(u); writeJSON(USERS, users);
    return send(res, 200, { ok: true, user: publicUser(u) }, { "Set-Cookie": ucookie(req, makeUserSession(u.id), 30 * 24 * 3600) });
  }
  if (p === "/api/member-login" && m === "POST") {
    if (!sameOrigin(req)) return send(res, 403, { error: "Forbidden" });
    let j; try { j = JSON.parse((await body(req, 2000)).toString("utf8")); } catch (e) { return send(res, 400, { error: "Bad request" }); }
    const idf = String(j.identifier || "").trim(), key = idf.includes("@") ? normEmail(idf) : normPhone(idf);
    if (limited("ml:" + ip(req), 15, 15 * 60e3) || limited("mk:" + key, 8, 15 * 60e3)) return send(res, 429, { error: "Too many attempts. Try again in 15 minutes." });
    const u = readJSON(USERS, []).find(x => idf.includes("@") ? x.email === key : (key && x.phone === key));
    const good = checkPw(j.password, u ? u.hash : DUMMY_HASH);
    if (!u || !good) return send(res, 401, { error: "Wrong email, phone or password" });
    return send(res, 200, { ok: true, user: publicUser(u) }, { "Set-Cookie": ucookie(req, makeUserSession(u.id), 30 * 24 * 3600) });
  }
  if (p === "/api/member-logout" && m === "POST") return send(res, 200, { ok: true }, { "Set-Cookie": ucookie(req, "", 0) });

  if (p === "/api/me" || p.startsWith("/api/me/")) {
    const me = userFrom(req); if (!me) return send(res, 401, { error: "Not signed in" });
    if (m !== "GET" && !sameOrigin(req)) return send(res, 403, { error: "Forbidden" });
    if (p === "/api/me" && m === "GET") {
      const batches = readJSON(BATCHES, []);
      const trees = readJSON(TREES, []).filter(t => t.ownerId === me.id).map(t => treeView(t, batches));
      const waitlist = readJSON(SIGNUPS, []).filter(r => r.userId === me.id || (me.email && normEmail(r.email) === me.email) || (me.phone && normPhone(r.phone) === me.phone))
        .map(r => ({ at: r.at, ref: r.ref, crop: r.crop || "avocado", qty: r.qty, gift: r.gift, recipient: r.recipient, status: r.status }));
      return send(res, 200, { user: publicUser(me), trees, waitlist });
    }
    if (p === "/api/me" && m === "PATCH") {
      let j; try { j = JSON.parse((await body(req, 2000)).toString("utf8")); } catch (e) { return send(res, 400, { error: "Bad request" }); }
      const users = readJSON(USERS, []), u = users.find(x => x.id === me.id);
      if (j.name !== undefined) { const n = clean(j.name, 100); if (!n) return send(res, 400, { error: "Name cannot be empty" }); u.name = n; }
      if (j.phone !== undefined) { const ph = normPhone(j.phone); if (ph && users.some(x => x.id !== u.id && x.phone === ph)) return send(res, 409, { error: "That phone is used by another account" }); u.phone = ph; }
      writeJSON(USERS, users); return send(res, 200, { ok: true, user: publicUser(u) });
    }
    if (p === "/api/me/password" && m === "POST") {
      let j; try { j = JSON.parse((await body(req, 2000)).toString("utf8")); } catch (e) { return send(res, 400, { error: "Bad request" }); }
      if (limited("mp:" + me.id, 8, 15 * 60e3)) return send(res, 429, { error: "Too many attempts" });
      if (!checkPw(j.current, me.hash)) return send(res, 401, { error: "Current password is wrong" });
      const np = String(j.next || ""); if (np.length < 8 || np.length > 200) return send(res, 400, { error: "Use a password of at least 8 characters" });
      const users = readJSON(USERS, []); users.find(x => x.id === me.id).hash = hashPw(np); writeJSON(USERS, users); return send(res, 200, { ok: true });
    }
    return send(res, 404, { error: "Not found" });
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

    mm = /^\/api\/admin\/images\/([a-zA-Z0-9]+)$/.exec(p);
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

    // members
    if (p === "/api/admin/members" && m === "GET") {
      const trees = readJSON(TREES, []);
      return send(res, 200, { members: readJSON(USERS, []).map(u => Object.assign(publicUser(u), { trees: trees.filter(t => t.ownerId === u.id).length })).reverse() });
    }
    mm = /^\/api\/admin\/members\/([a-f0-9]{10})(\/password)?$/.exec(p);
    if (mm && mm[2] && m === "POST") {
      let j; try { j = JSON.parse((await body(req, 1000)).toString("utf8")); } catch (e) { return send(res, 400, { error: "Bad request" }); }
      const np = String(j.password || ""); if (np.length < 8) return send(res, 400, { error: "At least 8 characters" });
      const users = readJSON(USERS, []), u = users.find(x => x.id === mm[1]); if (!u) return send(res, 404, { error: "Not found" });
      u.hash = hashPw(np); writeJSON(USERS, users); return send(res, 200, { ok: true });
    }
    if (mm && !mm[2] && m === "DELETE") {
      const users = readJSON(USERS, []), n = users.filter(x => x.id !== mm[1]); writeJSON(USERS, n);
      const trees = readJSON(TREES, []); trees.forEach(t => { if (t.ownerId === mm[1]) t.ownerId = null; }); writeJSON(TREES, trees);
      return send(res, 200, { ok: true, removed: users.length - n.length });
    }

    // batches
    if (p === "/api/admin/batches" && m === "GET") return send(res, 200, { batches: readJSON(BATCHES, []).map(b => Object.assign({}, b, { pct: pct(b) })) });
    if (p === "/api/admin/batches" && m === "POST") {
      let j; try { j = JSON.parse((await body(req, 4000)).toString("utf8")); } catch (e) { return send(res, 400, { error: "Bad request" }); }
      const name = clean(j.name, 80); if (!name) return send(res, 400, { error: "Batch needs a name" });
      const b = { id: rid(), name, location: clean(j.location, 120), kind: KINDS.includes(j.kind) ? j.kind : "commercial", plantedAt: okDate(j.plantedAt), total: Math.max(0, parseInt(j.total, 10) || 0), alive: Math.max(0, parseInt(j.alive, 10) || 0), checkedAt: okDate(j.checkedAt), note: clean(j.note, 500) };
      const all = readJSON(BATCHES, []); all.push(b); writeJSON(BATCHES, all); return send(res, 200, { ok: true, batch: b });
    }
    mm = /^\/api\/admin\/batches\/([a-f0-9]{10})$/.exec(p);
    if (mm && m === "PATCH") {
      let j; try { j = JSON.parse((await body(req, 4000)).toString("utf8")); } catch (e) { return send(res, 400, { error: "Bad request" }); }
      const all = readJSON(BATCHES, []), b = all.find(x => x.id === mm[1]); if (!b) return send(res, 404, { error: "Not found" });
      for (const k of ["name", "location", "note"]) if (j[k] !== undefined) b[k] = clean(j[k], k === "note" ? 500 : 120);
      if (j.kind !== undefined && KINDS.includes(j.kind)) b.kind = j.kind;
      for (const k of ["plantedAt", "checkedAt"]) if (j[k] !== undefined) b[k] = okDate(j[k]);
      for (const k of ["total", "alive"]) if (j[k] !== undefined) b[k] = Math.max(0, parseInt(j[k], 10) || 0);
      writeJSON(BATCHES, all); return send(res, 200, { ok: true, batch: Object.assign({}, b, { pct: pct(b) }) });
    }
    if (mm && m === "DELETE") {
      const all = readJSON(BATCHES, []), n = all.filter(x => x.id !== mm[1]); writeJSON(BATCHES, n);
      const trees = readJSON(TREES, []); trees.forEach(t => { if (t.batchId === mm[1]) t.batchId = ""; }); writeJSON(TREES, trees);
      return send(res, 200, { ok: true, removed: all.length - n.length });
    }

    // trees
    if (p === "/api/admin/trees" && m === "GET") {
      const users = readJSON(USERS, []), batches = readJSON(BATCHES, []);
      return send(res, 200, { trees: readJSON(TREES, []).map(t => { const o = users.find(u => u.id === t.ownerId), b = batches.find(x => x.id === t.batchId); return Object.assign({}, t, { ownerName: o ? o.name : "", ownerEmail: o ? o.email : "", batchName: b ? b.name : "" }); }) });
    }
    const treeFields = (t, j, users) => {
      if (j.code !== undefined) t.code = clean(j.code, 40);
      for (const k of ["location", "occasion", "recipient"]) if (j[k] !== undefined) t[k] = clean(j[k], 120);
      if (j.kind !== undefined && KINDS.includes(j.kind)) t.kind = j.kind;
      if (j.crop !== undefined && CROPS.includes(j.crop)) t.crop = j.crop;
      if (j.status !== undefined && STATUSES.includes(j.status)) t.status = j.status;
      if (j.plantedAt !== undefined) t.plantedAt = okDate(j.plantedAt);
      if (j.verifiedAt !== undefined) t.verifiedAt = okDate(j.verifiedAt);
      if (j.batchId !== undefined) t.batchId = /^[a-f0-9]{10}$/.test(j.batchId) ? j.batchId : "";
      if (j.owner !== undefined) {
        const q = String(j.owner || "").trim();
        if (!q) t.ownerId = null; else { const k = q.includes("@") ? normEmail(q) : normPhone(q), u = users.find(x => (q.includes("@") ? x.email === k : x.phone === k) || x.id === q); if (!u) return "No member found for " + q; t.ownerId = u.id; }
      }
      return "";
    };
    if (p === "/api/admin/trees" && m === "POST") {
      let j; try { j = JSON.parse((await body(req, 4000)).toString("utf8")); } catch (e) { return send(res, 400, { error: "Bad request" }); }
      const users = readJSON(USERS, []), all = readJSON(TREES, []);
      const count = Math.max(1, Math.min(1000, parseInt(j.count, 10) || 1));
      const prefix = clean(j.prefix, 30), start = Math.max(1, parseInt(j.start, 10) || 1);
      if (count > 1 && !prefix) return send(res, 400, { error: "Give a code prefix when adding several trees" });
      if (count === 1 && !clean(j.code, 40) && !prefix) return send(res, 400, { error: "Give the tree a code" });
      const made = [];
      for (let i = 0; i < count; i++) {
        const t = { id: rid(), code: "", ownerId: null, crop: "avocado", kind: "commercial", location: "", plantedAt: "", verifiedAt: "", batchId: "", status: "planned", occasion: "", recipient: "", photo: "", updates: [], at: new Date().toISOString() };
        const jj = Object.assign({}, j); jj.code = count === 1 && jj.code ? jj.code : prefix + String(start + i).padStart(3, "0");
        const err = treeFields(t, jj, users); if (err) return send(res, 400, { error: err });
        if (all.some(x => x.code === t.code) || made.some(x => x.code === t.code)) return send(res, 409, { error: "Code " + t.code + " already exists" });
        made.push(t);
      }
      writeJSON(TREES, all.concat(made)); return send(res, 200, { ok: true, created: made.length });
    }
    mm = /^\/api\/admin\/trees\/([a-f0-9]{10})(\/updates|\/photo)?$/.exec(p);
    if (mm) {
      const all = readJSON(TREES, []), t = all.find(x => x.id === mm[1]); if (!t) return send(res, 404, { error: "Not found" });
      if (!mm[2] && m === "PATCH") {
        let j; try { j = JSON.parse((await body(req, 4000)).toString("utf8")); } catch (e) { return send(res, 400, { error: "Bad request" }); }
        const err = treeFields(t, j, readJSON(USERS, [])); if (err) return send(res, 400, { error: err });
        if (all.some(x => x.id !== t.id && x.code === t.code)) return send(res, 409, { error: "Code already exists" });
        writeJSON(TREES, all); return send(res, 200, { ok: true });
      }
      if (!mm[2] && m === "DELETE") { writeJSON(TREES, all.filter(x => x.id !== t.id)); return send(res, 200, { ok: true }); }
      if (mm[2] === "/updates" && m === "POST") {
        let j; try { j = JSON.parse((await body(req, 3000)).toString("utf8")); } catch (e) { return send(res, 400, { error: "Bad request" }); }
        const text = clean(j.text, 500); if (!text) return send(res, 400, { error: "Write the update" });
        t.updates = t.updates || []; t.updates.push({ at: new Date().toISOString(), text, photo: "" }); writeJSON(TREES, all); return send(res, 200, { ok: true });
      }
      if (mm[2] === "/photo" && m === "PUT") {
        const buf = await body(req, 6 * 1024 * 1024).catch(() => null);
        if (!buf) return send(res, 413, { error: "Image is larger than 6 MB" });
        const kind = sniff(buf); if (!kind) return send(res, 400, { error: "Use a JPG, PNG or WebP image" });
        const name = "tree-" + t.id + "-" + Date.now().toString(36) + "." + kind;
        fs.writeFileSync(path.join(UP, name), buf, { mode: 0o640 });
        t.photo = "/uploads/" + name; t.updates = t.updates || [];
        t.updates.push({ at: new Date().toISOString(), text: clean(u.searchParams.get("text"), 500) || "New photo", photo: t.photo });
        writeJSON(TREES, all); return send(res, 200, { ok: true, url: t.photo });
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
