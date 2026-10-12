// Zero-dependency license server. Run: ADMIN_PASSWORD=yourpass node server.js
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-me-now";
const DB = path.join(process.env.DATA_DIR || __dirname, "licenses.json");
const load = () => { try { return JSON.parse(fs.readFileSync(DB, "utf8")); } catch { return {}; } };
const save = (d) => fs.writeFileSync(DB, JSON.stringify(d, null, 2));
const genKey = () => { const c = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; const p = () => Array.from(crypto.randomBytes(4), b => c[b % c.length]).join(""); return `CB-VIP-${p()}-${p()}-${p()}`; };
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const hits = {};
const limited = (ip) => { const n = Date.now(), h = (hits[ip] = (hits[ip] || []).filter(t => n - t < 60000)); h.push(n); return h.length > 20; };

function body(req) { return new Promise(r => { let s = ""; req.on("data", c => { s += c; if (s.length > 1e5) req.destroy(); }); req.on("end", () => { try { r(JSON.parse(s || "{}")); } catch { r({}); } }); }); }
function json(res, code, obj) { res.writeHead(code, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type,x-admin-token" }); res.end(JSON.stringify(obj)); }

http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") return json(res, 204, {});
  const url = req.url.split("?")[0];

  if (url === "/api/verify" && req.method === "POST") {
    if (limited(req.socket.remoteAddress)) return json(res, 429, { ok: false, error: "Too many attempts. Wait a minute." });
    const { key, device } = await body(req);
    const db = load(), L = db[key];
    if (!L || !device) return json(res, 200, { ok: false, error: "Invalid Key! Contact CB Traders Admin." });
    if (L.revoked) return json(res, 200, { ok: false, error: "This key has been revoked." });
    if (L.expiresAt && Date.now() > L.expiresAt) return json(res, 200, { ok: false, error: "License expired. Contact admin." });
    if (!L.devices.includes(device)) {
      if (L.devices.length >= L.maxDevices) return json(res, 200, { ok: false, error: "Device limit reached for this key." });
      L.devices.push(device);
    }
    if (!L.expiresAt && L.days > 0) L.expiresAt = Date.now() + L.days * 86400000; // first activation
    L.lastSeen = Date.now(); save(db);
    return json(res, 200, { ok: true, expiresAt: L.expiresAt || null });
  }

  if (url.startsWith("/admin/api/")) {
    if (!safeEq(req.headers["x-admin-token"] || "", ADMIN_PASSWORD)) return json(res, 401, { error: "Unauthorized" });
    const db = load();
    if (url === "/admin/api/keys" && req.method === "GET") return json(res, 200, db);
    const b = await body(req);
    if (url === "/admin/api/create") {
      const n = Math.min(Math.max(+b.count || 1, 1), 100), out = [];
      for (let i = 0; i < n; i++) { const k = genKey(); db[k] = { note: b.note || "", days: +b.days || 0, maxDevices: +b.maxDevices || 1, devices: [], revoked: false, expiresAt: null, created: Date.now() }; out.push(k); }
      save(db); return json(res, 200, { keys: out });
    }
    if (!db[b.key]) return json(res, 404, { error: "Not found" });
    if (url === "/admin/api/revoke") db[b.key].revoked = !db[b.key].revoked;
    else if (url === "/admin/api/reset") db[b.key].devices = [];
    else if (url === "/admin/api/delete") delete db[b.key];
    else return json(res, 404, { error: "Unknown" });
    save(db); return json(res, 200, { ok: true });
  }

  if (url === "/" || url === "/admin") { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); return res.end(fs.readFileSync(path.join(__dirname, "admin.html"))); }
  json(res, 404, { error: "Not found" });
}).listen(PORT, () => console.log("CB license server on :" + PORT));
