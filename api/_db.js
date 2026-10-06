// 공용 DB/보안 도우미 (파일명이 _로 시작해서 주소로는 열리지 않아요)
const crypto = require("crypto");
const URL_ = (process.env.TURSO_DATABASE_URL || "").replace(/^libsql:\/\//, "https://");
const TOKEN = process.env.TURSO_AUTH_TOKEN || "";

const val = (x) => (x === null || x === undefined ? { type: "null" } : typeof x === "number" ? { type: "integer", value: String(Math.trunc(x)) } : { type: "text", value: String(x) });

let sqlImpl = async function (statements) {
  if (!URL_ || !TOKEN) throw new Error("no-db");
  const r = await fetch(URL_ + "/v2/pipeline", {
    method: "POST",
    headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify({ requests: [...statements.map(([q, a]) => ({ type: "execute", stmt: { sql: q, args: (a || []).map(val) } })), { type: "close" }] }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error("db " + r.status);
  return j.results.slice(0, statements.length).map((x) => {
    if (x.type === "error") throw new Error((x.error && x.error.message) || "db error");
    const res = x.response && x.response.result;
    if (!res || !res.cols) return [];
    const cols = res.cols.map((c) => c.name);
    return res.rows.map((row) => Object.fromEntries(row.map((cell, i) => [cols[i], cell.type === "null" ? null : cell.value])));
  });
};
const sql = (st) => sqlImpl(st);
const setSql = (fn) => { sqlImpl = fn; };

const SCHEMA = [
  [`CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, updated_at TEXT,
    name TEXT NOT NULL, phone TEXT NOT NULL, spouse_name TEXT, spouse_phone TEXT,
    wedding_date TEXT NOT NULL, wedding_time TEXT NOT NULL, hall TEXT NOT NULL,
    snap_product TEXT, dvd_product TEXT, addons TEXT, partner_code TEXT,
    receipt_type TEXT, receipt_number TEXT, message TEXT, pw_hash TEXT NOT NULL,
    agreed_notice INTEGER NOT NULL, agreed_privacy INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT '접수', admin_memo TEXT)`],
  [`CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL, created_at TEXT NOT NULL)`],
  [`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`],
];
let schemaReady = false;
async function ensure() { if (!schemaReady) { await sql(SCHEMA); schemaReady = true; } }

function hashPw(pw) { const salt = crypto.randomBytes(16).toString("hex"); return salt + ":" + crypto.scryptSync(String(pw), salt, 32).toString("hex"); }
function checkPw(pw, stored) {
  if (!stored || !stored.includes(":")) return false;
  const [salt, h] = stored.split(":");
  const a = crypto.scryptSync(String(pw), salt, 32), b = Buffer.from(h, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function secret() {
  const [rows] = await sql([["SELECT value FROM settings WHERE key='secret'"]]);
  if (rows[0]) return rows[0].value;
  const s = crypto.randomBytes(32).toString("hex");
  await sql([["INSERT OR IGNORE INTO settings (key,value) VALUES ('secret',?)", [s]]]);
  const [again] = await sql([["SELECT value FROM settings WHERE key='secret'"]]);
  return again[0].value;
}
async function signToken(user) {
  const body = Buffer.from(JSON.stringify({ u: user, exp: Date.now() + 12 * 3600 * 1000 })).toString("base64url");
  const sig = crypto.createHmac("sha256", await secret()).update(body).digest("base64url");
  return body + "." + sig;
}
async function verifyToken(t) {
  if (!t || !t.includes(".")) return null;
  const [body, sig] = t.split(".");
  const good = crypto.createHmac("sha256", await secret()).update(body).digest("base64url");
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  const p = JSON.parse(Buffer.from(body, "base64url").toString());
  return p.exp > Date.now() ? p.u : null;
}

const clip = (s, n) => String(s ?? "").trim().slice(0, n);
const mask = (n) => { n = String(n || "").trim(); if (n.length <= 1) return n + "*"; if (n.length === 2) return n[0] + "*"; return n[0] + "*".repeat(n.length - 2) + n[n.length - 1]; };
const PHONE = /^01[016789]-\d{3,4}-\d{4}$/;
const BIZ = /^\d{3}-\d{2}-\d{5}$/;
const body = (req) => (typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {});
const fail = (res, code, msg) => res.status(code).json({ error: msg });

module.exports = { sql, setSql, ensure, hashPw, checkPw, signToken, verifyToken, clip, mask, PHONE, BIZ, body, fail };
