// 러브어바웃 예약 게시판 API (Vercel Serverless Function)
// GET  /api/reservations  → 예약글 목록 (개인정보는 가린 상태로만 반환)
// POST /api/reservations  → 예약글 작성
const URL_ = (process.env.TURSO_DATABASE_URL || "").replace(/^libsql:\/\//, "https://");
const TOKEN = process.env.TURSO_AUTH_TOKEN || "";

const v = (x) => (x === null || x === undefined ? { type: "null" } : typeof x === "number" ? { type: "integer", value: String(x) } : { type: "text", value: String(x) });

async function sql(statements) {
  const r = await fetch(URL_ + "/v2/pipeline", {
    method: "POST",
    headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify({ requests: [...statements.map(([q, args]) => ({ type: "execute", stmt: { sql: q, args: (args || []).map(v) } })), { type: "close" }] }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error("db " + r.status);
  return j.results.map((x) => {
    if (x.type === "error") throw new Error(x.error && x.error.message);
    const res = x.response && x.response.result;
    if (!res) return [];
    const cols = res.cols.map((c) => c.name);
    return res.rows.map((row) => Object.fromEntries(row.map((cell, i) => [cols[i], cell.value])));
  });
}

const CREATE = `CREATE TABLE IF NOT EXISTS reservations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  wedding_date TEXT NOT NULL,
  wedding_time TEXT NOT NULL,
  hall TEXT NOT NULL,
  product TEXT,
  message TEXT,
  agreed_notice INTEGER NOT NULL,
  agreed_privacy INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT '접수'
)`;

const mask = (n) => { n = String(n || "").trim(); if (n.length <= 1) return n + "*"; if (n.length === 2) return n[0] + "*"; return n[0] + "*".repeat(n.length - 2) + n[n.length - 1]; };
const clip = (s, n) => String(s || "").trim().slice(0, n);

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (!URL_ || !TOKEN) return res.status(500).json({ error: "저장소가 아직 연결되지 않았어요." });
  try {
    if (req.method === "GET") {
      const [, rows] = await sql([[CREATE], ["SELECT id, created_at, name, hall, status FROM reservations ORDER BY created_at DESC, id DESC LIMIT 200"]]);
      return res.status(200).json({ items: rows.map((r) => ({ id: Number(r.id), createdAt: r.created_at, name: mask(r.name), hall: r.hall, status: r.status })) });
    }
    if (req.method === "POST") {
      const b = typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};
      if (b.website) return res.status(200).json({ ok: true }); // 스팸 방지용 숨김칸
      const d = {
        name: clip(b.name, 20), phone: clip(b.phone, 13), wedding_date: clip(b.weddingDate, 10), wedding_time: clip(b.weddingTime, 20),
        hall: clip(b.hall, 60), product: clip(b.product, 40), message: clip(b.message, 1000),
      };
      const errs = [];
      if (!b.agreeNotice || !b.agreePrivacy) errs.push("필독사항과 개인정보 처리방침에 동의해 주세요.");
      if (d.name.length < 2) errs.push("성함을 적어주세요.");
      if (!/^01[016789]-\d{3,4}-\d{4}$/.test(d.phone)) errs.push("연락처는 010-0000-0000 형식으로 적어주세요.");
      if (!/^\d{4}-\d{2}-\d{2}$/.test(d.wedding_date)) errs.push("예식일을 선택해 주세요.");
      if (!d.wedding_time) errs.push("예식 시간을 적어주세요.");
      if (!d.hall) errs.push("예식장을 적어주세요.");
      if (errs.length) return res.status(400).json({ error: errs.join(" ") });
      const now = new Date().toISOString();
      await sql([[CREATE], ["INSERT INTO reservations (created_at,name,phone,wedding_date,wedding_time,hall,product,message,agreed_notice,agreed_privacy) VALUES (?,?,?,?,?,?,?,?,1,1)",
        [now, d.name, d.phone, d.wedding_date, d.wedding_time, d.hall, d.product, d.message]]]);
      return res.status(201).json({ ok: true });
    }
    res.setHeader("Allow", "GET, POST");
    return res.status(405).json({ error: "지원하지 않는 요청이에요." });
  } catch (e) {
    return res.status(500).json({ error: "잠시 후 다시 시도해 주세요." });
  }
};
