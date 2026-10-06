// 관리자 API: 최초 설정, 로그인, 예약 관리, 홈페이지 내용 수정
const { sql, ensure, hashPw, checkPw, signToken, verifyToken, clip, PHONE, body, fail } = require("./_db.js");
const { toFull } = require("./reservations.js");
const STATUSES = ["접수", "확인중", "예약확정", "촬영완료", "취소"];

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return fail(res, 405, "지원하지 않는 요청이에요."); }
  try {
    await ensure();
    const b = body(req);
    const [admins] = await sql([["SELECT id, username, pw_hash FROM admins"]]);
    if (b.action === "status") return res.status(200).json({ hasAdmin: admins.length > 0 });
    if (b.action === "setup") {
      if (admins.length) return fail(res, 403, "관리자 계정이 이미 있어요. 로그인해 주세요.");
      const u = clip(b.username, 30), p = String(b.password || "");
      if (!/^[A-Za-z0-9_.-]{4,30}$/.test(u)) return fail(res, 400, "아이디는 영문·숫자 4자 이상으로 정해주세요.");
      if (p.length < 8) return fail(res, 400, "비밀번호는 8자 이상으로 정해주세요.");
      await sql([["INSERT INTO admins (username,pw_hash,created_at) VALUES (?,?,?)", [u, hashPw(p), new Date().toISOString()]]]);
      return res.status(200).json({ token: await signToken(u), username: u });
    }
    if (b.action === "login") {
      const a = admins.find((x) => x.username === clip(b.username, 30));
      if (!a || !checkPw(String(b.password || ""), a.pw_hash)) { await new Promise((r) => setTimeout(r, 700)); return fail(res, 401, "아이디 또는 비밀번호가 맞지 않아요."); }
      return res.status(200).json({ token: await signToken(a.username), username: a.username });
    }
    const user = await verifyToken(b.token);
    if (!user || !admins.some((x) => x.username === user)) return fail(res, 401, "로그인이 필요해요.");

    if (b.action === "list") {
      const [rows] = await sql([["SELECT * FROM bookings ORDER BY created_at DESC, id DESC"]]);
      return res.status(200).json({ items: rows.map((r) => ({ ...toFull(r), adminMemo: r.admin_memo })), statuses: STATUSES });
    }
    if (b.action === "update") {
      const id = Number(b.id); const f = b.fields || {};
      const map = { status: "status", adminMemo: "admin_memo", name: "name", phone: "phone", spouseName: "spouse_name", spousePhone: "spouse_phone", weddingDate: "wedding_date", weddingTime: "wedding_time", hall: "hall", snapProduct: "snap_product", dvdProduct: "dvd_product", partnerCode: "partner_code", receiptType: "receipt_type", receiptNumber: "receipt_number", message: "message" };
      const sets = [], args = [];
      for (const [k, col] of Object.entries(map)) if (k in f) {
        let v = clip(f[k], k === "message" || k === "adminMemo" ? 2000 : 80);
        if (k === "status" && !STATUSES.includes(v)) return fail(res, 400, "상태 값을 다시 선택해 주세요.");
        if ((k === "phone" || (k === "spousePhone" && v)) && !PHONE.test(v)) return fail(res, 400, "연락처는 010-0000-0000 형식으로 적어주세요.");
        sets.push(col + "=?"); args.push(v);
      }
      if (!id || !sets.length) return fail(res, 400, "수정할 내용이 없어요.");
      sets.push("updated_at=?"); args.push(new Date().toISOString(), id);
      await sql([["UPDATE bookings SET " + sets.join(",") + " WHERE id=?", args]]);
      return res.status(200).json({ ok: true });
    }
    if (b.action === "delete") {
      await sql([["DELETE FROM bookings WHERE id=?", [Number(b.id)]]]);
      return res.status(200).json({ ok: true });
    }
    if (b.action === "saveContent") {
      const c = b.content;
      if (!c || typeof c !== "object") return fail(res, 400, "저장할 내용이 없어요.");
      const s = JSON.stringify(c);
      if (s.length > 200000) return fail(res, 400, "내용이 너무 길어요.");
      await sql([["INSERT INTO settings (key,value) VALUES ('content',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [s]]]);
      return res.status(200).json({ ok: true });
    }
    if (b.action === "changePassword") {
      const p = String(b.newPassword || "");
      if (p.length < 8) return fail(res, 400, "새 비밀번호는 8자 이상으로 정해주세요.");
      await sql([["UPDATE admins SET pw_hash=? WHERE username=?", [hashPw(p), user]]]);
      return res.status(200).json({ ok: true });
    }
    return fail(res, 400, "알 수 없는 요청이에요.");
  } catch (e) {
    return fail(res, 500, "잠시 후 다시 시도해 주세요.");
  }
};
