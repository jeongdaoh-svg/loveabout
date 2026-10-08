// 관리자 API: 최초 설정, 로그인, 예약 관리, 홈페이지 내용 수정
const { sql, ensure, hashPw, checkPw, signToken, verifyToken, encrypt, decrypt, clip, PHONE, body, fail } = require("./_db.js");
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
      // 목록은 가볍게: 게시판에 필요한 칸만 보내고, 글 내용은 열 때 따로 불러와요.
      const [rows] = await sql([["SELECT id, created_at, name, paid, confirmed, imported FROM bookings ORDER BY created_at DESC, id DESC"]]);
      const items = rows.map((r) => ({ id: Number(r.id), createdAt: r.created_at, name: r.name, paid: Number(r.paid) === 1, confirmed: Number(r.confirmed) >= 1, confirmLevel: Number(r.confirmed) || 0, imported: Number(r.imported) === 1, light: true }));
      return res.status(200).json({ items, statuses: STATUSES });
    }
    if (b.action === "get") {
      const [rows] = await sql([["SELECT * FROM bookings WHERE id=?", [Number(b.id)]]]);
      const r = rows[0];
      if (!r) return fail(res, 404, "예약글을 찾을 수 없어요.");
      return res.status(200).json({ item: { ...toFull(r), adminMemo: r.admin_memo, password: r.pw_enc ? await decrypt(r.pw_enc) : null } });
    }
    if (b.action === "update") {
      const id = Number(b.id); const f = b.fields || {};
      const map = { status: "status", adminMemo: "admin_memo", name: "name", phone: "phone", spouseName: "spouse_name", spousePhone: "spouse_phone", email: "email", weddingDate: "wedding_date", weddingTime: "wedding_time", hall: "hall", snapProduct: "snap_product", dvdProduct: "dvd_product", partnerCode: "partner_code", receiptType: "receipt_type", receiptNumber: "receipt_number", message: "message" };
      const sets = [], args = [];
      for (const [k, col] of Object.entries(map)) if (k in f) {
        let v = clip(f[k], k === "message" || k === "adminMemo" ? 2000 : 80);
        if (k === "status" && !STATUSES.includes(v)) return fail(res, 400, "상태 값을 다시 선택해 주세요.");
        if ((k === "phone" || (k === "spousePhone" && v)) && !PHONE.test(v)) return fail(res, 400, "연락처는 010-0000-0000 형식으로 적어주세요.");
        sets.push(col + "=?"); args.push(v);
      }
      if ("paid" in f) { sets.push("paid=?"); args.push(f.paid ? 1 : 0); }
      if ("confirmed" in f) { const c = typeof f.confirmed === "number" ? Math.max(0, Math.min(2, Math.round(f.confirmed))) : (f.confirmed ? 1 : 0); sets.push("confirmed=?"); args.push(c); }
      for (const [k, col] of [["priceTotal", "price_total"], ["discount", "discount"], ["deposit", "deposit"]]) if (k in f) {
        const n = Math.round(Number(String(f[k]).replace(/[^\d.-]/g, "")) || 0);
        if (n < 0 || n > 100000000) return fail(res, 400, "금액을 다시 확인해 주세요.");
        sets.push(col + "=?"); args.push(n);
      }
      if ("addons" in f) { sets.push("addons=?"); args.push(JSON.stringify((Array.isArray(f.addons) ? f.addons : []).slice(0, 20).map((a) => clip(a, 60)).filter(Boolean))); }
      if ("priceItems" in f) { sets.push("price_items=?"); args.push(JSON.stringify((Array.isArray(f.priceItems) ? f.priceItems : []).slice(0, 20).map((x) => ({ name: clip(x && x.name, 60), price: Math.max(0, Math.min(100000000, Math.round(Number(x && x.price) || 0))) })).filter((x) => x.name))); }
      if ("createdAt" in f) { const d = new Date(String(f.createdAt)); if (isNaN(d)) return fail(res, 400, "작성일을 다시 확인해 주세요."); sets.push("created_at=?"); args.push(d.toISOString()); }
      if (!id || !sets.length) return fail(res, 400, "수정할 내용이 없어요.");
      sets.push("updated_at=?"); args.push(new Date().toISOString(), id);
      await sql([["UPDATE bookings SET " + sets.join(",") + " WHERE id=?", args]]);
      return res.status(200).json({ ok: true });
    }
    if (b.action === "import") {
      // 이전 홈페이지 예약글 옮기기 (같은 legacyNo는 한 번만 들어가요)
      const items = Array.isArray(b.items) ? b.items.slice(0, 100) : [];
      if (!items.length) return fail(res, 400, "옮길 글이 없어요.");
      const nos = items.map((x) => Number(x.legacyNo) || 0).filter(Boolean);
      const [have] = await sql([["SELECT legacy_no FROM bookings WHERE legacy_no IN (" + nos.map(() => "?").join(",") + ")", nos]]);
      const seen = new Set(have.map((r) => Number(r.legacy_no)));
      const items2 = items.slice(0, 100);
      const st = [], upd = [];
      for (const x of items2) {
        const no = Number(x.legacyNo) || 0;
        if (no && seen.has(no) && x.email) { upd.push(["UPDATE bookings SET email=? WHERE legacy_no=? AND imported=1", [clip(x.email, 80), no]]); continue; }
        if (!no || seen.has(no)) continue; seen.add(no);
        const pw = String(x.password || "1234").slice(0, 30), ph = hashPw(pw), pe = await encrypt(pw);
        st.push(["INSERT INTO bookings (created_at,name,phone,spouse_name,spouse_phone,wedding_date,wedding_time,hall,snap_product,dvd_product,addons,partner_code,receipt_type,receipt_number,message,pw_hash,pw_enc,agreed_notice,agreed_privacy,status,admin_memo,deposit,price_total,price_items,imported,legacy_no,email) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,1,'접수',?,0,0,'[]',1,?,?)",
          [clip(x.createdAt, 30) || new Date().toISOString(), clip(x.name, 20), clip(x.phone, 13), clip(x.spouseName, 20), clip(x.spousePhone, 13), clip(x.weddingDate, 20), clip(x.weddingTime, 20), clip(x.hall, 60), clip(x.snapProduct, 60), clip(x.dvdProduct, 60),
           JSON.stringify((Array.isArray(x.addons) ? x.addons : []).slice(0, 10).map((a) => clip(a, 60))), clip(x.partnerCode, 30), ["personal", "business"].includes(x.receiptType) ? x.receiptType : "none", clip(x.receiptNumber, 13), clip(x.message, 1500), ph, pe, String(x.adminMemo || "").slice(0, 20000), no, clip(x.email, 80)]]);
      }
      const all = st.concat(upd);
      for (let i = 0; i < all.length; i += 100) await sql(all.slice(i, i + 100));
      return res.status(200).json({ ok: true, inserted: st.length, updated: upd.length, skipped: items2.length - st.length - upd.length });
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
