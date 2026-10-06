// 예약 게시판 API
// (공개 목록 없음 — 관리자 화면에서만 열람)
// POST {action:"create",...}   → 예약글 작성
// POST {action:"lookup",name,phone,password} → 본인 글 조회
const { sql, ensure, hashPw, checkPw, clip, mask, PHONE, BIZ, body, fail } = require("./_db.js");

const toFull = (r) => ({
  id: Number(r.id), createdAt: r.created_at, updatedAt: r.updated_at, status: r.status,
  name: r.name, phone: r.phone, spouseName: r.spouse_name, spousePhone: r.spouse_phone,
  weddingDate: r.wedding_date, weddingTime: r.wedding_time, hall: r.hall,
  snapProduct: r.snap_product, dvdProduct: r.dvd_product, addons: JSON.parse(r.addons || "[]"),
  partnerCode: r.partner_code, receiptType: r.receipt_type, receiptNumber: r.receipt_number, message: r.message,
});

function validate(b) {
  const d = {
    name: clip(b.name, 20), phone: clip(b.phone, 13), spouse_name: clip(b.spouseName, 20), spouse_phone: clip(b.spousePhone, 13),
    wedding_date: clip(b.weddingDate, 10), wedding_time: clip(b.weddingTime, 20), hall: clip(b.hall, 60),
    snap_product: clip(b.snapProduct, 60), dvd_product: clip(b.dvdProduct, 60),
    addons: JSON.stringify((Array.isArray(b.addons) ? b.addons : []).slice(0, 20).map((x) => clip(x, 60)).filter(Boolean)),
    partner_code: clip(b.partnerCode, 30), receipt_type: clip(b.receiptType, 20), receipt_number: clip(b.receiptNumber, 13), message: clip(b.message, 1500),
  };
  const e = [];
  if (!b.agreeNotice || !b.agreePrivacy) e.push("필독사항과 개인정보 처리방침에 동의해 주세요.");
  if (d.name.length < 2) e.push("예약자 성함을 적어주세요.");
  if (!PHONE.test(d.phone)) e.push("예약자 연락처를 010-0000-0000 형식으로 적어주세요.");
  if (d.spouse_phone && !PHONE.test(d.spouse_phone)) e.push("배우자 연락처를 010-0000-0000 형식으로 적어주세요.");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d.wedding_date)) e.push("예식일을 선택해 주세요.");
  if (!d.wedding_time) e.push("예식 시간을 적어주세요.");
  if (!d.hall) e.push("예식장을 적어주세요.");
  if (!d.snap_product && !d.dvd_product) e.push("상품을 하나 이상 선택해 주세요.");
  if (d.receipt_type === "personal" && !PHONE.test(d.receipt_number)) e.push("현금영수증 휴대폰 번호를 010-0000-0000 형식으로 적어주세요.");
  if (d.receipt_type === "business" && !BIZ.test(d.receipt_number)) e.push("사업자번호를 000-00-00000 형식으로 적어주세요.");
  if (!["personal", "business", "none", ""].includes(d.receipt_type)) e.push("현금영수증 종류를 다시 선택해 주세요.");
  if (d.receipt_type === "none" || !d.receipt_type) d.receipt_number = "";
  const pw = String(b.password || "");
  if (pw.length < 4 || pw.length > 30) e.push("비밀번호는 4자 이상으로 정해주세요.");
  return { d, e, pw };
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    await ensure();
    // 예약 목록은 관리자 화면(/api/admin)에서만 볼 수 있어요.
    if (req.method !== "POST") { res.setHeader("Allow", "POST"); return fail(res, 405, "지원하지 않는 요청이에요."); }
    const b = body(req);
    if (b.website) return res.status(200).json({ ok: true });
    if (b.action === "lookup") {
      const name = clip(b.name, 20), phone = clip(b.phone, 13), pw = String(b.password || "");
      if (!name || !PHONE.test(phone) || !pw) return fail(res, 400, "성함, 연락처, 비밀번호를 모두 적어주세요.");
      const [rows] = await sql([["SELECT * FROM bookings WHERE name=? AND phone=? ORDER BY created_at DESC", [name, phone]]]);
      const mine = rows.filter((r) => checkPw(pw, r.pw_hash));
      if (!mine.length) { await new Promise((r) => setTimeout(r, 600)); return fail(res, 404, "일치하는 예약 글이 없어요. 성함, 연락처, 비밀번호를 다시 확인해 주세요."); }
      return res.status(200).json({ items: mine.map(toFull) });
    }
    const { d, e, pw } = validate(b);
    if (e.length) return fail(res, 400, e.join(" "));
    const now = new Date().toISOString();
    await sql([["INSERT INTO bookings (created_at,name,phone,spouse_name,spouse_phone,wedding_date,wedding_time,hall,snap_product,dvd_product,addons,partner_code,receipt_type,receipt_number,message,pw_hash,agreed_notice,agreed_privacy) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,1)",
      [now, d.name, d.phone, d.spouse_name, d.spouse_phone, d.wedding_date, d.wedding_time, d.hall, d.snap_product, d.dvd_product, d.addons, d.partner_code, d.receipt_type, d.receipt_number, d.message, hashPw(pw)]]]);
    return res.status(201).json({ ok: true });
  } catch (err) {
    return fail(res, 500, "잠시 후 다시 시도해 주세요.");
  }
};
module.exports.toFull = toFull;
