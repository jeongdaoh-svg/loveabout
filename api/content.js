// 홈페이지 내용(상품·추가상품·필독사항·개인정보 처리방침) 조회
const { sql, ensure, fail } = require("./_db.js");
module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    await ensure();
    const [rows] = await sql([["SELECT value FROM settings WHERE key='content'"]]);
    return res.status(200).json({ content: rows[0] ? JSON.parse(rows[0].value) : null });
  } catch (e) { return fail(res, 500, "잠시 후 다시 시도해 주세요."); }
};
