const {
  COOKIE_NAME,
  parseCookies,
  verifySession,
  isAllowedOwner
} = require("../_lib/auth");

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json; charset=utf-8");

  const cookies = parseCookies(req);
  const session = verifySession(cookies[COOKIE_NAME]);

  if (!session) {
    res.status(401).json({
      authorized: false
    });
    return;
  }

  if (!isAllowedOwner(session.login)) {
    res.status(403).json({
      authorized: false
    });
    return;
  }

  res.status(200).json({
    authorized: true,
    login: session.login,
    avatar_url: session.avatar_url || ""
  });
};
