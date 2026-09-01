const {
  COOKIE_NAME,
  STATE_COOKIE,
  cookie,
  publicBaseUrl
} = require("../_lib/auth");

module.exports = async function handler(req, res) {
  res.setHeader(
    "Set-Cookie",
    [
      cookie(COOKIE_NAME, "", { maxAge: 0 }),
      cookie(STATE_COOKIE, "", { maxAge: 0 })
    ]
  );

  res.statusCode = 302;
  res.setHeader("Location", `${publicBaseUrl(req)}/`);
  res.end();
};
