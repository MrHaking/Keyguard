const crypto = require("crypto");
const {
  STATE_COOKIE,
  cookie,
  publicBaseUrl,
  env
} = require("../_lib/auth");

module.exports = async function handler(req, res) {
  try {
    const state = crypto.randomBytes(24).toString("hex");
    const redirectUri = `${publicBaseUrl(req)}/api/auth/callback`;

    res.setHeader(
      "Set-Cookie",
      cookie(STATE_COOKIE, state, {
        maxAge: 600,
        sameSite: "Lax"
      })
    );

    const params = new URLSearchParams({
      client_id: env("GITHUB_CLIENT_ID"),
      redirect_uri: redirectUri,
      scope: "read:user",
      state
    });

    res.statusCode = 302;
    res.setHeader(
      "Location",
      `https://github.com/login/oauth/authorize?${params.toString()}`
    );
    res.end();
  } catch (error) {
    res.status(500).json({
      error: "oauth_not_configured"
    });
  }
};
