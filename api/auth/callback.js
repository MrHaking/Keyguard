const {
  COOKIE_NAME,
  STATE_COOKIE,
  SESSION_TTL_SECONDS,
  createSession,
  parseCookies,
  cookie,
  publicBaseUrl,
  isAllowedOwner,
  env
} = require("../_lib/auth");

async function githubJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      "Accept": "application/vnd.github+json",
      "User-Agent": "KEYGUARD-Website",
      ...(options.headers || {})
    }
  });

  const data = await response.json().catch(() => ({}));
  return { response, data };
}

module.exports = async function handler(req, res) {
  const base = publicBaseUrl(req);
  const cookies = parseCookies(req);

  try {
    const code = String(req.query.code || "");
    const state = String(req.query.state || "");
    const savedState = cookies[STATE_COOKIE] || "";

    if (!code || !state || !savedState || state !== savedState) {
      res.statusCode = 302;
      res.setHeader("Location", `${base}/?admin=1&auth=invalid_state`);
      res.end();
      return;
    }

    const tokenResult = await githubJson(
      "https://github.com/login/oauth/access_token",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: env("GITHUB_CLIENT_ID"),
          client_secret: env("GITHUB_CLIENT_SECRET"),
          code,
          redirect_uri: `${base}/api/auth/callback`,
          state
        })
      }
    );

    const accessToken = tokenResult.data.access_token;

    if (!tokenResult.response.ok || !accessToken) {
      throw new Error("token_exchange_failed");
    }

    const userResult = await githubJson(
      "https://api.github.com/user",
      {
        headers: {
          "Authorization": `Bearer ${accessToken}`
        }
      }
    );

    if (!userResult.response.ok || !userResult.data.login) {
      throw new Error("user_lookup_failed");
    }

    // The server—not the browser—decides whether the account is the owner.
    if (!isAllowedOwner(userResult.data.login)) {
      res.setHeader(
        "Set-Cookie",
        [
          cookie(STATE_COOKIE, "", { maxAge: 0 }),
          cookie(COOKIE_NAME, "", { maxAge: 0 })
        ]
      );
      res.statusCode = 302;
      res.setHeader("Location", `${base}/?admin=1&auth=denied`);
      res.end();
      return;
    }

    const session = createSession(userResult.data);

    res.setHeader(
      "Set-Cookie",
      [
        cookie(STATE_COOKIE, "", { maxAge: 0 }),
        cookie(COOKIE_NAME, session, {
          maxAge: SESSION_TTL_SECONDS,
          sameSite: "Lax"
        })
      ]
    );

    res.statusCode = 302;
    res.setHeader("Location", `${base}/?admin=1`);
    res.end();

  } catch (error) {
    res.setHeader(
      "Set-Cookie",
      cookie(STATE_COOKIE, "", { maxAge: 0 })
    );
    res.statusCode = 302;
    res.setHeader("Location", `${base}/?admin=1&auth=error`);
    res.end();
  }
};
