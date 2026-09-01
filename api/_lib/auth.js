const crypto = require("crypto");

const COOKIE_NAME = "kg_owner_session";
const STATE_COOKIE = "kg_oauth_state";
const SESSION_TTL_SECONDS = 60 * 60 * 8; // 8 hours

function env(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing environment variable: ${name}`);
  }
  return value;
}

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4;
  return Buffer.from(normalized + (pad ? "=".repeat(4 - pad) : ""), "base64");
}

function sign(payload) {
  return base64url(
    crypto
      .createHmac("sha256", env("SESSION_SECRET"))
      .update(payload)
      .digest()
  );
}

function createSession(user) {
  const body = base64url(JSON.stringify({
    login: user.login,
    avatar_url: user.avatar_url || "",
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS
  }));

  return `${body}.${sign(body)}`;
}

function verifySession(value) {
  if (!value || !value.includes(".")) return null;

  const [body, signature] = value.split(".", 2);
  const expected = sign(body);

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return null;
  }

  try {
    const data = JSON.parse(fromBase64url(body).toString("utf8"));
    if (!data.exp || data.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return data;
  } catch {
    return null;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const result = {};

  header.split(";").forEach(part => {
    const index = part.indexOf("=");
    if (index < 0) return;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) result[key] = decodeURIComponent(value);
  });

  return result;
}

function cookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];

  parts.push(`Path=${options.path || "/"}`);

  if (options.maxAge !== undefined) {
    parts.push(`Max-Age=${options.maxAge}`);
  }

  if (options.httpOnly !== false) parts.push("HttpOnly");
  if (options.secure !== false) parts.push("Secure");
  parts.push(`SameSite=${options.sameSite || "Lax"}`);

  return parts.join("; ");
}

function publicBaseUrl(req) {
  if (process.env.SITE_URL) {
    return process.env.SITE_URL.replace(/\/+$/, "");
  }

  const proto =
    req.headers["x-forwarded-proto"] ||
    (req.connection && req.connection.encrypted ? "https" : "http");

  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

function isAllowedOwner(login) {
  const allowed = (process.env.ADMIN_GITHUB_LOGIN || "MrHaking").trim();
  return String(login || "").toLowerCase() === allowed.toLowerCase();
}

module.exports = {
  COOKIE_NAME,
  STATE_COOKIE,
  SESSION_TTL_SECONDS,
  createSession,
  verifySession,
  parseCookies,
  cookie,
  publicBaseUrl,
  isAllowedOwner,
  env
};
