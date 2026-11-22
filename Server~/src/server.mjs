import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "0.0.0.0";
const JWT_SECRET = process.env.JWT_SECRET || "dev-local-mock-secret-change-in-production-32bytes";
const JWT_ISSUER = process.env.JWT_ISSUER || "unity-auth-core-server";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "unity-game-client";
const ACCESS_TTL_SECONDS = Math.max(10, Number(process.env.ACCESS_TTL_SECONDS || 300));
const REFRESH_TTL_SECONDS = Math.max(60, Number(process.env.REFRESH_TTL_SECONDS || 604800));
const SERVER_API_KEY = process.env.SERVER_API_KEY || "";
const RATE_LIMIT_MAX = Math.max(5, Number(process.env.RATE_LIMIT_MAX || 120));
const RATE_LIMIT_WINDOW_MS = Math.max(1000, Number(process.env.RATE_LIMIT_WINDOW_MS || 60000));
const DATA_FILE = process.env.DATA_FILE || path.resolve(process.cwd(), "data", "auth-store.json");

const state = {
  accounts: {},
  emailIndex: {},
  deviceIndex: {},
  refreshTokens: {}
};

const rateBuckets = new Map();

/**
 * Loads persisted account, index, and refresh-token state from DATA_FILE into memory if present.
 */
function loadState() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
      Object.assign(state.accounts, parsed.accounts || {});
      Object.assign(state.emailIndex, parsed.emailIndex || {});
      Object.assign(state.deviceIndex, parsed.deviceIndex || {});
      Object.assign(state.refreshTokens, parsed.refreshTokens || {});
    }
  } catch (err) {
    console.warn("[UnityAuthCore Server] Starting with fresh store:", err.message);
  }
}

/**
 * Persists the current in-memory auth state to DATA_FILE as formatted UTF-8 JSON.
 */
function persistState() {
  try {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(state, null, 2), "utf8");
  } catch (err) {
    console.error("[UnityAuthCore Server] Persist error:", err.message);
  }
}

/**
 * Encodes a string or Buffer using RFC 7515 unpadded Base64Url encoding.
 * @param {Buffer|string} buf Raw bytes or UTF-8 string to encode.
 * @returns {string} Unpadded Base64Url string.
 */
function b64urlEncode(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/=+$/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

/**
 * Decodes a Base64Url string back into a raw Node.js Buffer.
 * @param {string} str Unpadded or padded Base64Url input.
 * @returns {Buffer} Decoded binary buffer.
 */
function b64urlDecode(str) {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4 !== 0) s += "=";
  return Buffer.from(s, "base64");
}

/**
 * Hashes a plaintext password with a random 16-byte salt using scrypt (64-byte derived key).
 * @param {string} password Plaintext password to hash.
 * @returns {string} Salted hash formatted as `<saltHex>:<derivedHex>`.
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derived}`;
}

/**
 * Verifies a plaintext password against a stored `<saltHex>:<derivedHex>` scrypt hash in constant time.
 * @param {string} password Candidate plaintext password.
 * @param {string} stored Stored salted hash string.
 * @returns {boolean} True when the password matches the stored hash.
 */
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(":")) return false;
  const [salt, expectedHex] = stored.split(":");
  const actual = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(expectedHex, "hex");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

/**
 * Signs a JSON payload object as a compact HS256 JWT using JWT_SECRET.
 * @param {object} payload JWT claims payload to encode.
 * @returns {string} Compact `<header>.<payload>.<signature>` JWT string.
 */
function signJwt(payload) {
  const header = b64urlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64urlEncode(JSON.stringify(payload));
  const input = `${header}.${body}`;
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(input).digest();
  return `${input}.${b64urlEncode(sig)}`;
}

/**
 * Verifies an HS256 JWT signature in constant time and validates exp, iss, and aud claims.
 * @param {string} token Compact JWT string to inspect.
 * @returns {object} Validation result containing `isValid` and either identity claims or `failureCode`/`failureReason`.
 */
function verifyJwt(token) {
  if (!token || typeof token !== "string") {
    return { isValid: false, failureCode: "TOKEN_MISSING", failureReason: "Access token is empty." };
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    return { isValid: false, failureCode: "TOKEN_MALFORMED", failureReason: "JWT must contain 3 segments." };
  }
  const input = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac("sha256", JWT_SECRET).update(input).digest();
  let provided;
  try {
    provided = b64urlDecode(parts[2]);
  } catch {
    return { isValid: false, failureCode: "TOKEN_MALFORMED", failureReason: "Invalid signature encoding." };
  }
  if (expected.length !== provided.length || !crypto.timingSafeEqual(expected, provided)) {
    return { isValid: false, failureCode: "SIGNATURE_INVALID", failureReason: "JWT HS256 signature invalid." };
  }
  let claims;
  try {
    claims = JSON.parse(b64urlDecode(parts[1]).toString("utf8"));
  } catch {
    return { isValid: false, failureCode: "TOKEN_PARSE_ERROR", failureReason: "Invalid JWT payload." };
  }
  const now = Math.floor(Date.now() / 1000);
  if (claims.exp && now > claims.exp) {
    return { isValid: false, failureCode: "TOKEN_EXPIRED", failureReason: "Access token expired." };
  }
  if (JWT_ISSUER && claims.iss !== JWT_ISSUER) {
    return { isValid: false, failureCode: "ISSUER_MISMATCH", failureReason: "Unexpected issuer." };
  }
  if (JWT_AUDIENCE && claims.aud !== JWT_AUDIENCE) {
    return { isValid: false, failureCode: "AUDIENCE_MISMATCH", failureReason: "Unexpected audience." };
  }
  return {
    isValid: true,
    accountId: claims.sub,
    displayName: claims.displayName || "",
    isGuest: Boolean(claims.isGuest),
    roles: Array.isArray(claims.roles) ? claims.roles : [],
    expiresAtUnixSeconds: claims.exp || 0
  };
}

/**
 * Projects an internal account record into the public OpenAPI `AuthUserProfile` response shape.
 * @param {object} acc Stored account record.
 * @returns {object} Public user profile without sensitive fields such as `passwordHash`.
 */
function toProfile(acc) {
  return {
    accountId: acc.accountId,
    displayName: acc.displayName,
    email: acc.email || "",
    avatarUrl: acc.avatarUrl || "",
    isGuest: Boolean(acc.isGuest),
    roles: acc.roles || ["player"],
    linkedProviders: acc.linkedProviders || [],
    metadataJson: acc.metadataJson || ""
  };
}

/**
 * Mints an HS256 access JWT and rotating refresh token for an account, persisting the updated store.
 * @param {object} acc Stored account record.
 * @param {string|null} [familyId=null] Existing refresh-token family ID when rotating, or null to start a new family.
 * @returns {object} `AuthSession` JSON response object.
 */
function issueSession(acc, familyId = null) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + ACCESS_TTL_SECONDS;
  const accessToken = signJwt({
    sub: acc.accountId,
    iss: JWT_ISSUER,
    aud: JWT_AUDIENCE,
    email: acc.email || "",
    displayName: acc.displayName,
    isGuest: Boolean(acc.isGuest),
    roles: acc.roles || ["player"],
    jti: crypto.randomUUID().replace(/-/g, ""),
    iat: now,
    exp
  });

  const refreshToken = "rt_" + crypto.randomBytes(24).toString("hex");
  const fam = familyId || "fam_" + crypto.randomBytes(8).toString("hex");
  state.refreshTokens[refreshToken] = {
    familyId: fam,
    accountId: acc.accountId,
    consumed: false,
    revoked: false,
    expiresAtUnix: now + REFRESH_TTL_SECONDS
  };
  persistState();

  return {
    accessToken,
    refreshToken,
    tokenType: "Bearer",
    expiresAtUnixSeconds: exp,
    providerId: "rest",
    user: toProfile(acc)
  };
}

/**
 * Revokes every refresh token belonging to the specified session family and persists state.
 * @param {string} familyId Session family identifier to revoke.
 */
function revokeFamily(familyId) {
  for (const rec of Object.values(state.refreshTokens)) {
    if (rec.familyId === familyId) rec.revoked = true;
  }
  persistState();
}

/**
 * Reads and parses a JSON HTTP request body up to 64 KiB, returning an empty object for blank bodies.
 * @param {http.IncomingMessage} req Incoming Node.js HTTP request stream.
 * @returns {Promise<object>} Parsed JSON payload.
 */
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", chunk => {
      raw += chunk;
      if (raw.length > 65536) {
        reject(new Error("Payload too large"));
      }
    });
    req.on("end", () => {
      if (!raw.trim()) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

/**
 * Writes a JSON response with CORS headers and `X-Request-Id` correlation header.
 * @param {http.ServerResponse} res Outgoing Node.js HTTP response.
 * @param {number} status HTTP status code (204 sends an empty body).
 * @param {object|null} payload Serializable JSON body.
 * @param {string} reqId Request correlation ID echoed in `X-Request-Id`.
 * @param {Record<string, string>} [extraHeaders={}] Additional HTTP response headers.
 */
function sendJson(res, status, payload, reqId, extraHeaders = {}) {
  const body = status === 204 ? "" : JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "X-Request-Id": reqId,
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Request-Id, X-Api-Key, X-Server-Key",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
    ...extraHeaders
  });
  res.end(body);
}

/**
 * Sends a structured `ApiError` JSON envelope and optional `Retry-After` header.
 * @param {http.ServerResponse} res Outgoing Node.js HTTP response.
 * @param {number} status HTTP error status code.
 * @param {string} errorCode Machine-readable error identifier.
 * @param {string} message Human-readable failure description.
 * @param {string} reqId Request correlation ID.
 * @param {number} [retryAfterSeconds=0] Optional retry wait time in seconds.
 */
function sendError(res, status, errorCode, message, reqId, retryAfterSeconds = 0) {
  const headers = retryAfterSeconds > 0 ? { "Retry-After": String(retryAfterSeconds) } : {};
  sendJson(res, status, { statusCode: status, errorCode, message, requestId: reqId, retryAfterSeconds }, reqId, headers);
}

/**
 * Applies fixed-window per-IP rate limiting using RATE_LIMIT_MAX and RATE_LIMIT_WINDOW_MS.
 * @param {string} ip Client remote IP address.
 * @returns {boolean} True when the request is within the allowed quota; false when rate limited.
 */
function checkRateLimit(ip) {
  const now = Date.now();
  let bucket = rateBuckets.get(ip);
  if (!bucket || now - bucket.windowStart >= RATE_LIMIT_WINDOW_MS) {
    bucket = { windowStart: now, count: 0 };
    rateBuckets.set(ip, bucket);
  }
  bucket.count += 1;
  return bucket.count <= RATE_LIMIT_MAX;
}

/**
 * Validates the `Authorization: Bearer` token on a protected route and resolves the owning account.
 * Writes a 401 error response automatically when authentication fails.
 * @param {http.IncomingMessage} req Incoming HTTP request.
 * @param {http.ServerResponse} res Outgoing HTTP response used to send 401 errors.
 * @param {string} reqId Request correlation ID.
 * @returns {object|null} Authenticated account record, or null if a 401 response was sent.
 */
function authenticateBearer(req, res, reqId) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) {
    sendError(res, 401, "MISSING_BEARER", "Authorization Bearer token is required.", reqId);
    return null;
  }
  const verified = verifyJwt(auth.slice(7).trim());
  if (!verified.isValid) {
    sendError(res, 401, verified.failureCode, verified.failureReason, reqId);
    return null;
  }
  const acc = state.accounts[verified.accountId];
  if (!acc) {
    sendError(res, 401, "ACCOUNT_NOT_FOUND", "Account not found.", reqId);
    return null;
  }
  return acc;
}

loadState();

const server = http.createServer(async (req, res) => {
  const reqId = req.headers["x-request-id"] || crypto.randomUUID().replace(/-/g, "");
  const method = (req.method || "GET").toUpperCase();
  const urlPath = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`).pathname;

  if (method === "OPTIONS") {
    return sendJson(res, 204, null, reqId);
  }

  if (method === "GET" && urlPath === "/healthz") {
    return sendJson(res, 200, { status: "ok", uptimeSeconds: Math.floor(process.uptime()) }, reqId);
  }

  const clientIp = req.socket.remoteAddress || "unknown";
  if (!checkRateLimit(clientIp)) {
    return sendError(res, 429, "RATE_LIMITED", "Rate limit exceeded.", reqId, Math.ceil(RATE_LIMIT_WINDOW_MS / 1000));
  }

  let body = {};
  if (method === "POST" || method === "PATCH" || method === "PUT") {
    try {
      body = await readJsonBody(req);
    } catch (err) {
      return sendError(res, 400, "INVALID_JSON", err.message, reqId);
    }
  }

  if (method === "POST" && urlPath === "/v1/auth/guest") {
    const deviceId = String(body.deviceId || "").trim() || crypto.randomUUID();
    let accId = state.deviceIndex[deviceId];
    let acc = accId ? state.accounts[accId] : null;
    if (!acc) {
      accId = "acc_" + crypto.randomBytes(6).toString("hex");
      acc = {
        accountId: accId,
        deviceId,
        displayName: String(body.displayName || "").trim() || `Guest_${accId.slice(4, 10)}`,
        email: "",
        passwordHash: "",
        avatarUrl: "",
        metadataJson: "",
        isGuest: true,
        roles: ["player"],
        linkedProviders: ["guest"]
      };
      state.accounts[accId] = acc;
      state.deviceIndex[deviceId] = accId;
      persistState();
    }
    return sendJson(res, 200, issueSession(acc), reqId);
  }

  if (method === "POST" && urlPath === "/v1/auth/register") {
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!email || !email.includes("@")) {
      return sendError(res, 400, "VALIDATION_ERROR", "A valid email address is required.", reqId);
    }
    if (password.length < 6) {
      return sendError(res, 400, "VALIDATION_ERROR", "Password must be at least 6 characters.", reqId);
    }
    if (state.emailIndex[email]) {
      return sendError(res, 409, "EMAIL_ALREADY_EXISTS", "An account with this email already exists.", reqId);
    }
    const accId = "acc_" + crypto.randomBytes(6).toString("hex");
    const acc = {
      accountId: accId,
      deviceId: "",
      displayName: String(body.displayName || "").trim() || email.split("@")[0],
      email,
      passwordHash: hashPassword(password),
      avatarUrl: "",
      metadataJson: "",
      isGuest: false,
      roles: ["player"],
      linkedProviders: ["email"]
    };
    state.accounts[accId] = acc;
    state.emailIndex[email] = accId;
    return sendJson(res, 201, issueSession(acc), reqId);
  }

  if (method === "POST" && urlPath === "/v1/auth/login") {
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const accId = state.emailIndex[email];
    const acc = accId ? state.accounts[accId] : null;
    if (!acc || !verifyPassword(password, acc.passwordHash)) {
      return sendError(res, 401, "INVALID_CREDENTIALS", "Invalid email or password.", reqId);
    }
    return sendJson(res, 200, issueSession(acc), reqId);
  }

  if (method === "POST" && urlPath === "/v1/auth/refresh") {
    const token = String(body.refreshToken || "");
    const rec = state.refreshTokens[token];
    if (!rec) {
      return sendError(res, 401, "INVALID_REFRESH_TOKEN", "Refresh token is unknown.", reqId);
    }
    const now = Math.floor(Date.now() / 1000);
    if (rec.revoked || rec.expiresAtUnix <= now) {
      return sendError(res, 401, "REFRESH_TOKEN_REVOKED", "Refresh token is revoked or expired.", reqId);
    }
    if (rec.consumed) {
      revokeFamily(rec.familyId);
      return sendError(res, 401, "REFRESH_TOKEN_REUSE_DETECTED", "Refresh token reuse detected. Session family revoked.", reqId);
    }
    rec.consumed = true;
    const acc = state.accounts[rec.accountId];
    if (!acc) {
      return sendError(res, 401, "ACCOUNT_NOT_FOUND", "Account no longer exists.", reqId);
    }
    return sendJson(res, 200, issueSession(acc, rec.familyId), reqId);
  }

  if (method === "POST" && urlPath === "/v1/auth/logout") {
    const token = String(body.refreshToken || "");
    const rec = state.refreshTokens[token];
    if (rec) revokeFamily(rec.familyId);
    return sendJson(res, 204, null, reqId);
  }

  if (method === "POST" && urlPath === "/v1/auth/introspect") {
    if (SERVER_API_KEY && req.headers["x-server-key"] !== SERVER_API_KEY) {
      return sendError(res, 403, "FORBIDDEN_SERVER_KEY", "Invalid X-Server-Key header.", reqId);
    }
    const result = verifyJwt(String(body.accessToken || ""));
    return sendJson(res, 200, result, reqId);
  }

  if (method === "GET" && urlPath === "/v1/account/me") {
    const acc = authenticateBearer(req, res, reqId);
    if (!acc) return;
    return sendJson(res, 200, toProfile(acc), reqId);
  }

  if (method === "PATCH" && urlPath === "/v1/account/me") {
    const acc = authenticateBearer(req, res, reqId);
    if (!acc) return;
    if (typeof body.displayName === "string" && body.displayName.trim()) acc.displayName = body.displayName.trim();
    if (typeof body.avatarUrl === "string") acc.avatarUrl = body.avatarUrl;
    if (typeof body.metadataJson === "string") acc.metadataJson = body.metadataJson;
    persistState();
    return sendJson(res, 200, toProfile(acc), reqId);
  }

  if (method === "POST" && urlPath === "/v1/account/link") {
    const acc = authenticateBearer(req, res, reqId);
    if (!acc) return;
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!email || !email.includes("@") || password.length < 6) {
      return sendError(res, 400, "VALIDATION_ERROR", "Valid email and password (min 6 chars) required.", reqId);
    }
    if (state.emailIndex[email] && state.emailIndex[email] !== acc.accountId) {
      return sendError(res, 409, "EMAIL_ALREADY_EXISTS", "Email is already linked to another account.", reqId);
    }
    acc.email = email;
    acc.passwordHash = hashPassword(password);
    acc.isGuest = false;
    if (!acc.linkedProviders.includes("email")) acc.linkedProviders.push("email");
    state.emailIndex[email] = acc.accountId;
    return sendJson(res, 200, issueSession(acc), reqId);
  }

  return sendError(res, 404, "NOT_FOUND", `Route not found: ${method} ${urlPath}`, reqId);
});

server.listen(PORT, HOST, () => {
  console.log(`[UnityAuthCore Reference Server] Listening on http://${HOST}:${PORT}`);
});

/**
 * Persists in-memory auth state to disk and closes the HTTP server before exiting.
 */
function shutdown() {
  persistState();
  server.close(() => process.exit(0));
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
