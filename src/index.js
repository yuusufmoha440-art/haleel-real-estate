// ============================================================
// HALEEL REAL ESTATE - CLOUDFLARE WORKER
// Authentication + Sessions + Online/Offline Presence
// ============================================================

const MAX_ACCOUNT_ID = 9999999;
const SESSION_DAYS = 30;

const PBKDF2_ITERATIONS = 10000;
const PASSWORD_HASH_LENGTH = 256;

const ONLINE_TIMEOUT_SECONDS = 60;

// ============================================================
// MAIN WORKER
// ============================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      // --------------------------------------------------------
      // CORS / OPTIONS
      // --------------------------------------------------------

      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: corsHeaders()
        });
      }

      // --------------------------------------------------------
      // API ROUTES
      // --------------------------------------------------------

      if (url.pathname === "/api/signup" && request.method === "POST") {
        return await signup(request, env);
      }

      if (url.pathname === "/api/login" && request.method === "POST") {
        return await login(request, env);
      }

      if (url.pathname === "/api/logout" && request.method === "POST") {
        return await logout(request, env);
      }

      if (url.pathname === "/api/me" && request.method === "GET") {
        return await me(request, env);
      }

      if (url.pathname === "/api/heartbeat" && request.method === "POST") {
        return await heartbeat(request, env);
      }

      if (
        url.pathname === "/api/online-status" &&
        request.method === "GET"
      ) {
        return await onlineStatus(request, env);
      }

      // --------------------------------------------------------
      // STATIC WEBSITE
      // --------------------------------------------------------

      return env.ASSETS.fetch(request);

    } catch (error) {
      console.error("WORKER ERROR:", error);

      return json(
        {
          ok: false,
          error: "Server error"
        },
        500
      );
    }
  }
};

// ============================================================
// SIGNUP
// ============================================================

async function signup(request, env) {
  const body = await readJSON(request);

  if (!body) {
    return json(
      {
        ok: false,
        error: "Invalid request body"
      },
      400
    );
  }

  const firstName = cleanName(body.firstName);
  const middleName = cleanName(body.middleName);
  const lastName = cleanName(body.lastName);
  const phoneNumber = cleanPhone(body.phoneNumber);
  const password = String(body.password || "");

  // ----------------------------------------------------------
  // VALIDATION
  // ----------------------------------------------------------

  if (!firstName) {
    return json(
      {
        ok: false,
        error: "First name is required"
      },
      400
    );
  }

  if (!middleName) {
    return json(
      {
        ok: false,
        error: "Middle name is required"
      },
      400
    );
  }

  if (!lastName) {
    return json(
      {
        ok: false,
        error: "Last name is required"
      },
      400
    );
  }

  if (!phoneNumber) {
    return json(
      {
        ok: false,
        error: "Phone number is required"
      },
      400
    );
  }

  if (password.length < 6) {
    return json(
      {
        ok: false,
        error: "Password must contain at least 6 characters"
      },
      400
    );
  }

  // ----------------------------------------------------------
  // CHECK DUPLICATE PHONE
  // ----------------------------------------------------------

  const existingUser = await env.ACCOUNTS_DB
    .prepare(
      "SELECT id, account_id FROM users WHERE phone_number = ? LIMIT 1"
    )
    .bind(phoneNumber)
    .first();

  if (existingUser) {
    return json(
      {
        ok: false,
        error: "Phone number is already registered"
      },
      409
    );
  }

  // ----------------------------------------------------------
  // GET NEXT ACCOUNT ID
  // ----------------------------------------------------------

  const sequence = await env.ACCOUNTS_DB
    .prepare(
      "SELECT next_id FROM account_sequence WHERE id = 1 LIMIT 1"
    )
    .first();

  let accountId;

  if (sequence && sequence.next_id) {
    accountId = Number(sequence.next_id);
  } else {
    accountId = 1;

    await env.ACCOUNTS_DB
      .prepare(
        "INSERT OR IGNORE INTO account_sequence (id, next_id) VALUES (1, 1)"
      )
      .run();
  }

  if (
    !Number.isInteger(accountId) ||
    accountId < 1 ||
    accountId > MAX_ACCOUNT_ID
  ) {
    return json(
      {
        ok: false,
        error: "Account ID limit reached"
      },
      500
    );
  }

  // ----------------------------------------------------------
  // HASH PASSWORD
  // ----------------------------------------------------------

  const passwordHash = await hashPassword(password);

  // ----------------------------------------------------------
  // SESSION
  // ----------------------------------------------------------

  const session = await buildSession();

  // ----------------------------------------------------------
  // CREATE USER
  // ----------------------------------------------------------

  const now = new Date().toISOString();

  await env.ACCOUNTS_DB
    .batch([
      env.ACCOUNTS_DB
        .prepare(
          "INSERT INTO users (account_id, password_hash, first_name, middle_name, last_name, phone_number) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(
          accountId,
          passwordHash,
          firstName,
          middleName,
          lastName,
          phoneNumber
        ),

      env.ACCOUNTS_DB
        .prepare(
          "UPDATE account_sequence SET next_id = ? WHERE id = 1"
        )
        .bind(accountId + 1),

      env.ACCOUNTS_DB
        .prepare(
          "INSERT INTO sessions (account_id, token_hash, expires_at) VALUES (?, ?, ?)"
        )
        .bind(
          accountId,
          session.tokenHash,
          session.expiresAt
        )
    ]);

  // ----------------------------------------------------------
  // CREATE PRESENCE TABLE + ONLINE
  // ----------------------------------------------------------

  await ensurePresenceTable(env);

  await markUserOnline(accountId, env);

  // ----------------------------------------------------------
  // RESPONSE
  // ----------------------------------------------------------

  return json(
    {
      ok: true,
      message: "Account created successfully",
      account: {
        accountId: formatAccountId(accountId),
        firstName,
        middleName,
        lastName,
        phoneNumber,
        online: true,
        status: "Online",
        lastSeen: now
      }
    },
    201,
    {
      "Set-Cookie": session.cookie
    }
  );
}

// ============================================================
// LOGIN
// ============================================================

async function login(request, env) {
  const body = await readJSON(request);

  if (!body) {
    return json(
      {
        ok: false,
        error: "Invalid request body"
      },
      400
    );
  }

  const accountIdText = String(body.accountId || "").trim();
  const password = String(body.password || "");

  if (!/^\d{7}$/.test(accountIdText)) {
    return json(
      {
        ok: false,
        error: "Account ID must contain 7 digits"
      },
      400
    );
  }

  if (!password) {
    return json(
      {
        ok: false,
        error: "Password is required"
      },
      400
    );
  }

  const accountId = Number(accountIdText);

  // ----------------------------------------------------------
  // FIND USER
  // ----------------------------------------------------------

  const user = await env.ACCOUNTS_DB
    .prepare(
      "SELECT id, account_id, password_hash, first_name, middle_name, last_name, phone_number FROM users WHERE account_id = ? LIMIT 1"
    )
    .bind(accountId)
    .first();

  if (!user) {
    return json(
      {
        ok: false,
        error: "Invalid Account ID or password"
      },
      401
    );
  }

  // ----------------------------------------------------------
  // VERIFY PASSWORD
  // ----------------------------------------------------------

  const validPassword = await verifyPassword(
    password,
    user.password_hash
  );

  if (!validPassword) {
    return json(
      {
        ok: false,
        error: "Invalid Account ID or password"
      },
      401
    );
  }

  // ----------------------------------------------------------
  // SESSION
  // ----------------------------------------------------------

  const session = await buildSession();

  await env.ACCOUNTS_DB
    .prepare(
      "INSERT INTO sessions (account_id, token_hash, expires_at) VALUES (?, ?, ?)"
    )
    .bind(
      accountId,
      session.tokenHash,
      session.expiresAt
    )
    .run();

  // ----------------------------------------------------------
  // ONLINE
  // ----------------------------------------------------------

  await ensurePresenceTable(env);
  await markUserOnline(accountId, env);

  // ----------------------------------------------------------
  // RESPONSE
  // ----------------------------------------------------------

  return json(
    {
      ok: true,
      message: "Login successful",
      account: {
        accountId: formatAccountId(user.account_id),
        firstName: user.first_name,
        middleName: user.middle_name,
        lastName: user.last_name,
        phoneNumber: user.phone_number,
        online: true,
        status: "Online",
        lastSeen: new Date().toISOString()
      }
    },
    200,
    {
      "Set-Cookie": session.cookie
    }
  );
}

// ============================================================
// LOGOUT
// ============================================================

async function logout(request, env) {
  const token = getCookie(request, "haleel_session");

  if (!token) {
    return json(
      {
        ok: true,
        message: "Already logged out"
      },
      200,
      {
        "Set-Cookie": clearSessionCookie()
      }
    );
  }

  const tokenHash = await sha256(token);

  // ----------------------------------------------------------
  // FIND SESSION
  // ----------------------------------------------------------

  const session = await env.ACCOUNTS_DB
    .prepare(
      "SELECT account_id FROM sessions WHERE token_hash = ? LIMIT 1"
    )
    .bind(tokenHash)
    .first();

  // ----------------------------------------------------------
  // DELETE SESSION
  // ----------------------------------------------------------

  await env.ACCOUNTS_DB
    .prepare(
      "DELETE FROM sessions WHERE token_hash = ?"
    )
    .bind(tokenHash)
    .run();

  // ----------------------------------------------------------
  // OFFLINE
  // ----------------------------------------------------------

  if (session && session.account_id) {
    await ensurePresenceTable(env);
    await markUserOffline(session.account_id, env);
  }

  return json(
    {
      ok: true,
      message: "Logged out successfully"
    },
    200,
    {
      "Set-Cookie": clearSessionCookie()
    }
  );
}

// ============================================================
// ME
// ============================================================

async function me(request, env) {
  const auth = await getAuthenticatedUser(request, env);

  if (!auth) {
    return json(
      {
        ok: false,
        authenticated: false,
        error: "Not authenticated"
      },
      401
    );
  }

  await ensurePresenceTable(env);

  const presence = await env.ACCOUNTS_DB
    .prepare(
      "SELECT account_id, last_seen FROM user_presence WHERE account_id = ? LIMIT 1"
    )
    .bind(auth.user.account_id)
    .first();

  const online = presence
    ? calculateOnline(presence.last_seen)
    : false;

  return json({
    ok: true,
    authenticated: true,
    account: {
      accountId: formatAccountId(auth.user.account_id),
      firstName: auth.user.first_name,
      middleName: auth.user.middle_name,
      lastName: auth.user.last_name,
      phoneNumber: auth.user.phone_number,
      online,
      status: online ? "Online" : "Offline",
      lastSeen: presence ? presence.last_seen : null
    }
  });
}

// ============================================================
// HEARTBEAT
// ============================================================

async function heartbeat(request, env) {
  const auth = await getAuthenticatedUser(request, env);

  if (!auth) {
    return json(
      {
        ok: false,
        authenticated: false,
        error: "Session expired"
      },
      401
    );
  }

  await ensurePresenceTable(env);

  const lastSeen = await markUserOnline(
    auth.user.account_id,
    env
  );

  return json({
    ok: true,
    online: true,
    status: "Online",
    lastSeen
  });
}

// ============================================================
// ONLINE STATUS
// ============================================================

async function onlineStatus(request, env) {
  const url = new URL(request.url);

  const accountIdText = String(
    url.searchParams.get("accountId") || ""
  ).trim();

  if (!/^\d{7}$/.test(accountIdText)) {
    return json(
      {
        ok: false,
        error: "accountId must contain 7 digits"
      },
      400
    );
  }

  const accountId = Number(accountIdText);

  // ----------------------------------------------------------
  // CHECK USER
  // ----------------------------------------------------------

  const user = await env.ACCOUNTS_DB
    .prepare(
      "SELECT account_id, first_name, middle_name, last_name FROM users WHERE account_id = ? LIMIT 1"
    )
    .bind(accountId)
    .first();

  if (!user) {
    return json(
      {
        ok: false,
        error: "Account not found"
      },
      404
    );
  }

  // ----------------------------------------------------------
  // PRESENCE
  // ----------------------------------------------------------

  await ensurePresenceTable(env);

  const presence = await env.ACCOUNTS_DB
    .prepare(
      "SELECT account_id, last_seen FROM user_presence WHERE account_id = ? LIMIT 1"
    )
    .bind(accountId)
    .first();

  const online = presence
    ? calculateOnline(presence.last_seen)
    : false;

  return json({
    ok: true,
    account: {
      accountId: formatAccountId(user.account_id),
      firstName: user.first_name,
      middleName: user.middle_name,
      lastName: user.last_name,
      online,
      status: online ? "Online" : "Offline",
      lastSeen: presence ? presence.last_seen : null
    }
  });
}

// ============================================================
// AUTHENTICATED USER
// ============================================================

async function getAuthenticatedUser(request, env) {
  const token = getCookie(request, "haleel_session");

  if (!token) {
    return null;
  }

  const tokenHash = await sha256(token);

  const session = await env.ACCOUNTS_DB
    .prepare(
      "SELECT id, account_id, token_hash, expires_at FROM sessions WHERE token_hash = ? LIMIT 1"
    )
    .bind(tokenHash)
    .first();

  if (!session) {
    return null;
  }

  const expiresAt = new Date(session.expires_at).getTime();

  if (!Number.isFinite(expiresAt)) {
    await env.ACCOUNTS_DB
      .prepare(
        "DELETE FROM sessions WHERE id = ?"
      )
      .bind(session.id)
      .run();

    return null;
  }

  if (expiresAt <= Date.now()) {
    await env.ACCOUNTS_DB
      .prepare(
        "DELETE FROM sessions WHERE id = ?"
      )
      .bind(session.id)
      .run();

    return null;
  }

  const user = await env.ACCOUNTS_DB
    .prepare(
      "SELECT id, account_id, first_name, middle_name, last_name, phone_number FROM users WHERE account_id = ? LIMIT 1"
    )
    .bind(session.account_id)
    .first();

  if (!user) {
    return null;
  }

  return {
    session,
    user
  };
}

// ============================================================
// PRESENCE TABLE
// ============================================================

async function ensurePresenceTable(env) {
  await env.ACCOUNTS_DB
    .prepare(
      "CREATE TABLE IF NOT EXISTS user_presence (" +
      "account_id INTEGER PRIMARY KEY, " +
      "last_seen TEXT NOT NULL" +
      ")"
    )
    .run();
}

// ============================================================
// MARK USER ONLINE
// ============================================================

async function markUserOnline(accountId, env) {
  const lastSeen = new Date().toISOString();

  await env.ACCOUNTS_DB
    .prepare(
      "INSERT INTO user_presence (account_id, last_seen) VALUES (?, ?) " +
      "ON CONFLICT(account_id) DO UPDATE SET last_seen = excluded.last_seen"
    )
    .bind(accountId, lastSeen)
    .run();

  return lastSeen;
}

// ============================================================
// MARK USER OFFLINE
// ============================================================

async function markUserOffline(accountId, env) {
  await env.ACCOUNTS_DB
    .prepare(
      "DELETE FROM user_presence WHERE account_id = ?"
    )
    .bind(accountId)
    .run();
}

// ============================================================
// CALCULATE ONLINE
// ============================================================

function calculateOnline(lastSeen) {
  if (!lastSeen) {
    return false;
  }

  const lastSeenTime = new Date(lastSeen).getTime();

  if (!Number.isFinite(lastSeenTime)) {
    return false;
  }

  const differenceSeconds =
    (Date.now() - lastSeenTime) / 1000;

  return differenceSeconds <= ONLINE_TIMEOUT_SECONDS;
}

// ============================================================
// BUILD SESSION
// ============================================================

async function buildSession() {
  const tokenBytes = new Uint8Array(32);

  crypto.getRandomValues(tokenBytes);

  const token = base64UrlEncode(tokenBytes);

  const tokenHash = await sha256(token);

  const expiresAtDate = new Date(
    Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000
  );

  const expiresAt = expiresAtDate.toISOString();

  const cookie =
    "haleel_session=" +
    token +
    "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" +
    SESSION_DAYS * 24 * 60 * 60;

  return {
    token,
    tokenHash,
    expiresAt,
    cookie
  };
}

// ============================================================
// CLEAR SESSION COOKIE
// ============================================================

function clearSessionCookie() {
  return (
    "haleel_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  );
}

// ============================================================
// PASSWORD HASH
// ============================================================

async function hashPassword(password) {
  const salt = new Uint8Array(16);

  crypto.getRandomValues(salt);

  const keyMaterial =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const derivedBits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      keyMaterial,
      PASSWORD_HASH_LENGTH
    );

  const hashBytes =
    new Uint8Array(derivedBits);

  return (
    "pbkdf2$sha256$" +
    PBKDF2_ITERATIONS +
    "$" +
    base64UrlEncode(salt) +
    "$" +
    base64UrlEncode(hashBytes)
  );
}

// ============================================================
// PASSWORD VERIFY
// ============================================================

async function verifyPassword(password, storedHash) {
  try {
    const parts = String(storedHash).split("$");

    if (parts.length !== 5) {
      return false;
    }

    const algorithm = parts[0];
    const hashName = parts[1];
    const iterations = Number(parts[2]);
    const saltText = parts[3];
    const storedHashText = parts[4];

    if (
      algorithm !== "pbkdf2" ||
      hashName !== "sha256" ||
      !Number.isFinite(iterations)
    ) {
      return false;
    }

    const salt = base64UrlDecode(saltText);
    const expectedHash =
      base64UrlDecode(storedHashText);

    const keyMaterial =
      await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
      );

    const derivedBits =
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt,
          iterations,
          hash: "SHA-256"
        },
        keyMaterial,
        PASSWORD_HASH_LENGTH
      );

    const actualHash =
      new Uint8Array(derivedBits);

    return timingSafeEqual(
      actualHash,
      expectedHash
    );

  } catch (error) {
    console.error("PASSWORD VERIFY ERROR:", error);
    return false;
  }
}

// ============================================================
// SHA-256
// ============================================================

async function sha256(value) {
  const data =
    new TextEncoder().encode(value);

  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );

  return base64UrlEncode(
    new Uint8Array(digest)
  );
}

// ============================================================
// TIMING SAFE EQUAL
// ============================================================

function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

// ============================================================
// GET COOKIE
// ============================================================

function getCookie(request, name) {
  const cookieHeader =
    request.headers.get("Cookie");

  if (!cookieHeader) {
    return null;
  }

  const cookies =
    cookieHeader.split(";");

  for (const cookie of cookies) {
    const index = cookie.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key =
      cookie.slice(0, index).trim();

    const value =
      cookie.slice(index + 1).trim();

    if (key === name) {
      return value;
    }
  }

  return null;
}

// ============================================================
// READ JSON
// ============================================================

async function readJSON(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

// ============================================================
// CLEAN NAME
// ============================================================

function cleanName(value) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ");
}

// ============================================================
// CLEAN PHONE
// ============================================================

function cleanPhone(value) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, "");
}

// ============================================================
// FORMAT ACCOUNT ID
// ============================================================

function formatAccountId(value) {
  return String(value)
    .padStart(7, "0");
}

// ============================================================
// BASE64 URL ENCODE
// ============================================================

function base64UrlEncode(bytes) {
  let binary = "";

  const chunkSize = 0x8000;

  for (
    let i = 0;
    i < bytes.length;
    i += chunkSize
  ) {
    binary += String.fromCharCode(
      ...bytes.subarray(
        i,
        Math.min(i + chunkSize, bytes.length)
      )
    );
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

// ============================================================
// BASE64 URL DECODE
// ============================================================

function base64UrlDecode(value) {
  let base64 = String(value)
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  while (base64.length % 4) {
    base64 += "=";
  }

  const binary = atob(base64);

  const bytes =
    new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

// ============================================================
// CORS HEADERS
// ============================================================

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods":
      "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type",
    "Access-Control-Allow-Credentials":
      "true"
  };
}

// ============================================================
// JSON RESPONSE
// ============================================================

function json(data, status = 200, extraHeaders = {}) {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    ...corsHeaders(),
    ...extraHeaders
  };

  return new Response(
    JSON.stringify(data),
    {
      status,
      headers
    }
  );
}
