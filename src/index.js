const MAX_ACCOUNT_ID = 9999999;
const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 200000;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/api/signup") {
        return await signup(request, env);
      }

      if (url.pathname === "/api/login") {
        return await login(request, env);
      }

      if (url.pathname === "/api/logout") {
        return await logout(request, env);
      }

      if (url.pathname === "/api/me") {
        return await getCurrentUser(request, env);
      }

      return env.ASSETS.fetch(request);

    } catch (error) {
      console.error("WORKER ERROR:", error);

      return json(
        {
          success: false,
          message: "Server error."
        },
        500
      );
    }
  }
};


// ============================================================
// SIGN UP
// ============================================================

async function signup(request, env) {

  if (request.method !== "POST") {
    return json(
      {
        success: false,
        message: "Method not allowed."
      },
      405
    );
  }

  if (!env.ACCOUNTS_DB) {
    return json(
      {
        success: false,
        message: "Accounts database is not connected."
      },
      500
    );
  }

  const body = await readJSON(request);

  if (!body || typeof body.password !== "string") {
    return json(
      {
        success: false,
        message: "Password is required."
      },
      400
    );
  }

  const password = body.password;

  if (password.length < 8) {
    return json(
      {
        success: false,
        message: "Password must contain at least 8 characters."
      },
      400
    );
  }

  if (password.length > 128) {
    return json(
      {
        success: false,
        message: "Password is too long."
      },
      400
    );
  }

  let passwordHash;

  try {
    passwordHash = await hashPassword(password);
  } catch (error) {
    console.error("PASSWORD HASH ERROR:", error);

    return json(
      {
        success: false,
        message: "Unable to secure password."
      },
      500
    );
  }

  let sequence;

  try {
    sequence = await env.ACCOUNTS_DB
      .prepare(`
        SELECT next_id
        FROM account_sequence
        WHERE id = 1
        LIMIT 1
      `)
      .first();

  } catch (error) {
    console.error("ACCOUNT SEQUENCE READ ERROR:", error);

    return json(
      {
        success: false,
        message: "Unable to read account sequence."
      },
      500
    );
  }

  if (!sequence) {
    return json(
      {
        success: false,
        message: "Account sequence is not configured."
      },
      500
    );
  }

  const accountId = Number(sequence.next_id);

  if (
    !Number.isInteger(accountId) ||
    accountId < 1 ||
    accountId > MAX_ACCOUNT_ID
  ) {
    return json(
      {
        success: false,
        message: "No more account IDs are available."
      },
      409
    );
  }

  const session = await buildSession(accountId);

  try {

    await env.ACCOUNTS_DB.batch([

      env.ACCOUNTS_DB
        .prepare(`
          INSERT INTO users (
            account_id,
            password_hash
          )
          VALUES (?, ?)
        `)
        .bind(
          accountId,
          passwordHash
        ),

      env.ACCOUNTS_DB
        .prepare(`
          UPDATE account_sequence
          SET next_id = next_id + 1
          WHERE id = 1
            AND next_id = ?
        `)
        .bind(accountId),

      env.ACCOUNTS_DB
        .prepare(`
          INSERT INTO sessions (
            account_id,
            token_hash,
            expires_at
          )
          VALUES (?, ?, ?)
        `)
        .bind(
          accountId,
          session.tokenHash,
          session.expiresAt
        )
    ]);

  } catch (error) {

    console.error(
      "SIGNUP DATABASE ERROR:",
      error
    );

    return json(
      {
        success: false,
        message: "Unable to create account."
      },
      500
    );
  }

  const formattedAccountId =
    String(accountId).padStart(7, "0");

  return new Response(
    JSON.stringify({
      success: true,
      accountId: formattedAccountId,
      message: "Account created successfully."
    }),
    {
      status: 201,
      headers: {
        "Content-Type":
          "application/json; charset=UTF-8",

        "Cache-Control":
          "no-store",

        "Set-Cookie":
          session.cookie
      }
    }
  );
}


// ============================================================
// LOGIN
// ============================================================

async function login(request, env) {

  if (request.method !== "POST") {
    return json(
      {
        success: false,
        message: "Method not allowed."
      },
      405
    );
  }

  if (!env.ACCOUNTS_DB) {
    return json(
      {
        success: false,
        message: "Accounts database is not connected."
      },
      500
    );
  }

  const body = await readJSON(request);

  if (!body) {
    return json(
      {
        success: false,
        message: "Invalid request."
      },
      400
    );
  }

  const accountId =
    String(body.accountId || "").trim();

  const password =
    typeof body.password === "string"
      ? body.password
      : "";

  if (!/^\d{7}$/.test(accountId)) {
    return invalidLogin();
  }

  if (!password) {
    return invalidLogin();
  }

  const numericAccountId =
    Number(accountId);

  if (
    !Number.isInteger(numericAccountId) ||
    numericAccountId < 1 ||
    numericAccountId > MAX_ACCOUNT_ID
  ) {
    return invalidLogin();
  }

  let user;

  try {

    user = await env.ACCOUNTS_DB
      .prepare(`
        SELECT
          account_id,
          password_hash
        FROM users
        WHERE account_id = ?
        LIMIT 1
      `)
      .bind(numericAccountId)
      .first();

  } catch (error) {

    console.error(
      "LOGIN DATABASE ERROR:",
      error
    );

    return json(
      {
        success: false,
        message: "Unable to access account database."
      },
      500
    );
  }

  if (!user) {
    return invalidLogin();
  }

  let validPassword = false;

  try {

    validPassword =
      await verifyPassword(
        password,
        user.password_hash
      );

  } catch (error) {

    console.error(
      "PASSWORD VERIFY ERROR:",
      error
    );

    return json(
      {
        success: false,
        message: "Unable to verify password."
      },
      500
    );
  }

  if (!validPassword) {
    return invalidLogin();
  }

  const session =
    await buildSession(
      Number(user.account_id)
    );

  try {

    await env.ACCOUNTS_DB
      .prepare(`
        INSERT INTO sessions (
          account_id,
          token_hash,
          expires_at
        )
        VALUES (?, ?, ?)
      `)
      .bind(
        Number(user.account_id),
        session.tokenHash,
        session.expiresAt
      )
      .run();

  } catch (error) {

    console.error(
      "LOGIN SESSION ERROR:",
      error
    );

    return json(
      {
        success: false,
        message: "Unable to create login session."
      },
      500
    );
  }

  return new Response(
    JSON.stringify({
      success: true,
      accountId:
        String(user.account_id).padStart(7, "0"),
      message: "Login successful."
    }),
    {
      status: 200,
      headers: {
        "Content-Type":
          "application/json; charset=UTF-8",

        "Cache-Control":
          "no-store",

        "Set-Cookie":
          session.cookie
      }
    }
  );
}


// ============================================================
// INVALID LOGIN
// ============================================================

function invalidLogin() {

  return json(
    {
      success: false,
      message: "Invalid ID or password."
    },
    401
  );
}


// ============================================================
// CURRENT USER
// ============================================================

async function getCurrentUser(
  request,
  env
) {

  if (request.method !== "GET") {
    return json(
      {
        success: false,
        message: "Method not allowed."
      },
      405
    );
  }

  if (!env.ACCOUNTS_DB) {
    return json(
      {
        success: false,
        loggedIn: false
      },
      500
    );
  }

  const token =
    getCookie(
      request,
      "haleel_session"
    );

  if (!token) {
    return json(
      {
        success: false,
        loggedIn: false
      },
      401
    );
  }

  let tokenHash;

  try {
    tokenHash = await sha256(token);
  } catch (error) {

    console.error(
      "TOKEN HASH ERROR:",
      error
    );

    return json(
      {
        success: false,
        loggedIn: false
      },
      500
    );
  }

  let session;

  try {

    session =
      await env.ACCOUNTS_DB
        .prepare(`
          SELECT
            account_id,
            expires_at
          FROM sessions
          WHERE token_hash = ?
            AND expires_at > ?
          LIMIT 1
        `)
        .bind(
          tokenHash,
          new Date().toISOString()
        )
        .first();

  } catch (error) {

    console.error(
      "SESSION LOOKUP ERROR:",
      error
    );

    return json(
      {
        success: false,
        loggedIn: false
      },
      500
    );
  }

  if (!session) {

    return new Response(
      JSON.stringify({
        success: false,
        loggedIn: false
      }),
      {
        status: 401,

        headers: {
          "Content-Type":
            "application/json; charset=UTF-8",

          "Cache-Control":
            "no-store",

          "Set-Cookie":
            clearSessionCookie()
        }
      }
    );
  }

  return json({
    success: true,
    loggedIn: true,
    accountId:
      String(session.account_id)
        .padStart(7, "0")
  });
}


// ============================================================
// LOGOUT
// ============================================================

async function logout(
  request,
  env
) {

  if (request.method !== "POST") {
    return json(
      {
        success: false,
        message: "Method not allowed."
      },
      405
    );
  }

  const token =
    getCookie(
      request,
      "haleel_session"
    );

  if (token && env.ACCOUNTS_DB) {

    try {

      const tokenHash =
        await sha256(token);

      await env.ACCOUNTS_DB
        .prepare(`
          DELETE FROM sessions
          WHERE token_hash = ?
        `)
        .bind(tokenHash)
        .run();

    } catch (error) {

      console.error(
        "LOGOUT DATABASE ERROR:",
        error
      );
    }
  }

  return new Response(
    JSON.stringify({
      success: true,
      message: "Logged out successfully."
    }),
    {
      status: 200,

      headers: {
        "Content-Type":
          "application/json; charset=UTF-8",

        "Cache-Control":
          "no-store",

        "Set-Cookie":
          clearSessionCookie()
      }
    }
  );
}


// ============================================================
// BUILD SESSION
// ============================================================

async function buildSession(
  accountId
) {

  const tokenBytes =
    new Uint8Array(32);

  crypto.getRandomValues(
    tokenBytes
  );

  const token =
    bytesToBase64Url(
      tokenBytes
    );

  const tokenHash =
    await sha256(token);

  const expiresAt =
    new Date(
      Date.now() +
      SESSION_DAYS *
      24 *
      60 *
      60 *
      1000
    ).toISOString();

  const cookie =
    `haleel_session=${token}; ` +
    `HttpOnly; ` +
    `Secure; ` +
    `SameSite=Lax; ` +
    `Path=/; ` +
    `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`;

  return {
    accountId,
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
    "haleel_session=; " +
    "HttpOnly; " +
    "Secure; " +
    "SameSite=Lax; " +
    "Path=/; " +
    "Max-Age=0"
  );
}


// ============================================================
// PASSWORD HASHING
// ============================================================

async function hashPassword(
  password
) {

  const salt =
    new Uint8Array(16);

  crypto.getRandomValues(
    salt
  );

  const encoder =
    new TextEncoder();

  const keyMaterial =
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const derivedBits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations:
          PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      keyMaterial,
      256
    );

  return [
    "pbkdf2",
    PBKDF2_ITERATIONS,
    bytesToBase64Url(salt),
    bytesToBase64Url(
      new Uint8Array(derivedBits)
    )
  ].join("$");
}


// ============================================================
// PASSWORD VERIFICATION
// ============================================================

async function verifyPassword(
  password,
  storedHash
) {

  try {

    if (
      typeof storedHash !== "string"
    ) {
      return false;
    }

    const parts =
      storedHash.split("$");

    if (parts.length !== 4) {
      return false;
    }

    const [
      algorithm,
      iterationsString,
      saltString,
      hashString
    ] = parts;

    if (algorithm !== "pbkdf2") {
      return false;
    }

    const iterations =
      Number(iterationsString);

    if (
      !Number.isInteger(iterations) ||
      iterations < 10000 ||
      iterations > 10000000
    ) {
      return false;
    }

    const salt =
      base64UrlToBytes(
        saltString
      );

    const expectedHash =
      base64UrlToBytes(
        hashString
      );

    if (
      salt.length === 0 ||
      expectedHash.length === 0
    ) {
      return false;
    }

    const encoder =
      new TextEncoder();

    const keyMaterial =
      await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
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
        expectedHash.length * 8
      );

    return timingSafeEqual(
      new Uint8Array(derivedBits),
      expectedHash
    );

  } catch (error) {

    console.error(
      "VERIFY ERROR:",
      error
    );

    return false;
  }
}


// ============================================================
// SHA-256
// ============================================================

async function sha256(
  value
) {

  const data =
    new TextEncoder()
      .encode(value);

  const hash =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );

  return bytesToBase64Url(
    new Uint8Array(hash)
  );
}


// ============================================================
// TIMING-SAFE COMPARISON
// ============================================================

function timingSafeEqual(
  a,
  b
) {

  if (
    a.length !== b.length
  ) {
    return false;
  }

  let difference = 0;

  for (
    let i = 0;
    i < a.length;
    i++
  ) {

    difference |=
      a[i] ^ b[i];
  }

  return difference === 0;
}


// ============================================================
// COOKIE READER
// ============================================================

function getCookie(
  request,
  name
) {

  const cookieHeader =
    request.headers.get("Cookie");

  if (!cookieHeader) {
    return null;
  }

  const cookies =
    cookieHeader.split(";");

  for (
    const cookie of cookies
  ) {

    const trimmed =
      cookie.trim();

    const separator =
      trimmed.indexOf("=");

    if (separator === -1) {
      continue;
    }

    const key =
      trimmed.slice(
        0,
        separator
      );

    const value =
      trimmed.slice(
        separator + 1
      );

    if (key === name) {
      return value || null;
    }
  }

  return null;
}


// ============================================================
// JSON READER
// ============================================================

async function readJSON(
  request
) {

  try {

    return await request.json();

  } catch {

    return null;
  }
}


// ============================================================
// JSON RESPONSE
// ============================================================

function json(
  data,
  status = 200
) {

  return new Response(
    JSON.stringify(data),
    {
      status,

      headers: {
        "Content-Type":
          "application/json; charset=UTF-8",

        "Cache-Control":
          "no-store"
      }
    }
  );
}


// ============================================================
// BYTES → BASE64URL
// ============================================================

function bytesToBase64Url(
  bytes
) {

  let binary = "";

  for (
    const byte of bytes
  ) {

    binary +=
      String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}


// ============================================================
// BASE64URL → BYTES
// ============================================================

function base64UrlToBytes(
  value
) {

  if (
    typeof value !== "string" ||
    value.length === 0
  ) {
    throw new Error(
      "Invalid base64url value."
    );
  }

  const base64 =
    value
      .replace(/-/g, "+")
      .replace(/_/g, "/");

  const padded =
    base64 +
    "=".repeat(
      (4 - (base64.length % 4)) % 4
    );

  const binary =
    atob(padded);

  const bytes =
    new Uint8Array(
      binary.length
    );

  for (
    let i = 0;
    i < binary.length;
    i++
  ) {

    bytes[i] =
      binary.charCodeAt(i);
  }

  return bytes;
}
