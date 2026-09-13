const MAX_ACCOUNT_ID = 9999999;
const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 200000;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      // ================================
      // API ROUTES
      // ================================

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

      // ================================
      // WEBSITE FILES
      // ================================

      return env.ASSETS.fetch(request);

    } catch (error) {
      console.error("Worker error:", error);

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

  // Hash password before storing it.
  const passwordHash = await hashPassword(password);

  /*
   * IMPORTANT:
   *
   * account_sequence.next_id is used as the account number.
   *
   * 1       -> 0000001
   * 2       -> 0000002
   * 3       -> 0000003
   *
   * ...
   *
   * 9999999 -> 9999999
   *
   * The INSERT and UPDATE are executed together
   * in one D1 batch.
   */

  const result = await env.ACCOUNTS_DB.batch([
    env.ACCOUNTS_DB
      .prepare(`
        INSERT INTO users
        (
          id,
          account_id,
          password_hash
        )
        SELECT
          next_id,
          next_id,
          ?
        FROM account_sequence
        WHERE id = 1
          AND next_id <= ?
      `)
      .bind(
        passwordHash,
        MAX_ACCOUNT_ID
      ),

    env.ACCOUNTS_DB
      .prepare(`
        UPDATE account_sequence
        SET next_id = next_id + 1
        WHERE id = 1
          AND next_id <= ?
      `)
      .bind(MAX_ACCOUNT_ID)
  ]);

  const insertResult = result[0];
  const sequenceResult = result[1];

  // Make sure exactly one user was created.
  if (
    !insertResult ||
    insertResult.meta?.changes !== 1
  ) {
    return json(
      {
        success: false,
        message: "Unable to create account."
      },
      500
    );
  }

  // Make sure the sequence advanced exactly once.
  if (
    !sequenceResult ||
    sequenceResult.meta?.changes !== 1
  ) {
    return json(
      {
        success: false,
        message: "Unable to allocate account ID."
      },
      500
    );
  }

  /*
   * users.id is intentionally set to next_id.
   *
   * Therefore last_row_id is the newly created
   * account number.
   */

  const accountId = Number(
    insertResult.meta?.last_row_id
  );

  if (
    !Number.isInteger(accountId) ||
    accountId < 1 ||
    accountId > MAX_ACCOUNT_ID
  ) {
    return json(
      {
        success: false,
        message: "Invalid account ID."
      },
      500
    );
  }

  // Automatically create a login session.
  const session = await createSession(
    accountId,
    env
  );

  return new Response(
    JSON.stringify({
      success: true,
      accountId: String(accountId).padStart(7, "0"),
      message: "Account created successfully."
    }),
    {
      status: 201,
      headers: {
        "Content-Type": "application/json; charset=UTF-8",
        "Cache-Control": "no-store",
        "Set-Cookie": session.cookie
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

  const accountId = String(
    body.accountId || ""
  ).trim();

  const password = String(
    body.password || ""
  );

  /*
   * Account ID must be exactly 7 digits.
   */

  if (!/^\d{7}$/.test(accountId)) {
    return json(
      {
        success: false,
        message: "Invalid ID or password."
      },
      401
    );
  }

  if (!password) {
    return json(
      {
        success: false,
        message: "Invalid ID or password."
      },
      401
    );
  }

  const user = await env.ACCOUNTS_DB
    .prepare(`
      SELECT
        account_id,
        password_hash
      FROM users
      WHERE account_id = ?
      LIMIT 1
    `)
    .bind(Number(accountId))
    .first();

  if (!user) {
    return json(
      {
        success: false,
        message: "Invalid ID or password."
      },
      401
    );
  }

  const validPassword = await verifyPassword(
    password,
    user.password_hash
  );

  if (!validPassword) {
    return json(
      {
        success: false,
        message: "Invalid ID or password."
      },
      401
    );
  }

  // Create a new session after successful login.
  const session = await createSession(
    Number(user.account_id),
    env
  );

  return new Response(
    JSON.stringify({
      success: true,
      accountId: String(
        user.account_id
      ).padStart(7, "0"),
      message: "Login successful."
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=UTF-8",
        "Cache-Control": "no-store",
        "Set-Cookie": session.cookie
      }
    }
  );
}


// ============================================================
// CURRENT USER
// ============================================================

async function getCurrentUser(request, env) {
  if (request.method !== "GET") {
    return json(
      {
        success: false,
        message: "Method not allowed."
      },
      405
    );
  }

  const token = getCookie(
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

  const tokenHash = await sha256(token);

  const session = await env.ACCOUNTS_DB
    .prepare(`
      SELECT
        account_id,
        expires_at
      FROM sessions
      WHERE token_hash = ?
        AND expires_at > datetime('now')
      LIMIT 1
    `)
    .bind(tokenHash)
    .first();

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
          "Cache-Control": "no-store",
          "Set-Cookie":
            "haleel_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
        }
      }
    );
  }

  return json({
    success: true,
    loggedIn: true,
    accountId: String(
      session.account_id
    ).padStart(7, "0")
  });
}


// ============================================================
// LOGOUT
// ============================================================

async function logout(request, env) {
  if (request.method !== "POST") {
    return json(
      {
        success: false,
        message: "Method not allowed."
      },
      405
    );
  }

  const token = getCookie(
    request,
    "haleel_session"
  );

  if (token) {
    const tokenHash = await sha256(token);

    await env.ACCOUNTS_DB
      .prepare(`
        DELETE FROM sessions
        WHERE token_hash = ?
      `)
      .bind(tokenHash)
      .run();
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
        "Cache-Control": "no-store",
        "Set-Cookie":
          "haleel_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
      }
    }
  );
}


// ============================================================
// CREATE SESSION
// ============================================================

async function createSession(accountId, env) {
  /*
   * Generate a cryptographically secure
   * 256-bit random session token.
   */

  const tokenBytes = new Uint8Array(32);

  crypto.getRandomValues(
    tokenBytes
  );

  const token = bytesToBase64Url(
    tokenBytes
  );

  /*
   * Only the hash is stored in D1.
   * The original token exists only inside
   * the user's HttpOnly cookie.
   */

  const tokenHash = await sha256(token);

  const expiresAt = new Date(
    Date.now() +
      SESSION_DAYS *
      24 *
      60 *
      60 *
      1000
  ).toISOString();

  await env.ACCOUNTS_DB
    .prepare(`
      INSERT INTO sessions
      (
        account_id,
        token_hash,
        expires_at
      )
      VALUES (?, ?, ?)
    `)
    .bind(
      accountId,
      tokenHash,
      expiresAt
    )
    .run();

  const cookie =
    `haleel_session=${token}; ` +
    `HttpOnly; ` +
    `Secure; ` +
    `SameSite=Lax; ` +
    `Path=/; ` +
    `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`;

  return {
    token,
    cookie
  };
}


// ============================================================
// PASSWORD HASHING
// ============================================================

async function hashPassword(password) {
  const salt = new Uint8Array(16);

  crypto.getRandomValues(
    salt
  );

  const encoder = new TextEncoder();

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
        iterations: PBKDF2_ITERATIONS,
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
      iterations < 10000
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

  } catch {
    return false;
  }
}


// ============================================================
// SHA-256
// ============================================================

async function sha256(value) {
  const data =
    new TextEncoder().encode(value);

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

function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
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

  for (const cookie of cookies) {
    const [
      key,
      ...valueParts
    ] = cookie
      .trim()
      .split("=");

    if (key === name) {
      return (
        valueParts.join("=") ||
        null
      );
    }
  }

  return null;
}


// ============================================================
// JSON READER
// ============================================================

async function readJSON(request) {
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

function bytesToBase64Url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(
      byte
    );
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}


// ============================================================
// BASE64URL → BYTES
// ============================================================

function base64UrlToBytes(value) {
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
