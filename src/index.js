const MAX_ACCOUNT_ID = 9999999;
const SESSION_DAYS = 30;

// Password hashing settings
const PBKDF2_ITERATIONS = 10000;
const PASSWORD_HASH_ALGORITHM = "PBKDF2";
const PASSWORD_HASH_LENGTH = 256;

// ============================================================
// MAIN WORKER
// ============================================================

export default {
async fetch(request, env) {
const url = new URL(request.url);

```
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
```

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

if (!body) {
return json(
{
success: false,
message: "Invalid request."
},
400
);
}

// ----------------------------------------------------------
// READ FIELDS
// ----------------------------------------------------------

if (
typeof body.firstName !== "string" ||
typeof body.middleName !== "string" ||
typeof body.lastName !== "string" ||
typeof body.phoneNumber !== "string" ||
typeof body.password !== "string"
) {
return json(
{
success: false,
message:
"First name, middle name, last name, phone number and password are required."
},
400
);
}

const firstName = body.firstName.trim();
const middleName = body.middleName.trim();
const lastName = body.lastName.trim();
const phoneNumber = body.phoneNumber.trim();
const password = body.password;

// ----------------------------------------------------------
// NAME VALIDATION
// ----------------------------------------------------------

if (!firstName || !middleName || !lastName) {
return json(
{
success: false,
message:
"First name, middle name and last name are required."
},
400
);
}

if (firstName.length > 100) {
return json(
{
success: false,
message: "First name is too long."
},
400
);
}

if (middleName.length > 100) {
return json(
{
success: false,
message: "Middle name is too long."
},
400
);
}

if (lastName.length > 100) {
return json(
{
success: false,
message: "Last name is too long."
},
400
);
}

// ----------------------------------------------------------
// PHONE NUMBER VALIDATION
// ----------------------------------------------------------

if (!phoneNumber) {
return json(
{
success: false,
message: "Phone number is required."
},
400
);
}

if (phoneNumber.length > 30) {
return json(
{
success: false,
message: "Phone number is too long."
},
400
);
}

// Allows:
// +252907469995
// 0907469995
// 252907469995
// spaces, -, parentheses and digits

if (!/^[0-9+-\s()]+$/.test(phoneNumber)) {
return json(
{
success: false,
message: "Invalid phone number."
},
400
);
}

// ----------------------------------------------------------
// PASSWORD VALIDATION
// ----------------------------------------------------------

if (password.length < 8) {
return json(
{
success: false,
message:
"Password must contain at least 8 characters."
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

// ----------------------------------------------------------
// CHECK PHONE NUMBER
// ----------------------------------------------------------

let existingPhone;

try {
existingPhone = await env.ACCOUNTS_DB
.prepare(`         SELECT account_id
        FROM users
        WHERE phone_number = ?
        LIMIT 1
      `)
.bind(phoneNumber)
.first();

} catch (error) {
console.error(
"PHONE CHECK ERROR:",
error
);

```
return json(
  {
    success: false,
    message: "Unable to check phone number."
  },
  500
);
```

}

if (existingPhone) {
return json(
{
success: false,
message:
"This phone number is already registered."
},
409
);
}

// ----------------------------------------------------------
// GET NEXT ACCOUNT ID
// ----------------------------------------------------------

let sequence;

try {
sequence = await env.ACCOUNTS_DB
.prepare(`         SELECT next_id
        FROM account_sequence
        WHERE id = 1
        LIMIT 1
      `)
.first();

} catch (error) {
console.error(
"ACCOUNT SEQUENCE READ ERROR:",
error
);

```
return json(
  {
    success: false,
    message:
      "Unable to read account sequence."
  },
  500
);
```

}

if (!sequence) {
return json(
{
success: false,
message:
"Account sequence is not configured."
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
message:
"No more account IDs are available."
},
409
);
}

// ----------------------------------------------------------
// HASH PASSWORD
// ----------------------------------------------------------

let passwordHash;

try {
passwordHash =
await hashPassword(password);

} catch (error) {
console.error(
"PASSWORD HASH ERROR:",
error
);

```
return json(
  {
    success: false,
    message:
      "Unable to secure password."
  },
  500
);
```

}

// ----------------------------------------------------------
// CREATE SESSION
// ----------------------------------------------------------

let session;

try {
session =
await buildSession(accountId);

} catch (error) {
console.error(
"SESSION BUILD ERROR:",
error
);

```
return json(
  {
    success: false,
    message:
      "Unable to create session."
  },
  500
);
```

}

// ----------------------------------------------------------
// SAVE USER + UPDATE SEQUENCE + SESSION
// ----------------------------------------------------------

try {

```
await env.ACCOUNTS_DB.batch([

  // ------------------------------------------------------
  // CREATE USER
  // ------------------------------------------------------

  env.ACCOUNTS_DB
    .prepare(`
      INSERT INTO users (
        account_id,
        password_hash,
        first_name,
        middle_name,
        last_name,
        phone_number
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `)
    .bind(
      accountId,
      passwordHash,
      firstName,
      middleName,
      lastName,
      phoneNumber
    ),

  // ------------------------------------------------------
  // UPDATE ACCOUNT SEQUENCE
  // ------------------------------------------------------

  env.ACCOUNTS_DB
    .prepare(`
      UPDATE account_sequence
      SET next_id = next_id + 1
      WHERE id = 1
        AND next_id = ?
    `)
    .bind(accountId),

  // ------------------------------------------------------
  // CREATE SESSION
  // ------------------------------------------------------

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
```

} catch (error) {

```
console.error(
  "SIGNUP DATABASE ERROR:",
  error
);

return json(
  {
    success: false,
    message:
      "Unable to create account."
  },
  500
);
```

}

// ----------------------------------------------------------
// FORMAT ACCOUNT ID
// ----------------------------------------------------------

const formattedAccountId =
String(accountId).padStart(7, "0");

return new Response(
JSON.stringify({

```
  success: true,

  accountId:
    formattedAccountId,

  firstName:
    firstName,

  middleName:
    middleName,

  lastName:
    lastName,

  phoneNumber:
    phoneNumber,

  message:
    "Account created successfully."

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
```

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
message:
"Accounts database is not connected."
},
500
);
}

const body = await readJSON(request);

if (!body) {
return json(
{
success: false,
message:
"Invalid request."
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

// ----------------------------------------------------------
// ACCOUNT ID VALIDATION
// ----------------------------------------------------------

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

// ----------------------------------------------------------
// FIND ACCOUNT
// ----------------------------------------------------------

let user;

try {

```
user = await env.ACCOUNTS_DB
  .prepare(`
    SELECT
      account_id,
      password_hash,
      first_name,
      middle_name,
      last_name,
      phone_number
    FROM users
    WHERE account_id = ?
    LIMIT 1
  `)
  .bind(numericAccountId)
  .first();
```

} catch (error) {

```
console.error(
  "LOGIN DATABASE ERROR:",
  error
);

return json(
  {
    success: false,
    message:
      "Unable to access account database."
  },
  500
);
```

}

if (!user) {
return invalidLogin();
}

// ----------------------------------------------------------
// VERIFY PASSWORD
// ----------------------------------------------------------

if (
typeof user.password_hash !== "string" ||
!user.password_hash
) {
return invalidLogin();
}

let passwordCorrect;

try {

```
passwordCorrect =
  await verifyPassword(
    password,
    user.password_hash
  );
```

} catch (error) {

```
console.error(
  "PASSWORD VERIFY ERROR:",
  error
);

return invalidLogin();
```

}

if (!passwordCorrect) {
return invalidLogin();
}

// ----------------------------------------------------------
// CREATE LOGIN SESSION
// ----------------------------------------------------------

let session;

try {

```
session =
  await buildSession(
    Number(user.account_id)
  );
```

} catch (error) {

```
console.error(
  "LOGIN SESSION BUILD ERROR:",
  error
);

return json(
  {
    success: false,
    message:
      "Unable to create login session."
  },
  500
);
```

}

// ----------------------------------------------------------
// SAVE LOGIN SESSION
// ----------------------------------------------------------

try {

```
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
```

} catch (error) {

```
console.error(
  "LOGIN SESSION ERROR:",
  error
);

return json(
  {
    success: false,
    message:
      "Unable to create login session."
  },
  500
);
```

}

// ----------------------------------------------------------
// LOGIN SUCCESS
// ----------------------------------------------------------

return new Response(
JSON.stringify({

```
  success: true,

  accountId:
    String(user.account_id)
      .padStart(7, "0"),

  firstName:
    user.first_name || "",

  middleName:
    user.middle_name || "",

  lastName:
    user.last_name || "",

  phoneNumber:
    user.phone_number || "",

  message:
    "Login successful."

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
```

);
}

// ============================================================
// INVALID LOGIN
// ============================================================

function invalidLogin() {

return json(
{
success: false,
message:
"Invalid ID or password."
},
401
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
message:
"Method not allowed."
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

// ----------------------------------------------------------
// GET SESSION COOKIE
// ----------------------------------------------------------

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

// ----------------------------------------------------------
// HASH SESSION TOKEN
// ----------------------------------------------------------

let tokenHash;

try {

```
tokenHash =
  await sha256(token);
```

} catch (error) {

```
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
```

}

// ----------------------------------------------------------
// FIND ACTIVE SESSION
// ----------------------------------------------------------

let session;

try {

```
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
```

} catch (error) {

```
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
```

}

// ----------------------------------------------------------
// SESSION INVALID / EXPIRED
// ----------------------------------------------------------

if (!session) {

```
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
```

}

// ----------------------------------------------------------
// GET USER INFORMATION
// ----------------------------------------------------------

let user;

try {

```
user =
  await env.ACCOUNTS_DB
    .prepare(`
      SELECT
        first_name,
        middle_name,
        last_name,
        phone_number
      FROM users
      WHERE account_id = ?
      LIMIT 1
    `)
    .bind(
      Number(session.account_id)
    )
    .first();
```

} catch (error) {

```
console.error(
  "CURRENT USER DATABASE ERROR:",
  error
);

return json(
  {
    success: false,
    loggedIn: false
  },
  500
);
```

}

if (!user) {

```
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
```

}

// ----------------------------------------------------------
// RETURN CURRENT USER
// ----------------------------------------------------------

return json({

```
success: true,

loggedIn: true,

accountId:
  String(session.account_id)
    .padStart(7, "0"),

firstName:
  user.first_name || "",

middleName:
  user.middle_name || "",

lastName:
  user.last_name || "",

phoneNumber:
  user.phone_number || ""
```

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
message:
"Method not allowed."
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

```
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
```

}

return new Response(
JSON.stringify({

```
  success: true,

  message:
    "Logged out successfully."

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
```

);
}

// ============================================================
// BUILD SESSION
// ============================================================

async function buildSession(accountId) {

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

```
accountId,

token,

tokenHash,

expiresAt,

cookie
```

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
// SHA-256
// ============================================================

async function sha256(value) {

const data =
new TextEncoder().encode(
value
);

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
// PASSWORD HASH
// ============================================================

async function hashPassword(password) {

const salt =
new Uint8Array(16);

crypto.getRandomValues(salt);

const key =
await crypto.subtle.importKey(
"raw",
new TextEncoder().encode(password),
{
name: PASSWORD_HASH_ALGORITHM
},
false,
["deriveBits"]
);

const bits =
await crypto.subtle.deriveBits(
{
name: PASSWORD_HASH_ALGORITHM,
salt: salt,
iterations: PBKDF2_ITERATIONS,
hash: "SHA-256"
},
key,
PASSWORD_HASH_LENGTH
);

const hash =
new Uint8Array(bits);

return (
"pbkdf2$" +
PBKDF2_ITERATIONS +
"$" +
bytesToBase64Url(salt) +
"$" +
bytesToBase64Url(hash)
);
}

// ============================================================
// VERIFY PASSWORD
// ============================================================

async function verifyPassword(
password,
storedHash
) {

const parts =
storedHash.split("$");

if (
parts.length !== 4 ||
parts[0] !== "pbkdf2"
) {
return false;
}

const iterations =
Number(parts[1]);

if (
!Number.isInteger(iterations) ||
iterations < 1
) {
return false;
}

const salt =
base64UrlToBytes(parts[2]);

const expectedHash =
base64UrlToBytes(parts[3]);

const key =
await crypto.subtle.importKey(
"raw",
new TextEncoder().encode(password),
{
name: PASSWORD_HASH_ALGORITHM
},
false,
["deriveBits"]
);

const bits =
await crypto.subtle.deriveBits(
{
name: PASSWORD_HASH_ALGORITHM,
salt: salt,
iterations: iterations,
hash: "SHA-256"
},
key,
expectedHash.length * 8
);

const actualHash =
new Uint8Array(bits);

return timingSafeEqual(
actualHash,
expectedHash
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

```
difference |=
  a[i] ^ b[i];
```

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

```
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
```

}

return null;
}

// ============================================================
// JSON READER
// ============================================================

async function readJSON(request) {

try {

```
return await request.json();
```

} catch {

```
return null;
```

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

```
  headers: {

    "Content-Type":
      "application/json; charset=UTF-8",

    "Cache-Control":
      "no-store"
  }
}
```

);
}

// ============================================================
// BYTES → BASE64URL
// ============================================================

function bytesToBase64Url(bytes) {

let binary = "";

for (const byte of bytes) {

```
binary +=
  String.fromCharCode(byte);
```

}

return btoa(binary)
.replace(/+/g, "-")
.replace(///g, "_")
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

const padding =
"=".repeat(
(4 - (base64.length % 4)) % 4
);

const binary =
atob(
base64 + padding
);

const bytes =
new Uint8Array(
binary.length
);

for (
let i = 0;
i < binary.length;
i++
) {

```
bytes[i] =
  binary.charCodeAt(i);
```

}

return bytes;
}
