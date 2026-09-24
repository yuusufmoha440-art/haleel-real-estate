const MAX_ACCOUNT_ID = 9999999;
const SESSION_DAYS = 30;

const PBKDF2_ITERATIONS = 10000;
const PASSWORD_HASH_LENGTH = 256;

const MAX_PROFILE_IMAGE_SIZE = 5 * 1024 * 1024;

const ALLOWED_IMAGE_TYPES = {
"image/jpeg": "jpg",
"image/png": "png",
"image/webp": "webp",
"image/gif": "gif"
};

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

  if (url.pathname === "/api/profile-picture") {
    if (request.method === "POST") {
      return await uploadProfilePicture(request, env);
    }

    if (request.method === "GET") {
      return await getProfilePicture(request, env);
    }

    if (request.method === "DELETE") {
      return await deleteProfilePicture(request, env);
    }

    return json(
      {
        success: false,
        message: "Method not allowed."
      },
      405
    );
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

if (!/^[0-9+-\s()]+$/.test(phoneNumber)) {
return json(
{
success: false,
message: "Invalid phone number."
},
400
);
}

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
// CHECK DUPLICATE PHONE NUMBER
// ----------------------------------------------------------

let existingPhone;

try {
existingPhone = await env.ACCOUNTS_DB
.prepare(
"SELECT account_id FROM users WHERE phone_number = ? LIMIT 1"
)
.bind(phoneNumber)
.first();

} catch (error) {
console.error("PHONE CHECK ERROR:", error);

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
.prepare(
"SELECT next_id FROM account_sequence WHERE id = 1 LIMIT 1"
)
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
    message: "Unable to read account sequence."
  },
  500
);
```

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

// ----------------------------------------------------------
// HASH PASSWORD
// ----------------------------------------------------------

let passwordHash;

try {
passwordHash = await hashPassword(password);

} catch (error) {
console.error(
"PASSWORD HASH ERROR:",
error
);

```
return json(
  {
    success: false,
    message: "Unable to secure password."
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
session = await buildSession(accountId);

} catch (error) {
console.error(
"SESSION BUILD ERROR:",
error
);

```
return json(
  {
    success: false,
    message: "Unable to create session."
  },
  500
);
```

}

// ----------------------------------------------------------
// SAVE USER
//
// users schema:
// id
// account_id
// created_at
// first_name
// middle_name
// last_name
// password_hash
// phone_number
// profile_picture
// ----------------------------------------------------------

try {
await env.ACCOUNTS_DB
.prepare(
"INSERT INTO users (account_id, first_name, middle_name, last_name, password_hash, phone_number, profile_picture) VALUES (?, ?, ?, ?, ?, ?, ?)"
)
.bind(
accountId,
firstName,
middleName,
lastName,
passwordHash,
phoneNumber,
null
)
.run();

```
await env.ACCOUNTS_DB
  .prepare(
    "UPDATE account_sequence SET next_id = next_id + 1 WHERE id = 1 AND next_id = ?"
  )
  .bind(accountId)
  .run();

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
```

} catch (error) {
console.error(
"SIGNUP DATABASE ERROR:",
error
);

```
return json(
  {
    success: false,
    message: "Unable to create account."
  },
  500
);
```

}

const formattedAccountId =
String(accountId).padStart(7, "0");

return new Response(
JSON.stringify({
success: true,
accountId: formattedAccountId,
firstName,
middleName,
lastName,
phoneNumber,
profilePicture: null,
message: "Account created successfully."
}),
{
status: 201,

```
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

// ----------------------------------------------------------
// FIND USER
// ----------------------------------------------------------

let user;

try {
user = await env.ACCOUNTS_DB
.prepare(
"SELECT account_id, password_hash, first_name, middle_name, last_name, phone_number, profile_picture FROM users WHERE account_id = ? LIMIT 1"
)
.bind(numericAccountId)
.first();

} catch (error) {
console.error(
"LOGIN DATABASE ERROR:",
error
);

```
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
passwordCorrect =
await verifyPassword(
password,
user.password_hash
);

} catch (error) {
console.error(
"PASSWORD VERIFY ERROR:",
error
);

```
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
session =
await buildSession(
Number(user.account_id)
);

} catch (error) {
console.error(
"LOGIN SESSION BUILD ERROR:",
error
);

```
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
await env.ACCOUNTS_DB
.prepare(
"INSERT INTO sessions (account_id, token_hash, expires_at) VALUES (?, ?, ?)"
)
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

```
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

return new Response(
JSON.stringify({
success: true,

```
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

  profilePicture:
    user.profile_picture || null,

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
message: "Invalid ID or password."
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
tokenHash =
await sha256(token);

} catch (error) {
console.error(
"TOKEN HASH ERROR:",
error
);

```
return json(
  {
    success: false,
    loggedIn: false
  },
  500
);
```

}

let session;

try {
session =
await env.ACCOUNTS_DB
.prepare(
"SELECT account_id, expires_at FROM sessions WHERE token_hash = ? AND expires_at > ? LIMIT 1"
)
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

```
return json(
  {
    success: false,
    loggedIn: false
  },
  500
);
```

}

if (!session) {
return new Response(
JSON.stringify({
success: false,
loggedIn: false
}),
{
status: 401,

```
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
// GET USER
// ----------------------------------------------------------

let user;

try {
user =
await env.ACCOUNTS_DB
.prepare(
"SELECT first_name, middle_name, last_name, phone_number, profile_picture FROM users WHERE account_id = ? LIMIT 1"
)
.bind(
Number(session.account_id)
)
.first();

} catch (error) {
console.error(
"CURRENT USER DATABASE ERROR:",
error
);

```
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
return new Response(
JSON.stringify({
success: false,
loggedIn: false
}),
{
status: 401,

```
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

return json({
success: true,
loggedIn: true,

```
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
  user.phone_number || "",

profilePicture:
  user.profile_picture || null
```

});
}

// ============================================================
// UPLOAD PROFILE PICTURE
// ============================================================

async function uploadProfilePicture(request, env) {
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

if (!env.PROFILE_BUCKET) {
return json(
{
success: false,
message:
"Profile image storage is not connected."
},
500
);
}

const auth =
await authenticateUser(
request,
env
);

if (!auth.success) {
return json(
{
success: false,
message: "You must be logged in."
},
401
);
}

const contentType =
request.headers.get("Content-Type") || "";

if (
!contentType
.toLowerCase()
.startsWith("multipart/form-data")
) {
return json(
{
success: false,
message:
"Please upload an image file."
},
400
);
}

let formData;

try {
formData =
await request.formData();

} catch (error) {
console.error(
"PROFILE FORM ERROR:",
error
);

```
return json(
  {
    success: false,
    message:
      "Unable to read uploaded image."
  },
  400
);
```

}

const file =
formData.get("profilePicture") ||
formData.get("profile_picture") ||
formData.get("file");

if (!(file instanceof File)) {
return json(
{
success: false,
message:
"Profile picture file is required."
},
400
);
}

if (file.size <= 0) {
return json(
{
success: false,
message:
"The image file is empty."
},
400
);
}

if (file.size > MAX_PROFILE_IMAGE_SIZE) {
return json(
{
success: false,
message:
"Profile picture must be 5 MB or smaller."
},
413
);
}

const extension =
ALLOWED_IMAGE_TYPES[file.type];

if (!extension) {
return json(
{
success: false,
message:
"Only JPG, PNG, WEBP and GIF images are allowed."
},
415
);
}

// ----------------------------------------------------------
// READ OLD R2 KEY
// ----------------------------------------------------------

let oldProfilePicture = null;

try {
const oldUser =
await env.ACCOUNTS_DB
.prepare(
"SELECT profile_picture FROM users WHERE account_id = ? LIMIT 1"
)
.bind(auth.accountId)
.first();

```
if (
  oldUser &&
  oldUser.profile_picture
) {
  oldProfilePicture =
    String(
      oldUser.profile_picture
    );
}
```

} catch (error) {
console.error(
"OLD PROFILE PICTURE READ ERROR:",
error
);
}

// ----------------------------------------------------------
// CREATE UNIQUE R2 OBJECT KEY
// ----------------------------------------------------------

const objectKey =
"profile-pictures/" +
String(auth.accountId) +
"/" +
crypto.randomUUID() +
"." +
extension;

// ----------------------------------------------------------
// UPLOAD TO R2
// ----------------------------------------------------------

try {
await env.PROFILE_BUCKET.put(
objectKey,
file.stream(),
{
httpMetadata: {
contentType: file.type,
cacheControl:
"private, max-age=3600"
},

```
    customMetadata: {
      accountId:
        String(auth.accountId)
    }
  }
);
```

} catch (error) {
console.error(
"R2 PROFILE UPLOAD ERROR:",
error
);

```
return json(
  {
    success: false,
    message:
      "Unable to save profile picture."
  },
  500
);
```

}

// ----------------------------------------------------------
// SAVE R2 KEY INTO D1
// ----------------------------------------------------------

try {
await env.ACCOUNTS_DB
.prepare(
"UPDATE users SET profile_picture = ? WHERE account_id = ?"
)
.bind(
objectKey,
auth.accountId
)
.run();

} catch (error) {
console.error(
"PROFILE DATABASE UPDATE ERROR:",
error
);

```
// Roll back the new R2 object.
try {
  await env.PROFILE_BUCKET.delete(
    objectKey
  );
} catch (deleteError) {
  console.error(
    "R2 ROLLBACK ERROR:",
    deleteError
  );
}

return json(
  {
    success: false,
    message:
      "Unable to save profile picture information."
  },
  500
);
```

}

// ----------------------------------------------------------
// DELETE OLD R2 OBJECT
// ----------------------------------------------------------

if (
oldProfilePicture &&
oldProfilePicture !== objectKey
) {
try {
await env.PROFILE_BUCKET.delete(
oldProfilePicture
);

```
} catch (error) {
  console.error(
    "OLD R2 PROFILE DELETE ERROR:",
    error
  );
}
```

}

return json({
success: true,

```
profilePicture:
  objectKey,

message:
  "Profile picture updated successfully."
```

});
}

// ============================================================
// GET PROFILE PICTURE
// ============================================================

async function getProfilePicture(request, env) {
if (request.method !== "GET") {
return json(
{
success: false,
message: "Method not allowed."
},
405
);
}

if (
!env.ACCOUNTS_DB ||
!env.PROFILE_BUCKET
) {
return json(
{
success: false,
message:
"Profile picture service is not connected."
},
500
);
}

const auth =
await authenticateUser(
request,
env
);

if (!auth.success) {
return json(
{
success: false,
message: "You must be logged in."
},
401
);
}

let user;

try {
user =
await env.ACCOUNTS_DB
.prepare(
"SELECT profile_picture FROM users WHERE account_id = ? LIMIT 1"
)
.bind(auth.accountId)
.first();

} catch (error) {
console.error(
"PROFILE PICTURE DATABASE ERROR:",
error
);

```
return json(
  {
    success: false,
    message:
      "Unable to access profile picture."
  },
  500
);
```

}

if (
!user ||
!user.profile_picture
) {
return json(
{
success: false,
message:
"No profile picture has been uploaded."
},
404
);
}

let object;

try {
object =
await env.PROFILE_BUCKET.get(
String(
user.profile_picture
)
);

} catch (error) {
console.error(
"R2 PROFILE GET ERROR:",
error
);

```
return json(
  {
    success: false,
    message:
      "Unable to load profile picture."
  },
  500
);
```

}

if (!object) {
return json(
{
success: false,
message:
"Profile picture was not found."
},
404
);
}

const headers =
new Headers();

object.writeHttpMetadata(
headers
);

headers.set(
"ETag",
object.httpEtag
);

headers.set(
"Cache-Control",
"private, max-age=3600"
);

return new Response(
object.body,
{
status: 200,
headers
}
);
}

// ============================================================
// DELETE PROFILE PICTURE
// ============================================================

async function deleteProfilePicture(request, env) {
if (request.method !== "DELETE") {
return json(
{
success: false,
message: "Method not allowed."
},
405
);
}

if (
!env.ACCOUNTS_DB ||
!env.PROFILE_BUCKET
) {
return json(
{
success: false,
message:
"Profile picture service is not connected."
},
500
);
}

const auth =
await authenticateUser(
request,
env
);

if (!auth.success) {
return json(
{
success: false,
message: "You must be logged in."
},
401
);
}

let user;

try {
user =
await env.ACCOUNTS_DB
.prepare(
"SELECT profile_picture FROM users WHERE account_id = ? LIMIT 1"
)
.bind(auth.accountId)
.first();

} catch (error) {
console.error(
"PROFILE DELETE LOOKUP ERROR:",
error
);

```
return json(
  {
    success: false,
    message:
      "Unable to access profile picture."
  },
  500
);
```

}

const objectKey =
user &&
user.profile_picture
? String(
user.profile_picture
)
: null;

if (objectKey) {
try {
await env.PROFILE_BUCKET.delete(
objectKey
);

```
} catch (error) {
  console.error(
    "R2 PROFILE DELETE ERROR:",
    error
  );
}
```

}

try {
await env.ACCOUNTS_DB
.prepare(
"UPDATE users SET profile_picture = NULL WHERE account_id = ?"
)
.bind(auth.accountId)
.run();

} catch (error) {
console.error(
"PROFILE COLUMN CLEAR ERROR:",
error
);

```
return json(
  {
    success: false,
    message:
      "Unable to remove profile picture."
  },
  500
);
```

}

return json({
success: true,
profilePicture: null,
message:
"Profile picture deleted successfully."
});
}

// ============================================================
// AUTHENTICATE USER
// ============================================================

async function authenticateUser(
request,
env
) {
if (!env.ACCOUNTS_DB) {
return {
success: false
};
}

const token =
getCookie(
request,
"haleel_session"
);

if (!token) {
return {
success: false
};
}

let tokenHash;

try {
tokenHash =
await sha256(token);

} catch {
return {
success: false
};
}

let session;

try {
session =
await env.ACCOUNTS_DB
.prepare(
"SELECT account_id, expires_at FROM sessions WHERE token_hash = ? AND expires_at > ? LIMIT 1"
)
.bind(
tokenHash,
new Date().toISOString()
)
.first();

} catch (error) {
console.error(
"AUTH SESSION ERROR:",
error
);

```
return {
  success: false
};
```

}

if (!session) {
return {
success: false
};
}

return {
success: true,
accountId:
Number(session.account_id)
};
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

const token =
getCookie(
request,
"haleel_session"
);

if (
token &&
env.ACCOUNTS_DB
) {
try {
const tokenHash =
await sha256(token);

```
  await env.ACCOUNTS_DB
    .prepare(
      "DELETE FROM sessions WHERE token_hash = ?"
    )
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
success: true,
message:
"Logged out successfully."
}),
{
status: 200,

```
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
"haleel_session=" +
token +
"; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=" +
(
SESSION_DAYS *
24 *
60 *
60
);

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

async function hashPassword(
password
) {
const salt =
new Uint8Array(16);

crypto.getRandomValues(
salt
);

const key =
await crypto.subtle.importKey(
"raw",
new TextEncoder().encode(
password
),
{
name: "PBKDF2"
},
false,
["deriveBits"]
);

const bits =
await crypto.subtle.deriveBits(
{
name: "PBKDF2",

```
    salt,

    iterations:
      PBKDF2_ITERATIONS,

    hash: "SHA-256"
  },

  key,

  PASSWORD_HASH_LENGTH
);
```

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

let salt;
let expectedHash;

try {
salt =
base64UrlToBytes(
parts[2]
);

```
expectedHash =
  base64UrlToBytes(
    parts[3]
  );
```

} catch {
return false;
}

if (
salt.length === 0 ||
expectedHash.length === 0
) {
return false;
}

const key =
await crypto.subtle.importKey(
"raw",
new TextEncoder().encode(
password
),
{
name: "PBKDF2"
},
false,
["deriveBits"]
);

const bits =
await crypto.subtle.deriveBits(
{
name: "PBKDF2",

```
    salt,

    iterations,

    hash: "SHA-256"
  },

  key,

  expectedHash.length * 8
);
```

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

function timingSafeEqual(
a,
b
) {
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
const trimmed =
cookie.trim();

```
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

function bytesToBase64Url(
bytes
) {
let binary = "";

for (const byte of bytes) {
binary +=
String.fromCharCode(byte);
}

return btoa(binary)
.replace(/+/g, "-")
.replace(///g, "_")
.replace(/=+$/g, "");
}

// ============================================================
// BASE64URL → BYTES
// ============================================================

function base64UrlToBytes(
value
) {
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
bytes[i] =
binary.charCodeAt(i);
}

return bytes;
}
