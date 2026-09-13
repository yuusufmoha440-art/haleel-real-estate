async function signup(request, env) {
  if (request.method !== "POST") {
    return json({
      success: false,
      message: "Method not allowed."
    }, 405);
  }

  const body = await readJSON(request);

  if (!body || typeof body.password !== "string") {
    return json({
      success: false,
      message: "Password is required."
    }, 400);
  }

  const password = body.password;

  if (password.length < 8) {
    return json({
      success: false,
      message: "Password must contain at least 8 characters."
    }, 400);
  }

  if (password.length > 128) {
    return json({
      success: false,
      message: "Password is too long."
    }, 400);
  }

  const passwordHash = await hashPassword(password);

  /*
   * Create the account and advance the sequence
   * in one atomic D1 batch.
   *
   * account IDs:
   * 0000001
   * 0000002
   * 0000003
   * ...
   * 9999999
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

  /*
   * The INSERT must create exactly one row.
   */
  if (
    !insertResult ||
    insertResult.meta?.changes !== 1
  ) {
    return json({
      success: false,
      message: "Unable to create account."
    }, 500);
  }

  /*
   * The sequence must also advance exactly once.
   */
  if (
    !sequenceResult ||
    sequenceResult.meta?.changes !== 1
  ) {
    return json({
      success: false,
      message: "Unable to allocate account ID."
    }, 500);
  }

  /*
   * Because users.id is set to next_id,
   * last_row_id is the newly created account ID.
   */
  const accountId = Number(
    insertResult.meta?.last_row_id
  );

  if (
    !Number.isInteger(accountId) ||
    accountId < 1 ||
    accountId > MAX_ACCOUNT_ID
  ) {
    return json({
      success: false,
      message: "Invalid account ID."
    }, 500);
  }

  /*
   * Automatically log the new account in.
   */
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
