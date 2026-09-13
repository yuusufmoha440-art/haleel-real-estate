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
      console.error("Worker error:", error);

      return json({
        success: false,
        message: "Server error."
      }, 500);
    }
  }
};
