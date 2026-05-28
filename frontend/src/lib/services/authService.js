import { DEFAULT_ALGORITHM } from "../config.js";
import { request } from "../api.js";
import { decodeJwt } from "../token.js";

export async function register(authForm) {
  return request("/api/auth/register", {
    method: "POST",
    body: {
      name: authForm.name.trim(),
      email: authForm.email.trim(),
      password: authForm.password
    }
  });
}

export async function signIn(authForm) {
  const { payload } = await request("/api/auth/signin", {
    method: "POST",
    body: {
      email: authForm.email.trim(),
      password: authForm.password,
      algorithm: DEFAULT_ALGORITHM
    }
  });
  return payload?.data || {};
}

export async function refresh(session) {
  const decodedRefresh = decodeJwt(session.refresh_token);
  const decodedAccess = decodeJwt(session.access_token);
  const userId = decodedRefresh?.payload?.user_id || decodedAccess?.payload?.user_id || "";

  const { payload } = await request("/api/auth/refresh", {
    method: "POST",
    body: {
      user_id: userId,
      refresh_token: session.refresh_token
    }
  });
  return payload?.data || {};
}

export async function getProfile(client) {
  const { payload } = await client("/api/profile");
  return payload?.data || null;
}
