import { STORAGE_KEY } from "../config.js";
import { decodeJwt } from "../token.js";

const REFRESH_SKEW_SECONDS = 0;
const ACCESS_REFRESH_SKEW_SECONDS = 30;

export function emptySession() {
  return {
    token_type: "Bearer",
    access_token: "",
    refresh_token: "",
    saved_at: ""
  };
}

export function normalizeSession(session) {
  return { ...emptySession(), ...(session || {}) };
}

export function readStoredSession() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored ? normalizeSession(JSON.parse(stored)) : emptySession();
  } catch {
    return emptySession();
  }
}

export function persistSession(session) {
  const normalized = normalizeSession(session);
  if (normalized.access_token && normalized.refresh_token) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(normalized));
  } else {
    localStorage.removeItem(STORAGE_KEY);
  }
  return normalized;
}

export function canUseSession(session) {
  const normalized = normalizeSession(session);
  return Boolean(
    tokenPayload(normalized.access_token) &&
      tokenPayload(normalized.refresh_token) &&
      !isTokenExpired(normalized.refresh_token, REFRESH_SKEW_SECONDS)
  );
}

export function shouldRefreshAccessToken(session) {
  return isTokenExpired(normalizeSession(session).access_token, ACCESS_REFRESH_SKEW_SECONDS);
}

function tokenPayload(token) {
  return decodeJwt(token)?.payload || null;
}

function isTokenExpired(token, skewSeconds) {
  const payload = tokenPayload(token);
  const expiresAt = Number(payload?.exp || 0);
  if (!expiresAt) {
    return true;
  }
  return expiresAt <= Math.floor(Date.now() / 1000) + skewSeconds;
}
