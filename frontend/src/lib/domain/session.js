import { STORAGE_KEY } from "../config.js";

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
