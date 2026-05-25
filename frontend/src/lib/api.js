export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "";

export class ApiError extends Error {
  constructor(message, status, payload) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

export async function request(path, options = {}) {
  const { method = "GET", body, token, signal } = options;
  const headers = new Headers({
    Accept: "application/json"
  });

  if (body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal
  });

  const payload = await readPayload(response);
  if (!response.ok) {
    throw new ApiError(errorMessage(payload, response.status), response.status, payload);
  }

  return {
    payload,
    headers: response.headers,
    status: response.status
  };
}

async function readPayload(response) {
  const text = await response.text();
  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function errorMessage(payload, status) {
  if (payload && typeof payload === "object") {
    return payload.message || payload.error || `Request failed (${status})`;
  }
  if (typeof payload === "string" && payload.trim()) {
    return payload;
  }
  return `Request failed (${status})`;
}
