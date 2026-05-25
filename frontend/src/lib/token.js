export function decodeJwt(token) {
  if (!token) {
    return null;
  }

  const parts = token.split(".");
  if (parts.length < 2) {
    return null;
  }

  try {
    return {
      header: decodePart(parts[0]),
      payload: decodePart(parts[1])
    };
  } catch {
    return null;
  }
}

export function compactToken(token) {
  if (!token) {
    return "";
  }
  if (token.length <= 28) {
    return token;
  }
  return `${token.slice(0, 14)}...${token.slice(-10)}`;
}

export function formatClaimDate(seconds) {
  if (!seconds) {
    return "-";
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(seconds * 1000));
}

export function tokenRemaining(seconds) {
  if (!seconds) {
    return "-";
  }

  const diffMs = seconds * 1000 - Date.now();
  if (diffMs <= 0) {
    return "Expired";
  }

  const totalMinutes = Math.floor(diffMs / 60000);
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  return `${minutes}m`;
}

function decodePart(part) {
  const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  const json = atob(padded);
  const bytes = Uint8Array.from(json, (char) => char.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}
