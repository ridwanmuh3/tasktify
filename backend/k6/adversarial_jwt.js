/**
 * adversarial_jwt.js
 *
 * k6 adversarial JWT security test — 8 black-box attack vectors
 *
 * Tests that the gateway correctly blocks all JWT attack scenarios.
 * Each attack manipulates a valid token and asserts 401/403 response.
 *
 * Attack map:
 *   #1  Signature Tampering       — flip byte in signature
 *   #2  Token Forgery             — empty / fake / random signature
 *   #3  Algorithm Confusion       — swap alg to HS256 / RS256 / ES256
 *   #4  None Algorithm Attack     — alg=none (with and without signature)
 *   #5  Payload Manipulation      — change email claim without re-signing
 *   #6  Expired Token Abuse       — set exp to past (payload mod, sig fails)
 *   #7  Unsigned Compact Token    — send compact JWS with empty signature
 *   #8  Cross-Algorithm Injection — classic header against Falcon verifier
 *
 * Usage:
 *   k6 run k6/adversarial_jwt.js
 *   k6 run -e ITERATIONS=20 k6/adversarial_jwt.js
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Counter, Rate } from "k6/metrics";
import exec from "k6/execution";
import encoding from "k6/encoding";
import { randomString } from "./k6-utils.js";

// ═══════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════

const BASE_URL = "http://localhost:3000";
const ITERATIONS = parseInt(__ENV.ITERATIONS || "10", 10);
const ALGORITHM = "Falcon-Precomputed-512";
const SUMMARY_DIR = (__ENV.BENCH_OUTPUT_DIR || "").replace(/\/+$/, "");

function summaryFile(name) {
  return SUMMARY_DIR ? `${SUMMARY_DIR}/${name}` : name;
}

// ═══════════════════════════════════════════════════════════════
// JWT Manipulation Helpers
// k6 encoding: b64decode(str, 'rawurl', 's') → string
//              b64encode(str, 'rawurl')       → base64url string (no padding)
// ═══════════════════════════════════════════════════════════════

function jwtDecodeSegment(seg) {
  return JSON.parse(encoding.b64decode(seg, "rawurl", "s"));
}

function jwtEncodeSegment(obj) {
  return encoding.b64encode(JSON.stringify(obj), "rawurl");
}

function withHeader(token, changes) {
  const parts = token.split(".");
  const hdr = jwtDecodeSegment(parts[0]);
  Object.assign(hdr, changes);
  parts[0] = jwtEncodeSegment(hdr);
  return parts.join(".");
}

function withPayload(token, changes) {
  const parts = token.split(".");
  const payload = jwtDecodeSegment(parts[1]);
  Object.assign(payload, changes);
  parts[1] = jwtEncodeSegment(payload);
  return parts.join(".");
}

// Character-level flip in the base64url-encoded signature string.
// Avoids re-encoding to preserve exact byte-length mismatch behavior.
function flipSigChar(token) {
  const parts = token.split(".");
  const sig = parts[2];
  if (sig.length === 0) return parts[0] + "." + parts[1] + ".AAAA";
  const idx = Math.floor(sig.length / 2);
  const ch = sig[idx];
  // substitute: 'A'→'B', anything else→'A'
  parts[2] = sig.slice(0, idx) + (ch === "A" ? "B" : "A") + sig.slice(idx + 1);
  return parts.join(".");
}

// ═══════════════════════════════════════════════════════════════
// Custom Metrics
// ═══════════════════════════════════════════════════════════════

const attackBlocked = new Counter("attack_blocked");
const attackAllowed = new Counter("attack_allowed");
const attackBlockRate = new Rate("attack_block_rate");

// Per-attack block rates (for thresholds and summary)
const blockRateSigTamper = new Rate("attack_block_rate_1_signature_tampering");
const blockRateTokenForgery = new Rate("attack_block_rate_2_token_forgery");
const blockRateAlgConfusion = new Rate("attack_block_rate_3_algorithm_confusion");
const blockRateNoneAlg = new Rate("attack_block_rate_4_none_algorithm");
const blockRatePayloadManip = new Rate("attack_block_rate_5_payload_manipulation");
const blockRateExpiredToken = new Rate("attack_block_rate_6_expired_token");
const blockRateUnsignedCompact = new Rate("attack_block_rate_7_unsigned_compact_token");
const blockRateCrossAlg = new Rate("attack_block_rate_8_cross_algorithm_injection");

// ═══════════════════════════════════════════════════════════════
// Scenarios & Thresholds
// ═══════════════════════════════════════════════════════════════

export const options = {
  scenarios: {
    adversarial_jwt: {
      executor: "shared-iterations",
      vus: 1,
      iterations: ITERATIONS,
      maxDuration: "300s",
      gracefulStop: "10s",
    },
  },
  thresholds: {
    // All attack vectors must be blocked 100%.
    attack_block_rate: ["rate>0.99"],
    attack_block_rate_1_signature_tampering: ["rate>0.99"],
    attack_block_rate_2_token_forgery: ["rate>0.99"],
    attack_block_rate_3_algorithm_confusion: ["rate>0.99"],
    attack_block_rate_4_none_algorithm: ["rate>0.99"],
    attack_block_rate_5_payload_manipulation: ["rate>0.99"],
    attack_block_rate_6_expired_token: ["rate>0.99"],
    attack_block_rate_7_unsigned_compact_token: ["rate>0.99"],
    attack_block_rate_8_cross_algorithm_injection: ["rate>0.99"],
  },
  setupTimeout: "120s",
};

// ═══════════════════════════════════════════════════════════════
// Setup
// ═══════════════════════════════════════════════════════════════

export function setup() {
  const suffix = randomString(8).toLowerCase();
  const user = {
    name: `attack-${suffix}`,
    email: `attack-${suffix}@attack.test`,
    password: "AttackTest!123",
  };

  const registerUrl = `${BASE_URL}/api/auth/register`;
  console.log(`[setup] Registering attack user at: ${registerUrl}`);

  let regRes;
  for (let attempt = 1; attempt <= 30; attempt++) {
    regRes = http.post(registerUrl, JSON.stringify(user), {
      headers: { "Content-Type": "application/json" },
      timeout: "10s",
    });
    if (regRes.status !== 0) break;
    console.log(`[setup] [${attempt}/30] Service not ready, retrying in 2s...`);
    sleep(2);
  }

  if (regRes.status === 0) {
    exec.test.abort(`Service ${registerUrl} unreachable after retries`);
  }
  if (regRes.status !== 201) {
    exec.test.abort(`Registration failed (${regRes.status}): ${regRes.body.slice(0, 200)}`);
  }

  console.log(`[setup] Attack user registered: ${user.email}`);
  return { user };
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

function getValidToken(data) {
  const res = http.post(
    `${BASE_URL}/api/benchmark/token`,
    JSON.stringify({ email: data.user.email, algorithm: ALGORITHM }),
    { headers: { "Content-Type": "application/json" }, timeout: "10s" },
  );
  if (res.status !== 200) {
    console.error(`[getValidToken] failed: status=${res.status}`);
    return "";
  }
  try {
    return JSON.parse(res.body).data?.access_token || "";
  } catch {
    return "";
  }
}

function hitProtected(token) {
  return http.get(`${BASE_URL}/api/profile`, {
    headers: { Authorization: `Bearer ${token}` },
    timeout: "5s",
  });
}

// Returns true when server blocks the request (401 or 403)
function isBlocked(res) {
  return res.status === 401 || res.status === 403;
}

function recordAttack(label, res, perAttackMetric, tags) {
  const blocked = isBlocked(res);
  check(res, { [`[${label}] blocked (401/403)`]: () => blocked });
  perAttackMetric.add(blocked, tags);
  attackBlockRate.add(blocked, tags);
  blocked ? attackBlocked.add(1, tags) : attackAllowed.add(1, tags);
}

// ═══════════════════════════════════════════════════════════════
// Main VU function
// ═══════════════════════════════════════════════════════════════

export default function (data) {
  const token = getValidToken(data);
  if (!token) {
    console.error("Cannot get valid token — skipping iteration");
    return;
  }

  // Sanity: confirm valid token passes authentication
  const validRes = hitProtected(token);
  check(validRes, { "[sanity] valid token accepted (200)": (r) => r.status === 200 });
  if (validRes.status !== 200) {
    console.error(`[sanity] valid token rejected (${validRes.status}) — check gateway`);
  }

  // ── #1 Signature Tampering ──────────────────────────────────
  group("1_signature_tampering", () => {
    const tags = { attack: "1_signature_tampering" };
    const tampered = flipSigChar(token);
    recordAttack("#1 Signature Tampering", hitProtected(tampered), blockRateSigTamper, tags);
  });

  // ── #2 Token Forgery (empty / fake / random signature) ─────
  group("2_token_forgery", () => {
    const tags = { attack: "2_token_forgery" };
    const parts = token.split(".");
    const hdrPayload = parts[0] + "." + parts[1];

    const cases = [
      ["#2a Token Forgery (empty sig)", hdrPayload + "."],
      ["#2b Token Forgery (fake short sig)", hdrPayload + ".fakesig123"],
      ["#2c Token Forgery (random garbage)", hdrPayload + ".AAAAAAAAAAAAAAAAAAAAAA"],
    ];

    for (const [label, forged] of cases) {
      recordAttack(label, hitProtected(forged), blockRateTokenForgery, tags);
    }
  });

  // ── #3 Algorithm Confusion (HS256 / RS256 / ES256) ─────────
  group("3_algorithm_confusion", () => {
    for (const alg of ["HS256", "RS256", "ES256"]) {
      const tags = { attack: "3_algorithm_confusion", alg };
      const forged = withHeader(token, { alg });
      recordAttack(
        `#3 Algorithm Confusion (${alg})`,
        hitProtected(forged),
        blockRateAlgConfusion,
        tags,
      );
    }
  });

  // ── #4 None Algorithm Attack ────────────────────────────────
  group("4_none_algorithm", () => {
    const tags = { attack: "4_none_algorithm" };

    // 4a: alg=none, signature stripped
    const noneStripped = withHeader(token, { alg: "none" }).split(".");
    noneStripped[2] = "";
    recordAttack(
      "#4a None Algorithm (no sig)",
      hitProtected(noneStripped.join(".")),
      blockRateNoneAlg,
      { ...tags, variant: "no_sig" },
    );

    // 4b: alg=none, original signature kept
    recordAttack(
      "#4b None Algorithm (with original sig)",
      hitProtected(withHeader(token, { alg: "none" })),
      blockRateNoneAlg,
      { ...tags, variant: "with_sig" },
    );
  });

  // ── #5 Payload / Claim Manipulation ────────────────────────
  group("5_payload_manipulation", () => {
    const tags = { attack: "5_payload_manipulation" };
    // Modify email to "admin" without re-signing
    const forged = withPayload(token, { email: "admin@admin.com" });
    recordAttack(
      "#5 Payload Manipulation (email=admin)",
      hitProtected(forged),
      blockRatePayloadManip,
      tags,
    );
  });

  // ── #6 Expired Token Abuse ──────────────────────────────────
  // Cannot create validly-signed expired token from k6 (no private key).
  // We modify exp to past — server rejects via signature mismatch AND/OR exp check.
  group("6_expired_token", () => {
    const tags = { attack: "6_expired_token" };
    const pastExp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
    const forged = withPayload(token, { exp: pastExp });
    recordAttack(
      "#6 Expired Token Abuse (exp in past)",
      hitProtected(forged),
      blockRateExpiredToken,
      tags,
    );
  });

  // ── #7 Unsigned compact token / empty signature ─────────────
  group("7_unsigned_compact_token", () => {
    const tags = { attack: "7_unsigned_compact_token" };
    const parts = token.split(".");
    const emptyToken = parts[0] + "." + parts[1] + ".";
    recordAttack(
      "#7 Unsigned Compact Token (empty signature)",
      hitProtected(emptyToken),
      blockRateUnsignedCompact,
      tags,
    );
  });

  // ── #8 Cross-Algorithm Injection (PQC vs Classic) ──────────
  group("8_cross_algorithm_injection", () => {
    for (const alg of ["RS256", "HS256", "ES256"]) {
      const tags = { attack: "8_cross_algorithm_injection", alg };
      // Classic alg header but Falcon signature → should be rejected
      const forged = withHeader(token, { alg });
      recordAttack(
        `#8 Cross-Algorithm Injection (${alg}→Falcon)`,
        hitProtected(forged),
        blockRateCrossAlg,
        tags,
      );
    }
  });

  sleep(0.1);
}

// ═══════════════════════════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════════════════════════

export function handleSummary(data) {
  const m = data.metrics;
  const attacks = [
    {
      id: 1,
      name: "Signature Tampering",
      metric: "attack_block_rate_1_signature_tampering",
      expected: "401/403",
    },
    {
      id: 2,
      name: "Token Forgery",
      metric: "attack_block_rate_2_token_forgery",
      expected: "401/403",
    },
    {
      id: 3,
      name: "Algorithm Confusion",
      metric: "attack_block_rate_3_algorithm_confusion",
      expected: "401/403",
    },
    {
      id: 4,
      name: "None Algorithm Attack",
      metric: "attack_block_rate_4_none_algorithm",
      expected: "401/403",
    },
    {
      id: 5,
      name: "Payload Manipulation",
      metric: "attack_block_rate_5_payload_manipulation",
      expected: "401/403",
    },
    {
      id: 6,
      name: "Expired Token Abuse",
      metric: "attack_block_rate_6_expired_token",
      expected: "401/403",
    },
    {
      id: 7,
      name: "Unsigned Compact Token",
      metric: "attack_block_rate_7_unsigned_compact_token",
      expected: "401/403",
    },
    {
      id: 8,
      name: "Cross-Algorithm Injection",
      metric: "attack_block_rate_8_cross_algorithm_injection",
      expected: "401/403",
    },
  ];

  function rate(metricName) {
    const v = m[metricName];
    if (!v) return "N/A";
    const r = v.values.rate;
    return r === undefined ? "N/A" : (r * 100).toFixed(1) + "%";
  }

  function rateNumber(metricName) {
    const v = m[metricName];
    if (!v || v.values.rate === undefined) return null;
    return Number((v.values.rate * 100).toFixed(2));
  }

  function counts(blockedMetric, allowedMetric) {
    const b = (m[blockedMetric] && m[blockedMetric].values.count) || 0;
    const a = (m[allowedMetric] && m[allowedMetric].values.count) || 0;
    return { blocked: b, allowed: a, total: b + a };
  }

  const SEP = "═".repeat(82);
  const LINE = "─".repeat(82);

  function pad(s, w) {
    const str = String(s);
    return str.length >= w ? str.slice(0, w - 1) + " " : str + " ".repeat(w - str.length);
  }

  let rows = "";
  let totalProtected = 0;
  let totalVulnerable = 0;
  const attackResults = [];

  for (const attack of attacks) {
    const label = `#${attack.id} ${attack.name}`;
    const r = rate(attack.metric);
    const rVal = r === "N/A" ? 0 : parseFloat(r);
    let status;
    if (r === "N/A") {
      status = "N/A";
    } else if (rVal >= 99.0) {
      status = "PROTECTED";
      totalProtected++;
    } else {
      status = "VULNERABLE";
      totalVulnerable++;
    }
    rows += `  ${pad(label, 32)} ${pad(r, 12)} ${pad(attack.expected, 24)} ${status}\n`;
    attackResults.push({
      id: attack.id,
      name: attack.name,
      metric: attack.metric,
      expected: attack.expected,
      block_rate_pct: rateNumber(attack.metric),
      status,
    });
  }

  const { blocked, allowed, total } = counts("attack_blocked", "attack_allowed");
  const overall = total > 0 ? ((blocked / total) * 100).toFixed(1) + "%" : "N/A";
  const overallRate = total > 0 ? Number(((blocked / total) * 100).toFixed(2)) : null;
  const result = {
    meta: {
      script: "k6/adversarial_jwt.js",
      algorithm: ALGORITHM,
      endpoint: BASE_URL,
      iterations: ITERATIONS,
    },
    summary: {
      protected: totalProtected,
      vulnerable: totalVulnerable,
      total_attack_vectors: attacks.length,
      blocked_requests: blocked,
      allowed_requests: allowed,
      total_requests: total,
      overall_block_rate_pct: overallRate,
    },
    attacks: attackResults,
  };

  const table = `
${SEP}
  ADVERSARIAL JWT TEST — ${attacks.length} ATTACK VECTORS
  Algorithm : ${ALGORITHM}
  Endpoint  : ${BASE_URL}
  Iterations: ${ITERATIONS}
${SEP}
  ${"Attack".padEnd(32)} ${"Block Rate".padEnd(12)} ${"Expected".padEnd(24)} Status
  ${LINE}
${rows}  ${LINE}
  Overall block rate: ${overall}  (${blocked} blocked / ${total} total)
${SEP}
  PROTECTED  : ${totalProtected} / ${attacks.length} attack vectors
  VULNERABLE : ${totalVulnerable} / ${attacks.length} attack vectors
${SEP}
  NOTES:
  #3 / #8  Algorithm confusion and cross-injection share same mechanism.
  #6       Expired token blocked via signature mismatch (payload modified w/o key).
${SEP}
`;

  return {
    stdout: table,
    [summaryFile("adversarial_result.json")]: JSON.stringify(result, null, 2),
    [summaryFile("adversarial_raw.json")]: JSON.stringify(data, null, 2),
  };
}
