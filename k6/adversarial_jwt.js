/**
 * adversarial_jwt.js
 *
 * k6 adversarial JWT security test — 10 Attack Vectors
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
 *   #7  Replay Attack             — reuse same valid token (stateless JWT)
 *   #8  Missing Sig Verification  — send token with empty signature
 *   #9  Cross-Algorithm Injection — RS256 header against Falcon verifier
 *   #10 Invalid Issuer Attack     — change iss to unknown value
 *
 * Usage:
 *   # Single gateway:
 *   k6 run -e BASE_URL=http://localhost:5001 k6/adversarial_jwt.js
 *
 *   # Custom iterations per attack:
 *   k6 run -e BASE_URL=http://localhost:5001 -e ITERATIONS=20 k6/adversarial_jwt.js
 *
 *   # Multi-gateway (docker-compose.benchmark.yml):
 *   k6 run -e BENCH_HOST=localhost k6/adversarial_jwt.js
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

function normalizeBase(url) {
  if (!url) return "";
  if (url.startsWith("http://") || url.startsWith("https://")) return url;
  return "http://" + url;
}

const _HOST = __ENV.BENCH_HOST;
const _BASE_URL = __ENV.BASE_URL;
const HOST_BASE = normalizeBase(_HOST);
const BASE_URL = _HOST
  ? `${HOST_BASE}:5001`
  : _BASE_URL
  ? normalizeBase(_BASE_URL)
  : "http://localhost:5001";

const ITERATIONS = parseInt(__ENV.ITERATIONS || "10", 10);
const ALGORITHM = __ENV.ALGORITHM || "Falcon-Precomputed-512";

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
const blockRateReplay = new Rate("attack_block_rate_7_replay");
const blockRateMissingSig = new Rate("attack_block_rate_8_missing_signature");
const blockRateCrossAlg = new Rate("attack_block_rate_9_cross_algorithm_injection");
const blockRateInvalidIssuer = new Rate("attack_block_rate_10_invalid_issuer");

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
    // All attack vectors except replay must be blocked 100%
    attack_block_rate: ["rate>0.85"],
    attack_block_rate_1_signature_tampering: ["rate>0.99"],
    attack_block_rate_2_token_forgery: ["rate>0.99"],
    attack_block_rate_3_algorithm_confusion: ["rate>0.99"],
    attack_block_rate_4_none_algorithm: ["rate>0.99"],
    attack_block_rate_5_payload_manipulation: ["rate>0.99"],
    attack_block_rate_6_expired_token: ["rate>0.99"],
    // #7 replay: stateless JWT → expected rate=0 (not a threshold failure)
    attack_block_rate_8_missing_signature: ["rate>0.99"],
    attack_block_rate_9_cross_algorithm_injection: ["rate>0.99"],
    attack_block_rate_10_invalid_issuer: ["rate>0.99"],
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
    exec.test.abort(
      `Registration failed (${regRes.status}): ${regRes.body.slice(0, 200)}`,
    );
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
  return blocked;
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

    let allBlocked = true;
    for (const [label, forged] of cases) {
      const blocked = recordAttack(label, hitProtected(forged), blockRateTokenForgery, tags);
      if (!blocked) allBlocked = false;
    }
  });

  // ── #3 Algorithm Confusion (HS256 / RS256 / ES256) ─────────
  group("3_algorithm_confusion", () => {
    for (const alg of ["HS256", "RS256", "ES256"]) {
      const tags = { attack: "3_algorithm_confusion", alg };
      const forged = withHeader(token, { alg });
      recordAttack(`#3 Algorithm Confusion (${alg})`, hitProtected(forged), blockRateAlgConfusion, tags);
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
    recordAttack("#5 Payload Manipulation (email=admin)", hitProtected(forged), blockRatePayloadManip, tags);
  });

  // ── #6 Expired Token Abuse ──────────────────────────────────
  // Cannot create validly-signed expired token from k6 (no private key).
  // We modify exp to past — server rejects via signature mismatch AND/OR exp check.
  group("6_expired_token", () => {
    const tags = { attack: "6_expired_token" };
    const pastExp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
    const forged = withPayload(token, { exp: pastExp });
    recordAttack("#6 Expired Token Abuse (exp in past)", hitProtected(forged), blockRateExpiredToken, tags);
  });

  // ── #7 Replay Attack ────────────────────────────────────────
  // Stateless JWT: same token is accepted multiple times (by design).
  // Mitigation requires JTI blacklist at the application layer.
  // Expected result: both requests succeed (block rate ≈ 0).
  group("7_replay_attack", () => {
    const tags = { attack: "7_replay_attack" };

    const res1 = hitProtected(token);
    const res2 = hitProtected(token); // replay

    check(res1, { "[#7 Replay] first request accepted (200)": (r) => r.status === 200 });
    check(res2, { "[#7 Replay] replay also accepted — stateless JWT (200)": (r) => r.status === 200 });

    const replayBlocked = isBlocked(res2);
    blockRateReplay.add(replayBlocked, tags);
    if (!replayBlocked) {
      console.log("[#7 Replay] Replay accepted — app layer JTI blacklist required for mitigation");
    }
  });

  // ── #8 Missing Signature Verification ──────────────────────
  group("8_missing_signature", () => {
    const tags = { attack: "8_missing_signature" };
    const parts = token.split(".");
    const emptyToken = parts[0] + "." + parts[1] + ".";
    recordAttack("#8 Missing Signature (empty)", hitProtected(emptyToken), blockRateMissingSig, tags);
  });

  // ── #9 Cross-Algorithm Injection (PQC vs Classic) ──────────
  group("9_cross_algorithm_injection", () => {
    for (const alg of ["RS256", "HS256", "ES256"]) {
      const tags = { attack: "9_cross_algorithm_injection", alg };
      // Classic alg header but Falcon signature → should be rejected
      const forged = withHeader(token, { alg });
      recordAttack(`#9 Cross-Algorithm Injection (${alg}→Falcon)`, hitProtected(forged), blockRateCrossAlg, tags);
    }
  });

  // ── #10 Invalid Issuer Attack ───────────────────────────────
  group("10_invalid_issuer", () => {
    for (const iss of ["example.com", "evil-service", "attacker.io", ""]) {
      const tags = { attack: "10_invalid_issuer", iss };
      const forged = withPayload(token, { iss });
      recordAttack(`#10 Invalid Issuer (iss=${iss || "empty"})`, hitProtected(forged), blockRateInvalidIssuer, tags);
    }
  });

  sleep(0.1);
}

// ═══════════════════════════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════════════════════════

export function handleSummary(data) {
  const m = data.metrics;

  function rate(metricName) {
    const v = m[metricName];
    if (!v) return "N/A";
    const r = v.values.rate;
    return r === undefined ? "N/A" : (r * 100).toFixed(1) + "%";
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

  const attacks = [
    ["#1  Signature Tampering",        "attack_block_rate_1_signature_tampering",   "401/403",          true],
    ["#2  Token Forgery",              "attack_block_rate_2_token_forgery",          "401/403",          true],
    ["#3  Algorithm Confusion",        "attack_block_rate_3_algorithm_confusion",    "401/403",          true],
    ["#4  None Algorithm Attack",      "attack_block_rate_4_none_algorithm",         "401/403",          true],
    ["#5  Payload Manipulation",       "attack_block_rate_5_payload_manipulation",   "401/403",          true],
    ["#6  Expired Token Abuse",        "attack_block_rate_6_expired_token",          "401/403",          true],
    ["#7  Replay Attack",              "attack_block_rate_7_replay",                 "Detect (app layer)", false],
    ["#8  Missing Sig Verification",   "attack_block_rate_8_missing_signature",      "401/403",          true],
    ["#9  Cross-Algorithm Injection",  "attack_block_rate_9_cross_algorithm_injection", "401/403",       true],
    ["#10 Invalid Issuer Attack",      "attack_block_rate_10_invalid_issuer",        "401/403",          true],
  ];

  let rows = "";
  let totalProtected = 0;
  let totalVulnerable = 0;

  for (const [name, metric, expected, requiresBlock] of attacks) {
    const r = rate(metric);
    const rVal = r === "N/A" ? 0 : parseFloat(r);
    let status;
    if (!requiresBlock) {
      status = "NOTE: stateless JWT — mitigation at app layer";
    } else if (r === "N/A") {
      status = "N/A";
    } else if (rVal >= 99.0) {
      status = "PROTECTED";
      totalProtected++;
    } else {
      status = "VULNERABLE";
      totalVulnerable++;
    }
    rows += `  ${pad(name, 32)} ${pad(r, 12)} ${pad(expected, 24)} ${status}\n`;
  }

  const { blocked, allowed, total } = counts("attack_blocked", "attack_allowed");
  const overall = total > 0 ? ((blocked / total) * 100).toFixed(1) + "%" : "N/A";

  const table = `
${SEP}
  ADVERSARIAL JWT TEST — 10 ATTACK VECTORS
  Algorithm : ${ALGORITHM}
  Endpoint  : ${BASE_URL}
  Iterations: ${ITERATIONS}
${SEP}
  ${"Attack".padEnd(32)} ${"Block Rate".padEnd(12)} ${"Expected".padEnd(24)} Status
  ${LINE}
${rows}  ${LINE}
  Overall block rate (excl. replay): ${overall}  (${blocked} blocked / ${total} total)
${SEP}
  PROTECTED  : ${totalProtected} / 9 attack vectors
  VULNERABLE : ${totalVulnerable} / 9 attack vectors
  REPLAY     : stateless JWT — both requests accepted (expected)
               Mitigation: track JTI in Redis/DB, reject duplicate JTI
${SEP}
  NOTES:
  #3 / #9  Algorithm confusion and cross-injection share same mechanism.
  #6       Expired token blocked via signature mismatch (payload modified w/o key).
  #7       Replay: add JTI claim blacklist at application layer for full protection.
${SEP}
`;

  return { stdout: table };
}
