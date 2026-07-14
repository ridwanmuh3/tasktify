/**
 * adversarial_jwt.js
 *
 * k6 adversarial JWT security test — 9 black-box attack vectors
 *
 * Tests that the gateway correctly blocks all JWT attack scenarios.
 * Each attack manipulates a valid token and asserts 401/403 response.
 *
 * Every vector is grounded in RFC 7519 (JWT) and/or RFC 8725 (JWT Best
 * Current Practices) — no attack here is invented ad hoc. See the
 * `reference` field on each entry in ATTACKS below and
 * docs/skenario-pengujian.md section 6.5 for the full citation table.
 *
 * Attack map:
 *   #1  Signature Tampering       — flip byte in signature
 *       RFC 8725 §3.3 Validate All Cryptographic Operations
 *   #2  Token Forgery             — empty / fake / random signature
 *       RFC 8725 §3.1 Perform Algorithm Verification, §3.3
 *   #3  Algorithm Confusion       — swap alg to HS256 / RS256 / ES256
 *       RFC 8725 §3.1 (explicitly names RS256→HS256 confusion)
 *   #4  None Algorithm Attack     — alg=none (with and without signature)
 *       RFC 7519 §6 Unsecured JWTs; RFC 8725 §3.1, §3.2
 *   #5  Payload Manipulation      — change email claim without re-signing
 *       RFC 8725 §3.3 Validate All Cryptographic Operations
 *   #6  Expired Token Abuse       — set exp to past (payload mod, sig fails)
 *       RFC 7519 §4.1.4 "exp" Claim
 *   #7  Unsigned Compact Token    — send compact JWS with empty signature
 *       RFC 7519 §6 Unsecured JWTs; RFC 8725 §3.1, §3.3
 *   #8  Cross-Algorithm Injection — classic header against PQC verifier
 *       RFC 8725 §3.1 Perform Algorithm Verification
 *   #9  RS256/HS256 Key Confusion — genuine HMAC-SHA256 forged with the
 *       RS256 public key bytes as secret (textbook JWT key-confusion attack,
 *       attacker only needs the public key). Only meaningful against a
 *       gateway whose allowlist accepts both RS256 and HS256 at once — the
 *       default single-gateway deployment (JWT_ALLOWED_ALGS unset) does;
 *       per-algorithm benchmark gateways (JWT_ALLOWED_ALGS=<one alg>) block
 *       it via the allowlist alone before key resolution is even reached.
 *       RFC 8725 §3.1, verbatim example: "attackers can change 'RS256' to
 *       'HS256' and use the RSA public key as an HMAC secret"
 *
 * Usage:
 *   k6 run k6/adversarial_jwt.js
 *   k6 run -e ITERATIONS=20 k6/adversarial_jwt.js
 *
 *   # Target one algorithm's isolated benchmark gateway (multi-gateway mode):
 *   k6 run -e BENCH_HOST=localhost -e ALGORITHM=RS256 k6/adversarial_jwt.js
 *
 *   # Target a specific single gateway URL:
 *   k6 run -e BASE_URL=https://host -e ALGORITHM=ES256 k6/adversarial_jwt.js
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Counter, Rate } from "k6/metrics";
import exec from "k6/execution";
import encoding from "k6/encoding";
import crypto from "k6/crypto";
import { randomString } from "./k6-utils.js";

// ═══════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════

const ITERATIONS = parseInt(__ENV.ITERATIONS || "10", 10);
const ALGORITHM = __ENV.ALGORITHM || "FN-DSA-Precomputed-512";
const SUMMARY_DIR = (__ENV.BENCH_OUTPUT_DIR || "").replace(/\/+$/, "");
// Output basenames are overridable so a per-algorithm sweep (make
// attack-adversarial-compare) writes one file per profile instead of
// clobbering a single adversarial_result.json.
const OUTPUT_NAME = __ENV.ADVERSARIAL_OUTPUT || "adversarial_result.json";
const RAW_OUTPUT_NAME = __ENV.ADVERSARIAL_RAW_OUTPUT || "adversarial_raw.json";

// Per-algorithm benchmark gateway ports (multi-gateway mode, see
// docker-compose.benchmark.yml / k6/benchmark_sign.js ALGORITHMS).
const ALG_PORTS = {
  "FN-DSA-Precomputed-512": 5001,
  "FN-DSA-512": 5002,
  HS256: 5003,
  RS256: 5004,
  ES256: 5005,
  EdDSA: 5006,
};

function normalizeBase(url) {
  if (!url) return "";
  if (url.startsWith("http://") || url.startsWith("https://")) return url;
  return "http://" + url;
}

const BENCH_HOST = normalizeBase(__ENV.BENCH_HOST);
const BASE_URL = __ENV.BASE_URL
  ? normalizeBase(__ENV.BASE_URL)
  : BENCH_HOST
    ? `${BENCH_HOST}:${ALG_PORTS[ALGORITHM] || 3000}`
    : "http://localhost:3000";

function summaryFile(name) {
  return SUMMARY_DIR ? `${SUMMARY_DIR}/${name}` : name;
}

// RS256 public key bytes for the #9 key-confusion attack. Loaded at init
// time (k6 requires open() at module scope); missing file (keys not
// generated yet) degrades to skipping #9 rather than aborting the script.
let RS256_PUBLIC_KEY_PEM = "";
try {
  RS256_PUBLIC_KEY_PEM = open("../keys/RS256_pk.pem");
} catch (e) {
  console.warn(`[init] RS256_pk.pem not found, attack #9 will be skipped: ${e}`);
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
const blockRateKeyConfusion = new Rate("attack_block_rate_9_rs256_hs256_key_confusion");

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
    attack_block_rate_9_rs256_hs256_key_confusion: ["rate>0.99"],
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
      // Classic alg header but FN-DSA signature → should be rejected
      const forged = withHeader(token, { alg });
      recordAttack(
        `#8 Cross-Algorithm Injection (${alg}→FN-DSA)`,
        hitProtected(forged),
        blockRateCrossAlg,
        tags,
      );
    }
  });

  // ── #9 RS256/HS256 Key Confusion ────────────────────────────
  // Textbook attack: attacker knows only the RS256 *public* key (not
  // secret) and uses it as the HMAC secret to forge an alg=HS256 token.
  // A vulnerable verifier that reuses the same key object for both RSA
  // verification and HMAC verification would accept this. This gateway
  // resolves the verify key per registered algorithm (see
  // multiAlgJwtUtil.configForHeaderAlg in pkg/utils/jwtutils/jwt.go), so
  // alg=HS256 is checked against the real HS256 secret, not the RS256
  // public key — the forged HMAC will not match either way.
  if (RS256_PUBLIC_KEY_PEM) {
    group("9_rs256_hs256_key_confusion", () => {
      const tags = { attack: "9_rs256_hs256_key_confusion" };
      const parts = token.split(".");
      const hdr = jwtDecodeSegment(parts[0]);
      hdr.alg = "HS256";
      const forgedHeader = jwtEncodeSegment(hdr);
      const signingInput = forgedHeader + "." + parts[1];
      const forgedSig = crypto.hmac("sha256", RS256_PUBLIC_KEY_PEM, signingInput, "base64rawurl");
      const forged = signingInput + "." + forgedSig;
      recordAttack(
        "#9 RS256/HS256 Key Confusion (forged HMAC via RS256 pubkey)",
        hitProtected(forged),
        blockRateKeyConfusion,
        tags,
      );
    });
  }

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
      reference: "RFC 8725 §3.3 Validate All Cryptographic Operations",
    },
    {
      id: 2,
      name: "Token Forgery",
      metric: "attack_block_rate_2_token_forgery",
      expected: "401/403",
      reference: "RFC 8725 §3.1 Perform Algorithm Verification; §3.3",
    },
    {
      id: 3,
      name: "Algorithm Confusion",
      metric: "attack_block_rate_3_algorithm_confusion",
      expected: "401/403",
      reference: "RFC 8725 §3.1 Perform Algorithm Verification",
    },
    {
      id: 4,
      name: "None Algorithm Attack",
      metric: "attack_block_rate_4_none_algorithm",
      expected: "401/403",
      reference: "RFC 7519 §6 Unsecured JWTs; RFC 8725 §3.1, §3.2",
    },
    {
      id: 5,
      name: "Payload Manipulation",
      metric: "attack_block_rate_5_payload_manipulation",
      expected: "401/403",
      reference: "RFC 8725 §3.3 Validate All Cryptographic Operations",
    },
    {
      id: 6,
      name: "Expired Token Abuse",
      metric: "attack_block_rate_6_expired_token",
      expected: "401/403",
      reference: 'RFC 7519 §4.1.4 "exp" (Expiration Time) Claim',
    },
    {
      id: 7,
      name: "Unsigned Compact Token",
      metric: "attack_block_rate_7_unsigned_compact_token",
      expected: "401/403",
      reference: "RFC 7519 §6 Unsecured JWTs; RFC 8725 §3.1, §3.3",
    },
    {
      id: 8,
      name: "Cross-Algorithm Injection",
      metric: "attack_block_rate_8_cross_algorithm_injection",
      expected: "401/403",
      reference: "RFC 8725 §3.1 Perform Algorithm Verification",
    },
    {
      id: 9,
      name: "RS256/HS256 Key Confusion",
      metric: "attack_block_rate_9_rs256_hs256_key_confusion",
      expected: "401/403",
      reference:
        'RFC 8725 §3.1 — verbatim: "attackers can change \'RS256\' to \'HS256\' and use the RSA public key as an HMAC secret"',
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
    rows += `    ${attack.reference}\n`;
    attackResults.push({
      id: attack.id,
      name: attack.name,
      metric: attack.metric,
      expected: attack.expected,
      reference: attack.reference,
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
      rfc_references: [
        "RFC 7519 — JSON Web Token (JWT), https://www.rfc-editor.org/rfc/rfc7519",
        "RFC 8725 — JSON Web Token Best Current Practices, https://www.rfc-editor.org/rfc/rfc8725",
      ],
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
  #9       Meaningful only against a gateway whose allowlist accepts both
           RS256 and HS256 (default single-gateway deployment). Skipped if
           RS256_pk.pem is not present at k6/../keys/RS256_pk.pem.
${SEP}
`;

  return {
    stdout: table,
    [summaryFile(OUTPUT_NAME)]: JSON.stringify(result, null, 2),
    [summaryFile(RAW_OUTPUT_NAME)]: JSON.stringify(data, null, 2),
  };
}
