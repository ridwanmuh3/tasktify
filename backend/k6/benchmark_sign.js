/**
 * benchmark_sign.js
 *
 * JWT generation latency study:
 *
 *   Phase 1 — ISOLATED (1 VU, server-side loop)
 *     POST /api/benchmark/jwt-issuance with N iterations.
 *     POST /api/benchmark/pure-signing with N iterations.
 *     Uses gateway-local JWT generation path, no DB/bcrypt/auth-service noise.
 *     Pure signing excludes JWT serialization, Base64URL, and compact assembly.
 *     Warmup iterations are discarded before measurement.
 *     Use these numbers in academic papers.
 *
 *   Phase 2 — STRESS TEST (10 / 30 / 50 VUs, constant-vus)
 *     Each VU hits /api/benchmark/token directly.
 *     Each VU also signs in and calls /api/auth/refresh to measure refresh latency.
 *     Shows how latency and throughput degrade under concurrent load.
 *     Thresholds fail the run if p95 or error rate exceeds per-algorithm budget.
 *
 * Usage:
 *   # docker-compose.benchmark.yml — ONE auth+gateway pair serves every
 *   # algorithm via JWT_ALLOWED_ALGS (see compose file). All ALGORITHMS entries
 *   # share port 5001, so BENCH_HOST=localhost and BASE_URL=http://localhost:5001
 *   # both resolve to the same gateway; BASE_URL is the simplest.
 *   k6 run --out json=benchmark_sign_samples.ndjson -e BASE_URL=http://localhost:5001 k6/benchmark_sign.js
 *
 *   # production / VPS:
 *   k6 run -e BASE_URL=https://poc-ridwanmuh3.my.id k6/benchmark_sign.js
 *
 *   # Tune iterations (default 100, min 100 for academic use):
 *   k6 run -e BASE_URL=... -e ITERATIONS=500 k6/benchmark_sign.js
 *
 *   # Skip isolated phase (stress only):
 *   k6 run -e BASE_URL=... -e STRESS_ONLY=true k6/benchmark_sign.js
 *
 *   # Skip stress phase (isolated only):
 *   k6 run -e BASE_URL=... -e ISOLATED_ONLY=true k6/benchmark_sign.js
 *
 *   # Attack block-rate only:
 *   k6 run -e BASE_URL=... -e ATTACK_ONLY=true -e ATTACK_ITERATIONS=50 k6/benchmark_sign.js
 *
 * Latency taxonomy:
 *   token_generation_clean = X-Token-Generation-Time-Ms / X-Sign-Time-Ms header
 *                            JWT generation from benchmark payload only; no DB/bcrypt/auth-service latency
 *   refresh_generation     = X-Refresh-Token-Generation-Time-Ms from /api/auth/refresh
 *   clean                  = k6 timings.waiting — TTFB/server processing approx
 *   dirty                  = k6 timings.duration — full client round-trip
 *   network                = dirty − clean
 *
 * Primary metrics:
 *   pure signing latency, JWT generation latency, p95 JWT generation latency,
 *   benchmark-token throughput, memory usage, CPU utilization, CPU time
 *
 * Secondary metrics:
 *   end-to-end response time, request per second, token/header/body size,
 *   attack block rate
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Trend, Counter, Rate } from "k6/metrics";
import exec from "k6/execution";
import { randomString } from "./k6-utils.js";

// ═══════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════

const _HOST = __ENV.BENCH_HOST;
const _BASE_URL = __ENV.BASE_URL;
const SUMMARY_DIR = (__ENV.BENCH_OUTPUT_DIR || "").replace(/\/+$/, "");

function normalizeBase(url) {
  if (!url) return "";
  if (url.startsWith("http://") || url.startsWith("https://")) return url;
  return "http://" + url;
}

function summaryFile(name) {
  return SUMMARY_DIR ? `${SUMMARY_DIR}/${name}` : name;
}

const HOST_BASE = normalizeBase(_HOST);
const SINGLE_BASE = _BASE_URL ? normalizeBase(_BASE_URL) : "http://localhost";
const isMultiGateway = !!_HOST;

// Iterations for isolated phase (server-side loop). Min 100 for academic use.
const ITERATIONS = parseInt(__ENV.ITERATIONS || "100", 10);
const ISOLATED_WARMUP = parseInt(__ENV.ISOLATED_WARMUP || "20", 10);
const STRESS_WARMUP = (__ENV.STRESS_WARMUP || "true") === "true";

// Phase enable flags
const STRESS_ONLY = __ENV.STRESS_ONLY === "true";
const ISOLATED_ONLY = __ENV.ISOLATED_ONLY === "true";
const ATTACK_ONLY = __ENV.ATTACK_ONLY === "true";

// Concurrent VU levels for stress phase
const CONCURRENCY_LEVELS = [10, 30, 50];

// Stress scenario duration (seconds per VU level per algorithm)
const STRESS_DURATION_S = 30;
const STRESS_GAP_S = 20; // settle gap between stress scenarios
const STRESS_THINK_TIME_S = 0.05;
const STRESS_WARMUP_REQUESTS = 3;
const ISOLATED_GAP_S = 5; // gap between isolated scenarios
const PHASE_GAP_S = 30; // settle gap between Phase 1 and Phase 2
const ATTACK_ITERATIONS = parseInt(__ENV.ATTACK_ITERATIONS || "25", 10);
const ATTACK_GAP_S = 5;
const JWT_ISSUANCE_ENDPOINT = "/api/benchmark/jwt-issuance";
const PURE_SIGNING_ENDPOINT = "/api/benchmark/pure-signing";
const RUN_ISOLATED = !STRESS_ONLY && !ATTACK_ONLY;
const RUN_STRESS = !ISOLATED_ONLY && !ATTACK_ONLY;
const RUN_ATTACKS = ((!ISOLATED_ONLY && !STRESS_ONLY) || ATTACK_ONLY) && ATTACK_ITERATIONS > 0;

// PQC (FN-DSA) benchmarked against classical baselines (HS256/RS256/ES256/EdDSA).
// All algorithms are served by ONE gateway container (JWT_ALLOWED_ALGS lists
// every one — see docker-compose.benchmark.yml), so noisy-neighbor CPU
// contention between per-algorithm containers is gone (docs/p0-penjelasan.md
// P0-7). The per-request "algorithm" field selects the signer, so every entry
// carries the same gateway port 5001 — both BENCH_HOST and BASE_URL modes then
// resolve to that one gateway.
const ALGORITHMS = [
  { id: "FNP512", name: "FN-DSA-Precomputed-512", category: "PQC", port: 5001 },
  { id: "FN512", name: "FN-DSA-512", category: "PQC", port: 5001 },
  { id: "HS256", name: "HS256", category: "Classical", port: 5001 },
  { id: "RS256", name: "RS256", category: "Classical", port: 5001 },
  { id: "ES256", name: "ES256", category: "Classical", port: 5001 },
  { id: "EdDSA", name: "EdDSA", category: "Classical", port: 5001 },
];

// Per-algorithm p95 latency budget for stress test thresholds (ms).
// Dirty = full k6 round-trip budget; Actual = server-side JWT generation budget.
const STRESS_BUDGET = {
  "FN-DSA-Precomputed-512": { dirty: 5000, actual: 500 },
  "FN-DSA-512": { dirty: 10000, actual: 1000 },
  HS256: { dirty: 3000, actual: 100 },
  RS256: { dirty: 3000, actual: 200 },
  ES256: { dirty: 3000, actual: 100 },
  EdDSA: { dirty: 3000, actual: 100 },
};
const DEFAULT_STRESS_BUDGET = { dirty: 300000, actual: 120000 };

function getBaseUrl(alg) {
  if (isMultiGateway) return `${HOST_BASE}:${alg.port}`;
  return SINGLE_BASE;
}

function benchmarkBody(email, algName) {
  return JSON.stringify({
    email,
    algorithm: algName,
  });
}

function jwsAlgForBenchmarkProfile(algName) {
  if (algName === "FN-DSA-Precomputed-512" || algName === "FN-DSA-512") {
    return "FN-DSA-512";
  }
  return algName;
}

function envOrNotProvided(name) {
  return __ENV[name] || "not provided";
}

function endpointUsesTLS() {
  const base = isMultiGateway ? HOST_BASE : SINGLE_BASE;
  return base.startsWith("https://");
}

// Fisher-Yates shuffle. Used only for the scenario execution ORDER (below),
// not for ALGORITHMS itself — lookups by id/name and report tables must stay
// stable/canonical; only which algorithm's isolated/stress/attack scenarios
// run first should vary between invocations, so a fixed order doesn't let
// one algorithm systematically benefit (or suffer) from cache/DB warmth left
// over from whichever algorithm always ran immediately before it (P1-6).
function shuffle(array) {
  const copy = array.slice();
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

const RUN_ORDER = shuffle(ALGORITHMS);
console.log(`Randomized algorithm execution order for this run: ${RUN_ORDER.map((a) => a.id).join(" -> ")}`);

// ═══════════════════════════════════════════════════════════════
// Scenarios
// ═══════════════════════════════════════════════════════════════

const scenarios = {};
let startDelay = 0;

// ── Phase 1: Isolated (1 VU, server loops ITERATIONS times) ──
if (RUN_ISOLATED) {
  for (const alg of RUN_ORDER) {
    // Conservative timeout: each signing iteration can take up to 1s for slow algs
    const timeoutS = Math.max(60, Math.ceil(ITERATIONS * 0.01) + 30);
    scenarios[`isolated_${alg.id}`] = {
      executor: "shared-iterations",
      vus: 1,
      iterations: 1,
      maxDuration: `${timeoutS}s`,
      startTime: `${startDelay}s`,
      exec: "runIsolated",
      env: { CURRENT_ALG: alg.id },
      gracefulStop: "10s",
    };
    startDelay += timeoutS + ISOLATED_GAP_S;
  }
  startDelay += PHASE_GAP_S; // settle before stress phase
}

// ── Phase 2: Stress Test (10 / 30 / 50 VU, constant-vus) ────
if (RUN_STRESS) {
  for (const alg of RUN_ORDER) {
    for (const vus of CONCURRENCY_LEVELS) {
      scenarios[`stress_${alg.id}_${vus}VU`] = {
        executor: "constant-vus",
        vus: vus,
        duration: `${STRESS_DURATION_S}s`,
        startTime: `${startDelay}s`,
        exec: "runStress",
        env: { CURRENT_ALG: alg.id, CURRENT_VUS: String(vus) },
        gracefulStop: "15s",
      };
      startDelay += STRESS_DURATION_S + STRESS_GAP_S;
    }
  }
}

// ── Phase 3: Attack block-rate check ──────────────────────────
if (RUN_ATTACKS) {
  for (const alg of RUN_ORDER) {
    scenarios[`attack_${alg.id}`] = {
      executor: "shared-iterations",
      vus: 1,
      iterations: ATTACK_ITERATIONS,
      maxDuration: "120s",
      startTime: `${startDelay}s`,
      exec: "runAttack",
      env: { CURRENT_ALG: alg.id },
      gracefulStop: "10s",
    };
    startDelay += ATTACK_GAP_S;
  }
}

// ═══════════════════════════════════════════════════════════════
// Custom Metrics
// ═══════════════════════════════════════════════════════════════

// ── Phase 1: Isolated — values reported by /api/benchmark/jwt-issuance ─
const benchSignP95 = new Trend("bench_sign_p95", true);
const benchSignAvg = new Trend("bench_sign_avg", true);
const benchSignMin = new Trend("bench_sign_min", true);
const benchSignMax = new Trend("bench_sign_max", true);
const benchSignStdev = new Trend("bench_sign_stdev", true);
const benchTokenGenerationP95 = new Trend("bench_token_generation_p95", true);
const benchTokenGenerationAvg = new Trend("bench_token_generation_avg", true);
const benchTokenGenerationStdev = new Trend("bench_token_generation_stdev", true);
const benchTokenGenerationGCFreeP95 = new Trend("bench_token_generation_gc_free_p95", true);
const benchTokenGenerationGCFreeAvg = new Trend("bench_token_generation_gc_free_avg", true);
const benchTokenGenerationGCFreeStdev = new Trend("bench_token_generation_gc_free_stdev", true);
const benchPureSigningP95 = new Trend("bench_pure_signing_p95", true);
const benchPureSigningAvg = new Trend("bench_pure_signing_avg", true);
const benchPureSigningStdev = new Trend("bench_pure_signing_stdev", true);
const benchPureSigningGCFreeP95 = new Trend("bench_pure_signing_gc_free_p95", true);
const benchPureSigningGCFreeAvg = new Trend("bench_pure_signing_gc_free_avg", true);
const benchPureSigningGCFreeStdev = new Trend("bench_pure_signing_gc_free_stdev", true);
const benchRefreshTokenGenerationP95 = new Trend("bench_refresh_token_generation_p95", true);
const benchRefreshTokenGenerationAvg = new Trend("bench_refresh_token_generation_avg", true);
const benchRefreshTokenGenerationStdev = new Trend("bench_refresh_token_generation_stdev", true);
const benchRefreshTokenGenerationGCFreeP95 = new Trend(
  "bench_refresh_token_generation_gc_free_p95",
  true,
);
const benchRefreshTokenGenerationGCFreeAvg = new Trend(
  "bench_refresh_token_generation_gc_free_avg",
  true,
);
const benchRefreshTokenGenerationGCFreeStdev = new Trend(
  "bench_refresh_token_generation_gc_free_stdev",
  true,
);
const benchTotalP95 = new Trend("bench_total_p95", true);
const benchTotalAvg = new Trend("bench_total_avg", true);
const benchTotalStdev = new Trend("bench_total_stdev", true);
const benchAuthCPUAvg = new Trend("bench_auth_cpu_avg", true);
const benchAuthCPUStdev = new Trend("bench_auth_cpu_stdev", true);
const benchAuthCPUTimeMsAvg = new Trend("bench_auth_cpu_time_ms_avg", true);
const benchAuthCPUTimeMsStdev = new Trend("bench_auth_cpu_time_ms_stdev", true);
const benchAuthCPUTimePerTokenMsAvg = new Trend("bench_auth_cpu_time_per_token_ms_avg", true);
const benchAuthCPUTimePerTokenMsStdev = new Trend(
  "bench_auth_cpu_time_per_token_ms_stdev",
  true,
);
const benchAuthMemoryAllocKBAvg = new Trend("bench_auth_memory_alloc_kb_avg");
const benchAuthMemoryAllocKBStdev = new Trend("bench_auth_memory_alloc_kb_stdev");
const benchAuthMemoryAllocDeltaKBAvg = new Trend("bench_auth_memory_alloc_delta_kb_avg");
const benchAuthMemoryAllocDeltaKBStdev = new Trend("bench_auth_memory_alloc_delta_kb_stdev");
const benchAuthMemorySysKBAvg = new Trend("bench_auth_memory_sys_kb_avg");
const benchAuthMemorySysKBStdev = new Trend("bench_auth_memory_sys_kb_stdev");
const benchAuthMemoryRSSKBAvg = new Trend("bench_auth_memory_rss_kb_avg");
const benchAuthMemoryRSSKBStdev = new Trend("bench_auth_memory_rss_kb_stdev");
// Pure-signing has its own resource-stats block server-side
// (BenchmarkPureSigningResult.Stats.Resource) distinct from jwt_issuance's —
// these carry it through; previously only latency was read from that scope.
const benchPureSigningMemoryAllocKBAvg = new Trend("bench_pure_signing_memory_alloc_kb_avg");
const benchPureSigningMemoryAllocKBStdev = new Trend("bench_pure_signing_memory_alloc_kb_stdev");
const benchPureSigningMemoryRSSKBAvg = new Trend("bench_pure_signing_memory_rss_kb_avg");
const benchPureSigningMemoryRSSKBStdev = new Trend("bench_pure_signing_memory_rss_kb_stdev");
const benchGCContaminatedCount = new Counter("bench_gc_contaminated_count");
const benchPureSigningGCContaminatedCount = new Counter(
  "bench_pure_signing_gc_contaminated_count",
);
const benchSuccess = new Counter("bench_success");
const benchFailed = new Counter("bench_failed");
const benchPureSigningSuccess = new Counter("bench_pure_signing_success");
const benchPureSigningFailed = new Counter("bench_pure_signing_failed");
// bench_success/failed above count HTTP calls (always 0 or 1 for a
// shared-iterations isolated scenario) — they gate thresholds, not report
// how many of the ITERATIONS server-side loop actually succeeded. These two
// carry the real per-iteration count so the summary doesn't mislabel a
// 100/100 success as "success_count: 1".
const benchIterationSuccess = new Counter("bench_iteration_success");
const benchIterationFailed = new Counter("bench_iteration_failed");
const benchPureSigningIterationSuccess = new Counter("bench_pure_signing_iteration_success");
const benchPureSigningIterationFailed = new Counter("bench_pure_signing_iteration_failed");
const benchSignSample = new Trend("bench_sign_sample", true);
const benchTokenGenerationSample = new Trend("bench_token_generation_sample", true);
const benchTokenGenerationGCFreeSample = new Trend("bench_token_generation_gc_free_sample", true);
const benchPureSigningSample = new Trend("bench_pure_signing_sample", true);
const benchPureSigningGCFreeSample = new Trend("bench_pure_signing_gc_free_sample", true);
const benchRefreshTokenGenerationSample = new Trend("bench_refresh_token_generation_sample", true);
const benchRefreshTokenGenerationGCFreeSample = new Trend(
  "bench_refresh_token_generation_gc_free_sample",
  true,
);
const benchTotalSample = new Trend("bench_total_sample", true);

// ── Phase 2: Stress — per benchmark token call, tagged {alg, vus} ─────
// tokenGenerationClean = X-Token-Generation-Time-Ms / X-Sign-Time-Ms
// clean                = timings.waiting (server processing approx — TTFB after send)
// dirty                = timings.duration (full k6 round-trip)
// network              = dirty - clean
const stressSignActual = new Trend("stress_sign_actual", true);
const stressTokenGenerationClean = new Trend("stress_token_generation_clean", true);
const stressSignClean = new Trend("stress_sign_clean", true);
const stressSignDirty = new Trend("stress_sign_dirty", true);
const stressSignNetwork = new Trend("stress_sign_network", true);
const stressLoginDirty = new Trend("stress_login_dirty", true);
const stressRefreshTokenGenerationClean = new Trend(
  "stress_refresh_token_generation_clean",
  true,
);
const stressRefreshDirty = new Trend("stress_refresh_dirty", true);
const stressRefreshSuccess = new Counter("stress_refresh_success");
const stressRefreshFailed = new Counter("stress_refresh_failed");
const stressRefreshErrorRate = new Rate("stress_refresh_error_rate");
const stressReqSuccess = new Counter("stress_req_success");
const stressReqFailed = new Counter("stress_req_failed");
const stressErrorRate = new Rate("stress_error_rate");

// ── Phase 3: Attack block-rate ─────────────────────────────────
const attackBlocked = new Counter("attack_blocked");
const attackAllowed = new Counter("attack_allowed");
const attackBlockRate = new Rate("attack_block_rate");

// ═══════════════════════════════════════════════════════════════
// Thresholds
// ═══════════════════════════════════════════════════════════════

const thresholds = {};

if (RUN_ISOLATED) {
  thresholds.bench_success = ["count>0"];
  thresholds.bench_pure_signing_success = ["count>0"];
}

if (RUN_STRESS) {
  thresholds.stress_error_rate = ["rate<0.01"]; // overall <1% error rate
  thresholds.stress_refresh_error_rate = ["rate<0.05"];
}

if (RUN_ATTACKS) {
  thresholds.attack_block_rate = ["rate>0.99"];
}

for (const alg of ALGORITHMS) {
  const b = STRESS_BUDGET[alg.name] || DEFAULT_STRESS_BUDGET;

  if (RUN_STRESS) {
    // Permissive per-{alg,vus} thresholds — force k6 to emit tagged sub-metric
    // entries in the summary JSON so handleSummary can read them.
    for (const vus of CONCURRENCY_LEVELS) {
      const tv = `{alg:${alg.name},vus:${vus}}`;
      thresholds[`stress_sign_dirty${tv}`] = [`p(95)<${b.dirty}`];
      thresholds[`stress_sign_actual${tv}`] = [`p(95)<${b.actual}`];
      thresholds[`stress_token_generation_clean${tv}`] = [`p(95)<${b.actual}`];
      thresholds[`stress_sign_clean${tv}`] = [`p(95)<9999999`];
      thresholds[`stress_sign_network${tv}`] = [`p(95)<9999999`];
      thresholds[`stress_login_dirty${tv}`] = [`p(95)<9999999`];
      thresholds[`stress_refresh_token_generation_clean${tv}`] = [`p(95)<${b.actual}`];
      thresholds[`stress_refresh_dirty${tv}`] = [`p(95)<9999999`];
      thresholds[`stress_refresh_success${tv}`] = [`count>=0`];
      thresholds[`stress_refresh_failed${tv}`] = [`count>=0`];
      thresholds[`stress_refresh_error_rate${tv}`] = [`rate<0.10`];
      thresholds[`stress_req_success${tv}`] = [`count>=0`];
      thresholds[`stress_req_failed${tv}`] = [`count>=0`];
      thresholds[`stress_error_rate${tv}`] = [`rate<0.05`]; // <5% per scenario
    }
  }

  // Isolated phase — one entry per algorithm (no vus tag)
  const ta = `{alg:${alg.name}}`;
  if (RUN_ISOLATED) {
    thresholds[`bench_sign_p95${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_sign_avg${ta}`] = [`avg>=0`];
    thresholds[`bench_sign_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_token_generation_p95${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_token_generation_avg${ta}`] = [`avg>=0`];
    thresholds[`bench_token_generation_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_token_generation_gc_free_p95${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_token_generation_gc_free_avg${ta}`] = [`avg>=0`];
    thresholds[`bench_token_generation_gc_free_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_pure_signing_p95${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_pure_signing_avg${ta}`] = [`avg>=0`];
    thresholds[`bench_pure_signing_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_pure_signing_gc_free_p95${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_pure_signing_gc_free_avg${ta}`] = [`avg>=0`];
    thresholds[`bench_pure_signing_gc_free_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_refresh_token_generation_p95${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_refresh_token_generation_avg${ta}`] = [`avg>=0`];
    thresholds[`bench_refresh_token_generation_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_refresh_token_generation_gc_free_p95${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_refresh_token_generation_gc_free_avg${ta}`] = [`avg>=0`];
    thresholds[`bench_refresh_token_generation_gc_free_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_total_p95${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_total_avg${ta}`] = [`avg>=0`];
    thresholds[`bench_total_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_auth_cpu_avg${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_auth_cpu_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_auth_cpu_time_ms_avg${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_auth_cpu_time_ms_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_auth_cpu_time_per_token_ms_avg${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_auth_cpu_time_per_token_ms_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_auth_memory_alloc_kb_avg${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_auth_memory_alloc_kb_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_auth_memory_alloc_delta_kb_avg${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_auth_memory_alloc_delta_kb_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_auth_memory_sys_kb_avg${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_auth_memory_sys_kb_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_auth_memory_rss_kb_avg${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_auth_memory_rss_kb_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_pure_signing_memory_alloc_kb_avg${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_pure_signing_memory_alloc_kb_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_pure_signing_memory_rss_kb_avg${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_pure_signing_memory_rss_kb_stdev${ta}`] = [`avg>=0`];
    thresholds[`bench_sign_sample${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_token_generation_sample${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_token_generation_gc_free_sample${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_pure_signing_sample${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_pure_signing_gc_free_sample${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_refresh_token_generation_sample${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_refresh_token_generation_gc_free_sample${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_total_sample${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_gc_contaminated_count${ta}`] = [`count>=0`];
    thresholds[`bench_pure_signing_gc_contaminated_count${ta}`] = [`count>=0`];
    thresholds[`bench_success${ta}`] = [`count>0`];
    thresholds[`bench_pure_signing_success${ta}`] = [`count>0`];
    thresholds[`bench_iteration_success${ta}`] = [`count>=0`];
    thresholds[`bench_iteration_failed${ta}`] = [`count>=0`];
    thresholds[`bench_pure_signing_iteration_success${ta}`] = [`count>=0`];
    thresholds[`bench_pure_signing_iteration_failed${ta}`] = [`count>=0`];
  }
  if (RUN_ATTACKS) {
    thresholds[`attack_block_rate${ta}`] = [`rate>0.99`];
  }
}

export const options = {
  scenarios,
  thresholds,
  summaryTrendStats: ["avg", "min", "med", "max", "p(90)", "p(95)", "p(99)"],
  noConnectionReuse: false,
  noVUConnectionReuse: false,
  setupTimeout: "240s",
  teardownTimeout: "30s",
};

// ═══════════════════════════════════════════════════════════════
// Setup — register benchmark user (shared across both phases)
// ═══════════════════════════════════════════════════════════════

export function setup() {
  const suffix = randomString(8).toLowerCase();
  const user = {
    name: `bench-${suffix}`,
    email: `bench-${suffix}@bench.test`,
    password: "BenchPass!123",
  };

  // ── Preflight: every algorithm gateway must actually sign a token ──
  // Each algorithm targets its own gateway (ports 5001-5006 in multi-gateway
  // mode). setup() previously probed only ALGORITHMS[0], so a broken gateway for
  // any other algorithm was never detected — its scenarios ran against nothing
  // and the summary emitted zero-filled latencies (threshold submetrics report
  // 0 with no samples) that look like real "0 ms" measurements.
  //
  // A bare liveness ping is not enough: a gateway can accept connections yet
  // fail every /api/benchmark/token call (e.g. missing signing key), which also
  // yields all-zero results. So probe the exact endpoint the stress phase uses
  // and require a 200 with an access_token for every algorithm. The token path
  // derives its user id from the email hash and does not need a registered
  // user, so this can run before registration.
  const preflightBody = (algName) =>
    benchmarkBody(`preflight-${suffix}@bench.test`, algName);
  const tokenOk = (res) => {
    if (res.status !== 200) return false;
    try {
      return !!JSON.parse(res.body).data?.access_token;
    } catch {
      return false;
    }
  };

  // Budget carved out of setupTimeout (240s) so it never starves the
  // registration retry loop below — that loop needs its own room, and both
  // run inside the same setup() call, sharing one k6-enforced ceiling.
  const PREFLIGHT_TIMEOUT_MS = 90000;
  const preflightDeadline = Date.now() + PREFLIGHT_TIMEOUT_MS;
  let pending = ALGORITHMS.slice();
  let lastFailure = {};
  let preflightRound = 0;
  while (pending.length > 0 && Date.now() < preflightDeadline) {
    preflightRound++;
    pending = pending.filter((alg) => {
      const res = http.post(
        `${getBaseUrl(alg)}/api/benchmark/token`,
        preflightBody(alg.name),
        { headers: { "Content-Type": "application/json" }, timeout: "5s" },
      );
      if (tokenOk(res)) return false; // healthy — drop from pending
      lastFailure[alg.name] =
        res.status === 0
          ? "unreachable (connection refused/timed out)"
          : `HTTP ${res.status}: ${String(res.body).slice(0, 120)}`;
      return true;
    });
    if (pending.length > 0) {
      console.log(
        `[preflight ${preflightRound}] ${pending.length}/${ALGORITHMS.length} gateway(s) not ready, retrying in 2s...`,
      );
      sleep(2);
    }
  }
  if (pending.length > 0) {
    const dead = pending
      .map((alg) => `${alg.name} → ${getBaseUrl(alg)} — ${lastFailure[alg.name]}`)
      .join("\n  ");
    exec.test.abort(
      `Preflight failed — ${pending.length}/${ALGORITHMS.length} gateway(s) cannot sign a token after 90s:\n  ${dead}\n` +
        `Bring every benchmark service up and healthy before running; ` +
        `otherwise these algorithms produce zero-filled (not actual) results.`,
    );
  }

  const firstAlg = ALGORITHMS[0];
  const registerUrl = `${getBaseUrl(firstAlg)}/api/auth/register`;
  console.log(`All ${ALGORITHMS.length} gateway(s) can sign. Registering benchmark user at: ${registerUrl}`);

  // Preflight already proved this gateway reachable and signing, so this loop
  // only needs to ride out the DB-backed register path warming up — its
  // budget is kept well inside what's left of setupTimeout after preflight.
  let regRes;
  for (let attempt = 1; attempt <= 45; attempt++) {
    regRes = http.post(registerUrl, JSON.stringify(user), {
      headers: { "Content-Type": "application/json" },
      timeout: "5s",
    });
    if (regRes.status !== 0) break;
    console.log(`[${attempt}/45] Service not ready, retrying in 2s...`);
    sleep(2);
  }

  if (regRes.status === 0) {
    exec.test.abort(
      `Service ${registerUrl} unreachable after 90s — ensure docker-compose is running`,
    );
  }

  if (regRes.status !== 201) {
    exec.test.abort(
      `Registration failed (status=${regRes.status}) — body: ${regRes.body.slice(0, 200)}`,
    );
  }

  console.log(`Benchmark user registered: ${user.email}`);
  return { user };
}

// ═══════════════════════════════════════════════════════════════
// Phase 1: Isolated — server-side N-iteration loop
// ═══════════════════════════════════════════════════════════════

export function runIsolated(data) {
  if (!data) exec.test.abort("Setup failed — no data");

  const algId = __ENV.CURRENT_ALG;
  const alg = ALGORITHMS.find((a) => a.id === algId);
  if (!alg) return;

  const BASE = getBaseUrl(alg);
  const tags = { alg: alg.name };

  const payload = JSON.stringify({
    algorithm: alg.name,
    iterations: ITERATIONS,
    warmup_iterations: ISOLATED_WARMUP,
    email: data.user.email,
    payload_note: `isolated-${alg.id}-${ITERATIONS}iter`,
  });

  const res = http.post(`${BASE}${JWT_ISSUANCE_ENDPOINT}`, payload, {
    headers: { "Content-Type": "application/json" },
    timeout: "600s",
  });

  const ok = check(res, {
    [`[isolated|${alg.name}] 200`]: (r) => r.status === 200,
    [`[isolated|${alg.name}] has stats`]: (r) => {
      try {
        const body = JSON.parse(r.body).data;
        return body?.metric_scope === "jwt_issuance" && body?.algorithm === alg.name && !!body?.stats;
      } catch {
        return false;
      }
    },
  });

  if (!ok) {
    benchFailed.add(1, tags);
    console.error(
      `[isolated|${alg.name}] FAILED status=${res.status} body=${res.body.slice(0, 300)}`,
    );
    return;
  }

  try {
    const result = JSON.parse(res.body).data;
    const successCount = successfulIterations(result, "sign_timings_ms");
    if (successCount <= 0) {
      benchFailed.add(1, tags);
      console.error(`[isolated|${alg.name}] no successful iterations`);
      return;
    }
    benchSuccess.add(1, tags);
    benchIterationSuccess.add(successCount, tags);
    benchIterationFailed.add(Math.max(0, (result.iterations ?? 0) - successCount), tags);
    const s = result.stats;
    const hasTokenGCFree =
      Array.isArray(result.token_generation_gc_free_timings_ms) &&
      result.token_generation_gc_free_timings_ms.length > 0;
    const hasRefreshGCFree =
      Array.isArray(result.refresh_token_generation_gc_free_timings_ms) &&
      result.refresh_token_generation_gc_free_timings_ms.length > 0;

    addNumber(benchSignP95, s.sign.p95_ms, tags);
    addNumber(benchSignAvg, s.sign.avg_ms, tags);
    addNumber(benchSignMin, s.sign.min_ms, tags);
    addNumber(benchSignMax, s.sign.max_ms, tags);
    addNumber(benchSignStdev, s.sign.stdev_ms, tags);
    addNumber(benchTokenGenerationP95, s.token_generation?.p95_ms ?? s.sign.p95_ms, tags);
    addNumber(benchTokenGenerationAvg, s.token_generation?.avg_ms ?? s.sign.avg_ms, tags);
    addNumber(benchTokenGenerationStdev, s.token_generation?.stdev_ms ?? s.sign.stdev_ms, tags);
    if (hasTokenGCFree) {
      addNumber(benchTokenGenerationGCFreeP95, s.token_generation_gc_free.p95_ms, tags);
      addNumber(benchTokenGenerationGCFreeAvg, s.token_generation_gc_free.avg_ms, tags);
      addNumber(benchTokenGenerationGCFreeStdev, s.token_generation_gc_free.stdev_ms, tags);
    }
    if (s.refresh_token_generation?.avg_ms != null) {
      addNumber(benchRefreshTokenGenerationP95, s.refresh_token_generation.p95_ms, tags);
      addNumber(benchRefreshTokenGenerationAvg, s.refresh_token_generation.avg_ms, tags);
      addNumber(benchRefreshTokenGenerationStdev, s.refresh_token_generation.stdev_ms, tags);
    }
    if (hasRefreshGCFree) {
      addNumber(benchRefreshTokenGenerationGCFreeP95, s.refresh_token_generation_gc_free.p95_ms, tags);
      addNumber(benchRefreshTokenGenerationGCFreeAvg, s.refresh_token_generation_gc_free.avg_ms, tags);
      addNumber(benchRefreshTokenGenerationGCFreeStdev, s.refresh_token_generation_gc_free.stdev_ms, tags);
    }
    addNumber(benchTotalP95, s.total.p95_ms, tags);
    addNumber(benchTotalAvg, s.total.avg_ms, tags);
    addNumber(benchTotalStdev, s.total.stdev_ms, tags);
    addStat(benchAuthCPUAvg, s.resource?.cpu_utilization_pct, "avg", tags);
    addStat(benchAuthCPUStdev, s.resource?.cpu_utilization_pct, "stdev", tags);
    addStat(benchAuthCPUTimeMsAvg, s.resource?.cpu_time_ms, "avg", tags);
    addStat(benchAuthCPUTimeMsStdev, s.resource?.cpu_time_ms, "stdev", tags);
    addStat(benchAuthCPUTimePerTokenMsAvg, s.resource?.cpu_time_per_token_ms, "avg", tags);
    addStat(benchAuthCPUTimePerTokenMsStdev, s.resource?.cpu_time_per_token_ms, "stdev", tags);
    addStat(benchAuthMemoryAllocKBAvg, s.resource?.memory_alloc_kb, "avg", tags);
    addStat(benchAuthMemoryAllocKBStdev, s.resource?.memory_alloc_kb, "stdev", tags);
    addStat(benchAuthMemoryAllocDeltaKBAvg, s.resource?.memory_alloc_delta_kb, "avg", tags);
    addStat(benchAuthMemoryAllocDeltaKBStdev, s.resource?.memory_alloc_delta_kb, "stdev", tags);
    addStat(benchAuthMemorySysKBAvg, s.resource?.memory_sys_kb, "avg", tags);
    addStat(benchAuthMemorySysKBStdev, s.resource?.memory_sys_kb, "stdev", tags);
    addStat(benchAuthMemoryRSSKBAvg, s.resource?.memory_rss_kb, "avg", tags);
    addStat(benchAuthMemoryRSSKBStdev, s.resource?.memory_rss_kb, "stdev", tags);
    benchGCContaminatedCount.add(result.gc_contaminated_count ?? 0, tags);
    addSamples(benchSignSample, result.sign_timings_ms, tags);
    addSamples(benchTokenGenerationSample, result.token_generation_timings_ms, tags);
    addSamples(
      benchTokenGenerationGCFreeSample,
      result.token_generation_gc_free_timings_ms,
      tags,
    );
    addSamples(benchRefreshTokenGenerationSample, result.refresh_token_generation_timings_ms, tags);
    addSamples(
      benchRefreshTokenGenerationGCFreeSample,
      result.refresh_token_generation_gc_free_timings_ms,
      tags,
    );
    addSamples(benchTotalSample, result.total_timings_ms, tags);

    const gcFree = s.token_generation_gc_free;
    const gcCount = result.gc_contaminated_count ?? 0;
    console.log(
      `[isolated|${alg.name}] n=${successCount}/${result.iterations}` +
        ` warmup=${result.warmup_iterations}` +
        ` gc_contaminated=${gcCount}` +
        ` | token_generation(all): avg=${(s.token_generation?.avg_ms ?? s.sign.avg_ms)?.toFixed(3)} p95=${(s.token_generation?.p95_ms ?? s.sign.p95_ms)?.toFixed(3)} stdev=${(s.token_generation?.stdev_ms ?? s.sign.stdev_ms)?.toFixed(3)} ms` +
        (s.refresh_token_generation?.avg_ms != null
          ? ` | refresh_generation(all): avg=${s.refresh_token_generation.avg_ms?.toFixed(3)} p95=${s.refresh_token_generation.p95_ms?.toFixed(3)} stdev=${s.refresh_token_generation.stdev_ms?.toFixed(3)} ms`
          : "") +
        (hasTokenGCFree
          ? ` | token_generation(gc_free): avg=${gcFree.avg_ms?.toFixed(3)} p95=${gcFree.p95_ms?.toFixed(3)} stdev=${gcFree.stdev_ms?.toFixed(3)} ms`
          : "") +
        ` | total: avg=${s.total.avg_ms?.toFixed(3)} p95=${s.total.p95_ms?.toFixed(3)} ms`,
    );
  } catch (e) {
    benchFailed.add(1, tags);
    console.error(`[isolated|${alg.name}] parse error: ${e}`);
  }

  const pureRes = http.post(`${BASE}${PURE_SIGNING_ENDPOINT}`, payload, {
    headers: { "Content-Type": "application/json" },
    timeout: "600s",
  });

  const pureOk = check(pureRes, {
    [`[pure-signing|${alg.name}] 200`]: (r) => r.status === 200,
    [`[pure-signing|${alg.name}] has stats`]: (r) => {
      try {
        const body = JSON.parse(r.body).data;
        return body?.metric_scope === "pure_signing" && body?.algorithm === alg.name && !!body?.stats;
      } catch {
        return false;
      }
    },
  });

  if (!pureOk) {
    benchPureSigningFailed.add(1, tags);
    console.error(
      `[pure-signing|${alg.name}] FAILED status=${pureRes.status} body=${pureRes.body.slice(0, 300)}`,
    );
    sleep(1);
    return;
  }

  try {
    const result = JSON.parse(pureRes.body).data;
    const successCount = successfulIterations(result, "pure_signing_timings_ms");
    if (successCount <= 0) {
      benchPureSigningFailed.add(1, tags);
      console.error(`[pure-signing|${alg.name}] no successful iterations`);
      sleep(1);
      return;
    }
    benchPureSigningSuccess.add(1, tags);
    benchPureSigningIterationSuccess.add(successCount, tags);
    benchPureSigningIterationFailed.add(Math.max(0, (result.iterations ?? 0) - successCount), tags);
    const s = result.stats;
    const hasPureGCFree =
      Array.isArray(result.pure_signing_gc_free_timings_ms) &&
      result.pure_signing_gc_free_timings_ms.length > 0;

    addNumber(benchPureSigningP95, s.pure_signing.p95_ms, tags);
    addNumber(benchPureSigningAvg, s.pure_signing.avg_ms, tags);
    addNumber(benchPureSigningStdev, s.pure_signing.stdev_ms, tags);
    if (hasPureGCFree) {
      addNumber(benchPureSigningGCFreeP95, s.pure_signing_gc_free.p95_ms, tags);
      addNumber(benchPureSigningGCFreeAvg, s.pure_signing_gc_free.avg_ms, tags);
      addNumber(benchPureSigningGCFreeStdev, s.pure_signing_gc_free.stdev_ms, tags);
    }
    addSamples(benchPureSigningSample, result.pure_signing_timings_ms, tags);
    addSamples(benchPureSigningGCFreeSample, result.pure_signing_gc_free_timings_ms, tags);
    addStat(benchPureSigningMemoryAllocKBAvg, s.resource?.memory_alloc_kb, "avg", tags);
    addStat(benchPureSigningMemoryAllocKBStdev, s.resource?.memory_alloc_kb, "stdev", tags);
    addStat(benchPureSigningMemoryRSSKBAvg, s.resource?.memory_rss_kb, "avg", tags);
    addStat(benchPureSigningMemoryRSSKBStdev, s.resource?.memory_rss_kb, "stdev", tags);

    const gcFree = s.pure_signing_gc_free;
    const gcCount = result.gc_contaminated_count ?? 0;
    benchPureSigningGCContaminatedCount.add(gcCount, tags);
    console.log(
      `[pure-signing|${alg.name}] n=${successCount}/${result.iterations}` +
        ` warmup=${result.warmup_iterations}` +
        ` gc_contaminated=${gcCount}` +
        ` | pure(all): avg=${s.pure_signing.avg_ms?.toFixed(3)} p95=${s.pure_signing.p95_ms?.toFixed(3)} stdev=${s.pure_signing.stdev_ms?.toFixed(3)} ms` +
        (hasPureGCFree
          ? ` | pure(gc_free): avg=${gcFree.avg_ms?.toFixed(3)} p95=${gcFree.p95_ms?.toFixed(3)} stdev=${gcFree.stdev_ms?.toFixed(3)} ms`
          : ""),
    );
  } catch (e) {
    benchPureSigningFailed.add(1, tags);
    console.error(`[pure-signing|${alg.name}] parse error: ${e}`);
  }

  sleep(1);
}

function getHeaderNumber(res, names) {
  for (const name of names) {
    const v = res.headers[name] || res.headers[name.toLowerCase()];
    if (v !== undefined && v !== "") {
      const n = parseFloat(v);
      if (!isNaN(n)) return n;
    }
  }
  return null;
}

function warmupBenchmarkToken(base, body, headers) {
  http.post(`${base}/api/benchmark/token`, body, { headers });
}

function addNumber(metric, value, tags) {
  if (typeof value === "number" && !isNaN(value)) metric.add(value, tags);
}

function addStat(metric, stats, field, tags) {
  if (!stats) return;
  addNumber(metric, stats[field], tags);
}

function addSamples(metric, values, tags) {
  if (!Array.isArray(values)) return;
  for (const value of values) {
    addNumber(metric, value, tags);
  }
}

function successfulIterations(result, timingField) {
  const explicit = result?.success_count ?? result?.successCount;
  if (typeof explicit === "number" && explicit > 0) return explicit;

  const timings = result?.[timingField];
  return Array.isArray(timings) ? timings.length : 0;
}

function tamperToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[2].length === 0) return token + "A";
  const sig = parts[2];
  const idx = Math.floor(sig.length / 2);
  const current = sig[idx];
  const replacement = current === "A" ? "B" : "A";
  parts[2] = sig.slice(0, idx) + replacement + sig.slice(idx + 1);
  return parts.join(".");
}

// ═══════════════════════════════════════════════════════════════
// Phase 2: Stress — concurrent benchmark-token calls, latency under load
// ═══════════════════════════════════════════════════════════════

export function runStress(data) {
  if (!data) exec.test.abort("Setup failed — no data");

  const algId = __ENV.CURRENT_ALG;
  const vuCount = __ENV.CURRENT_VUS;
  const alg = ALGORITHMS.find((a) => a.id === algId);
  if (!alg) return;

  const BASE = getBaseUrl(alg);
  const tags = { alg: alg.name, vus: vuCount };
  const jsonHdr = { "Content-Type": "application/json" };
  const body = benchmarkBody(data.user.email, alg.name);

  if (STRESS_WARMUP && __ITER === 0) {
    // First call primes the connection pool, subsequent calls warm code/data caches.
    for (let i = 0; i < STRESS_WARMUP_REQUESTS; i++) {
      warmupBenchmarkToken(BASE, body, jsonHdr);
    }
  }

  group(`stress ${alg.name} ${vuCount}VU`, () => {
    const res = http.post(`${BASE}/api/benchmark/token`, body, {
      headers: jsonHdr,
    });

    // Latency decomposition
    const dirty = res.timings.duration;
    const clean = res.timings.waiting;
    const network = dirty - clean;

    stressSignDirty.add(dirty, tags);
    stressSignClean.add(clean, tags);
    stressSignNetwork.add(network, tags);

    // clean token generation = pure JWT generation only.
    const tokenGenerationMs = getHeaderNumber(res, [
      "X-Token-Generation-Time-Ms",
      "x-token-generation-time-ms",
      "X-Sign-Time-Ms",
      "x-sign-time-ms",
    ]);
    if (tokenGenerationMs !== null) {
      stressSignActual.add(tokenGenerationMs, tags); // backward-compatible metric
      stressTokenGenerationClean.add(tokenGenerationMs, tags);
    }

    let accessToken = "";
    try {
      accessToken = JSON.parse(res.body).data?.access_token || "";
    } catch {
      accessToken = "";
    }

    const ok = check(res, {
      [`[stress|${alg.name}|${vuCount}VU] sign 200`]: (r) => r.status === 200,
      [`[stress|${alg.name}|${vuCount}VU] has token`]: (r) => {
        return !!accessToken;
      },
    });

    ok ? stressReqSuccess.add(1, tags) : stressReqFailed.add(1, tags);
    stressErrorRate.add(!ok, tags);
  });

  // Full login round-trip: bcrypt verify + DB lookup + JWT generation.
  // Measured separately so it doesn't pollute the benchmark-token latency above.
  const loginBody = JSON.stringify({
    email: data.user.email,
    password: data.user.password,
    algorithm: alg.name,
  });
  const loginRes = http.post(`${BASE}/api/auth/signin`, loginBody, {
    headers: jsonHdr,
  });
  stressLoginDirty.add(loginRes.timings.duration, tags);

  let refreshToken = "";
  try {
    refreshToken = JSON.parse(loginRes.body).data?.refresh_token || "";
  } catch {
    refreshToken = "";
  }

  if (refreshToken) {
    const refreshRes = http.post(
      `${BASE}/api/auth/refresh`,
      JSON.stringify({ refresh_token: refreshToken }),
      { headers: jsonHdr },
    );
    stressRefreshDirty.add(refreshRes.timings.duration, tags);

    const refreshGenerationMs = getHeaderNumber(refreshRes, [
      "X-Refresh-Token-Generation-Time-Ms",
      "x-refresh-token-generation-time-ms",
    ]);
    if (refreshGenerationMs !== null) {
      stressRefreshTokenGenerationClean.add(refreshGenerationMs, tags);
    }

    let newAccessToken = "";
    let newRefreshToken = "";
    try {
      const refreshData = JSON.parse(refreshRes.body).data || {};
      newAccessToken = refreshData.access_token || "";
      newRefreshToken = refreshData.refresh_token || "";
    } catch {
      newAccessToken = "";
      newRefreshToken = "";
    }

    const refreshOk = check(refreshRes, {
      [`[refresh|${alg.name}|${vuCount}VU] 200`]: (r) => r.status === 200,
      [`[refresh|${alg.name}|${vuCount}VU] has token pair`]: () => {
        return !!newAccessToken && !!newRefreshToken;
      },
    });

    refreshOk ? stressRefreshSuccess.add(1, tags) : stressRefreshFailed.add(1, tags);
    stressRefreshErrorRate.add(!refreshOk, tags);
  } else {
    stressRefreshFailed.add(1, tags);
    stressRefreshErrorRate.add(true, tags);
  }

  sleep(STRESS_THINK_TIME_S);
}

// ═══════════════════════════════════════════════════════════════
// Phase 3: Attack block-rate — tampered-token request must fail
// ═══════════════════════════════════════════════════════════════

export function runAttack(data) {
  if (!data) exec.test.abort("Setup failed — no data");

  const algId = __ENV.CURRENT_ALG;
  const alg = ALGORITHMS.find((a) => a.id === algId);
  if (!alg) return;

  const BASE = getBaseUrl(alg);
  const tags = { alg: alg.name };
  const jsonHdr = { "Content-Type": "application/json" };
  const body = benchmarkBody(data.user.email, alg.name);

  const signRes = http.post(`${BASE}/api/benchmark/token`, body, {
    headers: jsonHdr,
  });
  let token = "";
  try {
    token = JSON.parse(signRes.body).data?.access_token || "";
  } catch {
    token = "";
  }

  if (!token) {
    attackAllowed.add(1, tags);
    attackBlockRate.add(false, tags);
    return;
  }

  const tampered = tamperToken(token);
  const attackRes = http.get(`${BASE}/api/profile`, {
    headers: { Authorization: `Bearer ${tampered}` },
  });

  const blocked = attackRes.status === 401 || attackRes.status === 403;
  blocked ? attackBlocked.add(1, tags) : attackAllowed.add(1, tags);
  attackBlockRate.add(blocked, tags);

  check(attackRes, {
    [`[attack|${alg.name}] tampered token blocked`]: () => blocked,
  });
}

// ═══════════════════════════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════════════════════════

export function handleSummary(data) {
  const m = data.metrics;

  function getMetricKey(metric, algName, vuCount) {
    return vuCount !== null
      ? `${metric}{alg:${algName},vus:${vuCount}}`
      : `${metric}{alg:${algName}}`;
  }

  function getVal(metric, algName, vuCount, stat, digits = 3) {
    const key = getMetricKey(metric, algName, vuCount);
    if (!(key in m)) return "—";
    const v = m[key].values[stat];
    if (v === undefined) return "—";
    if (stat === "rate") return (v * 100).toFixed(1) + "%";
    return v.toFixed(digits);
  }

  function getValFallback(metric, fallbackMetric, algName, vuCount, stat, digits = 3) {
    const v = getVal(metric, algName, vuCount, stat, digits);
    if (v !== "—") return v;
    return getVal(fallbackMetric, algName, vuCount, stat, digits);
  }

  function getCount(metric, algName, vuCount) {
    const key = getMetricKey(metric, algName, vuCount);
    return (m[key] && m[key].values.count) || 0;
  }

  function getNumber(metric, algName, vuCount, stat) {
    const key = getMetricKey(metric, algName, vuCount);
    if (!(key in m)) return null;
    const v = m[key].values[stat];
    return v === undefined ? null : v;
  }

  function divideOrNull(num, den) {
    if (num === null || den === null || den === 0) return null;
    return num / den;
  }

  function subtractOrNull(left, right) {
    if (left === null || right === null) return null;
    return left - right;
  }

  function getThroughput(algName, vuCount) {
    const sk = `stress_req_success{alg:${algName},vus:${vuCount}}`;
    const sc = (m[sk] && m[sk].values.count) || 0;
    if (sc === 0) return "—";
    return (sc / STRESS_DURATION_S).toFixed(2);
  }

  function getRequestRate(algName, vuCount) {
    const sk = `stress_req_success{alg:${algName},vus:${vuCount}}`;
    const fk = `stress_req_failed{alg:${algName},vus:${vuCount}}`;
    const sc = (m[sk] && m[sk].values.count) || 0;
    const fc = (m[fk] && m[fk].values.count) || 0;
    const total = sc + fc;
    if (total === 0) return "—";
    return (total / STRESS_DURATION_S).toFixed(2);
  }

  function getErrRate(algName, vuCount) {
    const sk = `stress_req_success{alg:${algName},vus:${vuCount}}`;
    const fk = `stress_req_failed{alg:${algName},vus:${vuCount}}`;
    const sc = (m[sk] && m[sk].values.count) || 0;
    const fc = (m[fk] && m[fk].values.count) || 0;
    const total = sc + fc;
    if (total === 0) return "—";
    return ((fc / total) * 100).toFixed(1) + "%";
  }

  function getAttackBlockRate(algName) {
    const blocked = getCount("attack_blocked", algName, null);
    const allowed = getCount("attack_allowed", algName, null);
    const total = blocked + allowed;
    if (total === 0) return "—";
    return ((blocked / total) * 100).toFixed(1) + "%";
  }

  function buildAcademicResult() {
    const result = {
      generated_at: new Date().toISOString(),
      mode: ATTACK_ONLY
        ? "Attack only"
        : STRESS_ONLY
          ? "Stress only"
          : ISOLATED_ONLY
            ? "Isolated only"
            : "Isolated + Stress + Attack",
      endpoint: isMultiGateway ? `${HOST_BASE}:{5001-${5000 + ALGORITHMS.length}}` : SINGLE_BASE,
      methodology: {
        primary_metric: "isolated_gc_free_token_generation",
        pure_signing_metric: "isolated_gc_free_pure_signing",
        supporting_metric: "stress_concurrent_jwt_generation",
        isolated_endpoint: JWT_ISSUANCE_ENDPOINT,
        pure_signing_endpoint: PURE_SIGNING_ENDPOINT,
        isolated_iterations: ITERATIONS,
        isolated_warmup_iterations: ISOLATED_WARMUP,
        stress_duration_seconds: STRESS_DURATION_S,
        stress_stage_model: {
          executor: "constant-vus",
          load_model: "closed-loop",
          ramp_up_seconds: 0,
          steady_state_seconds: STRESS_DURATION_S,
          ramp_down_seconds: 0,
          settle_gap_between_stress_scenarios_seconds: STRESS_GAP_S,
          graceful_stop_seconds: 15,
          think_time_seconds: STRESS_THINK_TIME_S,
          warmup_requests_per_vu: STRESS_WARMUP ? STRESS_WARMUP_REQUESTS : 0,
        },
        stress_transport: {
          request_timeout: "k6 default unless request overrides it; setup registration uses 10s",
          connection_reuse: "enabled",
          http_protocol: "negotiated by k6/server; see benchmark_sign_raw.json http_req_* protocol tags if emitted",
          tls_enabled: endpointUsesTLS(),
        },
        stress_environment: {
          database_pool_idle: envOrNotProvided("DB_POOL_IDLE"),
          database_pool_open: envOrNotProvided("DB_POOL_OPEN"),
          rate_limit: envOrNotProvided("RATE_LIMIT"),
          cpu_quota: envOrNotProvided("CPU_QUOTA"),
          memory_quota: envOrNotProvided("MEMORY_QUOTA"),
        },
        stress_warmup_enabled: STRESS_WARMUP,
        concurrency_levels: CONCURRENCY_LEVELS,
        notes: [
          "Isolated metrics use gateway-local JWT generation path.",
          "Pure signing metrics use /api/benchmark/pure-signing and exclude JWT serialization, Base64URL, and compact assembly.",
          "Stress metrics use /api/benchmark/token instead of /api/auth/signin.",
          "Refresh metrics use /api/auth/refresh with refresh tokens returned by /api/auth/signin.",
          "Raw k6 aggregate metrics are omitted here because they mix algorithms and scenarios.",
        ],
      },
      algorithms: [],
    };

    for (const alg of ALGORITHMS) {
      const isolatedTokenAvg = getNumber("bench_token_generation_avg", alg.name, null, "avg");
      const isolatedTokenP95 = getNumber("bench_token_generation_p95", alg.name, null, "avg");
      const isolatedTokenStdev = getNumber("bench_token_generation_stdev", alg.name, null, "avg");
      const isolatedJWTSuccess = getCount("bench_iteration_success", alg.name, null);
      const isolatedJWTFailed = getCount("bench_iteration_failed", alg.name, null);
      const hasIsolatedJWT = isolatedJWTSuccess > 0;
      const isolatedRefreshAvg = getNumber(
        "bench_refresh_token_generation_avg",
        alg.name,
        null,
        "avg",
      );
      const isolatedRefreshP95 = getNumber(
        "bench_refresh_token_generation_p95",
        alg.name,
        null,
        "avg",
      );
      const isolatedRefreshStdev = getNumber(
        "bench_refresh_token_generation_stdev",
        alg.name,
        null,
        "avg",
      );
      const isolatedTokenGCFreeAvg = getNumber(
        "bench_token_generation_gc_free_avg",
        alg.name,
        null,
        "avg",
      );
      const isolatedTokenGCFreeP95 = getNumber(
        "bench_token_generation_gc_free_p95",
        alg.name,
        null,
        "avg",
      );
      const isolatedTokenGCFreeStdev = getNumber(
        "bench_token_generation_gc_free_stdev",
        alg.name,
        null,
        "avg",
      );
      const isolatedPureSuccess = getCount("bench_pure_signing_iteration_success", alg.name, null);
      const isolatedPureFailed = getCount("bench_pure_signing_iteration_failed", alg.name, null);
      const isolatedPureGCCnt = getCount(
        "bench_pure_signing_gc_contaminated_count",
        alg.name,
        null,
      );
      const hasIsolatedPure = isolatedPureSuccess > 0;
      const isolatedPureAvg = hasIsolatedPure
        ? getNumber("bench_pure_signing_avg", alg.name, null, "avg")
        : null;
      const isolatedPureP95 = hasIsolatedPure
        ? getNumber("bench_pure_signing_p95", alg.name, null, "avg")
        : null;
      const isolatedPureStdev = hasIsolatedPure
        ? getNumber("bench_pure_signing_stdev", alg.name, null, "avg")
        : null;
      const isolatedPureGCFreeAvg = hasIsolatedPure
        ? getNumber("bench_pure_signing_gc_free_avg", alg.name, null, "avg")
        : null;
      const isolatedPureGCFreeP95 = hasIsolatedPure
        ? getNumber("bench_pure_signing_gc_free_p95", alg.name, null, "avg")
        : null;
      const isolatedPureGCFreeStdev = hasIsolatedPure
        ? getNumber("bench_pure_signing_gc_free_stdev", alg.name, null, "avg")
        : null;
      const isolatedRefreshGCFreeAvg = getNumber(
        "bench_refresh_token_generation_gc_free_avg",
        alg.name,
        null,
        "avg",
      );
      const isolatedRefreshGCFreeP95 = getNumber(
        "bench_refresh_token_generation_gc_free_p95",
        alg.name,
        null,
        "avg",
      );
      const isolatedRefreshGCFreeStdev = getNumber(
        "bench_refresh_token_generation_gc_free_stdev",
        alg.name,
        null,
        "avg",
      );
      const isolatedTotalAvg = getNumber("bench_total_avg", alg.name, null, "avg");
      const isolatedTotalP95 = getNumber("bench_total_p95", alg.name, null, "avg");
      const isolatedTotalStdev = getNumber("bench_total_stdev", alg.name, null, "avg");
      const isolatedCPUAvg = getNumber("bench_auth_cpu_avg", alg.name, null, "avg");
      const isolatedCPUStdev = getNumber("bench_auth_cpu_stdev", alg.name, null, "avg");
      const isolatedCPUTimeAvg = getNumber("bench_auth_cpu_time_ms_avg", alg.name, null, "avg");
      const isolatedCPUTimeStdev = getNumber(
        "bench_auth_cpu_time_ms_stdev",
        alg.name,
        null,
        "avg",
      );
      const isolatedCPUTimePerTokenAvg = getNumber(
        "bench_auth_cpu_time_per_token_ms_avg",
        alg.name,
        null,
        "avg",
      );
      const isolatedCPUTimePerTokenStdev = getNumber(
        "bench_auth_cpu_time_per_token_ms_stdev",
        alg.name,
        null,
        "avg",
      );
      const isolatedMemAvg = getNumber("bench_auth_memory_alloc_kb_avg", alg.name, null, "avg");
      const isolatedMemStdev = getNumber(
        "bench_auth_memory_alloc_kb_stdev",
        alg.name,
        null,
        "avg",
      );
      const isolatedMemDeltaAvg = getNumber(
        "bench_auth_memory_alloc_delta_kb_avg",
        alg.name,
        null,
        "avg",
      );
      const isolatedMemDeltaStdev = getNumber(
        "bench_auth_memory_alloc_delta_kb_stdev",
        alg.name,
        null,
        "avg",
      );
      const isolatedMemSysAvg = getNumber("bench_auth_memory_sys_kb_avg", alg.name, null, "avg");
      const isolatedMemSysStdev = getNumber(
        "bench_auth_memory_sys_kb_stdev",
        alg.name,
        null,
        "avg",
      );
      const isolatedMemRSSAvg = getNumber("bench_auth_memory_rss_kb_avg", alg.name, null, "avg");
      const isolatedMemRSSStdev = getNumber(
        "bench_auth_memory_rss_kb_stdev",
        alg.name,
        null,
        "avg",
      );
      const isolatedGCCnt = getCount("bench_gc_contaminated_count", alg.name, null);
      const isolatedPureMemAvg = hasIsolatedPure
        ? getNumber("bench_pure_signing_memory_alloc_kb_avg", alg.name, null, "avg")
        : null;
      const isolatedPureMemStdev = hasIsolatedPure
        ? getNumber("bench_pure_signing_memory_alloc_kb_stdev", alg.name, null, "avg")
        : null;
      const isolatedPureMemRSSAvg = hasIsolatedPure
        ? getNumber("bench_pure_signing_memory_rss_kb_avg", alg.name, null, "avg")
        : null;
      const isolatedPureMemRSSStdev = hasIsolatedPure
        ? getNumber("bench_pure_signing_memory_rss_kb_stdev", alg.name, null, "avg")
        : null;

      const item = {
        algorithm: alg.name,
        jws_alg: jwsAlgForBenchmarkProfile(alg.name),
        category: alg.category,
        isolated: RUN_ISOLATED
          ? {
              iterations: ITERATIONS,
              endpoint: JWT_ISSUANCE_ENDPOINT,
              pure_signing_endpoint: PURE_SIGNING_ENDPOINT,
              metric_scope: "jwt_issuance",
              pure_signing_metric_scope: "pure_signing",
              jwt_issuance_success_count: isolatedJWTSuccess,
              jwt_issuance_failed_count: isolatedJWTFailed,
              pure_signing_success_count: isolatedPureSuccess,
              pure_signing_failed_count: isolatedPureFailed,
              gc_contaminated_count: isolatedGCCnt || 0,
              pure_signing_gc_contaminated_count: isolatedPureGCCnt || 0,
              pure_signing_ms: hasIsolatedPure
                ? {
                    avg: isolatedPureAvg,
                    min: getNumber("bench_pure_signing_sample", alg.name, null, "min"),
                    max: getNumber("bench_pure_signing_sample", alg.name, null, "max"),
                    p50: getNumber("bench_pure_signing_sample", alg.name, null, "med"),
                    p95: isolatedPureP95,
                    p99: getNumber("bench_pure_signing_sample", alg.name, null, "p(99)"),
                    sd: isolatedPureStdev,
                  }
                : null,
              pure_signing_gc_free_ms: hasIsolatedPure && isolatedPureGCFreeAvg != null
                ? {
                    avg: isolatedPureGCFreeAvg,
                    min: getNumber("bench_pure_signing_gc_free_sample", alg.name, null, "min"),
                    max: getNumber("bench_pure_signing_gc_free_sample", alg.name, null, "max"),
                    p50: getNumber("bench_pure_signing_gc_free_sample", alg.name, null, "med"),
                    p95: isolatedPureGCFreeP95,
                    p99: getNumber(
                      "bench_pure_signing_gc_free_sample",
                      alg.name,
                      null,
                      "p(99)",
                    ),
                    sd: isolatedPureGCFreeStdev,
                  }
                : null,
              pure_signing_memory_alloc_kb: hasIsolatedPure
                ? { avg: isolatedPureMemAvg, sd: isolatedPureMemStdev }
                : null,
              pure_signing_memory_rss_kb: hasIsolatedPure
                ? { avg: isolatedPureMemRSSAvg, sd: isolatedPureMemRSSStdev }
                : null,
              token_generation_ms: hasIsolatedJWT
                ? {
                    avg: isolatedTokenAvg,
                    min: getNumber("bench_token_generation_sample", alg.name, null, "min"),
                    max: getNumber("bench_token_generation_sample", alg.name, null, "max"),
                    p50: getNumber("bench_token_generation_sample", alg.name, null, "med"),
                    p95: isolatedTokenP95,
                    p99: getNumber("bench_token_generation_sample", alg.name, null, "p(99)"),
                    sd: isolatedTokenStdev,
                  }
                : null,
              token_generation_gc_free_ms: hasIsolatedJWT && isolatedTokenGCFreeAvg != null
                ? {
                    avg: isolatedTokenGCFreeAvg,
                    min: getNumber("bench_token_generation_gc_free_sample", alg.name, null, "min"),
                    max: getNumber("bench_token_generation_gc_free_sample", alg.name, null, "max"),
                    p50: getNumber("bench_token_generation_gc_free_sample", alg.name, null, "med"),
                    p95: isolatedTokenGCFreeP95,
                    p99: getNumber(
                      "bench_token_generation_gc_free_sample",
                      alg.name,
                      null,
                      "p(99)",
                    ),
                    sd: isolatedTokenGCFreeStdev,
                  }
                : null,
              refresh_token_generation_ms: hasIsolatedJWT
                ? {
                    avg: isolatedRefreshAvg,
                    min: getNumber(
                      "bench_refresh_token_generation_sample",
                      alg.name,
                      null,
                      "min",
                    ),
                    max: getNumber(
                      "bench_refresh_token_generation_sample",
                      alg.name,
                      null,
                      "max",
                    ),
                    p50: getNumber(
                      "bench_refresh_token_generation_sample",
                      alg.name,
                      null,
                      "med",
                    ),
                    p95: isolatedRefreshP95,
                    p99: getNumber(
                      "bench_refresh_token_generation_sample",
                      alg.name,
                      null,
                      "p(99)",
                    ),
                    sd: isolatedRefreshStdev,
                  }
                : null,
              refresh_token_generation_gc_free_ms: hasIsolatedJWT && isolatedRefreshGCFreeAvg != null
                ? {
                    avg: isolatedRefreshGCFreeAvg,
                    min: getNumber(
                      "bench_refresh_token_generation_gc_free_sample",
                      alg.name,
                      null,
                      "min",
                    ),
                    max: getNumber(
                      "bench_refresh_token_generation_gc_free_sample",
                      alg.name,
                      null,
                      "max",
                    ),
                    p50: getNumber(
                      "bench_refresh_token_generation_gc_free_sample",
                      alg.name,
                      null,
                      "med",
                    ),
                    p95: isolatedRefreshGCFreeP95,
                    p99: getNumber(
                      "bench_refresh_token_generation_gc_free_sample",
                      alg.name,
                      null,
                      "p(99)",
                    ),
                    sd: isolatedRefreshGCFreeStdev,
                  }
                : null,
              total_ms: hasIsolatedJWT
                ? {
                    avg: isolatedTotalAvg,
                    min: getNumber("bench_total_sample", alg.name, null, "min"),
                    max: getNumber("bench_total_sample", alg.name, null, "max"),
                    p50: getNumber("bench_total_sample", alg.name, null, "med"),
                    p95: isolatedTotalP95,
                    p99: getNumber("bench_total_sample", alg.name, null, "p(99)"),
                    sd: isolatedTotalStdev,
                  }
                : null,
              overhead_avg_ms:
                hasIsolatedJWT && isolatedTokenAvg != null && isolatedTotalAvg != null
                  ? isolatedTotalAvg - isolatedTokenAvg
                  : null,
              jwt_issuance_over_pure_avg_ms: hasIsolatedJWT
                ? subtractOrNull(isolatedTokenAvg, isolatedPureAvg)
                : null,
              jwt_issuance_over_pure_ratio: hasIsolatedJWT
                ? divideOrNull(isolatedTokenAvg, isolatedPureAvg)
                : null,
              jwt_issuance_over_pure_gc_free_avg_ms: subtractOrNull(
                hasIsolatedJWT ? isolatedTokenGCFreeAvg : null,
                isolatedPureGCFreeAvg,
              ),
              jwt_issuance_over_pure_gc_free_ratio: divideOrNull(
                hasIsolatedJWT ? isolatedTokenGCFreeAvg : null,
                isolatedPureGCFreeAvg,
              ),
              cpu_pct: hasIsolatedJWT
                ? {
                    avg: isolatedCPUAvg,
                    min: getNumber("bench_auth_cpu_avg", alg.name, null, "min"),
                    max: getNumber("bench_auth_cpu_avg", alg.name, null, "max"),
                    p50: getNumber("bench_auth_cpu_avg", alg.name, null, "med"),
                    p95: getNumber("bench_auth_cpu_avg", alg.name, null, "p(95)"),
                    p99: getNumber("bench_auth_cpu_avg", alg.name, null, "p(99)"),
                    sd: isolatedCPUStdev,
                  }
                : null,
              cpu_time_ms: hasIsolatedJWT
                ? {
                    avg: isolatedCPUTimeAvg,
                    min: getNumber("bench_auth_cpu_time_ms_avg", alg.name, null, "min"),
                    max: getNumber("bench_auth_cpu_time_ms_avg", alg.name, null, "max"),
                    p50: getNumber("bench_auth_cpu_time_ms_avg", alg.name, null, "med"),
                    p95: getNumber("bench_auth_cpu_time_ms_avg", alg.name, null, "p(95)"),
                    p99: getNumber("bench_auth_cpu_time_ms_avg", alg.name, null, "p(99)"),
                    sd: isolatedCPUTimeStdev,
                  }
                : null,
              cpu_time_per_token_ms: hasIsolatedJWT
                ? {
                    avg: isolatedCPUTimePerTokenAvg,
                    min: getNumber("bench_auth_cpu_time_per_token_ms_avg", alg.name, null, "min"),
                    max: getNumber("bench_auth_cpu_time_per_token_ms_avg", alg.name, null, "max"),
                    p50: getNumber("bench_auth_cpu_time_per_token_ms_avg", alg.name, null, "med"),
                    p95: getNumber("bench_auth_cpu_time_per_token_ms_avg", alg.name, null, "p(95)"),
                    p99: getNumber("bench_auth_cpu_time_per_token_ms_avg", alg.name, null, "p(99)"),
                    sd: isolatedCPUTimePerTokenStdev,
                  }
                : null,
              memory_alloc_kb: hasIsolatedJWT
                ? {
                    avg: isolatedMemAvg,
                    min: getNumber("bench_auth_memory_alloc_kb_avg", alg.name, null, "min"),
                    max: getNumber("bench_auth_memory_alloc_kb_avg", alg.name, null, "max"),
                    p50: getNumber("bench_auth_memory_alloc_kb_avg", alg.name, null, "med"),
                    p95: getNumber("bench_auth_memory_alloc_kb_avg", alg.name, null, "p(95)"),
                    p99: getNumber("bench_auth_memory_alloc_kb_avg", alg.name, null, "p(99)"),
                    sd: isolatedMemStdev,
                  }
                : null,
              memory_alloc_delta_kb: hasIsolatedJWT
                ? {
                    avg: isolatedMemDeltaAvg,
                    min: getNumber("bench_auth_memory_alloc_delta_kb_avg", alg.name, null, "min"),
                    max: getNumber("bench_auth_memory_alloc_delta_kb_avg", alg.name, null, "max"),
                    p50: getNumber("bench_auth_memory_alloc_delta_kb_avg", alg.name, null, "med"),
                    p95: getNumber("bench_auth_memory_alloc_delta_kb_avg", alg.name, null, "p(95)"),
                    p99: getNumber("bench_auth_memory_alloc_delta_kb_avg", alg.name, null, "p(99)"),
                    sd: isolatedMemDeltaStdev,
                  }
                : null,
              memory_sys_kb: hasIsolatedJWT
                ? {
                    avg: isolatedMemSysAvg,
                    min: getNumber("bench_auth_memory_sys_kb_avg", alg.name, null, "min"),
                    max: getNumber("bench_auth_memory_sys_kb_avg", alg.name, null, "max"),
                    p50: getNumber("bench_auth_memory_sys_kb_avg", alg.name, null, "med"),
                    p95: getNumber("bench_auth_memory_sys_kb_avg", alg.name, null, "p(95)"),
                    p99: getNumber("bench_auth_memory_sys_kb_avg", alg.name, null, "p(99)"),
                    sd: isolatedMemSysStdev,
                  }
                : null,
              memory_rss_kb: hasIsolatedJWT
                ? {
                    avg: isolatedMemRSSAvg,
                    min: getNumber("bench_auth_memory_rss_kb_avg", alg.name, null, "min"),
                    max: getNumber("bench_auth_memory_rss_kb_avg", alg.name, null, "max"),
                    p50: getNumber("bench_auth_memory_rss_kb_avg", alg.name, null, "med"),
                    p95: getNumber("bench_auth_memory_rss_kb_avg", alg.name, null, "p(95)"),
                    p99: getNumber("bench_auth_memory_rss_kb_avg", alg.name, null, "p(99)"),
                    sd: isolatedMemRSSStdev,
                  }
                : null,
            }
          : null,
        stress: [],
        attack: null,
      };

      // ── Stress: extract full k6 Trend distributions ───────────
      for (const vus of CONCURRENCY_LEVELS) {
        const vusKey = String(vus);
        function stressStat(metric, stat) {
          return getNumber(metric, alg.name, vusKey, stat);
        }

        const benchmarkTokenSuccess = getCount("stress_req_success", alg.name, vusKey);
        const benchmarkTokenFailed = getCount("stress_req_failed", alg.name, vusKey);
        const refreshSuccess = getCount("stress_refresh_success", alg.name, vusKey);
        const refreshFailed = getCount("stress_refresh_failed", alg.name, vusKey);
        const loginTotal = stressStat("stress_login_dirty", "count") || 0;

        if (
          benchmarkTokenSuccess + benchmarkTokenFailed + refreshSuccess + refreshFailed + loginTotal ===
          0
        ) {
          continue;
        }

        const signAvg = getNumber("stress_token_generation_clean", alg.name, vusKey, "avg");
        const refreshAvg = getNumber(
          "stress_refresh_token_generation_clean",
          alg.name,
          vusKey,
          "avg",
        );
        const e2eAvg = getNumber("stress_sign_dirty", alg.name, vusKey, "avg");

        if (signAvg === null && refreshAvg === null && e2eAvg === null) {
          continue;
        }

        item.stress.push({
          vus,
          load: {
            executor: "constant-vus",
            load_model: "closed-loop",
            duration_seconds: STRESS_DURATION_S,
            ramp_up_seconds: 0,
            steady_state_seconds: STRESS_DURATION_S,
            ramp_down_seconds: 0,
            think_time_seconds: STRESS_THINK_TIME_S,
          },
          requests: {
            benchmark_token_success: benchmarkTokenSuccess,
            benchmark_token_failed: benchmarkTokenFailed,
            benchmark_token_total: benchmarkTokenSuccess + benchmarkTokenFailed,
            login_total: loginTotal,
            refresh_success: refreshSuccess,
            refresh_failed: refreshFailed,
            refresh_total: refreshSuccess + refreshFailed,
          },
          token_generation_ms: {
            avg: stressStat("stress_token_generation_clean", "avg"),
            min: stressStat("stress_token_generation_clean", "min"),
            max: stressStat("stress_token_generation_clean", "max"),
            med: stressStat("stress_token_generation_clean", "med"),
            p95: stressStat("stress_token_generation_clean", "p(95)"),
            p99: stressStat("stress_token_generation_clean", "p(99)"),
          },
          refresh_token_generation_ms: {
            avg: stressStat("stress_refresh_token_generation_clean", "avg"),
            min: stressStat("stress_refresh_token_generation_clean", "min"),
            max: stressStat("stress_refresh_token_generation_clean", "max"),
            med: stressStat("stress_refresh_token_generation_clean", "med"),
            p95: stressStat("stress_refresh_token_generation_clean", "p(95)"),
            p99: stressStat("stress_refresh_token_generation_clean", "p(99)"),
          },
          refresh_ms: {
            avg: stressStat("stress_refresh_dirty", "avg"),
            min: stressStat("stress_refresh_dirty", "min"),
            max: stressStat("stress_refresh_dirty", "max"),
            med: stressStat("stress_refresh_dirty", "med"),
            p95: stressStat("stress_refresh_dirty", "p(95)"),
            p99: stressStat("stress_refresh_dirty", "p(99)"),
          },
          e2e_ms: {
            avg: stressStat("stress_sign_dirty", "avg"),
            min: stressStat("stress_sign_dirty", "min"),
            max: stressStat("stress_sign_dirty", "max"),
            med: stressStat("stress_sign_dirty", "med"),
            p95: stressStat("stress_sign_dirty", "p(95)"),
            p99: stressStat("stress_sign_dirty", "p(99)"),
          },
          throughput_ok_per_s: parseFloat(getThroughput(alg.name, vusKey)) || 0,
          request_rate_per_s: parseFloat(getRequestRate(alg.name, vusKey)) || 0,
          login_ms: {
            avg: stressStat("stress_login_dirty", "avg"),
            min: stressStat("stress_login_dirty", "min"),
            max: stressStat("stress_login_dirty", "max"),
            med: stressStat("stress_login_dirty", "med"),
            p95: stressStat("stress_login_dirty", "p(95)"),
            p99: stressStat("stress_login_dirty", "p(99)"),
          },
          error_rate_pct: (() => {
            const v = getErrRate(alg.name, vusKey);
            return v === "—" ? null : parseFloat(v);
          })(),
          refresh_error_rate_pct: (() => {
            const key = `stress_refresh_error_rate{alg:${alg.name},vus:${vusKey}}`;
            if (!(key in m)) return null;
            const v = m[key].values.rate;
            return v === undefined ? null : v * 100;
          })(),
        });
      }

      const attackRate = getAttackBlockRate(alg.name);
      if (attackRate !== "—") {
        item.attack = {
          tampered_token_block_rate_pct: parseFloat(attackRate),
        };
      }

      result.algorithms.push(item);
    }

    return result;
  }

  const SEP = "═".repeat(170);
  const LINE = "─".repeat(170);

  function pad(s, w) {
    const str = String(s);
    return str.length >= w ? str.slice(0, w - 1) + " " : str + " ".repeat(w - str.length);
  }

  function appendRow(section, row) {
    return section + row;
  }

  // ── TABLE 1: Isolated GC-free JWT generation baseline ────────
  const WI = [28, 6, 12, 12, 12, 12, 12, 12, 12, 10, 10];

  const hdrI = [
    pad("Algorithm", WI[0]),
    pad("N", WI[1]),
    pad("Pure avg", WI[2]),
    pad("Pure p95", WI[3]),
    pad("Access avg", WI[4]),
    pad("Access p95", WI[5]),
    pad("Refresh avg", WI[6]),
    pad("Refresh p95", WI[7]),
    pad("E2E avg", WI[8]),
    pad("CPU avg", WI[9]),
    pad("RSS avg", WI[10]),
  ].join("");

  const unitI = [
    pad("", WI[0]),
    pad("iters", WI[1]),
    pad("(ms)", WI[2]),
    pad("(ms)", WI[3]),
    pad("(ms)", WI[4]),
    pad("(ms)", WI[5]),
    pad("(ms)", WI[6]),
    pad("(ms)", WI[7]),
    pad("(ms)", WI[8]),
    pad("(%)", WI[9]),
    pad("(KB)", WI[10]),
  ].join("");

  let isolated = "";

  for (const alg of ALGORITHMS) {
    const n = alg.name;
    const hasJWT = getCount("bench_success", n, null) > 0;
    const hasPure = getCount("bench_pure_signing_success", n, null) > 0;
    const pa = hasPure
      ? getValFallback("bench_pure_signing_gc_free_avg", "bench_pure_signing_avg", n, null, "avg")
      : "—";
    const pp = hasPure
      ? getValFallback("bench_pure_signing_gc_free_p95", "bench_pure_signing_p95", n, null, "avg")
      : "—";
    const sa = hasJWT
      ? getValFallback(
          "bench_token_generation_gc_free_avg",
          "bench_token_generation_avg",
          n,
          null,
          "avg",
        )
      : "—";
    const sp = hasJWT
      ? getValFallback(
          "bench_token_generation_gc_free_p95",
          "bench_token_generation_p95",
          n,
          null,
          "avg",
        )
      : "—";
    const ra = hasJWT
      ? getValFallback(
          "bench_refresh_token_generation_gc_free_avg",
          "bench_refresh_token_generation_avg",
          n,
          null,
          "avg",
        )
      : "—";
    const rp = hasJWT
      ? getValFallback(
          "bench_refresh_token_generation_gc_free_p95",
          "bench_refresh_token_generation_p95",
          n,
          null,
          "avg",
        )
      : "—";
    const ta = hasJWT ? getVal("bench_total_avg", n, null, "avg") : "—";
    const cpu = hasJWT ? getVal("bench_auth_cpu_avg", n, null, "avg") : "—";
    const rss = hasJWT ? getVal("bench_auth_memory_rss_kb_avg", n, null, "avg") : "—";

    const row =
      [
        pad(n, WI[0]),
        pad(ITERATIONS, WI[1]),
        pad(pa, WI[2]),
        pad(pp, WI[3]),
        pad(sa, WI[4]),
        pad(sp, WI[5]),
        pad(ra, WI[6]),
        pad(rp, WI[7]),
        pad(ta, WI[8]),
        pad(cpu, WI[9]),
        pad(rss, WI[10]),
      ].join("") + "\n";

    isolated = appendRow(isolated, row);
  }

  // ── TABLE 2: Primary stress metrics ──────────────────────────
  const WP = [28, 6, 12, 12, 12, 12, 12];

  const hdrP = [
    pad("Algorithm", WP[0]),
    pad("VUs", WP[1]),
    pad("Access avg", WP[2]),
    pad("Access p95", WP[3]),
    pad("Refresh avg", WP[4]),
    pad("Refresh p95", WP[5]),
    pad("Token ok/s", WP[6]),
  ].join("");

  const unitP = [
    pad("", WP[0]),
    pad("", WP[1]),
    pad("(ms)", WP[2]),
    pad("(ms)", WP[3]),
    pad("(ms)", WP[4]),
    pad("(ms)", WP[5]),
    pad("(ok/s)", WP[6]),
  ].join("");

  // ── TABLE 3: Secondary stress metrics ────────────────────────
  const WS = [28, 6, 12, 12, 12, 12, 12, 12, 12, 12, 12];

  const hdrS = [
    pad("Algorithm", WS[0]),
    pad("VUs", WS[1]),
    pad("Login avg", WS[2]),
    pad("Login p95", WS[3]),
    pad("Refresh avg", WS[4]),
    pad("Refresh p95", WS[5]),
    pad("E2E avg", WS[6]),
    pad("E2E p95", WS[7]),
    pad("RPS", WS[8]),
    pad("ErrRate", WS[9]),
    pad("Atk block", WS[10]),
  ].join("");

  const unitS = [
    pad("", WS[0]),
    pad("", WS[1]),
    pad("(ms)", WS[2]),
    pad("(ms)", WS[3]),
    pad("(ms)", WS[4]),
    pad("(ms)", WS[5]),
    pad("(ms)", WS[6]),
    pad("(ms)", WS[7]),
    pad("req/s", WS[8]),
    pad("", WS[9]),
    pad("", WS[10]),
  ].join("");

  let primary = "";
  let secondary = "";

  for (const alg of ALGORITHMS) {
    const n = alg.name;
    const attackRate = getAttackBlockRate(n);
    for (let i = 0; i < CONCURRENCY_LEVELS.length; i++) {
      const vus = String(CONCURRENCY_LEVELS[i]);
      const label = i === 0 ? n : "";

      const rowP =
        [
          pad(label, WP[0]),
          pad(vus, WP[1]),
          pad(getVal("stress_token_generation_clean", n, vus, "avg"), WP[2]),
          pad(getVal("stress_token_generation_clean", n, vus, "p(95)"), WP[3]),
          pad(getVal("stress_refresh_token_generation_clean", n, vus, "avg"), WP[4]),
          pad(getVal("stress_refresh_token_generation_clean", n, vus, "p(95)"), WP[5]),
          pad(getThroughput(n, vus), WP[6]),
        ].join("") + "\n";

      const rowS =
        [
          pad(label, WS[0]),
          pad(vus, WS[1]),
          pad(getVal("stress_login_dirty", n, vus, "avg"), WS[2]),
          pad(getVal("stress_login_dirty", n, vus, "p(95)"), WS[3]),
          pad(getVal("stress_refresh_dirty", n, vus, "avg"), WS[4]),
          pad(getVal("stress_refresh_dirty", n, vus, "p(95)"), WS[5]),
          pad(getVal("stress_sign_dirty", n, vus, "avg"), WS[6]),
          pad(getVal("stress_sign_dirty", n, vus, "p(95)"), WS[7]),
          pad(getRequestRate(n, vus), WS[8]),
          pad(getErrRate(n, vus), WS[9]),
          pad(i === 0 ? attackRate : "", WS[10]),
        ].join("") + "\n";

      primary = appendRow(primary, rowP);
      secondary = appendRow(secondary, rowS);
    }
    const sepP = pad("", WP[0] + WP[1]) + "─".repeat(WP.slice(2).reduce((a, b) => a + b, 0)) + "\n";
    const sepS = pad("", WS[0] + WS[1]) + "─".repeat(WS.slice(2).reduce((a, b) => a + b, 0)) + "\n";
    primary = appendRow(primary, sepP);
    secondary = appendRow(secondary, sepS);
  }

  const table = `
${SEP}
  JWT GENERATION LATENCY STUDY  —  ${new Date().toISOString()}
  Mode      : ${ATTACK_ONLY ? "Attack only" : STRESS_ONLY ? "Stress only" : ISOLATED_ONLY ? "Isolated only" : "Isolated + Stress + Attack"}
  Endpoint  : ${isMultiGateway ? `${HOST_BASE}:{5001-${5000 + ALGORITHMS.length}}` : SINGLE_BASE}
${SEP}

  ── PRIMARY THESIS METRIC: ISOLATED GC-FREE JWT GENERATION (1 VU, ${ITERATIONS} iterations) ──
  ${hdrI}
  ${unitI}
  ${LINE}
  ${isolated.trimEnd().split("\n").join("\n  ")}

  Pure           = GC-free direct SigningMethod.Sign over fixed message; fallback to all samples
  Access/Refresh = GC-free JWT generation from benchmark payload when available; fallback to all samples
  E2E            = Full local JWT issuance handler iteration during isolated benchmark
  Warmup         = ${ISOLATED_WARMUP} discarded iterations before each isolated measurement

  ── SUPPORTING SYSTEM METRICS: STRESS (${CONCURRENCY_LEVELS.join(" / ")} VUs, ${STRESS_DURATION_S}s each) ──
  ${hdrP}
  ${unitP}
  ${LINE}
  ${primary.trimEnd().split("\n").join("\n  ")}

  ── SECONDARY METRICS: END-TO-END, ERROR RATE, ATTACK BLOCK RATE ──
  ${hdrS}
  ${unitS}
  ${LINE}
  ${secondary.trimEnd().split("\n").join("\n  ")}

  Pure avg/p95 = /api/benchmark/pure-signing; no JWT serialization/Base64URL/compact assembly
  Access avg/p95 = X-Token-Generation-Time-Ms header; JWT generation from benchmark payload only
  Refresh avg/p95 = X-Refresh-Token-Generation-Time-Ms header on /api/auth/refresh
  Token ok/s   = Successful /api/benchmark/token responses / ${STRESS_DURATION_S}s
  Login        = Full /api/auth/signin round-trip: bcrypt verify + DB lookup + JWT generation
  Refresh      = Full /api/auth/refresh round-trip: refresh-token verify + JWT rotation
  E2E          = Full k6 client round-trip for /api/benchmark/token (JWT generation only, no bcrypt/DB)
  RPS          = Total benchmark-token requests / ${STRESS_DURATION_S}s
  Atk block    = Tampered-token /api/profile requests blocked with 401/403
  Thesis note  = Primary thesis result = isolated table; supporting system result = stress tables
${SEP}
`;

  return {
    stdout: table,
    [summaryFile("benchmark_sign_result.json")]: JSON.stringify(buildAcademicResult(), null, 2),
    [summaryFile("benchmark_sign_raw.json")]: JSON.stringify(data, null, 2),
  };
}
