/**
 * benchmark_sign.js
 *
 * Two-phase signing latency study:
 *
 *   Phase 1 — ISOLATED (1 VU, server-side loop)
 *     POST /api/benchmark/sign with N iterations.
 *     Uses gateway-local pure signing path, no DB/bcrypt/auth-service noise.
 *     Warmup iterations are discarded before measurement.
 *     Use these numbers in academic papers.
 *
 *   Phase 2 — STRESS TEST (10 / 30 / 50 VUs, constant-vus)
 *     Each VU hits /api/benchmark/token directly.
 *     Shows how latency and throughput degrade under concurrent load.
 *     Thresholds fail the run if p95 or error rate exceeds per-algorithm budget.
 *
 * Usage:
 *   # Single-gateway (production / VPS):
 *   k6 run -e BASE_URL=https://poc-ridwanmuh3.my.id k6/benchmark_sign.js
 *
 *   # Multi-gateway (docker-compose.benchmark.yml):
 *   k6 run -e BENCH_HOST=localhost k6/benchmark_sign.js
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
 *                            pure JWT generation only, no DB/bcrypt/auth-service latency
 *   clean                  = k6 timings.waiting — TTFB/server processing approx
 *   dirty                  = k6 timings.duration — full client round-trip
 *   network                = dirty − clean
 *
 * Primary metrics:
 *   signing latency, p95 signing latency, authentication throughput,
 *   memory usage, CPU utilization
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

function normalizeBase(url) {
  if (!url) return "";
  if (url.startsWith("http://") || url.startsWith("https://")) return url;
  return "http://" + url;
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
const ISOLATED_GAP_S = 5; // gap between isolated scenarios
const PHASE_GAP_S = 30; // settle gap between Phase 1 and Phase 2
const ATTACK_ITERATIONS = parseInt(__ENV.ATTACK_ITERATIONS || "25", 10);
const ATTACK_GAP_S = 5;
const RUN_ISOLATED = !STRESS_ONLY && !ATTACK_ONLY;
const RUN_STRESS = !ISOLATED_ONLY && !ATTACK_ONLY;
const RUN_ATTACKS =
  ((!ISOLATED_ONLY && !STRESS_ONLY) || ATTACK_ONLY) && ATTACK_ITERATIONS > 0;

const ALGORITHMS = [
  { id: "FNP512", name: "Falcon-Precomputed-512", category: "PQC", port: 5001 },
  { id: "FN512", name: "Falcon-512", category: "PQC", port: 5002 },
  { id: "MLDSA44", name: "ML-DSA-44", category: "PQC", port: 5003 },
  { id: "SLHDSA128f", name: "SLH-DSA-SHA2-128f", category: "PQC", port: 5004 },
  { id: "SLHDSA128s", name: "SLH-DSA-SHA2-128s", category: "PQC", port: 5005 },
  // { id: "ES256",   name: "ES256",                   category: "Classic", port: 5008 },
  // { id: "RS256",   name: "RS256",                   category: "Classic", port: 5009 },
  // { id: "HS256",   name: "HS256",                   category: "Classic", port: 5010 },
  // { id: "EdDSA",   name: "EdDSA",                   category: "Classic", port: 5011 },
];

// Per-algorithm p95 latency budget for stress test thresholds (ms).
// Dirty = full k6 round-trip budget; Actual = server-side pure signing budget.
const STRESS_BUDGET = {
  "Falcon-Precomputed-512": { dirty: 5000, actual: 500 },
  "Falcon-512": { dirty: 10000, actual: 1000 },
  "ML-DSA-44": { dirty: 10000, actual: 500 },
  "SLH-DSA-SHA2-128f": { dirty: 90000, actual: 30000 },
  "SLH-DSA-SHA2-128s": { dirty: 300000, actual: 120000 },
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

// ═══════════════════════════════════════════════════════════════
// Scenarios
// ═══════════════════════════════════════════════════════════════

const scenarios = {};
let startDelay = 0;

// ── Phase 1: Isolated (1 VU, server loops ITERATIONS times) ──
if (RUN_ISOLATED) {
  for (const alg of ALGORITHMS) {
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
  for (const alg of ALGORITHMS) {
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
  for (const alg of ALGORITHMS) {
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

// ── Phase 1: Isolated — values reported by /api/benchmark/sign ─
const benchSignP95 = new Trend("bench_sign_p95", true);
const benchSignAvg = new Trend("bench_sign_avg", true);
const benchSignMin = new Trend("bench_sign_min", true);
const benchSignMax = new Trend("bench_sign_max", true);
const benchSignStdev = new Trend("bench_sign_stdev", true);
const benchTokenGenerationP95 = new Trend("bench_token_generation_p95", true);
const benchTokenGenerationAvg = new Trend("bench_token_generation_avg", true);
const benchTokenGenerationStdev = new Trend(
  "bench_token_generation_stdev",
  true,
);
const benchTotalP95 = new Trend("bench_total_p95", true);
const benchTotalAvg = new Trend("bench_total_avg", true);
const benchAuthCPUAvg = new Trend("bench_auth_cpu_avg", true);
const benchAuthMemoryAllocAvg = new Trend("bench_auth_memory_alloc_avg", true);
const benchAuthMemoryAllocDeltaAvg = new Trend("bench_auth_memory_alloc_delta_avg", true);
const benchAuthMemorySysAvg = new Trend("bench_auth_memory_sys_avg", true);
const benchTokenSizeAvg = new Trend("bench_token_size_avg");
const benchTokenHeaderSizeAvg = new Trend("bench_token_header_size_avg");
const benchTokenBodySizeAvg = new Trend("bench_token_body_size_avg");
const benchSuccess = new Counter("bench_success");
const benchFailed = new Counter("bench_failed");

// ── Phase 2: Stress — per benchmark sign call, tagged {alg, vus} ──────
// tokenGenerationClean = X-Token-Generation-Time-Ms / X-Sign-Time-Ms
// clean                = timings.waiting (server processing approx — TTFB after send)
// dirty                = timings.duration (full k6 round-trip)
// network              = dirty - clean
const stressSignActual = new Trend("stress_sign_actual", true);
const stressTokenGenerationClean = new Trend(
  "stress_token_generation_clean",
  true,
);
const stressSignClean = new Trend("stress_sign_clean", true);
const stressSignDirty = new Trend("stress_sign_dirty", true);
const stressSignNetwork = new Trend("stress_sign_network", true);
const stressAuthCPU = new Trend("stress_auth_cpu", true);
const stressAuthMemoryAlloc = new Trend("stress_auth_memory_alloc", true);
const stressAuthMemoryAllocDelta = new Trend("stress_auth_memory_alloc_delta", true);
const stressAuthMemorySys = new Trend("stress_auth_memory_sys", true);
const stressTokenSize = new Trend("stress_token_size");
const stressTokenHeaderSize = new Trend("stress_token_header_size");
const stressTokenBodySize = new Trend("stress_token_body_size");
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
}

if (RUN_STRESS) {
  thresholds.stress_error_rate = ["rate<0.01"]; // overall <1% error rate
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
      thresholds[`stress_auth_cpu${tv}`] = [`p(95)<9999999`];
      thresholds[`stress_auth_memory_alloc${tv}`] = [`p(95)<9999999`];
      thresholds[`stress_auth_memory_alloc_delta${tv}`] = [`p(95)<9999999`];
      thresholds[`stress_auth_memory_sys${tv}`] = [`p(95)<9999999`];
      thresholds[`stress_token_size${tv}`] = [`avg>=0`];
      thresholds[`stress_token_header_size${tv}`] = [`avg>=0`];
      thresholds[`stress_token_body_size${tv}`] = [`avg>=0`];
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
    thresholds[`bench_total_p95${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_total_avg${ta}`] = [`avg>=0`];
    thresholds[`bench_auth_cpu_avg${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_auth_memory_alloc_avg${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_auth_memory_alloc_delta_avg${ta}`] = [`p(95)<9999999`];
    thresholds[`bench_token_size_avg${ta}`] = [`avg>=0`];
    thresholds[`bench_token_header_size_avg${ta}`] = [`avg>=0`];
    thresholds[`bench_token_body_size_avg${ta}`] = [`avg>=0`];
    thresholds[`bench_success${ta}`] = [`count>=0`];
  }
  if (RUN_ATTACKS) {
    thresholds[`attack_block_rate${ta}`] = [`rate>0.99`];
  }
}

export const options = {
  scenarios,
  thresholds,
  setupTimeout: "180s",
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

  const firstAlg = ALGORITHMS[0];
  const registerUrl = `${getBaseUrl(firstAlg)}/api/auth/register`;
  console.log(`Registering benchmark user at: ${registerUrl}`);

  let regRes;
  for (let attempt = 1; attempt <= 90; attempt++) {
    regRes = http.post(registerUrl, JSON.stringify(user), {
      headers: { "Content-Type": "application/json" },
      timeout: "5s",
    });
    if (regRes.status !== 0) break;
    console.log(`[${attempt}/90] Service not ready, retrying in 2s...`);
    sleep(2);
  }

  if (regRes.status === 0) {
    exec.test.abort(
      `Service ${registerUrl} unreachable after 180s — ensure docker-compose is running`,
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

  const res = http.post(`${BASE}/api/benchmark/sign`, payload, {
    headers: { "Content-Type": "application/json" },
    timeout: "600s",
  });

  const ok = check(res, {
    [`[isolated|${alg.name}] 200`]: (r) => r.status === 200,
    [`[isolated|${alg.name}] has stats`]: (r) => {
      try {
        return !!JSON.parse(r.body).data?.stats;
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

  benchSuccess.add(1, tags);

  try {
    const result = JSON.parse(res.body).data;
    const s = result.stats;

    benchSignP95.add(s.sign.p95_ms, tags);
    benchSignAvg.add(s.sign.avg_ms, tags);
    benchSignMin.add(s.sign.min_ms, tags);
    benchSignMax.add(s.sign.max_ms, tags);
    benchSignStdev.add(s.sign.stdev_ms, tags);
    benchTokenGenerationP95.add(
      s.token_generation?.p95_ms ?? s.sign.p95_ms,
      tags,
    );
    benchTokenGenerationAvg.add(
      s.token_generation?.avg_ms ?? s.sign.avg_ms,
      tags,
    );
    benchTokenGenerationStdev.add(
      s.token_generation?.stdev_ms ?? s.sign.stdev_ms,
      tags,
    );
    benchTotalP95.add(s.total.p95_ms, tags);
    benchTotalAvg.add(s.total.avg_ms, tags);
    benchAuthCPUAvg.add(s.resource?.cpu_utilization_pct?.avg ?? 0, tags);
    benchAuthMemoryAllocAvg.add(s.resource?.memory_alloc_mb?.avg ?? 0, tags);
    benchAuthMemoryAllocDeltaAvg.add(s.resource?.memory_alloc_delta_mb?.avg ?? 0, tags);
    benchAuthMemorySysAvg.add(s.resource?.memory_sys_mb?.avg ?? 0, tags);
    benchTokenSizeAvg.add(s.token_size?.token?.avg ?? 0, tags);
    benchTokenHeaderSizeAvg.add(s.token_size?.header?.avg ?? 0, tags);
    benchTokenBodySizeAvg.add(s.token_size?.body?.avg ?? 0, tags);

    console.log(
      `[isolated|${alg.name}] n=${result.success_count}/${result.iterations}` +
        ` warmup=${result.warmup_iterations}` +
        ` | token_generation: avg=${(s.token_generation?.avg_ms ?? s.sign.avg_ms)?.toFixed(3)} p95=${(s.token_generation?.p95_ms ?? s.sign.p95_ms)?.toFixed(3)} stdev=${(s.token_generation?.stdev_ms ?? s.sign.stdev_ms)?.toFixed(3)} ms` +
        ` | total: avg=${s.total.avg_ms?.toFixed(3)} p95=${s.total.p95_ms?.toFixed(3)} ms`,
    );
  } catch (e) {
    console.error(`[isolated|${alg.name}] parse error: ${e}`);
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

function addTokenSizeMetrics(token, tags) {
  if (!token) return;
  stressTokenSize.add(token.length, tags);
  const parts = token.split(".");
  if (parts.length !== 3) return;
  stressTokenHeaderSize.add(parts[0].length, tags);
  stressTokenBodySize.add(parts[1].length, tags);
}

function warmupBenchmarkToken(base, body, headers) {
  http.post(`${base}/api/benchmark/token`, body, { headers });
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
// Phase 2: Stress — concurrent pure-sign calls, latency under load
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
    warmupBenchmarkToken(BASE, body, jsonHdr);
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

    const cpuPct = getHeaderNumber(res, ["X-Auth-CPU-Pct", "x-auth-cpu-pct"]);
    if (cpuPct !== null) stressAuthCPU.add(cpuPct, tags);

    const memAllocMB = getHeaderNumber(res, [
      "X-Auth-Mem-Alloc-MB",
      "x-auth-mem-alloc-mb",
    ]);
    if (memAllocMB !== null) stressAuthMemoryAlloc.add(memAllocMB, tags);

    const memAllocDeltaMB = getHeaderNumber(res, [
      "X-Auth-Mem-Alloc-Delta-MB",
      "x-auth-mem-alloc-delta-mb",
    ]);
    if (memAllocDeltaMB !== null) stressAuthMemoryAllocDelta.add(memAllocDeltaMB, tags);

    const memSysMB = getHeaderNumber(res, [
      "X-Auth-Mem-Sys-MB",
      "x-auth-mem-sys-mb",
    ]);
    if (memSysMB !== null) stressAuthMemorySys.add(memSysMB, tags);

    let accessToken = "";
    try {
      accessToken = JSON.parse(res.body).data?.access_token || "";
      addTokenSizeMetrics(accessToken, tags);
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

  sleep(0.05);
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
      endpoint: isMultiGateway
        ? `${HOST_BASE}:{5001-${5000 + ALGORITHMS.length}}`
        : SINGLE_BASE,
      methodology: {
        primary_metric: "isolated_clean_token_generation",
        supporting_metric: "stress_concurrent_signing",
        isolated_iterations: ITERATIONS,
        isolated_warmup_iterations: ISOLATED_WARMUP,
        stress_duration_seconds: STRESS_DURATION_S,
        stress_warmup_enabled: STRESS_WARMUP,
        concurrency_levels: CONCURRENCY_LEVELS,
        notes: [
          "Isolated metrics use gateway-local pure signing path.",
          "Stress metrics use /api/benchmark/token instead of /api/auth/signin.",
          "Raw k6 aggregate metrics are omitted here because they mix algorithms and scenarios.",
        ],
      },
      algorithms: [],
    };

    for (const alg of ALGORITHMS) {
      const item = {
        algorithm: alg.name,
        category: alg.category,
        isolated: null,
        stress: [],
        attack: null,
      };

      const isolatedTokenAvg = getNumber("bench_token_generation_avg", alg.name, null, "avg");
      const isolatedTokenP95 = getNumber("bench_token_generation_p95", alg.name, null, "avg");
      const isolatedTokenStdev = getNumber("bench_token_generation_stdev", alg.name, null, "avg");
      const isolatedTotalAvg = getNumber("bench_total_avg", alg.name, null, "avg");
      const isolatedTotalP95 = getNumber("bench_total_p95", alg.name, null, "avg");
      const isolatedCPUAvg = getNumber("bench_auth_cpu_avg", alg.name, null, "avg");
      const isolatedMemAvg = getNumber("bench_auth_memory_alloc_avg", alg.name, null, "avg");
      const isolatedMemDeltaAvg = getNumber("bench_auth_memory_alloc_delta_avg", alg.name, null, "avg");
      const isolatedTokBytes = getNumber("bench_token_size_avg", alg.name, null, "avg");

      if (isolatedTokenAvg !== null || isolatedTotalAvg !== null) {
        item.isolated = {
          token_generation_avg_ms: isolatedTokenAvg,
          token_generation_p95_ms: isolatedTokenP95,
          token_generation_stdev_ms: isolatedTokenStdev,
          total_avg_ms: isolatedTotalAvg,
          total_p95_ms: isolatedTotalP95,
          overhead_avg_ms:
            isolatedTokenAvg !== null && isolatedTotalAvg !== null
              ? isolatedTotalAvg - isolatedTokenAvg
              : null,
          cpu_avg_pct: isolatedCPUAvg,
          memory_alloc_avg_mb: isolatedMemAvg,
          memory_alloc_delta_avg_mb: isolatedMemDeltaAvg,
          memory_sys_avg_mb: getNumber("bench_auth_memory_sys_avg", alg.name, null, "avg"),
          token_size_avg_bytes: isolatedTokBytes,
        };
      }

      for (const vus of CONCURRENCY_LEVELS) {
        const vusKey = String(vus);
        const signAvg = getNumber("stress_token_generation_clean", alg.name, vusKey, "avg");
        const signP95 = getNumber("stress_token_generation_clean", alg.name, vusKey, "p(95)");
        const e2eAvg = getNumber("stress_sign_dirty", alg.name, vusKey, "avg");
        const e2eP95 = getNumber("stress_sign_dirty", alg.name, vusKey, "p(95)");

        if (signAvg === null && e2eAvg === null) {
          continue;
        }

        item.stress.push({
          vus,
          token_generation_avg_ms: signAvg,
          token_generation_p95_ms: signP95,
          e2e_avg_ms: e2eAvg,
          e2e_p95_ms: e2eP95,
          throughput_ok_per_s: parseFloat(getThroughput(alg.name, vusKey)) || 0,
          request_rate_per_s: parseFloat(getRequestRate(alg.name, vusKey)) || 0,
          cpu_avg_pct: getNumber("stress_auth_cpu", alg.name, vusKey, "avg"),
          memory_alloc_avg_mb: getNumber("stress_auth_memory_alloc", alg.name, vusKey, "avg"),
          memory_alloc_delta_avg_mb: getNumber("stress_auth_memory_alloc_delta", alg.name, vusKey, "avg"),
          memory_sys_avg_mb: getNumber("stress_auth_memory_sys", alg.name, vusKey, "avg"),
          error_rate_pct:
            (() => {
              const v = getErrRate(alg.name, vusKey);
              return v === "—" ? null : parseFloat(v);
            })(),
          token_size_avg_bytes: getNumber("stress_token_size", alg.name, vusKey, "avg"),
          token_header_avg_bytes: getNumber("stress_token_header_size", alg.name, vusKey, "avg"),
          token_body_avg_bytes: getNumber("stress_token_body_size", alg.name, vusKey, "avg"),
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

  const SEP = "═".repeat(156);
  const LINE = "─".repeat(156);

  function pad(s, w) {
    const str = String(s);
    return str.length >= w
      ? str.slice(0, w - 1) + " "
      : str + " ".repeat(w - str.length);
  }

  function appendRow(section, row) {
    return section + row;
  }

  // ── TABLE 1: Isolated clean token-generation baseline ─────────
  const WI = [28, 6, 12, 12, 12, 12, 12, 10, 10];

  const hdrI = [
    pad("Algorithm", WI[0]),
    pad("N", WI[1]),
    pad("Token avg", WI[2]),
    pad("Token p95", WI[3]),
    pad("Token stdev", WI[4]),
    pad("E2E avg", WI[5]),
    pad("E2E p95", WI[6]),
    pad("CPU avg", WI[7]),
    pad("Mem avg", WI[8]),
    pad("Tok bytes", WI[8]),
  ].join("");

  const unitI = [
    pad("", WI[0]),
    pad("iters", WI[1]),
    pad("(ms)", WI[2]),
    pad("(ms)", WI[3]),
    pad("(ms)", WI[4]),
    pad("(ms)", WI[5]),
    pad("(ms)", WI[6]),
    pad("(%)", WI[7]),
    pad("(MB)", WI[8]),
    pad("(B)", WI[8]),
  ].join("");

  let isolated = "";

  for (const alg of ALGORITHMS) {
    const n = alg.name;
    const sa = getVal("bench_token_generation_avg", n, null, "avg");
    const sp = getVal("bench_token_generation_p95", n, null, "avg");
    const ss = getVal("bench_token_generation_stdev", n, null, "avg");
    const ta = getVal("bench_total_avg", n, null, "avg");
    const tp = getVal("bench_total_p95", n, null, "avg");
    const cpu = getVal("bench_auth_cpu_avg", n, null, "avg");
    const mem = getVal("bench_auth_memory_alloc_avg", n, null, "avg");
    const tok = getVal("bench_token_size_avg", n, null, "avg", 0);

    const row =
      [
        pad(n, WI[0]),
        pad(ITERATIONS, WI[1]),
        pad(sa, WI[2]),
        pad(sp, WI[3]),
        pad(ss, WI[4]),
        pad(ta, WI[5]),
        pad(tp, WI[6]),
        pad(cpu, WI[7]),
        pad(mem, WI[8]),
        pad(tok, WI[8]),
      ].join("") + "\n";

    isolated = appendRow(isolated, row);
  }

  // ── TABLE 2: Primary stress metrics ──────────────────────────
  const WP = [28, 6, 12, 12, 12, 12, 12];

  const hdrP = [
    pad("Algorithm", WP[0]),
    pad("VUs", WP[1]),
    pad("Sign avg", WP[2]),
    pad("Sign p95", WP[3]),
    pad("Auth thrpt", WP[4]),
    pad("CPU avg", WP[5]),
    pad("Mem avg", WP[6]),
  ].join("");

  const unitP = [
    pad("", WP[0]),
    pad("", WP[1]),
    pad("(ms)", WP[2]),
    pad("(ms)", WP[3]),
    pad("(ok/s)", WP[4]),
    pad("(%)", WP[5]),
    pad("(MB)", WP[6]),
  ].join("");

  // ── TABLE 3: Secondary stress metrics ────────────────────────
  const WS = [28, 6, 12, 12, 10, 10, 10, 10, 10, 10];

  const hdrS = [
    pad("Algorithm", WS[0]),
    pad("VUs", WS[1]),
    pad("E2E avg", WS[2]),
    pad("E2E p95", WS[3]),
    pad("RPS", WS[4]),
    pad("Tok bytes", WS[5]),
    pad("Hdr bytes", WS[6]),
    pad("Body bytes", WS[7]),
    pad("ErrRate", WS[8]),
    pad("Atk block", WS[9]),
  ].join("");

  const unitS = [
    pad("", WS[0]),
    pad("", WS[1]),
    pad("(ms)", WS[2]),
    pad("(ms)", WS[3]),
    pad("req/s", WS[4]),
    pad("(B)", WS[5]),
    pad("(B)", WS[6]),
    pad("(B)", WS[7]),
    pad("", WS[8]),
    pad("", WS[9]),
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
          pad(getThroughput(n, vus), WP[4]),
          pad(getVal("stress_auth_cpu", n, vus, "avg"), WP[5]),
          pad(getVal("stress_auth_memory_alloc", n, vus, "avg"), WP[6]),
        ].join("") + "\n";

      const rowS =
        [
          pad(label, WS[0]),
          pad(vus, WS[1]),
          pad(getVal("stress_sign_dirty", n, vus, "avg"), WS[2]),
          pad(getVal("stress_sign_dirty", n, vus, "p(95)"), WS[3]),
          pad(getRequestRate(n, vus), WS[4]),
          pad(getVal("stress_token_size", n, vus, "avg", 0), WS[5]),
          pad(getVal("stress_token_header_size", n, vus, "avg", 0), WS[6]),
          pad(getVal("stress_token_body_size", n, vus, "avg", 0), WS[7]),
          pad(getErrRate(n, vus), WS[8]),
          pad(i === 0 ? attackRate : "", WS[9]),
        ].join("") + "\n";

      primary = appendRow(primary, rowP);
      secondary = appendRow(secondary, rowS);
    }
    const sepP =
      pad("", WP[0] + WP[1]) +
      "─".repeat(WP.slice(2).reduce((a, b) => a + b, 0)) +
      "\n";
    const sepS =
      pad("", WS[0] + WS[1]) +
      "─".repeat(WS.slice(2).reduce((a, b) => a + b, 0)) +
      "\n";
    primary = appendRow(primary, sepP);
    secondary = appendRow(secondary, sepS);
  }

  const table = `
${SEP}
  SIGNING LATENCY STUDY  —  ${new Date().toISOString()}
  Mode      : ${ATTACK_ONLY ? "Attack only" : STRESS_ONLY ? "Stress only" : ISOLATED_ONLY ? "Isolated only" : "Isolated + Stress + Attack"}
  Endpoint  : ${isMultiGateway ? `${HOST_BASE}:{5001-${5000 + ALGORITHMS.length}}` : SINGLE_BASE}
${SEP}

  ── PRIMARY THESIS METRIC: ISOLATED CLEAN TOKEN GENERATION (1 VU, ${ITERATIONS} iterations) ──
  ${hdrI}
  ${unitI}
  ${LINE}
  ${isolated.trimEnd().split("\n").join("\n  ")}

  Token   = JWT generation measured in local benchmark signer only; excludes DB lookup, bcrypt, auth-service, and network
  E2E     = Full local benchmark handler iteration during isolated benchmark
  Warmup  = ${ISOLATED_WARMUP} discarded iterations before each isolated measurement

  ── SUPPORTING SYSTEM METRICS: STRESS (${CONCURRENCY_LEVELS.join(" / ")} VUs, ${STRESS_DURATION_S}s each) ──
  ${hdrP}
  ${unitP}
  ${LINE}
  ${primary.trimEnd().split("\n").join("\n  ")}

  ── SECONDARY METRICS: END-TO-END, SIZE, ATTACK BLOCK RATE ──
  ${hdrS}
  ${unitS}
  ${LINE}
  ${secondary.trimEnd().split("\n").join("\n  ")}

  Sign avg/p95 = X-Token-Generation-Time-Ms header; pure JWT generation only
  Auth thrpt   = Successful benchmark-sign requests / ${STRESS_DURATION_S}s
  CPU/Mem      = Runtime samples from benchmark gateway process
  E2E          = Full k6 client round-trip for /api/benchmark/token
  RPS          = Total benchmark-sign requests / ${STRESS_DURATION_S}s
  Tok/Hdr/Body = JWT string and base64url segment sizes in bytes
  Atk block    = Tampered-token /api/profile requests blocked with 401/403
  Thesis note  = Primary thesis result = isolated table; supporting system result = stress tables
${SEP}
`;

  return {
    stdout: table,
    "benchmark_sign_result.json": JSON.stringify(buildAcademicResult(), null, 2),
    "benchmark_sign_raw.json": JSON.stringify(data, null, 2),
  };
}
