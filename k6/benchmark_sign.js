/**
 * benchmark_sign.js
 *
 * Two-phase signing latency study:
 *
 *   Phase 1 — ISOLATED (1 VU, server-side loop)
 *     POST /api/benchmark/sign with N iterations.
 *     Eliminates concurrent-user noise. Reports clean vs dirty latency statistics.
 *     Use these numbers in academic papers.
 *
 *   Phase 2 — STRESS TEST (10 / 30 / 50 VUs, constant-vus)
 *     Each VU hits /api/auth/signin directly.
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
 *   # Tune iterations (default 200, min 100 for academic use):
 *   k6 run -e BASE_URL=... -e ITERATIONS=500 k6/benchmark_sign.js
 *
 *   # Skip isolated phase (stress only):
 *   k6 run -e BASE_URL=... -e STRESS_ONLY=true k6/benchmark_sign.js
 *
 *   # Skip stress phase (isolated only):
 *   k6 run -e BASE_URL=... -e ISOLATED_ONLY=true k6/benchmark_sign.js
 *
 * Latency taxonomy:
 *   actual  = X-Sign-Time-Ms header — pure PQC signing op in auth-service (clean)
 *   clean   = k6 timings.waiting    — TTFB after send, server processing approx
 *   dirty   = k6 timings.duration   — full client round-trip including network
 *   network = dirty − clean         — connection + send + receive overhead
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Trend, Counter, Rate } from "k6/metrics";
import exec from "k6/execution";
import { randomString } from "./k6-utils.js";

// ═══════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════

const _HOST     = __ENV.BENCH_HOST;
const _BASE_URL = __ENV.BASE_URL;

function normalizeBase(url) {
  if (!url) return "";
  if (url.startsWith("http://") || url.startsWith("https://")) return url;
  return "http://" + url;
}

const HOST_BASE      = normalizeBase(_HOST);
const SINGLE_BASE    = _BASE_URL ? normalizeBase(_BASE_URL) : "http://localhost";
const isMultiGateway = !!_HOST;

// Iterations for isolated phase (server-side loop). Min 100 for academic use.
const ITERATIONS = parseInt(__ENV.ITERATIONS || "200", 10);

// Phase enable flags
const STRESS_ONLY   = __ENV.STRESS_ONLY   === "true";
const ISOLATED_ONLY = __ENV.ISOLATED_ONLY === "true";

// Concurrent VU levels for stress phase
const CONCURRENCY_LEVELS = [10, 30, 50];

// Stress scenario duration (seconds per VU level per algorithm)
const STRESS_DURATION_S = 30;
const STRESS_GAP_S      = 20;  // settle gap between stress scenarios
const ISOLATED_GAP_S    = 5;   // gap between isolated scenarios
const PHASE_GAP_S       = 30;  // settle gap between Phase 1 and Phase 2

const ALGORITHMS = [
  { id: "FNP512",     name: "Falcon-Precomputed-512", category: "PQC",     port: 5001 },
  { id: "FN512",      name: "Falcon-512",              category: "PQC",     port: 5002 },
  { id: "MLDSA44",    name: "ML-DSA-44",               category: "PQC",     port: 5003 },
  { id: "SLHDSA128f", name: "SLH-DSA-SHA2-128f",       category: "PQC",     port: 5004 },
  { id: "SLHDSA128s", name: "SLH-DSA-SHA2-128s",       category: "PQC",     port: 5005 },
  // { id: "ES256",   name: "ES256",                   category: "Classic", port: 5008 },
  // { id: "RS256",   name: "RS256",                   category: "Classic", port: 5009 },
  // { id: "HS256",   name: "HS256",                   category: "Classic", port: 5010 },
  // { id: "EdDSA",   name: "EdDSA",                   category: "Classic", port: 5011 },
];

// Per-algorithm p95 latency budget for stress test thresholds (ms).
// Dirty = full k6 round-trip budget; Actual = server-side pure signing budget.
const STRESS_BUDGET = {
  "Falcon-Precomputed-512": { dirty: 5000,   actual: 500   },
  "Falcon-512":             { dirty: 10000,  actual: 1000  },
  "ML-DSA-44":              { dirty: 10000,  actual: 500   },
  "SLH-DSA-SHA2-128f":      { dirty: 90000,  actual: 30000 },
  "SLH-DSA-SHA2-128s":      { dirty: 300000, actual: 120000},
};
const DEFAULT_STRESS_BUDGET = { dirty: 300000, actual: 120000 };

function getBaseUrl(alg) {
  if (isMultiGateway) return `${HOST_BASE}:${alg.port}`;
  return SINGLE_BASE;
}

// ═══════════════════════════════════════════════════════════════
// Scenarios
// ═══════════════════════════════════════════════════════════════

const scenarios = {};
let startDelay = 0;

// ── Phase 1: Isolated (1 VU, server loops ITERATIONS times) ──
if (!STRESS_ONLY) {
  for (const alg of ALGORITHMS) {
    // Conservative timeout: each signing iteration can take up to 1s for slow algs
    const timeoutS = Math.max(60, Math.ceil(ITERATIONS * 0.010) + 30);
    scenarios[`isolated_${alg.id}`] = {
      executor:    "shared-iterations",
      vus:         1,
      iterations:  1,
      maxDuration: `${timeoutS}s`,
      startTime:   `${startDelay}s`,
      exec:        "runIsolated",
      env:         { CURRENT_ALG: alg.id },
      gracefulStop: "10s",
    };
    startDelay += timeoutS + ISOLATED_GAP_S;
  }
  startDelay += PHASE_GAP_S; // settle before stress phase
}

// ── Phase 2: Stress Test (10 / 30 / 50 VU, constant-vus) ────
if (!ISOLATED_ONLY) {
  for (const alg of ALGORITHMS) {
    for (const vus of CONCURRENCY_LEVELS) {
      scenarios[`stress_${alg.id}_${vus}VU`] = {
        executor:    "constant-vus",
        vus:         vus,
        duration:    `${STRESS_DURATION_S}s`,
        startTime:   `${startDelay}s`,
        exec:        "runStress",
        env:         { CURRENT_ALG: alg.id, CURRENT_VUS: String(vus) },
        gracefulStop: "15s",
      };
      startDelay += STRESS_DURATION_S + STRESS_GAP_S;
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// Custom Metrics
// ═══════════════════════════════════════════════════════════════

// ── Phase 1: Isolated — values reported by /api/benchmark/sign ─
const benchSignP95   = new Trend("bench_sign_p95",   true);
const benchSignAvg   = new Trend("bench_sign_avg",   true);
const benchSignMin   = new Trend("bench_sign_min",   true);
const benchSignMax   = new Trend("bench_sign_max",   true);
const benchSignStdev = new Trend("bench_sign_stdev", true);
const benchTotalP95  = new Trend("bench_total_p95",  true);
const benchTotalAvg  = new Trend("bench_total_avg",  true);
const benchSuccess   = new Counter("bench_success");
const benchFailed    = new Counter("bench_failed");

// ── Phase 2: Stress — per sign-in call, tagged {alg, vus} ──────
// actual = X-Sign-Time-Ms header (pure PQC signing, server-measured)
// clean  = timings.waiting (server processing approx — TTFB after send)
// dirty  = timings.duration (full k6 round-trip)
// network= dirty - clean
const stressSignActual  = new Trend("stress_sign_actual",  true);
const stressSignClean   = new Trend("stress_sign_clean",   true);
const stressSignDirty   = new Trend("stress_sign_dirty",   true);
const stressSignNetwork = new Trend("stress_sign_network", true);
const stressReqSuccess  = new Counter("stress_req_success");
const stressReqFailed   = new Counter("stress_req_failed");
const stressErrorRate   = new Rate("stress_error_rate");

// ═══════════════════════════════════════════════════════════════
// Thresholds
// ═══════════════════════════════════════════════════════════════

const thresholds = {
  bench_success:    ["count>0"],
  stress_error_rate: ["rate<0.01"], // overall <1% error rate
};

for (const alg of ALGORITHMS) {
  const b = STRESS_BUDGET[alg.name] || DEFAULT_STRESS_BUDGET;

  // Permissive per-{alg,vus} thresholds — force k6 to emit tagged sub-metric
  // entries in the summary JSON so handleSummary can read them.
  for (const vus of CONCURRENCY_LEVELS) {
    const tv = `{alg:${alg.name},vus:${vus}}`;
    thresholds[`stress_sign_dirty${tv}`]   = [`p(95)<${b.dirty}`];
    thresholds[`stress_sign_actual${tv}`]  = [`p(95)<${b.actual}`];
    thresholds[`stress_sign_clean${tv}`]   = [`p(95)<9999999`];
    thresholds[`stress_sign_network${tv}`] = [`p(95)<9999999`];
    thresholds[`stress_req_success${tv}`]  = [`count>=0`];
    thresholds[`stress_req_failed${tv}`]   = [`count>=0`];
    thresholds[`stress_error_rate${tv}`]   = [`rate<0.05`]; // <5% per scenario
  }

  // Isolated phase — one entry per algorithm (no vus tag)
  const ta = `{alg:${alg.name}}`;
  thresholds[`bench_sign_p95${ta}`]   = [`p(95)<9999999`];
  thresholds[`bench_total_p95${ta}`]  = [`p(95)<9999999`];
  thresholds[`bench_success${ta}`]    = [`count>=0`];
}

export const options = {
  scenarios,
  thresholds,
  setupTimeout:    "180s",
  teardownTimeout: "30s",
};

// ═══════════════════════════════════════════════════════════════
// Setup — register benchmark user (shared across both phases)
// ═══════════════════════════════════════════════════════════════

export function setup() {
  const suffix = randomString(8).toLowerCase();
  const user = {
    name:     `bench-${suffix}`,
    email:    `bench-${suffix}@bench.test`,
    password: "BenchPass!123",
  };

  const firstAlg    = ALGORITHMS[0];
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
  const alg   = ALGORITHMS.find((a) => a.id === algId);
  if (!alg) return;

  const BASE = getBaseUrl(alg);
  const tags = { alg: alg.name };

  const payload = JSON.stringify({
    algorithm:    alg.name,
    iterations:   ITERATIONS,
    email:        data.user.email,
    password:     data.user.password,
    payload_note: `isolated-${alg.id}-${ITERATIONS}iter`,
  });

  const res = http.post(`${BASE}/api/benchmark/sign`, payload, {
    headers: { "Content-Type": "application/json" },
    timeout: "600s",
  });

  const ok = check(res, {
    [`[isolated|${alg.name}] 200`]: (r) => r.status === 200,
    [`[isolated|${alg.name}] has stats`]: (r) => {
      try { return !!JSON.parse(r.body).data?.stats; }
      catch { return false; }
    },
  });

  if (!ok) {
    benchFailed.add(1, tags);
    console.error(`[isolated|${alg.name}] FAILED status=${res.status} body=${res.body.slice(0, 300)}`);
    return;
  }

  benchSuccess.add(1, tags);

  try {
    const result = JSON.parse(res.body).data;
    const s = result.stats;

    benchSignP95.add(s.sign.p95_ms,    tags);
    benchSignAvg.add(s.sign.avg_ms,    tags);
    benchSignMin.add(s.sign.min_ms,    tags);
    benchSignMax.add(s.sign.max_ms,    tags);
    benchSignStdev.add(s.sign.stdev_ms, tags);
    benchTotalP95.add(s.total.p95_ms,  tags);
    benchTotalAvg.add(s.total.avg_ms,  tags);

    console.log(
      `[isolated|${alg.name}] n=${result.success_count}/${result.iterations}` +
      ` | sign: avg=${s.sign.avg_ms?.toFixed(3)} p95=${s.sign.p95_ms?.toFixed(3)} stdev=${s.sign.stdev_ms?.toFixed(3)} ms` +
      ` | total: avg=${s.total.avg_ms?.toFixed(3)} p95=${s.total.p95_ms?.toFixed(3)} ms`,
    );
  } catch (e) {
    console.error(`[isolated|${alg.name}] parse error: ${e}`);
  }

  sleep(1);
}

// ═══════════════════════════════════════════════════════════════
// Phase 2: Stress — concurrent sign-in calls, latency under load
// ═══════════════════════════════════════════════════════════════

export function runStress(data) {
  if (!data) exec.test.abort("Setup failed — no data");

  const algId   = __ENV.CURRENT_ALG;
  const vuCount = __ENV.CURRENT_VUS;
  const alg     = ALGORITHMS.find((a) => a.id === algId);
  if (!alg) return;

  const BASE = getBaseUrl(alg);
  const tags = { alg: alg.name, vus: vuCount };
  const jsonHdr = { "Content-Type": "application/json" };

  const body = JSON.stringify({
    email:     data.user.email,
    password:  data.user.password,
    ...(isMultiGateway ? {} : { algorithm: alg.name }),
  });

  group(`stress ${alg.name} ${vuCount}VU`, () => {
    const res = http.post(`${BASE}/api/auth/signin`, body, { headers: jsonHdr });

    // Latency decomposition
    const dirty   = res.timings.duration;
    const clean   = res.timings.waiting;
    const network = dirty - clean;

    stressSignDirty.add(dirty,     tags);
    stressSignClean.add(clean,     tags);
    stressSignNetwork.add(network, tags);

    // actual = server-measured pure PQC signing time (clean time)
    const signHdr = res.headers["X-Sign-Time-Ms"] || res.headers["x-sign-time-ms"];
    if (signHdr) {
      const actual = parseFloat(signHdr);
      if (!isNaN(actual)) stressSignActual.add(actual, tags);
    }

    const ok = check(res, {
      [`[stress|${alg.name}|${vuCount}VU] signin 200`]: (r) => r.status === 200,
      [`[stress|${alg.name}|${vuCount}VU] has token`]: (r) => {
        try { return !!JSON.parse(r.body).data?.access_token; }
        catch { return false; }
      },
    });

    ok ? stressReqSuccess.add(1, tags) : stressReqFailed.add(1, tags);
    stressErrorRate.add(!ok, tags);
  });

  sleep(0.05);
}

// ═══════════════════════════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════════════════════════

export function handleSummary(data) {
  const m = data.metrics;

  function getVal(metric, algName, vuCount, stat) {
    const key = vuCount !== null
      ? `${metric}{alg:${algName},vus:${vuCount}}`
      : `${metric}{alg:${algName}}`;
    if (!(key in m)) return "—";
    const v = m[key].values[stat];
    if (v === undefined) return "—";
    if (stat === "rate") return (v * 100).toFixed(1) + "%";
    return v.toFixed(3);
  }

  function getThroughput(algName, vuCount) {
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

  const SEP  = "═".repeat(130);
  const LINE = "─".repeat(130);

  function pad(s, w) {
    const str = String(s);
    return str.length >= w ? str.slice(0, w - 1) + " " : str + " ".repeat(w - str.length);
  }

  // ── TABLE 1: Isolated phase ──────────────────────────────────
  // [Algorithm, N, SignAvg, SignP95, SignStdev, SignMin, SignMax, TotalAvg, TotalP95, Overhead]
  const WI = [28, 6, 12, 12, 12, 10, 10, 12, 12, 12];

  const hdrI = [
    pad("Algorithm",   WI[0]), pad("N",          WI[1]),
    pad("Sign avg",    WI[2]), pad("Sign p95",    WI[3]),
    pad("Sign stdev",  WI[4]), pad("Sign min",    WI[5]),
    pad("Sign max",    WI[6]), pad("Total avg",   WI[7]),
    pad("Total p95",   WI[8]), pad("Overhead",    WI[9]),
  ].join("");

  const unitI = [
    pad("",            WI[0]), pad("iters",       WI[1]),
    pad("(ms)",        WI[2]), pad("(ms)",        WI[3]),
    pad("(ms)",        WI[4]), pad("(ms)",        WI[5]),
    pad("(ms)",        WI[6]), pad("(ms)",        WI[7]),
    pad("(ms)",        WI[8]), pad("total-sign",  WI[9]),
  ].join("");

  let isolPQC = "", isolClassic = "";

  for (const alg of ALGORITHMS) {
    const n  = alg.name;
    const sa = getVal("bench_sign_avg",   n, null, "avg");
    const sp = getVal("bench_sign_p95",   n, null, "avg");
    const ss = getVal("bench_sign_stdev", n, null, "avg");
    const sm = getVal("bench_sign_min",   n, null, "avg");
    const sx = getVal("bench_sign_max",   n, null, "avg");
    const ta = getVal("bench_total_avg",  n, null, "avg");
    const tp = getVal("bench_total_p95",  n, null, "avg");
    const oh = (sa !== "—" && ta !== "—")
      ? (parseFloat(ta) - parseFloat(sa)).toFixed(3) : "—";

    const row = [
      pad(n, WI[0]), pad(ITERATIONS, WI[1]),
      pad(sa, WI[2]), pad(sp, WI[3]),
      pad(ss, WI[4]), pad(sm, WI[5]),
      pad(sx, WI[6]), pad(ta, WI[7]),
      pad(tp, WI[8]), pad(oh, WI[9]),
    ].join("") + "\n";

    alg.category === "PQC" ? (isolPQC += row) : (isolClassic += row);
  }

  // ── TABLE 2: Stress phase ────────────────────────────────────
  // [Algorithm, VUs, DirtyAvg, DirtyP95, CleanAvg, ActualAvg, ActualP95, RPS, ErrRate]
  const WS = [28, 6, 12, 12, 12, 12, 12, 10, 8];

  const hdrS = [
    pad("Algorithm",   WS[0]), pad("VUs",         WS[1]),
    pad("Dirty avg",   WS[2]), pad("Dirty p95",   WS[3]),
    pad("Clean avg",   WS[4]), pad("Actual avg",  WS[5]),
    pad("Actual p95",  WS[6]), pad("RPS",         WS[7]),
    pad("ErrRate",     WS[8]),
  ].join("");

  const unitS = [
    pad("",            WS[0]), pad("",            WS[1]),
    pad("(ms)",        WS[2]), pad("(ms)",        WS[3]),
    pad("(ms)",        WS[4]), pad("(ms)",        WS[5]),
    pad("(ms)",        WS[6]), pad("req/s",       WS[7]),
    pad("",            WS[8]),
  ].join("");

  let stressPQC = "", stressClassic = "";

  for (const alg of ALGORITHMS) {
    const n = alg.name;
    for (let i = 0; i < CONCURRENCY_LEVELS.length; i++) {
      const vus   = String(CONCURRENCY_LEVELS[i]);
      const label = i === 0 ? n : "";

      const row = [
        pad(label,                                          WS[0]),
        pad(vus,                                            WS[1]),
        pad(getVal("stress_sign_dirty",   n, vus, "avg"),   WS[2]),
        pad(getVal("stress_sign_dirty",   n, vus, "p(95)"), WS[3]),
        pad(getVal("stress_sign_clean",   n, vus, "avg"),   WS[4]),
        pad(getVal("stress_sign_actual",  n, vus, "avg"),   WS[5]),
        pad(getVal("stress_sign_actual",  n, vus, "p(95)"), WS[6]),
        pad(getThroughput(n, vus),                          WS[7]),
        pad(getErrRate(n, vus),                             WS[8]),
      ].join("") + "\n";

      alg.category === "PQC" ? (stressPQC += row) : (stressClassic += row);
    }
    const sep =
      pad("", WS[0] + WS[1]) +
      "─".repeat(WS.slice(2).reduce((a, b) => a + b, 0)) + "\n";
    alg.category === "PQC" ? (stressPQC += sep) : (stressClassic += sep);
  }

  const table = `
${SEP}
  SIGNING LATENCY STUDY  —  ${new Date().toISOString()}
  Mode      : ${STRESS_ONLY ? "Stress only" : ISOLATED_ONLY ? "Isolated only" : "Isolated + Stress (10 / 30 / 50 VU)"}
  Endpoint  : ${isMultiGateway ? `${HOST_BASE}:{5001-${5000 + ALGORITHMS.length}}` : SINGLE_BASE}
${SEP}

  ── PHASE 1: ISOLATED BASELINE (1 VU, ${ITERATIONS} iterations, no concurrent noise) ──
  ${hdrI}
  ${unitI}
  ${LINE}
  [ PQC ]
  ${isolPQC.trimEnd().split("\n").join("\n  ")}
  ${LINE}
  [ Classical ]
  ${isolClassic.trimEnd().split("\n").join("\n  ") || "(none)"}

  Sign    = Pure PQC signing op measured server-side via X-Sign-Time-Ms gRPC trailer → use for academic comparison
  Total   = Full gRPC gateway↔auth-service round-trip per signing call
  Overhead= Total avg − Sign avg  (network + gRPC serialization + DB lookup + bcrypt)
  StDev   = Standard deviation of sign time — lower = more deterministic algorithm

  ── PHASE 2: STRESS TEST (${CONCURRENCY_LEVELS.join(" / ")} VUs, ${STRESS_DURATION_S}s each, direct /api/auth/signin) ──
  ${hdrS}
  ${unitS}
  ${LINE}
  [ PQC ]
  ${stressPQC.trimEnd().split("\n").join("\n  ")}
  ${LINE}
  [ Classical ]
  ${stressClassic.trimEnd().split("\n").join("\n  ") || "(none)"}

  Dirty   = Full k6 client round-trip (network + queuing + server) — "wall-clock" latency under load
  Clean   = k6 timings.waiting (TTFB) — server-side processing approximation under load
  Actual  = X-Sign-Time-Ms header — pure PQC signing time even under concurrent load
  RPS     = Successful sign-in requests / ${STRESS_DURATION_S}s (authentication throughput)
  ErrRate = Failed sign-in requests / total requests — threshold: <5% per scenario, <1% overall
${SEP}
`;

  return {
    stdout: table,
    "benchmark_sign_result.json": JSON.stringify(data, null, 2),
  };
}
