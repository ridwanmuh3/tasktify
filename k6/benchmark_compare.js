/**
 * benchmark_compare.js
 *
 * Perbandingan performa JWT dengan variasi concurrent users (VUs).
 *
 * Mode 1 — Multi-gateway (local benchmark via docker-compose.benchmark.yml):
 *   k6 run -e HOST=localhost k6/benchmark_compare.js
 *   Setiap algoritma punya gateway sendiri di port berbeda (5001-5004).
 *
 * Mode 2 — Single-gateway (production / VPS):
 *   k6 run -e BASE_URL=https://poc-ridwanmuh3.my.id k6/benchmark_compare.js
 *   Satu endpoint, algoritma dipilih via field "algorithm" di request body.
 *
 * Skenario: 4 algoritma × 3 level konkuren (100, 500, 1000 VU) = 12 skenario
 * Durasi per skenario: 30 detik sustain load
 *
 *   PQC  : Falcon-Precomputed-512 (:5001), Falcon-512 (:5002),
 *          ML-DSA-44 (:5003), SLH-DSA-SHA2-128f (:5004),
 *          SLH-DSA-SHA2-128s (:5005), SLH-DSA-SHAKE-128f (:5006),
 *          SLH-DSA-SHAKE-128s (:5007)
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Trend, Counter, Rate } from "k6/metrics";
import encoding from "k6/encoding";
import exec from "k6/execution";
import { randomString } from "./k6-utils.js";

// ═══════════════════════════════════════════════════════════════
// Konfigurasi
// ═══════════════════════════════════════════════════════════════

const _HOST = __ENV.BENCH_HOST;
const _BASE_URL = __ENV.BASE_URL;

const isMultiGateway = !!_HOST;

function normalizeBase(url) {
  if (!url) return "";
  if (url.startsWith("http://") || url.startsWith("https://")) return url;
  return "http://" + url;
}

const HOST_BASE = normalizeBase(_HOST);
const SINGLE_BASE_URL = _BASE_URL
  ? normalizeBase(_BASE_URL)
  : "http://localhost";

// Port gateway per algoritma sesuai docker-compose.benchmark.yml
// scenarioDuration: per-algorithm window (SLH-DSA-128s variants need longer to complete ≥1 iteration)
const ALGORITHMS = [
  {
    id: "FNP512",
    name: "Falcon-Precomputed-512",
    category: "PQC",
    port: 5001,
    scenarioDuration: 30,
  },
  {
    id: "FN512",
    name: "Falcon-512",
    category: "PQC",
    port: 5002,
    scenarioDuration: 30,
  },
  {
    id: "MLDSA44",
    name: "ML-DSA-44",
    category: "PQC",
    port: 5003,
    scenarioDuration: 30,
  },
  {
    id: "SLHDSA128f",
    name: "SLH-DSA-SHA2-128f",
    category: "PQC",
    port: 5004,
    scenarioDuration: 90,
  },
  {
    id: "SLHDSA128s",
    name: "SLH-DSA-SHA2-128s",
    category: "PQC",
    port: 5005,
    scenarioDuration: 180,
  },
  // { id: "SLHSHK128f", name: "SLH-DSA-SHAKE-128f",     category: "PQC", port: 5006, scenarioDuration: 90  },
  // { id: "SLHSHK128s", name: "SLH-DSA-SHAKE-128s",     category: "PQC", port: 5007, scenarioDuration: 180 },
  // { id: "ES256",  name: "ES256",  category: "Classic", port: 5008, scenarioDuration: 30 },
  // { id: "RS256",  name: "RS256",  category: "Classic", port: 5009, scenarioDuration: 30 },
  // { id: "HS256",  name: "HS256",  category: "Classic", port: 5010, scenarioDuration: 30 },
  // { id: "EdDSA",  name: "EdDSA",  category: "Classic", port: 5011, scenarioDuration: 30 },
];

// Level konkuren yang diuji
// Smoke test: [1] — Full benchmark: [10, 50, 100]
const CONCURRENCY_LEVELS = [10, 30, 50];

// Default durasi per skenario (detik) dan jeda antar skenario
const SCENARIO_DURATION_S = 30;
const SCENARIO_GAP_S = 20;

function getBaseUrl(alg) {
  if (isMultiGateway) return `${HOST_BASE}:${alg.port}`;
  return SINGLE_BASE_URL;
}

const DISPLAY_ENDPOINT = isMultiGateway
  ? `${HOST_BASE}:{5001-${5000 + ALGORITHMS.length}} (multi-gateway)`
  : SINGLE_BASE_URL;

// ═══════════════════════════════════════════════════════════════
// Custom Metrics
// ═══════════════════════════════════════════════════════════════

// ── Primary ─────────────────────────────────────────────────────
// signing_latency_dirty  : full k6 round-trip (network + queuing + server)
// signing_latency_clean  : k6 timings.waiting — server processing approx (excludes conn setup)
// signing_latency_network: dirty - clean — pure network+connection overhead
// signing_latency_actual : X-Sign-Time-Ms header — pure PQC signing op measured server-side
const signingLatencyDirty   = new Trend("signing_latency_dirty",   true);
const signingLatencyClean   = new Trend("signing_latency_clean",   true);
const signingLatencyNetwork = new Trend("signing_latency_network", true);
const signingLatencyActual  = new Trend("signing_latency_actual",  true);

// Auth-specific throughput counters (sign-in only, excludes CRUD/verification)
const authReqSuccess = new Counter("auth_req_success");
const authReqFailed  = new Counter("auth_req_failed");

// ── Legacy / Secondary (kept for backwards-compat) ───────────────
const tokenGenTime = new Trend("token_gen_time", true);
const tokenVerTime = new Trend("token_ver_time", true);
const respDuration = new Trend("resp_duration", true);
const respBodySize = new Trend("resp_body_size");
const reqHeaderSize = new Trend("req_header_size");
const attackBlock = new Rate("attack_block_rate");
const reqSuccess = new Counter("req_success");
const reqFailed = new Counter("req_failed");

// ═══════════════════════════════════════════════════════════════
// Scenarios: tiap algoritma × tiap level VU, dijalankan berurutan
// ═══════════════════════════════════════════════════════════════

const scenarios = {};
let startDelay = 0;

for (const alg of ALGORITHMS) {
  const dur = alg.scenarioDuration || SCENARIO_DURATION_S;
  for (const vus of CONCURRENCY_LEVELS) {
    const id = `${alg.id}_${vus}VU`;
    scenarios[id] = {
      executor: "constant-vus",
      vus: vus,
      duration: `${dur}s`,
      startTime: `${startDelay}s`,
      exec: "benchmark",
      env: { CURRENT_ALG: alg.id, CURRENT_VUS: String(vus) },
      gracefulStop: "30s",
    };
    startDelay += dur + SCENARIO_GAP_S;
  }
}

// ═══════════════════════════════════════════════════════════════
// Thresholds — per algoritma (tanpa per-VU agar tabel tidak terlalu panjang)
// ═══════════════════════════════════════════════════════════════

// Per-algorithm time budgets (ms, p95).
// SLH-DSA signing is inherently slow; budgets reflect real-world expectations
// under concurrent load rather than acting as hard performance gates.
const ALG_BUDGET = {
  "Falcon-Precomputed-512": { gen: 60000, ver: 30000, resp: 60000 },
  "Falcon-512": { gen: 60000, ver: 30000, resp: 60000 },
  "ML-DSA-44": { gen: 60000, ver: 30000, resp: 60000 },
  "SLH-DSA-SHA2-128f": { gen: 300000, ver: 60000, resp: 300000 },
  "SLH-DSA-SHA2-128s": { gen: 600000, ver: 60000, resp: 600000 },
  // "SLH-DSA-SHAKE-128f":     { gen: 300000, ver: 60000, resp: 300000 },
  // "SLH-DSA-SHAKE-128s":     { gen: 600000, ver: 60000, resp: 600000 },
};
const DEFAULT_BUDGET = { gen: 600000, ver: 60000, resp: 600000 };

const thresholds = {
  // Allow ≥99% block rate — 5xx server errors under peak load should not
  // be counted as "attack passed", but may occur due to resource exhaustion.
  attack_block_rate: ["rate>=0.99"],
};
for (const alg of ALGORITHMS) {
  const t = `{alg:${alg.name}}`;
  const b = ALG_BUDGET[alg.name] || DEFAULT_BUDGET;
  thresholds[`token_gen_time${t}`] = [`p(95)<${b.gen}`];
  thresholds[`token_ver_time${t}`] = [`p(95)<${b.ver}`];
  thresholds[`resp_duration${t}`] = [`p(95)<${b.resp}`];
  thresholds[`attack_block_rate${t}`] = ["rate>=0.99"];

  // k6 only emits tagged sub-metric entries in the summary JSON when a threshold
  // is defined for that exact tag combination. These permissive thresholds exist
  // solely to force k6 to create {alg,vus} entries so handleSummary can read them.
  for (const vus of CONCURRENCY_LEVELS) {
    const tv = `{alg:${alg.name},vus:${vus}}`;
    thresholds[`token_gen_time${tv}`]         = [`p(95)<9999999`];
    thresholds[`token_ver_time${tv}`]         = [`p(95)<9999999`];
    thresholds[`resp_duration${tv}`]          = [`p(95)<9999999`];
    thresholds[`resp_body_size${tv}`]         = [`p(95)<9999999`];
    thresholds[`req_header_size${tv}`]        = [`p(95)<9999999`];
    thresholds[`req_success${tv}`]            = [`count>=0`];
    thresholds[`req_failed${tv}`]             = [`count>=0`];
    // New latency-decomposition metrics
    thresholds[`signing_latency_dirty${tv}`]   = [`p(95)<9999999`];
    thresholds[`signing_latency_clean${tv}`]   = [`p(95)<9999999`];
    thresholds[`signing_latency_network${tv}`] = [`p(95)<9999999`];
    thresholds[`signing_latency_actual${tv}`]  = [`p(95)<9999999`];
    thresholds[`auth_req_success${tv}`]        = [`count>=0`];
    thresholds[`auth_req_failed${tv}`]         = [`count>=0`];
  }
  // Attack rate only at the highest VU level
  const attackVus = CONCURRENCY_LEVELS[CONCURRENCY_LEVELS.length - 1];
  thresholds[`attack_block_rate{alg:${alg.name},vus:${attackVus}}`] = [
    "rate>=0.99",
  ];
}

export const options = {
  scenarios,
  thresholds,
  setupTimeout: "180s",
  teardownTimeout: "30s",
};

// ═══════════════════════════════════════════════════════════════
// Setup: hanya registrasi user — tiap VU sign-in sendiri saat berjalan
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
  console.log(`Mendaftar ke: ${registerUrl}`);

  // Retry until service is ready (max 90 x 2s = 180s)
  let regRes;
  for (let attempt = 1; attempt <= 90; attempt++) {
    regRes = http.post(registerUrl, JSON.stringify(user), {
      headers: { "Content-Type": "application/json" },
      timeout: "5s",
    });
    // status 0 = connection refused / not ready yet
    if (regRes.status !== 0) break;
    console.log(`[${attempt}/90] Service belum siap, menunggu 2s...`);
    sleep(2);
  }

  if (regRes.status === 0) {
    exec.test.abort(
      `Service ${registerUrl} tidak dapat dijangkau dalam 180 detik — pastikan docker-compose benchmark sudah berjalan`,
    );
  }

  if (regRes.status !== 201) {
    exec.test.abort(
      `Register gagal (status=${regRes.status}) di ${registerUrl}\nBody: ${regRes.body}`,
    );
  }

  console.log(`User terdaftar: ${user.email}`);
  return { user };
}

// ═══════════════════════════════════════════════════════════════
// VU-local state — token per-VU, reset saat skenario berganti
// ═══════════════════════════════════════════════════════════════

let _vuToken = null;
// let _vuRefreshToken = null;
let _vuScenarioKey = null;

// ═══════════════════════════════════════════════════════════════
// Helper
// ═══════════════════════════════════════════════════════════════

function estimateHeaderSize(headers) {
  return Object.entries(headers).reduce(
    (s, [k, v]) => s + k.length + 2 + String(v).length + 2,
    0,
  );
}

function b64url(str) {
  return encoding
    .b64encode(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fakeJwt(alg, claimsOverride, sig) {
  const header = b64url(JSON.stringify({ alg, typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(
    JSON.stringify(
      Object.assign(
        {
          sub: "00000000-0000-0000-0000-000000000000",
          email: "attacker@evil.com",
          iss: "tasktify",
          exp: now + 3600,
          iat: now,
        },
        claimsOverride || {},
      ),
    ),
  );
  return `${header}.${payload}.${sig !== undefined ? sig : "fakesig"}`;
}

function tamperedToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return token;
  const evilPayload = b64url(
    JSON.stringify({
      sub: "99999999-9999-9999-9999-999999999999",
      email: "hijacked@evil.com",
      iss: "tasktify",
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    }),
  );
  return `${parts[0]}.${evilPayload}.${parts[2]}`;
}

// ═══════════════════════════════════════════════════════════════
// Fungsi Benchmark Utama
// ═══════════════════════════════════════════════════════════════

export function benchmark(data) {
  if (!data) exec.test.abort("Setup gagal — tidak ada data");

  const algId = __ENV.CURRENT_ALG;
  const vuCount = __ENV.CURRENT_VUS;
  const alg = ALGORITHMS.find((a) => a.id === algId);
  if (!alg) return;

  const BASE = getBaseUrl(alg);
  const tags = { alg: alg.name, vus: vuCount };
  const jsonHdr = { "Content-Type": "application/json" };

  // Reset token VU-local jika skenario berganti (algoritma atau level VU berbeda)
  const scenarioKey = `${algId}_${vuCount}`;
  if (_vuScenarioKey !== scenarioKey) {
    _vuScenarioKey = scenarioKey;
    _vuToken = null;
    // _vuRefreshToken = null;
  }

  // ─── 1. Token Generation Time ───────────────────────────────
  // Setiap iterasi sign-in: mengukur waktu signing + mendapatkan token segar
  group("1. Token Generation", () => {
    const body = { email: data.user.email, password: data.user.password };
    if (!isMultiGateway) body.algorithm = alg.name;

    const res = http.post(`${BASE}/api/auth/signin`, JSON.stringify(body), {
      headers: jsonHdr,
    });

    // ── Primary: Signing Latency Decomposition ────────────────
    // dirty  = full k6 round-trip (network + server processing)
    // clean  = timings.waiting = time-to-first-byte after send (server processing approx)
    // network= dirty - clean = connection setup + send + receive overhead
    // actual = X-Sign-Time-Ms header = pure PQC signing op measured server-side
    const dirty   = res.timings.duration;
    const clean   = res.timings.waiting;
    const network = dirty - clean;

    signingLatencyDirty.add(dirty,   tags);
    signingLatencyClean.add(clean,   tags);
    signingLatencyNetwork.add(network, tags);

    const signTimeHdr = res.headers["X-Sign-Time-Ms"] || res.headers["x-sign-time-ms"];
    if (signTimeHdr) {
      const actual = parseFloat(signTimeHdr);
      if (!isNaN(actual)) signingLatencyActual.add(actual, tags);
    }

    // ── Legacy metrics (kept for backwards compat) ────────────
    tokenGenTime.add(dirty, tags);
    respDuration.add(dirty, tags);
    respBodySize.add(res.body.length, tags);
    reqHeaderSize.add(estimateHeaderSize(jsonHdr), tags);

    const ok = check(res, {
      [`[${alg.name}|${vuCount}VU] sign-in 200`]: (r) => r.status === 200,
      [`[${alg.name}|${vuCount}VU] has access_token`]: (r) => {
        try {
          return !!JSON.parse(r.body).data?.access_token;
        } catch {
          return false;
        }
      },
    });
    ok ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);
    ok ? authReqSuccess.add(1, tags) : authReqFailed.add(1, tags);

    if (res.status === 200) {
      try {
        const b = JSON.parse(res.body);
        _vuToken = b.data.access_token;
      } catch (_) {}
    }
  });

  if (!_vuToken) return; // sign-in gagal, lewati iterasi ini

  const authHdr = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${_vuToken}`,
  };

  // ─── 2. Token Verification Time ─────────────────────────────
  group("2. Token Verification", () => {
    const res = http.get(`${BASE}/api/profile`, { headers: authHdr });

    tokenVerTime.add(res.timings.duration, tags);
    respDuration.add(res.timings.duration, tags);
    respBodySize.add(res.body.length, tags);
    reqHeaderSize.add(estimateHeaderSize(authHdr), tags);

    const ok = check(res, {
      [`[${alg.name}|${vuCount}VU] profile 200`]: (r) => r.status === 200,
      [`[${alg.name}|${vuCount}VU] profile has email`]: (r) => {
        try {
          return !!JSON.parse(r.body).data?.email;
        } catch {
          return false;
        }
      },
    });
    ok ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);
  });

  // ─── 3. Task CRUD ────────────────────────────────────────────
  group("3. Task CRUD", () => {
    // Unique title per iteration — used to find the created task in the list
    // (Create endpoint returns no task ID per proto definition)
    const uniqueTitle = `bench-${randomString(10)}`;

    const createRes = http.post(
      `${BASE}/api/tasks/`,
      JSON.stringify({
        title: uniqueTitle,
        description: `benchmark [${alg.name}]`,
        status: "PENDING",
        due_date: Date.now() + 86400000,
      }),
      { headers: authHdr },
    );
    respDuration.add(createRes.timings.duration, tags);
    respBodySize.add(createRes.body.length, tags);
    check(createRes, {
      [`[${alg.name}|${vuCount}VU] create 201`]: (r) => r.status === 201,
    })
      ? reqSuccess.add(1, tags)
      : reqFailed.add(1, tags);

    // Find the task ID by listing and matching the unique title.
    // Create returns no data (proto: Empty), so we must look it up.
    let taskId = null;
    const listRes = http.get(`${BASE}/api/tasks/`, { headers: authHdr });
    respDuration.add(listRes.timings.duration, tags);
    respBodySize.add(listRes.body.length, tags);
    check(listRes, {
      [`[${alg.name}|${vuCount}VU] list 200`]: (r) => r.status === 200,
    })
      ? reqSuccess.add(1, tags)
      : reqFailed.add(1, tags);

    if (createRes.status === 201 && listRes.status === 200) {
      try {
        const tasks = JSON.parse(listRes.body).data || [];
        const created = tasks.find((t) => t.title === uniqueTitle);
        taskId = created ? created.id : null;
      } catch (_) {}
    }

    if (taskId) {
      const getRes = http.get(`${BASE}/api/tasks/${taskId}`, {
        headers: authHdr,
        tags: { name: "/api/tasks/:id" },
      });
      respDuration.add(getRes.timings.duration, tags);
      check(getRes, {
        [`[${alg.name}|${vuCount}VU] get 200`]: (r) => r.status === 200,
      })
        ? reqSuccess.add(1, tags)
        : reqFailed.add(1, tags);

      const updRes = http.put(
        `${BASE}/api/tasks/${taskId}`,
        JSON.stringify({
          title: `bench-upd-${randomString(4)}`,
          description: "updated by k6",
          status: "IN_PROGRESS",
          due_date: Date.now() + 172800000,
        }),
        { headers: authHdr, tags: { name: "/api/tasks/:id" } },
      );
      respDuration.add(updRes.timings.duration, tags);
      check(updRes, {
        [`[${alg.name}|${vuCount}VU] update 200`]: (r) => r.status === 200,
      })
        ? reqSuccess.add(1, tags)
        : reqFailed.add(1, tags);

      const delRes = http.del(`${BASE}/api/tasks/${taskId}`, null, {
        headers: authHdr,
        tags: { name: "/api/tasks/:id" },
      });
      respDuration.add(delRes.timings.duration, tags);
      check(delRes, {
        [`[${alg.name}|${vuCount}VU] delete 200`]: (r) => r.status === 200,
      })
        ? reqSuccess.add(1, tags)
        : reqFailed.add(1, tags);
    }
  });

  // // ─── 4. Refresh Token ────────────────────────────────────────
  // group("4. Refresh Token", () => {
  //   const res = http.post(
  //     `${BASE}/api/auth/refresh`,
  //     JSON.stringify({ refresh_token: _vuRefreshToken }),
  //     { headers: jsonHdr },
  //   );
  //   tokenGenTime.add(res.timings.duration, tags);
  //   respDuration.add(res.timings.duration, tags);
  //   respBodySize.add(res.body.length, tags);

  //   const ok = check(res, {
  //     [`[${alg.name}|${vuCount}VU] refresh 200`]: (r) => r.status === 200,
  //   });
  //   ok ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);

  //   if (res.status === 200) {
  //     try {
  //       const b = JSON.parse(res.body);
  //       _vuToken = b.data.access_token;
  //       _vuRefreshToken = b.data.refresh_token;
  //     } catch (_) {}
  //   }
  // });

  // ─── 5. JWT Confusion Attack Resistance ─────────────────────
  // Hanya dijalankan pada level VU tertinggi untuk efisiensi
  const ATTACK_LEVEL = String(
    CONCURRENCY_LEVELS[CONCURRENCY_LEVELS.length - 1],
  );
  if (vuCount === ATTACK_LEVEL) {
    group("5. JWT Confusion Attacks", () => {
      const url = `${BASE}/api/profile`;
      const now = Math.floor(Date.now() / 1000);

      const attacks = [
        {
          name: "alg=none",
          hdr: { Authorization: `Bearer ${fakeJwt("none", {}, "")}` },
        },
        {
          name: "alg=HS256",
          hdr: { Authorization: `Bearer ${fakeJwt("HS256")}` },
        },
        {
          name: "alg=RS256",
          hdr: { Authorization: `Bearer ${fakeJwt("RS256")}` },
        },
        {
          name: "alg=ES256",
          hdr: { Authorization: `Bearer ${fakeJwt("ES256")}` },
        },
        {
          name: "alg=Falcon-512",
          hdr: { Authorization: `Bearer ${fakeJwt("Falcon-512")}` },
        },
        {
          name: "alg=ML-DSA-44",
          hdr: { Authorization: `Bearer ${fakeJwt("ML-DSA-44")}` },
        },
        {
          name: "sig stripped",
          hdr: { Authorization: `Bearer ${fakeJwt(alg.name, {}, "")}` },
        },
        {
          name: "random sig",
          hdr: {
            Authorization: `Bearer ${fakeJwt(alg.name, {}, randomString(32))}`,
          },
        },
        {
          name: "expired",
          hdr: {
            Authorization: `Bearer ${fakeJwt(alg.name, { exp: now - 3600, iat: now - 7200 }, "fakesig")}`,
          },
        },
        {
          name: "future iat",
          hdr: {
            Authorization: `Bearer ${fakeJwt(alg.name, { iat: now + 3600 }, "fakesig")}`,
          },
        },
        {
          name: "iss spoof",
          hdr: {
            Authorization: `Bearer ${fakeJwt(alg.name, { iss: "evil-issuer" }, "fakesig")}`,
          },
        },
        { name: "2 segments", hdr: { Authorization: "Bearer aaa.bbb" } },
        {
          name: "random garbage",
          hdr: { Authorization: `Bearer ${randomString(200)}` },
        },
        {
          name: "tampered payload",
          hdr: { Authorization: `Bearer ${tamperedToken(_vuToken)}` },
        },
      ];

      for (const atk of attacks) {
        const res = http.get(url, {
          headers: { ...atk.hdr, "Content-Type": "application/json" },
        });
        const blocked = res.status !== 200;
        attackBlock.add(blocked, tags);
        check(res, {
          [`[${alg.name}] attack:${atk.name} → blocked`]: () => blocked,
        });
      }

      const validRes = http.get(url, { headers: authHdr });
      check(validRes, {
        [`[${alg.name}] valid token: accepted`]: (r) => r.status === 200,
      });
      validRes.status === 200
        ? reqSuccess.add(1, tags)
        : reqFailed.add(1, tags);
    });
  }

  sleep(0.05);
}

// ═══════════════════════════════════════════════════════════════
// Custom Summary — Tabel Perbandingan per Algoritma × VU Level
// ═══════════════════════════════════════════════════════════════

export function handleSummary(data) {
  const m = data.metrics;

  // Ambil nilai metrik dengan tag alg + vus
  function getVal(metric, algName, vuCount, stat) {
    const key = `${metric}{alg:${algName},vus:${vuCount}}`;
    if (!(key in m)) return "—";
    const v = m[key].values[stat];
    if (v === undefined) return "—";
    if (stat === "rate") return (v * 100).toFixed(1) + "%";
    return v.toFixed(2);
  }

  // Ambil attack rate dari level VU tertinggi (attack hanya berjalan di level itu)
  const ATTACK_LEVEL = String(
    CONCURRENCY_LEVELS[CONCURRENCY_LEVELS.length - 1],
  );
  function getAttack(algName) {
    const key = `attack_block_rate{alg:${algName},vus:${ATTACK_LEVEL}}`;
    if (!(key in m)) {
      // Fallback: aggregate across all VUs
      const fallback = `attack_block_rate{alg:${algName}}`;
      if (!(fallback in m)) return "—";
      const v = m[fallback].values["rate"];
      return v !== undefined ? (v * 100).toFixed(1) + "%" : "—";
    }
    const v = m[key].values["rate"];
    if (v === undefined) return "—";
    return (v * 100).toFixed(1) + "%";
  }

  const sep = "═".repeat(132);
  const line = "─".repeat(132);

  function pad(s, w) {
    const str = String(s);
    return str.length >= w
      ? str.slice(0, w - 1) + " "
      : str + " ".repeat(w - str.length);
  }

  // Total request throughput (all endpoints)
  function getThroughput(algName, vuCount) {
    const sk = `req_success{alg:${algName},vus:${vuCount}}`;
    const fk = `req_failed{alg:${algName},vus:${vuCount}}`;
    const sc = (m[sk] && m[sk].values.count) || 0;
    const fc = (m[fk] && m[fk].values.count) || 0;
    const total = sc + fc;
    if (total === 0) return "—";
    const algDef = ALGORITHMS.find((a) => a.name === algName);
    const dur = (algDef && algDef.scenarioDuration) || SCENARIO_DURATION_S;
    return (total / dur).toFixed(2);
  }

  // Auth-only throughput (sign-in requests per second)
  function getAuthThroughput(algName, vuCount) {
    const sk = `auth_req_success{alg:${algName},vus:${vuCount}}`;
    const fk = `auth_req_failed{alg:${algName},vus:${vuCount}}`;
    const sc = (m[sk] && m[sk].values.count) || 0;
    const fc = (m[fk] && m[fk].values.count) || 0;
    const total = sc + fc;
    if (total === 0) return "—";
    const algDef = ALGORITHMS.find((a) => a.name === algName);
    const dur = (algDef && algDef.scenarioDuration) || SCENARIO_DURATION_S;
    return (total / dur).toFixed(2);
  }

  // ── Table 1: Primary + Secondary Metrics ───────────────────
  // [Algorithm, VUs, GenAvg, Genp95, VerAvg, Verp95, RespAvg, Respp95, AuthRPS, TotalRPS, Attack]
  const W = [26, 6, 10, 10, 10, 10, 10, 10, 10, 10, 9];

  const hdr = [
    pad("Algorithm", W[0]),
    pad("VUs", W[1]),
    pad("GenTime", W[2]),
    pad("Gen p95", W[3]),
    pad("VerTime", W[4]),
    pad("Ver p95", W[5]),
    pad("Resp avg", W[6]),
    pad("Resp p95", W[7]),
    pad("AuthRPS", W[8]),
    pad("TotalRPS", W[9]),
    pad("Attack", W[10]),
  ].join("");

  const unit = [
    pad("", W[0]),
    pad("", W[1]),
    pad("avg (ms)", W[2]),
    pad("(ms)", W[3]),
    pad("avg (ms)", W[4]),
    pad("(ms)", W[5]),
    pad("(ms)", W[6]),
    pad("(ms)", W[7]),
    pad("(req/s)", W[8]),
    pad("(req/s)", W[9]),
    pad("Blocked", W[10]),
  ].join("");

  // ── Table 2: Signing Latency Decomposition ──────────────────
  // dirty=full k6 round-trip | clean=server processing (timings.waiting)
  // network=dirty-clean | actual=X-Sign-Time-Ms (pure PQC signing op)
  const WL = [26, 6, 10, 10, 10, 10, 10, 10, 10, 10];

  const hdrL = [
    pad("Algorithm", WL[0]),
    pad("VUs", WL[1]),
    pad("Dirty avg", WL[2]),
    pad("Dirty p95", WL[3]),
    pad("Clean avg", WL[4]),
    pad("Clean p95", WL[5]),
    pad("Net avg",   WL[6]),
    pad("Net p95",   WL[7]),
    pad("Actual avg",WL[8]),
    pad("Actual p95",WL[9]),
  ].join("");

  const unitL = [
    pad("", WL[0]),
    pad("", WL[1]),
    pad("(ms)", WL[2]),
    pad("(ms)", WL[3]),
    pad("(ms)", WL[4]),
    pad("(ms)", WL[5]),
    pad("(ms)", WL[6]),
    pad("(ms)", WL[7]),
    pad("(ms)", WL[8]),
    pad("(ms)", WL[9]),
  ].join("");

  let pqcRows = "", classicRows = "";
  let pqcRowsL = "", classicRowsL = "";

  for (const alg of ALGORITHMS) {
    const n = alg.name;
    for (let i = 0; i < CONCURRENCY_LEVELS.length; i++) {
      const vus = String(CONCURRENCY_LEVELS[i]);
      const label = i === 0 ? n : "";

      const row =
        [
          pad(label, W[0]),
          pad(vus, W[1]),
          pad(getVal("token_gen_time", n, vus, "avg"), W[2]),
          pad(getVal("token_gen_time", n, vus, "p(95)"), W[3]),
          pad(getVal("token_ver_time", n, vus, "avg"), W[4]),
          pad(getVal("token_ver_time", n, vus, "p(95)"), W[5]),
          pad(getVal("resp_duration", n, vus, "avg"), W[6]),
          pad(getVal("resp_duration", n, vus, "p(95)"), W[7]),
          pad(getAuthThroughput(n, vus), W[8]),
          pad(getThroughput(n, vus), W[9]),
          pad(i === 0 ? getAttack(n) : "", W[10]),
        ].join("") + "\n";

      const rowL =
        [
          pad(label, WL[0]),
          pad(vus, WL[1]),
          pad(getVal("signing_latency_dirty",   n, vus, "avg"),   WL[2]),
          pad(getVal("signing_latency_dirty",   n, vus, "p(95)"), WL[3]),
          pad(getVal("signing_latency_clean",   n, vus, "avg"),   WL[4]),
          pad(getVal("signing_latency_clean",   n, vus, "p(95)"), WL[5]),
          pad(getVal("signing_latency_network", n, vus, "avg"),   WL[6]),
          pad(getVal("signing_latency_network", n, vus, "p(95)"), WL[7]),
          pad(getVal("signing_latency_actual",  n, vus, "avg"),   WL[8]),
          pad(getVal("signing_latency_actual",  n, vus, "p(95)"), WL[9]),
        ].join("") + "\n";

      alg.category === "PQC" ? (pqcRows  += row)  : (classicRows  += row);
      alg.category === "PQC" ? (pqcRowsL += rowL) : (classicRowsL += rowL);
    }
    const sep1 =
      pad("", W[0] + W[1]) +
      "─".repeat(W.slice(2).reduce((a, b) => a + b, 0)) + "\n";
    const sep2 =
      pad("", WL[0] + WL[1]) +
      "─".repeat(WL.slice(2).reduce((a, b) => a + b, 0)) + "\n";
    alg.category === "PQC" ? (pqcRows  += sep1) : (classicRows  += sep1);
    alg.category === "PQC" ? (pqcRowsL += sep2) : (classicRowsL += sep2);
  }

  const totalScenarios = ALGORITHMS.length * CONCURRENCY_LEVELS.length;
  const SEP = "═".repeat(116);
  const LINE = "─".repeat(116);

  const table = `
${SEP}
  JWT ALGORITHM PERFORMANCE COMPARISON  —  Concurrent Users: ${CONCURRENCY_LEVELS.join(" / ")} VU
  Endpoint  : ${DISPLAY_ENDPOINT}
  Skenario  : ${totalScenarios} (${ALGORITHMS.length} algoritma × ${CONCURRENCY_LEVELS.length} level VU)
  Durasi    : ${SCENARIO_DURATION_S}s sustain per skenario
  Attack    = diukur hanya pada level ${CONCURRENCY_LEVELS[CONCURRENCY_LEVELS.length - 1]} VU
${SEP}
  ── TABLE 1: PRIMARY + SECONDARY METRICS ──
  ${hdr}
  ${unit}
  ${LINE}
  [ PQC Algorithms ]
  ${pqcRows.trimEnd().split("\n").join("\n  ")}
  ${LINE}
  [ Classical Algorithms ]
  ${classicRows.trimEnd().split("\n").join("\n  ") || "(tidak ada)"}

  ── TABLE 2: SIGNING LATENCY DECOMPOSITION (clean vs dirty) ──
  ${hdrL}
  ${unitL}
  ${LINE}
  [ PQC Algorithms ]
  ${pqcRowsL.trimEnd().split("\n").join("\n  ")}
  ${LINE}
  [ Classical Algorithms ]
  ${classicRowsL.trimEnd().split("\n").join("\n  ") || "(tidak ada)"}
${SEP}
  TABLE 1 LEGEND
  GenTime    = Token Generation Time (sign-in full round-trip), avg & p95
  VerTime    = Token Verification Time (profile/middleware), avg & p95
  Resp       = Total response duration all endpoints, avg & p95
  AuthRPS    = Auth sign-in requests per second (authentication throughput)
  TotalRPS   = All requests / scenario duration (req/s)
  Attack     = JWT Confusion Attack block rate (100.0% = all attacks rejected)

  TABLE 2 LEGEND
  Dirty      = Full k6 client round-trip (network + queuing + server)  → "dirty" latency
  Clean      = timings.waiting: time-to-first-byte after send (server processing approx)
  Network    = Dirty − Clean: connection setup + send + receive overhead
  Actual     = X-Sign-Time-Ms header: pure PQC signing op measured server-side → "clean" latency
               (requires auth-service to set gRPC trailer x-sign-time-ms)
${SEP}
`;

  return {
    stdout: table,
    "benchmark_compare_result.json": JSON.stringify(data, null, 2),
  };
}
