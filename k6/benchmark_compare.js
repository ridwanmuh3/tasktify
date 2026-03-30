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
 *          ML-DSA-44 (:5003), SLH-DSA-SHA2-128f (:5004)
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Trend, Counter, Rate } from "k6/metrics";
import encoding from "k6/encoding";
import exec from "k6/execution";
import { randomString } from "https://jslib.k6.io/k6-utils/1.4.0/index.js";

// ═══════════════════════════════════════════════════════════════
// Konfigurasi
// ═══════════════════════════════════════════════════════════════

const _HOST     = __ENV.HOST;
const _BASE_URL = __ENV.BASE_URL;

const isMultiGateway = !!_HOST;

function normalizeBase(url) {
  if (!url) return "";
  if (url.startsWith("http://") || url.startsWith("https://")) return url;
  return "http://" + url;
}

const HOST_BASE       = normalizeBase(_HOST);
const SINGLE_BASE_URL = _BASE_URL ? normalizeBase(_BASE_URL) : "https://poc-ridwanmuh3.my.id";

// Port gateway per algoritma sesuai docker-compose.benchmark.yml
const ALGORITHMS = [
  { id: "FNP512",  name: "Falcon-Precomputed-512", category: "PQC", port: 5001 },
  { id: "FN512",   name: "Falcon-512",             category: "PQC", port: 5002 },
  { id: "MLDSA44", name: "ML-DSA-44",              category: "PQC", port: 5003 },
  { id: "SLHDSA",  name: "SLH-DSA-SHA2-128f",      category: "PQC", port: 5004 },
  // { id: "ES256",  name: "ES256",  category: "Classic", port: 5005 },
  // { id: "RS256",  name: "RS256",  category: "Classic", port: 5006 },
  // { id: "HS256",  name: "HS256",  category: "Classic", port: 5007 },
  // { id: "EdDSA",  name: "EdDSA",  category: "Classic", port: 5008 },
];

// Level konkuren yang diuji
const CONCURRENCY_LEVELS = [100, 500, 1000];

// Durasi sustain per skenario (detik) dan jeda antar skenario
const SCENARIO_DURATION_S = 30;
const SCENARIO_GAP_S      = 20;

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

const tokenGenTime = new Trend("token_gen_time", true);
const tokenVerTime = new Trend("token_ver_time", true);
const respDuration  = new Trend("resp_duration",  true);
const respBodySize  = new Trend("resp_body_size");
const reqHeaderSize = new Trend("req_header_size");
const attackBlock   = new Rate("attack_block_rate");
const reqSuccess    = new Counter("req_success");
const reqFailed     = new Counter("req_failed");

// ═══════════════════════════════════════════════════════════════
// Scenarios: tiap algoritma × tiap level VU, dijalankan berurutan
// ═══════════════════════════════════════════════════════════════

const scenarios = {};
let startDelay = 0;

for (const alg of ALGORITHMS) {
  for (const vus of CONCURRENCY_LEVELS) {
    const id = `${alg.id}_${vus}VU`;
    scenarios[id] = {
      executor:     "constant-vus",
      vus:          vus,
      duration:     `${SCENARIO_DURATION_S}s`,
      startTime:    `${startDelay}s`,
      exec:         "benchmark",
      env:          { CURRENT_ALG: alg.id, CURRENT_VUS: String(vus) },
      gracefulStop: "10s",
    };
    startDelay += SCENARIO_DURATION_S + SCENARIO_GAP_S;
  }
}

// ═══════════════════════════════════════════════════════════════
// Thresholds — per algoritma (tanpa per-VU agar tabel tidak terlalu panjang)
// ═══════════════════════════════════════════════════════════════

const thresholds = {
  attack_block_rate: ["rate==1.0"],
};
for (const alg of ALGORITHMS) {
  const t = `{alg:${alg.name}}`;
  thresholds[`token_gen_time${t}`]    = ["p(95)<15000"];
  thresholds[`token_ver_time${t}`]    = ["p(95)<10000"];
  thresholds[`resp_duration${t}`]     = ["p(95)<15000"];
  thresholds[`attack_block_rate${t}`] = ["rate==1.0"];
}

export const options = {
  scenarios,
  thresholds,
  setupTimeout:    "60s",
  teardownTimeout: "30s",
};

// ═══════════════════════════════════════════════════════════════
// Setup: hanya registrasi user — tiap VU sign-in sendiri saat berjalan
// ═══════════════════════════════════════════════════════════════

export function setup() {
  const suffix = randomString(8).toLowerCase();
  const user = {
    name:     `bench-${suffix}`,
    email:    `bench-${suffix}@bench.test`,
    password: "BenchPass!123",
  };

  const firstAlg    = ALGORITHMS[0];
  const registerUrl = `${getBaseUrl(firstAlg)}/api/register`;
  console.log(`Mendaftar ke: ${registerUrl}`);

  const regRes = http.post(registerUrl, JSON.stringify(user), {
    headers: { "Content-Type": "application/json" },
    timeout: "30s",
  });

  if (regRes.status !== 201) {
    exec.test.abort(
      `Register gagal (${regRes.status}) di ${registerUrl} — ${regRes.body}`
    );
  }
  console.log(`User terdaftar: ${user.email}`);

  return { user };
}

// ═══════════════════════════════════════════════════════════════
// VU-local state — token per-VU, reset saat skenario berganti
// ═══════════════════════════════════════════════════════════════

let _vuToken        = null;
let _vuRefreshToken = null;
let _vuScenarioKey  = null;

// ═══════════════════════════════════════════════════════════════
// Helper
// ═══════════════════════════════════════════════════════════════

function estimateHeaderSize(headers) {
  return Object.entries(headers).reduce(
    (s, [k, v]) => s + k.length + 2 + String(v).length + 2, 0,
  );
}

function b64url(str) {
  return encoding.b64encode(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fakeJwt(alg, claimsOverride, sig) {
  const header  = b64url(JSON.stringify({ alg, typ: "JWT" }));
  const now     = Math.floor(Date.now() / 1000);
  const payload = b64url(JSON.stringify(Object.assign(
    { sub: "00000000-0000-0000-0000-000000000000", email: "attacker@evil.com",
      iss: "tasktify", exp: now + 3600, iat: now },
    claimsOverride || {},
  )));
  return `${header}.${payload}.${sig !== undefined ? sig : "fakesig"}`;
}

function tamperedToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return token;
  const evilPayload = b64url(JSON.stringify({
    sub: "99999999-9999-9999-9999-999999999999", email: "hijacked@evil.com",
    iss: "tasktify", exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
  }));
  return `${parts[0]}.${evilPayload}.${parts[2]}`;
}

// ═══════════════════════════════════════════════════════════════
// Fungsi Benchmark Utama
// ═══════════════════════════════════════════════════════════════

export function benchmark(data) {
  if (!data) exec.test.abort("Setup gagal — tidak ada data");

  const algId   = __ENV.CURRENT_ALG;
  const vuCount = __ENV.CURRENT_VUS;
  const alg     = ALGORITHMS.find((a) => a.id === algId);
  if (!alg) return;

  const BASE    = getBaseUrl(alg);
  const tags    = { alg: alg.name, vus: vuCount };
  const jsonHdr = { "Content-Type": "application/json" };

  // Reset token VU-local jika skenario berganti (algoritma atau level VU berbeda)
  const scenarioKey = `${algId}_${vuCount}`;
  if (_vuScenarioKey !== scenarioKey) {
    _vuScenarioKey  = scenarioKey;
    _vuToken        = null;
    _vuRefreshToken = null;
  }

  // ─── 1. Token Generation Time ───────────────────────────────
  // Setiap iterasi sign-in: mengukur waktu signing + mendapatkan token segar
  group("1. Token Generation", () => {
    const body = { email: data.user.email, password: data.user.password };
    if (!isMultiGateway) body.algorithm = alg.name;

    const res = http.post(`${BASE}/api/auth/sign-in`, JSON.stringify(body), {
      headers: jsonHdr,
    });

    tokenGenTime.add(res.timings.duration, tags);
    respDuration.add(res.timings.duration, tags);
    respBodySize.add(res.body.length, tags);
    reqHeaderSize.add(estimateHeaderSize(jsonHdr), tags);

    const ok = check(res, {
      [`[${alg.name}|${vuCount}VU] sign-in 200`]:      (r) => r.status === 200,
      [`[${alg.name}|${vuCount}VU] has access_token`]: (r) => {
        try { return !!JSON.parse(r.body).data?.access_token; } catch { return false; }
      },
    });
    ok ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);

    if (res.status === 200) {
      try {
        const b        = JSON.parse(res.body);
        _vuToken        = b.data.access_token;
        _vuRefreshToken = b.data.refresh_token;
      } catch (_) {}
    }
  });

  if (!_vuToken) return; // sign-in gagal, lewati iterasi ini

  const authHdr = {
    "Content-Type": "application/json",
    Authorization:  `Bearer ${_vuToken}`,
  };

  // ─── 2. Token Verification Time ─────────────────────────────
  group("2. Token Verification", () => {
    const res = http.get(`${BASE}/api/profile`, { headers: authHdr });

    tokenVerTime.add(res.timings.duration, tags);
    respDuration.add(res.timings.duration, tags);
    respBodySize.add(res.body.length, tags);
    reqHeaderSize.add(estimateHeaderSize(authHdr), tags);

    const ok = check(res, {
      [`[${alg.name}|${vuCount}VU] profile 200`]:       (r) => r.status === 200,
      [`[${alg.name}|${vuCount}VU] profile has email`]: (r) => {
        try { return !!JSON.parse(r.body).data?.email; } catch { return false; }
      },
    });
    ok ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);
  });

  // ─── 3. Task CRUD ────────────────────────────────────────────
  group("3. Task CRUD", () => {
    const createRes = http.post(
      `${BASE}/api/tasks/`,
      JSON.stringify({
        title:       `bench-${randomString(6)}`,
        description: `benchmark [${alg.name}]`,
        status:      "PENDING",
        due_date:    Date.now() + 86400000,
      }),
      { headers: authHdr },
    );
    respDuration.add(createRes.timings.duration, tags);
    respBodySize.add(createRes.body.length, tags);
    check(createRes, { [`[${alg.name}|${vuCount}VU] create 201`]: (r) => r.status === 201 })
      ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);

    const listRes = http.get(`${BASE}/api/tasks/`, { headers: authHdr });
    respDuration.add(listRes.timings.duration, tags);
    respBodySize.add(listRes.body.length, tags);
    check(listRes, { [`[${alg.name}|${vuCount}VU] list 200`]: (r) => r.status === 200 })
      ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);

    let taskId = null;
    try {
      const tasks = JSON.parse(listRes.body).data;
      if (Array.isArray(tasks) && tasks.length > 0) taskId = tasks[0].id;
    } catch (_) {}

    if (taskId) {
      const getRes = http.get(`${BASE}/api/tasks/${taskId}`, { headers: authHdr });
      respDuration.add(getRes.timings.duration, tags);
      check(getRes, { [`[${alg.name}|${vuCount}VU] get 200`]: (r) => r.status === 200 })
        ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);

      const updRes = http.put(
        `${BASE}/api/tasks/${taskId}`,
        JSON.stringify({
          title:       `bench-upd-${randomString(4)}`,
          description: "updated by k6",
          status:      "IN_PROGRESS",
          due_date:    Date.now() + 172800000,
        }),
        { headers: authHdr },
      );
      respDuration.add(updRes.timings.duration, tags);
      check(updRes, { [`[${alg.name}|${vuCount}VU] update 200`]: (r) => r.status === 200 })
        ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);

      const delRes = http.del(`${BASE}/api/tasks/${taskId}`, null, { headers: authHdr });
      respDuration.add(delRes.timings.duration, tags);
      check(delRes, { [`[${alg.name}|${vuCount}VU] delete 200`]: (r) => r.status === 200 })
        ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);
    }
  });

  // ─── 4. Refresh Token ────────────────────────────────────────
  group("4. Refresh Token", () => {
    const res = http.post(
      `${BASE}/api/auth/refresh-token`,
      JSON.stringify({ refresh_token: _vuRefreshToken }),
      { headers: jsonHdr },
    );
    tokenGenTime.add(res.timings.duration, tags);
    respDuration.add(res.timings.duration, tags);
    respBodySize.add(res.body.length, tags);

    const ok = check(res, {
      [`[${alg.name}|${vuCount}VU] refresh 200`]: (r) => r.status === 200,
    });
    ok ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);

    if (res.status === 200) {
      try {
        const b        = JSON.parse(res.body);
        _vuToken        = b.data.access_token;
        _vuRefreshToken = b.data.refresh_token;
      } catch (_) {}
    }
  });

  // ─── 5. JWT Confusion Attack Resistance ─────────────────────
  // Hanya dijalankan pada 100 VU untuk efisiensi (hasil serupa di semua level)
  if (vuCount === "100") {
    group("5. JWT Confusion Attacks", () => {
      const url = `${BASE}/api/profile`;
      const now = Math.floor(Date.now() / 1000);

      const attacks = [
        { name: "alg=none",         hdr: { Authorization: `Bearer ${fakeJwt("none", {}, "")}` } },
        { name: "alg=HS256",        hdr: { Authorization: `Bearer ${fakeJwt("HS256")}` } },
        { name: "alg=RS256",        hdr: { Authorization: `Bearer ${fakeJwt("RS256")}` } },
        { name: "alg=ES256",        hdr: { Authorization: `Bearer ${fakeJwt("ES256")}` } },
        { name: "alg=Falcon-512",   hdr: { Authorization: `Bearer ${fakeJwt("Falcon-512")}` } },
        { name: "alg=ML-DSA-44",    hdr: { Authorization: `Bearer ${fakeJwt("ML-DSA-44")}` } },
        { name: "sig stripped",     hdr: { Authorization: `Bearer ${fakeJwt(alg.name, {}, "")}` } },
        { name: "random sig",       hdr: { Authorization: `Bearer ${fakeJwt(alg.name, {}, randomString(32))}` } },
        { name: "expired",          hdr: { Authorization: `Bearer ${fakeJwt(alg.name, { exp: now - 3600, iat: now - 7200 }, "fakesig")}` } },
        { name: "future iat",       hdr: { Authorization: `Bearer ${fakeJwt(alg.name, { iat: now + 3600 }, "fakesig")}` } },
        { name: "iss spoof",        hdr: { Authorization: `Bearer ${fakeJwt(alg.name, { iss: "evil-issuer" }, "fakesig")}` } },
        { name: "2 segments",       hdr: { Authorization: "Bearer aaa.bbb" } },
        { name: "random garbage",   hdr: { Authorization: `Bearer ${randomString(200)}` } },
        { name: "tampered payload", hdr: { Authorization: `Bearer ${tamperedToken(_vuToken)}` } },
      ];

      for (const atk of attacks) {
        const res     = http.get(url, { headers: { ...atk.hdr, "Content-Type": "application/json" } });
        const blocked = res.status === 401 || res.status === 400;
        attackBlock.add(blocked, tags);
        check(res, { [`[${alg.name}] attack:${atk.name} → blocked`]: () => blocked });
      }

      const validRes = http.get(url, { headers: authHdr });
      check(validRes, { [`[${alg.name}] valid token: accepted`]: (r) => r.status === 200 });
      validRes.status === 200 ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);
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

  // Ambil attack rate hanya dari tag alg (karena attack hanya di level 100 VU)
  function getAttack(algName) {
    const key = `attack_block_rate{alg:${algName},vus:100}`;
    if (!(key in m)) return "—";
    const v = m[key].values["rate"];
    if (v === undefined) return "—";
    return (v * 100).toFixed(1) + "%";
  }

  const sep  = "═".repeat(118);
  const line = "─".repeat(118);

  function pad(s, w) {
    const str = String(s);
    return str.length >= w ? str.slice(0, w - 1) + " " : str + " ".repeat(w - str.length);
  }

  // [Algorithm, VUs, GenAvg, Genp95, VerAvg, Verp95, RespAvg, Respp95, BodyAvg, HdrAvg, Attack]
  const W = [26, 6, 10, 10, 10, 10, 10, 10, 10, 10, 9];

  const hdr = [
    pad("Algorithm", W[0]),
    pad("VUs",       W[1]),
    pad("GenTime",   W[2]),
    pad("Gen p95",   W[3]),
    pad("VerTime",   W[4]),
    pad("Ver p95",   W[5]),
    pad("Resp avg",  W[6]),
    pad("Resp p95",  W[7]),
    pad("Body avg",  W[8]),
    pad("Hdr avg",   W[9]),
    pad("Attack",    W[10]),
  ].join("");

  const unit = [
    pad("", W[0]),
    pad("", W[1]),
    pad("avg (ms)", W[2]),
    pad("(ms)",     W[3]),
    pad("avg (ms)", W[4]),
    pad("(ms)",     W[5]),
    pad("(ms)",     W[6]),
    pad("(ms)",     W[7]),
    pad("(B)",      W[8]),
    pad("(B)",      W[9]),
    pad("Blocked",  W[10]),
  ].join("");

  let pqcRows = "", classicRows = "";

  for (const alg of ALGORITHMS) {
    const n = alg.name;
    for (let i = 0; i < CONCURRENCY_LEVELS.length; i++) {
      const vus   = String(CONCURRENCY_LEVELS[i]);
      // Tampilkan nama algoritma hanya di baris pertama (level 100 VU)
      const label = i === 0 ? n : "";

      const row = [
        pad(label,                              W[0]),
        pad(vus,                                W[1]),
        pad(getVal("token_gen_time",  n, vus, "avg"),   W[2]),
        pad(getVal("token_gen_time",  n, vus, "p(95)"), W[3]),
        pad(getVal("token_ver_time",  n, vus, "avg"),   W[4]),
        pad(getVal("token_ver_time",  n, vus, "p(95)"), W[5]),
        pad(getVal("resp_duration",   n, vus, "avg"),   W[6]),
        pad(getVal("resp_duration",   n, vus, "p(95)"), W[7]),
        pad(getVal("resp_body_size",  n, vus, "avg"),   W[8]),
        pad(getVal("req_header_size", n, vus, "avg"),   W[9]),
        pad(i === 0 ? getAttack(n) : "",        W[10]),
      ].join("") + "\n";

      alg.category === "PQC" ? (pqcRows += row) : (classicRows += row);
    }
    // Baris pemisah antar algoritma
    const separator = pad("", W[0] + W[1]) + "─".repeat(W.slice(2).reduce((a, b) => a + b, 0)) + "\n";
    alg.category === "PQC" ? (pqcRows += separator) : (classicRows += separator);
  }

  const totalScenarios = ALGORITHMS.length * CONCURRENCY_LEVELS.length;
  const table = `
${sep}
  JWT ALGORITHM PERFORMANCE COMPARISON  —  Concurrent Users: ${CONCURRENCY_LEVELS.join(" / ")} VU
  Endpoint  : ${DISPLAY_ENDPOINT}
  Skenario  : ${totalScenarios} (${ALGORITHMS.length} algoritma × ${CONCURRENCY_LEVELS.length} level VU)
  Durasi    : ${SCENARIO_DURATION_S}s sustain per skenario
  Attack    = diukur hanya pada level ${CONCURRENCY_LEVELS[0]} VU
${sep}
  ${hdr}
  ${unit}
  ${line}
  [ PQC Algorithms ]
  ${pqcRows.trimEnd().split("\n").join("\n  ")}
  ${line}
  [ Classical Algorithms ]
  ${classicRows.trimEnd().split("\n").join("\n  ") || "(tidak ada)"}
${sep}
  GenTime  = Token Generation Time (sign-in + refresh), avg & p95
  VerTime  = Token Verification Time (middleware gateway), avg & p95
  Resp     = Total response duration semua endpoint, avg & p95
  Body     = Ukuran response body rata-rata (bytes)
  Hdr      = Ukuran request header rata-rata (bytes, mencerminkan ukuran JWT)
  Attack   = JWT Confusion Attack block rate (100.0% = semua serangan ditolak)
${sep}
`;

  return {
    stdout: table,
    "k6/benchmark_compare_result.json": JSON.stringify(data, null, 2),
  };
}
