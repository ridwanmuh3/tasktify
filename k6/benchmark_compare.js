/**
 * benchmark_compare.js
 *
 * Perbandingan performa seluruh algoritma JWT via SATU endpoint production.
 * Algoritma dipilih lewat field "algorithm" di request body sign-in.
 *
 *   PQC  : Falcon-Precomputed-512, Falcon-512, ML-DSA-44, SLH-DSA-SHA2-128f
 *   Klasik: ES256, RS256, HS256, EdDSA
 *
 * Parameter uji per algoritma (100 iterasi):
 *   - Token Generation Time  (durasi sign-in)
 *   - Token Verification Time (durasi profile endpoint)
 *   - Response Body Size
 *   - Request Header Size
 *   - Response Time (semua endpoint)
 *   - Throughput (request berhasil per detik)
 *   - JWT Confusion Attack Resistance
 *
 * Jalankan:
 *   k6 run k6/benchmark_compare.js
 *   k6 run -e BASE_URL=https://poc-ridwanmuh3.my.id k6/benchmark_compare.js
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Trend, Counter, Rate } from "k6/metrics";
import encoding from "k6/encoding";
import { randomString } from "https://jslib.k6.io/k6-utils/1.4.0/index.js";

// ═══════════════════════════════════════════════════════════════
// Konfigurasi
// ═══════════════════════════════════════════════════════════════

const BASE_URL = __ENV.BASE_URL || "https://poc-ridwanmuh3.my.id";

const ALGORITHMS = [
  { id: "FNP512", name: "Falcon-Precomputed-512", category: "PQC" },
  { id: "FN512", name: "Falcon-512", category: "PQC" },
  { id: "MLDSA44", name: "ML-DSA-44", category: "PQC" },
  { id: "SLHDSA", name: "SLH-DSA-SHA2-128f", category: "PQC" },
  // { id: "ES256",   name: "ES256",                   category: "Classic" },
  // { id: "RS256",   name: "RS256",                   category: "Classic" },
  // { id: "HS256",   name: "HS256",                   category: "Classic" },
  // { id: "EdDSA",   name: "EdDSA",                   category: "Classic" },
];

// ═══════════════════════════════════════════════════════════════
// Custom Metrics — tagged per algoritma via threshold sub-metrics
// ═══════════════════════════════════════════════════════════════

const tokenGenTime = new Trend("token_gen_time", true);
const tokenVerTime = new Trend("token_ver_time", true);
const respDuration = new Trend("resp_duration", true);
const respBodySize = new Trend("resp_body_size");
const reqHeaderSize = new Trend("req_header_size");
const attackBlock = new Rate("attack_block_rate");
const reqSuccess = new Counter("req_success");
const reqFailed = new Counter("req_failed");

// ═══════════════════════════════════════════════════════════════
// Scenarios: 100 iterasi per algoritma, dijalankan berurutan
// ═══════════════════════════════════════════════════════════════

const scenarios = {};
let startDelay = 0;
for (const alg of ALGORITHMS) {
  scenarios[alg.id] = {
    executor: "per-vu-iterations",
    vus: 1,
    iterations: 100,
    startTime: `${startDelay}s`,
    exec: "benchmark",
    env: { CURRENT_ALG: alg.id },
    gracefulStop: "10s",
  };
  startDelay += 3;
}

// ═══════════════════════════════════════════════════════════════
// Thresholds — k6 membuat sub-metric per tag {alg:...}
// ═══════════════════════════════════════════════════════════════

const thresholds = {
  attack_block_rate: ["rate==1.0"],
};
for (const alg of ALGORITHMS) {
  const t = `{alg:${alg.name}}`;
  thresholds[`token_gen_time${t}`] = ["p(95)<15000"];
  thresholds[`token_ver_time${t}`] = ["p(95)<10000"];
  thresholds[`resp_duration${t}`] = ["p(95)<15000"];
  thresholds[`attack_block_rate${t}`] = ["rate==1.0"];
}

export const options = {
  scenarios,
  thresholds,
  setupTimeout: "180s",
  teardownTimeout: "30s",
};

// ═══════════════════════════════════════════════════════════════
// Setup: daftarkan satu user, lalu sign-in dengan tiap algoritma
// ═══════════════════════════════════════════════════════════════

export function setup() {
  const suffix = randomString(8).toLowerCase();
  const user = {
    name: `bench-${suffix}`,
    email: `bench-${suffix}@bench.test`,
    password: "BenchPass!123",
  };

  // Registrasi sekali — satu user untuk semua algoritma
  const regRes = http.post(`${BASE_URL}/api/register`, JSON.stringify(user), {
    headers: { "Content-Type": "application/json" },
  });
  if (regRes.status !== 201) {
    console.error(`Register gagal: ${regRes.status} — ${regRes.body}`);
    return null;
  }
  console.log(`User terdaftar: ${user.email}`);

  // Sign-in per algoritma untuk mendapatkan token awal
  const tokens = {};
  for (const alg of ALGORITHMS) {
    const res = http.post(
      `${BASE_URL}/api/auth/sign-in`,
      JSON.stringify({
        email: user.email,
        password: user.password,
        algorithm: alg.name,
      }),
      { headers: { "Content-Type": "application/json" } },
    );
    if (res.status !== 200) {
      console.error(`[${alg.name}] Sign-in gagal: ${res.status} — ${res.body}`);
      tokens[alg.id] = null;
      continue;
    }
    const body = JSON.parse(res.body);
    tokens[alg.id] = {
      accessToken: body.data.access_token,
      refreshToken: body.data.refresh_token,
    };
    console.log(`[${alg.name}] Token awal didapat`);
  }

  return { user, tokens };
}

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
  if (!data) {
    console.warn("Tidak ada setup data");
    return;
  }

  const algId = __ENV.CURRENT_ALG;
  const alg = ALGORITHMS.find((a) => a.id === algId);
  if (!alg) return;

  const td = data.tokens[algId];
  if (!td) {
    console.warn(`[${alg.name}] Tidak ada token, iterasi dilewati`);
    return;
  }

  const tags = { alg: alg.name };
  const authHdr = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${td.accessToken}`,
  };
  const jsonHdr = { "Content-Type": "application/json" };

  // ─── 1. Token Generation Time ───────────────────────────────
  // Sign-in dengan "algorithm" di body — mengukur waktu signing
  group("1. Token Generation", () => {
    const payload = JSON.stringify({
      email: data.user.email,
      password: data.user.password,
      algorithm: alg.name, // ← pilih algoritma via request body
    });
    const res = http.post(`${BASE_URL}/api/auth/sign-in`, payload, {
      headers: jsonHdr,
    });

    tokenGenTime.add(res.timings.duration, tags);
    respDuration.add(res.timings.duration, tags);
    respBodySize.add(res.body.length, tags);
    reqHeaderSize.add(estimateHeaderSize(jsonHdr), tags);

    const ok = check(res, {
      [`[${alg.name}] sign-in 200`]: (r) => r.status === 200,
      [`[${alg.name}] has access_token`]: (r) => {
        try {
          return !!JSON.parse(r.body).data?.access_token;
        } catch {
          return false;
        }
      },
    });
    ok ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);

    // Perbarui token agar verification pakai token algoritma yang benar
    if (res.status === 200) {
      try {
        const b = JSON.parse(res.body);
        td.accessToken = b.data.access_token;
        td.refreshToken = b.data.refresh_token;
      } catch (_) {}
    }
  });

  // ─── 2. Token Verification Time ─────────────────────────────
  // Gateway memverifikasi signature algoritma yang ditentukan token header
  group("2. Token Verification", () => {
    const res = http.get(`${BASE_URL}/api/profile`, { headers: authHdr });

    tokenVerTime.add(res.timings.duration, tags);
    respDuration.add(res.timings.duration, tags);
    respBodySize.add(res.body.length, tags);
    reqHeaderSize.add(estimateHeaderSize(authHdr), tags);

    const ok = check(res, {
      [`[${alg.name}] profile 200`]: (r) => r.status === 200,
      [`[${alg.name}] profile has email`]: (r) => {
        try {
          return !!JSON.parse(r.body).data?.email;
        } catch {
          return false;
        }
      },
    });
    ok ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);
  });

  // ─── 3. Task CRUD — Response Time & Throughput ──────────────
  group("3. Task CRUD", () => {
    const createRes = http.post(
      `${BASE_URL}/api/tasks/`,
      JSON.stringify({
        title: `bench-${randomString(6)}`,
        description: `benchmark [${alg.name}]`,
        status: "PENDING",
        due_date: Date.now() + 86400000,
      }),
      { headers: authHdr },
    );
    respDuration.add(createRes.timings.duration, tags);
    respBodySize.add(createRes.body.length, tags);
    check(createRes, { [`[${alg.name}] create 201`]: (r) => r.status === 201 })
      ? reqSuccess.add(1, tags)
      : reqFailed.add(1, tags);

    const listRes = http.get(`${BASE_URL}/api/tasks/`, { headers: authHdr });
    respDuration.add(listRes.timings.duration, tags);
    respBodySize.add(listRes.body.length, tags);
    check(listRes, { [`[${alg.name}] list 200`]: (r) => r.status === 200 })
      ? reqSuccess.add(1, tags)
      : reqFailed.add(1, tags);

    let taskId = null;
    try {
      const tasks = JSON.parse(listRes.body).data;
      if (Array.isArray(tasks) && tasks.length > 0) taskId = tasks[0].id;
    } catch (_) {}

    if (taskId) {
      const getRes = http.get(`${BASE_URL}/api/tasks/${taskId}`, {
        headers: authHdr,
      });
      respDuration.add(getRes.timings.duration, tags);
      check(getRes, { [`[${alg.name}] get 200`]: (r) => r.status === 200 })
        ? reqSuccess.add(1, tags)
        : reqFailed.add(1, tags);

      const updRes = http.put(
        `${BASE_URL}/api/tasks/${taskId}`,
        JSON.stringify({
          title: `bench-upd-${randomString(4)}`,
          description: "updated by k6",
          status: "IN_PROGRESS",
          due_date: Date.now() + 172800000,
        }),
        { headers: authHdr },
      );
      respDuration.add(updRes.timings.duration, tags);
      check(updRes, { [`[${alg.name}] update 200`]: (r) => r.status === 200 })
        ? reqSuccess.add(1, tags)
        : reqFailed.add(1, tags);

      const delRes = http.del(`${BASE_URL}/api/tasks/${taskId}`, null, {
        headers: authHdr,
      });
      respDuration.add(delRes.timings.duration, tags);
      check(delRes, { [`[${alg.name}] delete 200`]: (r) => r.status === 200 })
        ? reqSuccess.add(1, tags)
        : reqFailed.add(1, tags);
    }
  });

  // ─── 4. Refresh Token ────────────────────────────────────────
  group("4. Refresh Token", () => {
    const res = http.post(
      `${BASE_URL}/api/auth/refresh-token`,
      JSON.stringify({ refresh_token: td.refreshToken }),
      { headers: jsonHdr },
    );
    tokenGenTime.add(res.timings.duration, tags);
    respDuration.add(res.timings.duration, tags);
    respBodySize.add(res.body.length, tags);

    const ok = check(res, {
      [`[${alg.name}] refresh 200`]: (r) => r.status === 200,
    });
    ok ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);

    if (res.status === 200) {
      try {
        const b = JSON.parse(res.body);
        td.accessToken = b.data.access_token;
        td.refreshToken = b.data.refresh_token;
      } catch (_) {}
    }
  });

  // ─── 5. JWT Confusion Attack Resistance ─────────────────────
  group("5. JWT Confusion Attacks", () => {
    const url = `${BASE_URL}/api/profile`;
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
        hdr: { Authorization: `Bearer ${tamperedToken(td.accessToken)}` },
      },
    ];

    for (const atk of attacks) {
      const res = http.get(url, {
        headers: { ...atk.hdr, "Content-Type": "application/json" },
      });
      const blocked = res.status === 401 || res.status === 400;
      attackBlock.add(blocked, tags);
      check(res, {
        [`[${alg.name}] attack:${atk.name} → blocked`]: () => blocked,
      });
    }

    // Token valid harus diterima
    const validRes = http.get(url, { headers: authHdr });
    check(validRes, {
      [`[${alg.name}] valid token: accepted`]: (r) => r.status === 200,
    });
    validRes.status === 200 ? reqSuccess.add(1, tags) : reqFailed.add(1, tags);
  });

  sleep(0.05);
}

// ═══════════════════════════════════════════════════════════════
// Custom Summary — Tabel Perbandingan
// ═══════════════════════════════════════════════════════════════

export function handleSummary(data) {
  const m = data.metrics;

  function getTagVal(metric, algName, stat) {
    const key = `${metric}{alg:${algName}}`;
    if (!(key in m)) return "—";
    const v = m[key].values[stat];
    if (v === undefined) return "—";
    if (stat === "rate") return (v * 100).toFixed(1) + "%";
    return v.toFixed(2);
  }

  const sep = "═".repeat(112);
  const line = "─".repeat(112);

  function pad(s, w) {
    const str = String(s);
    return str.length >= w
      ? str.slice(0, w - 1) + " "
      : str + " ".repeat(w - str.length);
  }

  const W = [28, 10, 10, 10, 10, 10, 10, 10, 10, 9];

  const hdr = [
    pad("Algorithm", W[0]),
    pad("GenTime", W[1]),
    pad("Gen p95", W[2]),
    pad("VerTime", W[3]),
    pad("Ver p95", W[4]),
    pad("Resp avg", W[5]),
    pad("Resp p95", W[6]),
    pad("Body avg", W[7]),
    pad("Hdr avg", W[8]),
    pad("Attack", W[9]),
  ].join("");

  const unit = [
    pad("", W[0]),
    pad("avg (ms)", W[1]),
    pad("(ms)", W[2]),
    pad("avg (ms)", W[3]),
    pad("(ms)", W[4]),
    pad("(ms)", W[5]),
    pad("(ms)", W[6]),
    pad("(B)", W[7]),
    pad("(B)", W[8]),
    pad("Blocked", W[9]),
  ].join("");

  let pqcRows = "",
    classicRows = "";
  for (const alg of ALGORITHMS) {
    const n = alg.name;
    const row =
      [
        pad(n, W[0]),
        pad(getTagVal("token_gen_time", n, "avg"), W[1]),
        pad(getTagVal("token_gen_time", n, "p(95)"), W[2]),
        pad(getTagVal("token_ver_time", n, "avg"), W[3]),
        pad(getTagVal("token_ver_time", n, "p(95)"), W[4]),
        pad(getTagVal("resp_duration", n, "avg"), W[5]),
        pad(getTagVal("resp_duration", n, "p(95)"), W[6]),
        pad(getTagVal("resp_body_size", n, "avg"), W[7]),
        pad(getTagVal("req_header_size", n, "avg"), W[8]),
        pad(getTagVal("attack_block_rate", n, "rate"), W[9]),
      ].join("") + "\n";
    alg.category === "PQC" ? (pqcRows += row) : (classicRows += row);
  }

  const table = `
${sep}
  JWT ALGORITHM PERFORMANCE COMPARISON
  Endpoint : ${BASE_URL}
  Iterasi  : 100 per algoritma  |  Total : ${ALGORITHMS.length * 100}
${sep}
  ${hdr}
  ${unit}
  ${line}
  [ PQC Algorithms ]
  ${pqcRows.trim().split("\n").join("\n  ")}
  ${line}
  [ Classical Algorithms ]
  ${classicRows.trim().split("\n").join("\n  ")}
${sep}
  GenTime  = Token Generation Time (sign-in + refresh)
  VerTime  = Token Verification Time (verifikasi di middleware gateway)
  Resp     = Total response duration semua endpoint
  Body     = Ukuran response body rata-rata (bytes)
  Hdr      = Ukuran request header rata-rata (bytes)
  Attack   = JWT Confusion Attack block rate  (100% = semua serangan ditolak)
${sep}
`;

  return {
    stdout: table,
    "k6/benchmark_compare_result.json": JSON.stringify(data, null, 2),
  };
}
