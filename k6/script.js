import http from "k6/http";
import { check, group, sleep } from "k6";
import { Trend, Counter, Rate } from "k6/metrics";
import encoding from "k6/encoding";
import { randomString } from "https://jslib.k6.io/k6-utils/1.4.0/index.js";

// ═══════════════════════════════════════════════════
// Custom Metrics
// ═══════════════════════════════════════════════════

const tokenGenerationTime = new Trend("token_generation_time", true);
const tokenVerificationTime = new Trend("token_verification_time", true);
const responseBodySize = new Trend("response_body_size");
const requestHeaderSize = new Trend("request_header_size");
const successfulRequests = new Counter("successful_requests");
const failedRequests = new Counter("failed_requests");
const confusionAttackBlocked = new Counter("jwt_confusion_attack_blocked");
const confusionAttackPassed = new Counter("jwt_confusion_attack_passed");
const confusionAttackBlockRate = new Rate("jwt_confusion_attack_block_rate");

// ═══════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════

const BASE_URL = __ENV.BASE_URL || "https://poc-ridwanmuh3.my.id";

export const options = {
  iterations: 100,
  vus: 10,
  thresholds: {
    token_generation_time: ["p(95)<5000"],
    token_verification_time: ["p(95)<2000"],
    http_req_duration: ["p(95)<5000"],
    jwt_confusion_attack_block_rate: ["rate==1.0"],
  },
};

// ═══════════════════════════════════════════════════
// Setup: register test user & sign in
// ═══════════════════════════════════════════════════

export function setup() {
  const suffix = randomString(8);
  const testUser = {
    name: `k6-tester-${suffix}`,
    email: `k6test-${suffix}@example.com`,
    password: "K6TestPass!123",
  };

  const regRes = http.post(
    `${BASE_URL}/api/register`,
    JSON.stringify(testUser),
    { headers: { "Content-Type": "application/json" } },
  );

  check(regRes, {
    "register: status 201": (r) => r.status === 201,
  });

  if (regRes.status !== 201) {
    console.error(`Registration failed: ${regRes.status} - ${regRes.body}`);
  }

  const signInRes = http.post(
    `${BASE_URL}/api/auth/sign-in`,
    JSON.stringify({ email: testUser.email, password: testUser.password }),
    { headers: { "Content-Type": "application/json" } },
  );

  check(signInRes, {
    "setup sign-in: status 200": (r) => r.status === 200,
  });

  const body = JSON.parse(signInRes.body);

  return {
    user: testUser,
    accessToken: body.data.access_token,
    refreshToken: body.data.refresh_token,
  };
}

// ═══════════════════════════════════════════════════
// Helper: estimate header size in bytes
// ═══════════════════════════════════════════════════

function estimateHeaderSize(headers) {
  let size = 0;
  for (const [key, value] of Object.entries(headers)) {
    size += key.length + 2 + String(value).length + 2;
  }
  return size;
}

// ═══════════════════════════════════════════════════
// Helper: Base64url encode (no padding)
// ═══════════════════════════════════════════════════

function b64url(str) {
  const b64 = encoding.b64encode(str);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

// ═══════════════════════════════════════════════════
// Helper: build a fake JWT with given alg and claims
// ═══════════════════════════════════════════════════

function fakeJwt(alg, claimsOverride, sig) {
  const header = b64url(JSON.stringify({ alg: alg, typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const claims = Object.assign(
    {
      sub: "00000000-0000-0000-0000-000000000000",
      email: "attacker@evil.com",
      iss: "tasktify",
      exp: now + 3600,
      iat: now,
    },
    claimsOverride || {},
  );
  const payload = b64url(JSON.stringify(claims));
  return `${header}.${payload}.${sig !== undefined ? sig : "fakesig"}`;
}

// ═══════════════════════════════════════════════════
// Main Test
// ═══════════════════════════════════════════════════

export default function (data) {
  const authHeaders = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${data.accessToken}`,
  };

  // ───── 1. Token Generation Time ─────
  group("Token Generation", () => {
    const headers = { "Content-Type": "application/json" };
    const payload = JSON.stringify({
      email: data.user.email,
      password: data.user.password,
    });

    const res = http.post(`${BASE_URL}/api/auth/sign-in`, payload, {
      headers,
    });

    tokenGenerationTime.add(res.timings.duration);
    responseBodySize.add(res.body.length);
    requestHeaderSize.add(estimateHeaderSize(headers));

    const ok = check(res, {
      "sign-in: status 200": (r) => r.status === 200,
      "sign-in: has access_token": (r) => {
        const b = JSON.parse(r.body);
        return b.data && b.data.access_token;
      },
      "sign-in: has refresh_token": (r) => {
        const b = JSON.parse(r.body);
        return b.data && b.data.refresh_token;
      },
    });

    ok ? successfulRequests.add(1) : failedRequests.add(1);
  });

  // ───── 2. Token Verification Time ─────
  group("Token Verification", () => {
    const res = http.get(`${BASE_URL}/api/profile`, { headers: authHeaders });

    tokenVerificationTime.add(res.timings.duration);
    responseBodySize.add(res.body.length);
    requestHeaderSize.add(estimateHeaderSize(authHeaders));

    const ok = check(res, {
      "profile: status 200": (r) => r.status === 200,
      "profile: has user data": (r) => {
        const b = JSON.parse(r.body);
        return b.data && b.data.email;
      },
    });

    ok ? successfulRequests.add(1) : failedRequests.add(1);
  });

  // ───── 3. Task CRUD (Response Time & Throughput) ─────
  group("Task CRUD", () => {
    // Create
    const createRes = http.post(
      `${BASE_URL}/api/tasks/`,
      JSON.stringify({
        title: `k6-task-${randomString(6)}`,
        description: "Load test task",
        status: "PENDING",
        due_date: Date.now() + 86400000,
      }),
      { headers: authHeaders },
    );
    responseBodySize.add(createRes.body.length);
    requestHeaderSize.add(estimateHeaderSize(authHeaders));
    check(createRes, { "create task: status 201": (r) => r.status === 201 })
      ? successfulRequests.add(1)
      : failedRequests.add(1);

    // List
    const listRes = http.get(`${BASE_URL}/api/tasks/`, {
      headers: authHeaders,
    });
    responseBodySize.add(listRes.body.length);
    check(listRes, { "list tasks: status 200": (r) => r.status === 200 })
      ? successfulRequests.add(1)
      : failedRequests.add(1);

    // Extract task ID
    let taskId = null;
    try {
      const listBody = JSON.parse(listRes.body);
      if (listBody.data && listBody.data.length > 0) {
        taskId = listBody.data[0].id;
      }
    } catch (_) {}

    if (taskId) {
      // Get single
      const getRes = http.get(`${BASE_URL}/api/tasks/${taskId}`, {
        headers: authHeaders,
      });
      responseBodySize.add(getRes.body.length);
      check(getRes, { "get task: status 200": (r) => r.status === 200 })
        ? successfulRequests.add(1)
        : failedRequests.add(1);

      // Update
      const updateRes = http.put(
        `${BASE_URL}/api/tasks/${taskId}`,
        JSON.stringify({
          title: `k6-updated-${randomString(4)}`,
          description: "Updated by k6",
          status: "IN_PROGRESS",
          due_date: Date.now() + 172800000,
        }),
        { headers: authHeaders },
      );
      responseBodySize.add(updateRes.body.length);
      check(updateRes, { "update task: status 200": (r) => r.status === 200 })
        ? successfulRequests.add(1)
        : failedRequests.add(1);

      // Delete
      const deleteRes = http.del(`${BASE_URL}/api/tasks/${taskId}`, null, {
        headers: authHeaders,
      });
      responseBodySize.add(deleteRes.body.length);
      check(deleteRes, { "delete task: status 200": (r) => r.status === 200 })
        ? successfulRequests.add(1)
        : failedRequests.add(1);
    }
  });

  // ───── 4. Refresh Token ─────
  group("Refresh Token", () => {
    const res = http.post(
      `${BASE_URL}/api/auth/refresh-token`,
      JSON.stringify({ refresh_token: data.refreshToken }),
      { headers: { "Content-Type": "application/json" } },
    );
    tokenGenerationTime.add(res.timings.duration);
    responseBodySize.add(res.body.length);
    check(res, { "refresh: status 200": (r) => r.status === 200 })
      ? successfulRequests.add(1)
      : failedRequests.add(1);
  });

  // ───── 5. JWT Confusion Attack Tests ─────
  group("JWT Confusion Attacks", () => {
    const url = `${BASE_URL}/api/profile`;

    const attacks = [
      { name: "no token", headers: {} },
      {
        name: "alg=none",
        headers: { Authorization: `Bearer ${fakeJwt("none", {}, "")}` },
      },
      {
        name: "alg=HS256",
        headers: { Authorization: `Bearer ${fakeJwt("HS256")}` },
      },
      {
        name: "alg=RS256",
        headers: { Authorization: `Bearer ${fakeJwt("RS256")}` },
      },
      {
        name: "alg=ES256",
        headers: { Authorization: `Bearer ${fakeJwt("ES256")}` },
      },
      {
        name: "alg=Falcon-512",
        headers: { Authorization: `Bearer ${fakeJwt("Falcon-512")}` },
      },
      {
        name: "alg=Falcon-1024",
        headers: { Authorization: `Bearer ${fakeJwt("Falcon-1024")}` },
      },
      {
        name: "signature stripped",
        headers: {
          Authorization: `Bearer ${fakeJwt("Falcon-Precomputed-512", {}, "")}`,
        },
      },
      {
        name: "expired token",
        headers: {
          Authorization: `Bearer ${fakeJwt(
            "Falcon-Precomputed-512",
            {
              exp: Math.floor(Date.now() / 1000) - 7200,
              iat: Math.floor(Date.now() / 1000) - 14400,
            },
            "invalidsig",
          )}`,
        },
      },
      {
        name: "issuer spoof",
        headers: {
          Authorization: `Bearer ${fakeJwt(
            "Falcon-Precomputed-512",
            { iss: "evil-issuer" },
            "invalidsig",
          )}`,
        },
      },
      {
        name: "malformed (2 segments)",
        headers: { Authorization: "Bearer aaa.bbb" },
      },
      {
        name: "random garbage",
        headers: { Authorization: `Bearer ${randomString(200)}` },
      },
    ];

    for (const atk of attacks) {
      const res = http.get(url, { headers: atk.headers });
      const blocked = res.status === 401 || res.status === 400;

      confusionAttackBlockRate.add(blocked);
      blocked ? confusionAttackBlocked.add(1) : confusionAttackPassed.add(1);

      check(res, {
        [`attack: ${atk.name} → rejected`]: () => blocked,
      });
    }

    // Tampered payload (reuse valid token header+sig, swap payload)
    const parts = data.accessToken.split(".");
    if (parts.length === 3) {
      const tamperedPayload = b64url(
        JSON.stringify({
          sub: "99999999-9999-9999-9999-999999999999",
          email: "hijacked@evil.com",
          iss: "tasktify",
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
        }),
      );
      const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
      const res = http.get(url, {
        headers: { Authorization: `Bearer ${tamperedToken}` },
      });
      const blocked = res.status === 401 || res.status === 400;
      confusionAttackBlockRate.add(blocked);
      blocked ? confusionAttackBlocked.add(1) : confusionAttackPassed.add(1);
      check(res, {
        "attack: tampered payload → rejected": () => blocked,
      });
    }

    // Valid token (should pass)
    const validRes = http.get(url, { headers: authHeaders });
    check(validRes, {
      "valid token: accepted (200)": (r) => r.status === 200,
    });
    validRes.status === 200 ? successfulRequests.add(1) : failedRequests.add(1);
  });

  sleep(0.1);
}
