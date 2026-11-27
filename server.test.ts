import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createVmQueueApp,
  type AuthFailureInfo,
  type VmQueueApp,
} from "./server.ts";

const ADMIN_TOKEN = "test-admin-token-0123456789abcdef";
const WORKER_TOKEN = "test-worker-token-fedcba9876543210";

let tmpDirs: string[] = [];
let apps: VmQueueApp[] = [];

function startTestApp(
  nowFn?: () => number,
  onAuthFailure?: (info: AuthFailureInfo) => void,
): { baseUrl: string; app: VmQueueApp } {
  const dir = mkdtempSync(join(tmpdir(), "vm-queue-test-"));
  tmpDirs.push(dir);
  const dbPath = join(dir, "test.db");
  const app = createVmQueueApp({
    dbPath,
    adminToken: ADMIN_TOKEN,
    workerToken: WORKER_TOKEN,
    host: "127.0.0.1",
    port: 0,
    now: nowFn,
    onAuthFailure,
  });
  apps.push(app);
  return { baseUrl: `http://127.0.0.1:${app.server.port}`, app };
}

afterEach(() => {
  for (const app of apps) {
    try {
      app.close();
    } catch {
      // ignore
    }
  }
  apps = [];
  for (const dir of tmpDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  tmpDirs = [];
});

describe("vm-queue server", () => {
  test("1. GET /healthz returns 200 without auth and sets security headers", async () => {
    const { baseUrl } = startTestApp();
    const res = await fetch(`${baseUrl}/healthz`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, service: "vm-queue" });
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("content-security-policy")).toBe("default-src 'none'");
  });

  test("2. Enforces auth (401) and strict admin/worker role separation (403)", async () => {
    const { baseUrl } = startTestApp();

    const noAuth = await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind: "probe" }),
    });
    expect(noAuth.status).toBe(401);

    const badAuth = await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: {
        Authorization: "Bearer wrong-token",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ kind: "probe" }),
    });
    expect(badAuth.status).toBe(401);

    const workerCreate = await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ kind: "probe" }),
    });
    expect(workerCreate.status).toBe(403);

    const workerGet = await fetch(`${baseUrl}/jobs/probe-1`, {
      headers: { Authorization: `Bearer ${WORKER_TOKEN}` },
    });
    expect(workerGet.status).toBe(403);

    const adminClaim = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "w1" }),
    });
    expect(adminClaim.status).toBe(403);
  });

  test("3. Rejects disallowed kind values with 400 unsupported_kind", async () => {
    const { baseUrl } = startTestApp();
    for (const kind of ["shell", "exec", ""]) {
      const res = await fetch(`${baseUrl}/jobs`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${ADMIN_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ kind }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("unsupported_kind");
    }
  });

  test("4. Enforces max_input_bytes with 413 input_too_large", async () => {
    const { baseUrl } = startTestApp();
    const res = await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        job_id: "big-input-1",
        kind: "probe",
        max_input_bytes: 32,
        input: { payload: "x".repeat(64) },
      }),
    });
    expect(res.status).toBe(413);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("input_too_large");
  });

  test("5. Full probe round-trip succeeds end-to-end", async () => {
    const { baseUrl } = startTestApp();
    const createRes = await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        job_id: "probe-roundtrip-1",
        kind: "probe",
        input: { check: "basic" },
      }),
    });
    expect(createRes.status).toBe(201);

    const claimRes = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "cue-1", lease_sec: 60 }),
    });
    expect(claimRes.status).toBe(200);
    const claimBody = (await claimRes.json()) as {
      job: { job_id: string; kind: string; lease_token: string; attempts: number };
    };
    expect(claimBody.job.job_id).toBe("probe-roundtrip-1");
    expect(claimBody.job.kind).toBe("probe");
    expect(claimBody.job.attempts).toBe(1);

    const inputRes = await fetch(`${baseUrl}/jobs/${claimBody.job.job_id}/input`, {
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "X-Worker-Id": "cue-1",
        "X-Lease-Token": claimBody.job.lease_token,
      },
    });
    expect(inputRes.status).toBe(200);
    expect(await inputRes.json()).toEqual({ check: "basic" });

    const hbRes = await fetch(`${baseUrl}/jobs/${claimBody.job.job_id}/heartbeat`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        worker_id: "cue-1",
        lease_token: claimBody.job.lease_token,
        lease_sec: 90,
      }),
    });
    expect(hbRes.status).toBe(200);

    const completeRes = await fetch(
      `${baseUrl}/jobs/${claimBody.job.job_id}/complete`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${WORKER_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          worker_id: "cue-1",
          lease_token: claimBody.job.lease_token,
          output: { uname_m: "x86_64", nproc: "8" },
        }),
      },
    );
    expect(completeRes.status).toBe(200);

    const getRes = await fetch(`${baseUrl}/jobs/probe-roundtrip-1`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect(getRes.status).toBe(200);
    const job = (await getRes.json()) as Record<string, unknown>;
    expect(job.status).toBe("completed");
    expect(job.output).toEqual({ uname_m: "x86_64", nproc: "8" });
    expect("lease_token" in job).toBe(false);
  });

  test("6a. Lease expiry reassignment with injected clock", async () => {
    let nowMs = 1_700_000_000_000;
    const { baseUrl } = startTestApp(() => nowMs);

    await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ job_id: "lease-clk-1", kind: "probe" }),
    });

    const c1 = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "worker-1", lease_sec: 10 }),
    });
    const j1 = (await c1.json()) as {
      job: { job_id: string; lease_token: string; attempts: number };
    };
    expect(j1.job.attempts).toBe(1);

    const c2Early = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "worker-2", lease_sec: 10 }),
    });
    expect((await c2Early.json()).job).toBeNull();

    nowMs += 11_000;

    const lateComplete = await fetch(`${baseUrl}/jobs/lease-clk-1/complete`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        worker_id: "worker-1",
        lease_token: j1.job.lease_token,
        output: { ok: true },
      }),
    });
    expect(lateComplete.status).toBe(409);

    const c2Reclaim = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "worker-2", lease_sec: 10 }),
    });
    const j2 = (await c2Reclaim.json()) as {
      job: { job_id: string; lease_token: string; attempts: number };
    };
    expect(j2.job.job_id).toBe("lease-clk-1");
    expect(j2.job.attempts).toBe(2);

    const okComplete = await fetch(`${baseUrl}/jobs/lease-clk-1/complete`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        worker_id: "worker-2",
        lease_token: j2.job.lease_token,
        output: { ok: true },
      }),
    });
    expect(okComplete.status).toBe(200);
  });

  test("6b. Lease expiry reassignment with real wall-clock sleep", async () => {
    const { baseUrl } = startTestApp();
    await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ job_id: "lease-real-1", kind: "probe" }),
    });

    const c1 = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "worker-1", lease_sec: 1 }),
    });
    const j1 = (await c1.json()) as { job: { lease_token: string; attempts: number } };
    expect(j1.job.attempts).toBe(1);

    await Bun.sleep(1150);

    const c2 = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "worker-2", lease_sec: 30 }),
    });
    const j2 = (await c2.json()) as { job: { job_id: string; attempts: number } };
    expect(j2.job.job_id).toBe("lease-real-1");
    expect(j2.job.attempts).toBe(2);
  });

  test("7. Enforces max_output_bytes without altering leased state", async () => {
    const { baseUrl } = startTestApp();
    await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        job_id: "out-limit-1",
        kind: "probe",
        max_output_bytes: 64,
      }),
    });

    const c1 = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "w1" }),
    });
    const j1 = (await c1.json()) as { job: { lease_token: string } };

    const bigComplete = await fetch(`${baseUrl}/jobs/out-limit-1/complete`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        worker_id: "w1",
        lease_token: j1.job.lease_token,
        output: { text: "a".repeat(128) },
      }),
    });
    expect(bigComplete.status).toBe(413);
    expect((await bigComplete.json()).error).toBe("output_too_large");

    const statusRes = await fetch(`${baseUrl}/jobs/out-limit-1`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect((await statusRes.json()).status).toBe("leased");
  });

  test("8. Blocks secret patterns and configured tokens with 422", async () => {
    const { baseUrl } = startTestApp();
    await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ job_id: "sec-filter-1", kind: "probe" }),
    });

    const c1 = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "w1" }),
    });
    const j1 = (await c1.json()) as { job: { lease_token: string } };

    const samples = [
      { leaked: "sk-" + "dummy0123456789abcdef" },
      { leaked: "tskey-auth-" + "dummy0123456789" },
      { leaked: "-----BEGIN RSA PRIVATE KEY-----\nabc" },
      { leaked: WORKER_TOKEN },
    ];

    for (const output of samples) {
      const res = await fetch(`${baseUrl}/jobs/sec-filter-1/complete`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${WORKER_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          worker_id: "w1",
          lease_token: j1.job.lease_token,
          output,
        }),
      });
      expect(res.status).toBe(422);
      expect((await res.json()).error).toBe("secret_pattern_detected");
    }

    const job = (await (
      await fetch(`${baseUrl}/jobs/sec-filter-1`, {
        headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
      })
    ).json()) as { status: string; output: unknown };
    expect(job.status).toBe("leased");
    expect(job.output).toBeNull();
  });

  test("9. POST /jobs/:id/fail records failure and rejects secrets/oversized errors", async () => {
    const { baseUrl } = startTestApp();
    await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        job_id: "fail-case-1",
        kind: "probe",
        max_output_bytes: 32,
      }),
    });

    const c1 = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "w1" }),
    });
    const j1 = (await c1.json()) as { job: { lease_token: string } };

    const oversizedErr = await fetch(`${baseUrl}/jobs/fail-case-1/fail`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        worker_id: "w1",
        lease_token: j1.job.lease_token,
        error: "e".repeat(64),
      }),
    });
    expect(oversizedErr.status).toBe(413);

    const secretErr = await fetch(`${baseUrl}/jobs/fail-case-1/fail`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        worker_id: "w1",
        lease_token: j1.job.lease_token,
        error: "sk-proj-0123456789abcd",
      }),
    });
    expect(secretErr.status).toBe(422);

    const okErr = await fetch(`${baseUrl}/jobs/fail-case-1/fail`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        worker_id: "w1",
        lease_token: j1.job.lease_token,
        error: "probe_failed",
      }),
    });
    expect(okErr.status).toBe(200);

    const job = (await (
      await fetch(`${baseUrl}/jobs/fail-case-1`, {
        headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
      })
    ).json()) as { status: string; error: string };
    expect(job.status).toBe("failed");
    expect(job.error).toBe("probe_failed");
  });

  test("10. Job TTL expiry transitions queued job to expired and prevents claiming", async () => {
    let nowMs = 1_700_000_000_000;
    const { baseUrl } = startTestApp(() => nowMs);

    await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        job_id: "ttl-expire-1",
        kind: "probe",
        ttl_sec: 5,
      }),
    });

    nowMs += 6000;

    const claimRes = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "w1" }),
    });
    expect((await claimRes.json()).job).toBeNull();

    const jobRes = await fetch(`${baseUrl}/jobs/ttl-expire-1`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect((await jobRes.json()).status).toBe("expired");
  });

  test("11. Reports secret-free auth failure diagnostics on 401 and 403", async () => {
    const events: AuthFailureInfo[] = [];
    const { baseUrl } = startTestApp(undefined, (info) => {
      events.push(info);
    });

    const missingRes = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ worker_id: "w1" }),
    });
    expect(missingRes.status).toBe(401);

    const doubleBearerRes = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: "Bearer Bearer dummy-secret-value",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "w1" }),
    });
    expect(doubleBearerRes.status).toBe(401);

    const envPrefixRes = await fetch(
      `${baseUrl}/jobs/probe-1/input?worker_id=w1&lease_token=dummy-secret-value`,
      {
        headers: {
          Authorization: "Bearer VM_QUEUE_WORKER_TOKEN=dummy-secret-value",
        },
      },
    );
    expect(envPrefixRes.status).toBe(401);

    const angleRes = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: "Bearer <dummy-secret-value>",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "w1" }),
    });
    expect(angleRes.status).toBe(401);

    const roleRes = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "w1" }),
    });
    expect(roleRes.status).toBe(403);

    expect(events).toHaveLength(5);
    expect(events[0]).toEqual({
      method: "POST",
      path: "/jobs/claim",
      status: 401,
      requiredRole: "worker",
      reason: "missing_auth_header",
      scheme: "none",
      partCount: 0,
      tokenLen: 0,
      flags: [],
    });
    expect(events[1]).toEqual({
      method: "POST",
      path: "/jobs/claim",
      status: 401,
      requiredRole: "worker",
      reason: "malformed_auth_header",
      scheme: "bearer",
      partCount: 3,
      tokenLen: "Bearer dummy-secret-value".length,
      flags: ["double_bearer", "contains_whitespace"],
    });
    expect(events[2]).toEqual({
      method: "GET",
      path: "/jobs/probe-1/input",
      status: 401,
      requiredRole: "worker",
      reason: "token_mismatch",
      scheme: "bearer",
      partCount: 2,
      tokenLen: "VM_QUEUE_WORKER_TOKEN=dummy-secret-value".length,
      flags: ["env_key_prefix"],
    });
    expect(events[3]).toEqual({
      method: "POST",
      path: "/jobs/claim",
      status: 401,
      requiredRole: "worker",
      reason: "token_mismatch",
      scheme: "bearer",
      partCount: 2,
      tokenLen: "<dummy-secret-value>".length,
      flags: ["angle_brackets"],
    });
    expect(events[4]).toEqual({
      method: "POST",
      path: "/jobs/claim",
      status: 403,
      requiredRole: "worker",
      reason: "role_mismatch",
      scheme: "bearer",
      partCount: 2,
      tokenLen: ADMIN_TOKEN.length,
      flags: [],
    });

    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain("dummy-secret-value");
    expect(serialized).not.toContain(WORKER_TOKEN);
    expect(serialized).not.toContain(ADMIN_TOKEN);
  });

  test("12. Validates repo_check input strictly and rejects shell/non-GitHub fields", async () => {
    const { baseUrl } = startTestApp();

    const okRes = await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        job_id: "repo-check-valid-1",
        kind: "repo_check",
        input: {
          repo_url: "https://github.com/example-org/sample-repo",
          preset: "bun_test",
          ref: "main",
          timeout_sec: 120,
        },
      }),
    });
    expect(okRes.status).toBe(201);

    const badInputs: Array<Record<string, unknown>> = [
      { repo_url: "https://gitlab.com/org/repo", preset: "git_info" },
      { repo_url: "ssh://git@github.com/org/repo.git", preset: "git_info" },
      { repo_url: "file:///etc/passwd", preset: "git_info" },
      { repo_url: "https://user:pass@github.com/org/repo", preset: "git_info" },
      { repo_url: "https://github.com/org/repo", preset: "git_info", cmd: "whoami" },
      { repo_url: "https://github.com/org/repo", preset: "shell_exec" },
      { repo_url: "https://github.com/org/repo", preset: "pytest", ref: "--upload-pack=bad" },
      { repo_url: "https://github.com/org/repo", preset: "pytest", ref: "feat/../main" },
      { repo_url: "https://github.com/org/repo", preset: "go_test", timeout_sec: 5 },
    ];

    for (const input of badInputs) {
      const badRes = await fetch(`${baseUrl}/jobs`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${ADMIN_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ kind: "repo_check", input }),
      });
      expect(badRes.status).toBe(400);
      const errBody = (await badRes.json()) as { error: string };
      expect(errBody.error).toBe("invalid_repo_check_input");
    }
  });

  test("13. GET /jobs/:id/input includes X-Job-Id and X-Job-Kind headers", async () => {
    const { baseUrl } = startTestApp();

    await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        job_id: "header-meta-1",
        kind: "repo_check",
        input: {
          repo_url: "https://github.com/example-org/sample-repo",
          preset: "git_info",
        },
      }),
    });

    const claimRes = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "w1" }),
    });
    const claimBody = (await claimRes.json()) as {
      job: { job_id: string; lease_token: string };
    };

    const inputRes = await fetch(`${baseUrl}/jobs/${claimBody.job.job_id}/input`, {
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "X-Worker-Id": "w1",
        "X-Lease-Token": claimBody.job.lease_token,
      },
    });
    expect(inputRes.status).toBe(200);
    expect(inputRes.headers.get("x-job-id")).toBe("header-meta-1");
    expect(inputRes.headers.get("x-job-kind")).toBe("repo_check");
    expect(await inputRes.json()).toEqual({
      repo_url: "https://github.com/example-org/sample-repo",
      preset: "git_info",
    });
  });

  test("14. POST /jobs/:id/requeue resets leased/failed/expired jobs and guards completed", async () => {
    let nowMs = 1_700_000_000_000;
    const { baseUrl } = startTestApp(() => nowMs);

    await fetch(`${baseUrl}/jobs`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        job_id: "requeue-target-1",
        kind: "probe",
        ttl_sec: 30,
      }),
    });

    const claim1 = (await (
      await fetch(`${baseUrl}/jobs/claim`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${WORKER_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ worker_id: "w1", lease_sec: 60 }),
      })
    ).json()) as { job: { lease_token: string } };

    // Worker token cannot requeue (403)
    const workerRequeue = await fetch(`${baseUrl}/jobs/requeue-target-1/requeue`, {
      method: "POST",
      headers: { Authorization: `Bearer ${WORKER_TOKEN}` },
    });
    expect(workerRequeue.status).toBe(403);

    // Admin requeue while leased -> queued immediately
    const rqLeased = await fetch(`${baseUrl}/jobs/requeue-target-1/requeue`, {
      method: "POST",
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect(rqLeased.status).toBe(200);
    expect((await rqLeased.json()).status).toBe("queued");

    // Claim again and mark failed -> requeue
    const claim2 = (await (
      await fetch(`${baseUrl}/jobs/claim`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${WORKER_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ worker_id: "w2", lease_sec: 60 }),
      })
    ).json()) as { job: { lease_token: string } };
    expect(claim2.job.lease_token).not.toBe(claim1.job.lease_token);

    await fetch(`${baseUrl}/jobs/requeue-target-1/fail`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        worker_id: "w2",
        lease_token: claim2.job.lease_token,
        error: "temp_failure",
      }),
    });

    const rqFailed = await fetch(`${baseUrl}/jobs/requeue-target-1/requeue`, {
      method: "POST",
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect(rqFailed.status).toBe(200);
    expect((await rqFailed.json()).status).toBe("queued");

    // Advance past TTL -> expired -> requeue extends expires_at
    nowMs += 40_000;
    const rqExpired = await fetch(`${baseUrl}/jobs/requeue-target-1/requeue`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ttl_sec: 120 }),
    });
    expect(rqExpired.status).toBe(200);
    const rqExpiredBody = (await rqExpired.json()) as {
      status: string;
      ttl_sec: number;
      expires_at: number;
    };
    expect(rqExpiredBody.status).toBe("queued");
    expect(rqExpiredBody.ttl_sec).toBe(120);
    expect(rqExpiredBody.expires_at).toBe(nowMs + 120_000);

    // Complete -> requeue rejected (409)
    const claim3 = (await (
      await fetch(`${baseUrl}/jobs/claim`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${WORKER_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ worker_id: "w3", lease_sec: 60 }),
      })
    ).json()) as { job: { lease_token: string } };
    await fetch(`${baseUrl}/jobs/requeue-target-1/complete`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        worker_id: "w3",
        lease_token: claim3.job.lease_token,
        output: { ok: true },
      }),
    });

    const rqCompleted = await fetch(`${baseUrl}/jobs/requeue-target-1/requeue`, {
      method: "POST",
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect(rqCompleted.status).toBe(409);
  });
});
