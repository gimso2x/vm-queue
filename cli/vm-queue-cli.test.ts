import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createVmQueueApp, type VmQueueApp } from "../server.ts";
import { runCli } from "./vm-queue-cli.ts";

const ADMIN_TOKEN = "cli-test-admin-token-0123456789abcdef";
const WORKER_TOKEN = "cli-test-worker-token-fedcba9876543210";

let tmpDirs: string[] = [];
let apps: VmQueueApp[] = [];

function startApp(): { baseUrl: string; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "vm-queue-cli-test-"));
  tmpDirs.push(dir);
  const app = createVmQueueApp({
    dbPath: join(dir, "queue.db"),
    adminToken: ADMIN_TOKEN,
    workerToken: WORKER_TOKEN,
    host: "127.0.0.1",
    port: 0,
  });
  apps.push(app);
  return { baseUrl: `http://127.0.0.1:${app.server.port}`, dir };
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

describe("vm-queue-cli", () => {
  test("submits probe and repo_check, checks status/list, requeues, and never prints tokens", async () => {
    const { baseUrl, dir } = startApp();
    const envPath = join(dir, ".env");
    writeFileSync(
      envPath,
      `VM_QUEUE_ADMIN_TOKEN=${ADMIN_TOKEN}\nVM_QUEUE_URL=${baseUrl}\n`,
      "utf8",
    );

    const out: string[] = [];
    const err: string[] = [];
    const run = (argv: string[]) =>
      runCli(argv, {
        env: {},
        homeDir: dir,
        stdout: (line) => out.push(line),
        stderr: (line) => err.push(line),
      });

    expect(
      await run([
        "--env-file",
        envPath,
        "submit-probe",
        "--job-id",
        "cli-probe-1",
        "--ttl",
        "120",
      ]),
    ).toBe(0);
    expect(JSON.parse(out.at(-1)!).job_id).toBe("cli-probe-1");

    expect(
      await run([
        "--env-file",
        envPath,
        "submit-repo-check",
        "--job-id",
        "cli-repo-1",
        "--repo",
        "https://github.com/example-org/sample-repo",
        "--preset",
        "git_info",
        "--ref",
        "main",
        "--timeout",
        "90",
      ]),
    ).toBe(0);
    expect(JSON.parse(out.at(-1)!).kind).toBe("repo_check");

    expect(await run(["--env-file", envPath, "list"])).toBe(0);
    const listData = JSON.parse(out.at(-1)!) as { jobs: Array<{ job_id: string }> };
    expect(listData.jobs.map((j) => j.job_id)).toContain("cli-repo-1");

    // Claim cli-probe-1 as worker, then requeue via CLI
    const claimRes = await fetch(`${baseUrl}/jobs/claim`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "w-cli" }),
    });
    expect(claimRes.status).toBe(200);

    expect(
      await run(["--env-file", envPath, "requeue", "cli-probe-1", "--ttl", "300"]),
    ).toBe(0);
    expect(JSON.parse(out.at(-1)!).status).toBe("queued");

    expect(await run(["--env-file", envPath, "status", "cli-probe-1"])).toBe(0);
    expect(JSON.parse(out.at(-1)!).status).toBe("queued");

    // Default preset=auto when omitted
    expect(
      await run([
        "--env-file",
        envPath,
        "submit-repo-check",
        "--job-id",
        "cli-auto-1",
        "--repo",
        "https://github.com/example-org/sample-repo",
      ]),
    ).toBe(0);
    expect(JSON.parse(out.at(-1)!).kind).toBe("repo_check");

    // Invalid input exits non-zero and logs without token
    expect(
      await run([
        "--env-file",
        envPath,
        "submit-repo-check",
        "--repo",
        "https://gitlab.com/org/repo",
        "--preset",
        "git_info",
      ]),
    ).toBe(1);

    const allLogs = [...out, ...err].join("\n");
    expect(allLogs).not.toContain(ADMIN_TOKEN);
    expect(allLogs).not.toContain(WORKER_TOKEN);
  });

  test("workers and offload handle both offline and online worker states", async () => {
    const { baseUrl, dir } = startApp();
    const envPath = join(dir, ".env");
    writeFileSync(
      envPath,
      `VM_QUEUE_ADMIN_TOKEN=${ADMIN_TOKEN}\nVM_QUEUE_URL=${baseUrl}\nVM_QUEUE_PUBLIC_URL=http://100.64.0.10:8790\n`,
      "utf8",
    );

    const out: string[] = [];
    const err: string[] = [];
    const run = (argv: string[]) =>
      runCli(argv, {
        env: {},
        homeDir: dir,
        stdout: (line) => out.push(line),
        stderr: (line) => err.push(line),
        pollIntervalMs: 25,
      });

    // Offline initially
    expect(await run(["--env-file", envPath, "workers", "--window", "60"])).toBe(0);
    expect(JSON.parse(out.at(-1)!).any_online).toBe(false);

    expect(
      await run([
        "--env-file",
        envPath,
        "offload",
        "--job-id",
        "cli-offload-offline-1",
        "--repo",
        "https://github.com/example-org/sample-repo",
      ]),
    ).toBe(0);
    const offlinePayload = JSON.parse(out.at(-1)!) as {
      mode: string;
      worker_online: boolean;
      wake_command: string;
      job: { job_id: string };
    };
    expect(offlinePayload.mode).toBe("queued_worker_offline");
    expect(offlinePayload.worker_online).toBe(false);
    expect(offlinePayload.job.job_id).toBe("cli-offload-offline-1");
    expect(offlinePayload.wake_command).toContain("--mode poll --max-idle-sec 1800");
    expect(offlinePayload.wake_command).toContain("http://100.64.0.10:8790");

    // Register online worker via /workers/ping
    await fetch(`${baseUrl}/workers/ping`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${WORKER_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ worker_id: "cue-online-1", arch: "x86_64", cpus: 8 }),
    });
    expect(await run(["--env-file", envPath, "workers", "--window", "60"])).toBe(0);
    expect(JSON.parse(out.at(-1)!).any_online).toBe(true);

    // Simulate worker processing cli-offload-offline-1 and then cli-offload-online-1
    const simulateWorkerDrain = async () => {
      await new Promise((r) => setTimeout(r, 30));
      for (;;) {
        const c = (await (
          await fetch(`${baseUrl}/jobs/claim`, {
            method: "POST",
            headers: {
              Authorization: `Bearer ${WORKER_TOKEN}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ worker_id: "cue-online-1" }),
          })
        ).json()) as { job: { job_id: string; lease_token: string } | null };
        if (!c.job) break;
        await fetch(`${baseUrl}/jobs/${c.job.job_id}/complete`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${WORKER_TOKEN}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            worker_id: "cue-online-1",
            lease_token: c.job.lease_token,
            output: { passed: true, summary: "ok" },
          }),
        });
      }
    };

    const workerTask = simulateWorkerDrain();
    const offloadCode = await run([
      "--env-file",
      envPath,
      "offload",
      "--job-id",
      "cli-offload-online-1",
      "--repo",
      "https://github.com/example-org/sample-repo",
      "--wait",
      "10",
    ]);
    await workerTask;
    expect(offloadCode).toBe(0);

    const onlinePayload = JSON.parse(out.at(-1)!) as {
      mode: string;
      worker_online: boolean;
      job: { job_id: string; status: string };
    };
    expect(onlinePayload.mode).toBe("auto_completed");
    expect(onlinePayload.worker_online).toBe(true);
    expect(onlinePayload.job.job_id).toBe("cli-offload-online-1");
    expect(onlinePayload.job.status).toBe("completed");

    const allLogs = [...out, ...err].join("\n");
    expect(allLogs).not.toContain(ADMIN_TOKEN);
    expect(allLogs).not.toContain(WORKER_TOKEN);
  });

  test("rejects missing token cleanly without leaking anything", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vm-queue-cli-notok-"));
    tmpDirs.push(dir);
    const err: string[] = [];
    const code = await runCli(["list"], {
      env: {},
      homeDir: dir,
      stderr: (line) => err.push(line),
    });
    expect(code).toBe(2);
    expect(err.join("\n")).toContain("VM_QUEUE_ADMIN_TOKEN");
  });

  test("submits freqtrade_backtest and qa_scenario jobs cleanly", async () => {
    const { baseUrl, dir } = startApp();
    const envPath = join(dir, ".env");
    writeFileSync(
      envPath,
      `VM_QUEUE_ADMIN_TOKEN=${ADMIN_TOKEN}\nVM_QUEUE_URL=${baseUrl}\n`,
      "utf8",
    );
    const briefPath = join(dir, "brief.md");
    const taskPath = join(dir, "task.md");
    const lessonsPath = join(dir, "lessons.md");
    writeFileSync(briefPath, "# QA Brief\n", "utf8");
    writeFileSync(taskPath, "Test config handling\n", "utf8");
    writeFileSync(lessonsPath, "- Lesson 1\n", "utf8");

    const out: string[] = [];
    const err: string[] = [];
    const run = (argv: string[]) =>
      runCli(argv, {
        env: {},
        homeDir: dir,
        stdout: (line) => out.push(line),
        stderr: (line) => err.push(line),
      });

    expect(
      await run([
        "--env-file",
        envPath,
        "submit-backtest",
        "--job-id",
        "cli-bt-1",
        "--repo",
        "https://github.com/example-org/sample-strategy",
        "--strategy",
        "SampleStrategy",
        "--timerange",
        "20250101-20250201",
        "--mode",
        "hyperopt",
        "--pairs",
        "BTC/USDT,ETH/USDT",
        "--epochs",
        "25",
        "--spaces",
        "buy,sell",
        "--stake-amount",
        "50",
        "--max-open-trades",
        "2",
      ]),
    ).toBe(0);
    expect(JSON.parse(out.at(-1)!).kind).toBe("freqtrade_backtest");

    expect(
      await run([
        "--env-file",
        envPath,
        "submit-qa",
        "--job-id",
        "cli-qa-1",
        "--repo",
        "https://github.com/example-org/sample-repo",
        "--scenario-id",
        "01",
        "--scenario-name",
        "config check",
        "--brief-file",
        briefPath,
        "--task-file",
        taskPath,
        "--lessons-file",
        lessonsPath,
        "--model",
        "deepseek-v4.1-flash:max",
        "--phase1",
        "600",
        "--wrap",
        "120",
        "--tools",
        "read,bash,grep",
      ]),
    ).toBe(0);
    expect(JSON.parse(out.at(-1)!).kind).toBe("qa_scenario");

    // Missing brief file fails cleanly with code 2
    expect(
      await run([
        "--env-file",
        envPath,
        "submit-qa",
        "--repo",
        "https://github.com/example-org/sample-repo",
        "--scenario-id",
        "02",
        "--scenario-name",
        "missing file",
        "--brief-file",
        join(dir, "nope.md"),
        "--task-file",
        taskPath,
      ]),
    ).toBe(2);

    const allLogs = [...out, ...err].join("\n");
    expect(allLogs).not.toContain(ADMIN_TOKEN);
    expect(allLogs).not.toContain(WORKER_TOKEN);
  });
});
