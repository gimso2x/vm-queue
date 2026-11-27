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
});
