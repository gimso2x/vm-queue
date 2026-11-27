import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface CliIO {
  env?: Record<string, string | undefined>;
  stdout?: (line: string) => void;
  stderr?: (line: string) => void;
  fetchImpl?: typeof fetch;
  homeDir?: string;
  pollIntervalMs?: number;
  sleepFn?: (ms: number) => Promise<void>;
}

interface ParsedArgs {
  url?: string;
  envFile?: string;
  positionals: string[];
  flags: Record<string, string>;
}

function parseDotEnv(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eqIdx = line.indexOf("=");
    if (eqIdx <= 0) continue;
    const key = line.slice(0, eqIdx).trim();
    let val = line.slice(eqIdx + 1).trim();
    if (
      val.length >= 2 &&
      ((val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'")))
    ) {
      val = val.slice(1, -1);
    }
    result[key] = val;
  }
  return result;
}

function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags: Record<string, string> = {};
  let url: string | undefined;
  let envFile: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      flags.help = "true";
      continue;
    }
    if (arg.startsWith("--")) {
      const eqIdx = arg.indexOf("=");
      let key: string;
      let val: string;
      if (eqIdx >= 0) {
        key = arg.slice(2, eqIdx);
        val = arg.slice(eqIdx + 1);
      } else {
        key = arg.slice(2);
        if (i + 1 >= argv.length) {
          throw new Error(`Missing value for --${key}`);
        }
        val = argv[++i];
      }
      if (key === "url") {
        url = val;
      } else if (key === "env-file") {
        envFile = val;
      } else {
        flags[key] = val;
      }
      continue;
    }
    positionals.push(arg);
  }

  return { url, envFile, positionals, flags };
}

function parseOptionalInt(
  raw: string | undefined,
  name: string,
  min?: number,
  max?: number,
): number | undefined {
  if (raw === undefined) return undefined;
  if (!/^-?\d+$/.test(raw)) {
    throw new Error(`Invalid integer for --${name}: ${raw}`);
  }
  const num = Number(raw);
  if (min !== undefined && num < min) {
    throw new Error(`--${name} must be >= ${min}`);
  }
  if (max !== undefined && num > max) {
    throw new Error(`--${name} must be <= ${max}`);
  }
  return num;
}

function usageText(): string {
  return [
    "Usage: bun run cli/vm-queue-cli.ts [global-flags] <subcommand> [flags]",
    "",
    "Global flags:",
    "  --url <url>          vm-queue base URL (default: $VM_QUEUE_URL or http://127.0.0.1:8790)",
    "  --env-file <path>    .env file with VM_QUEUE_ADMIN_TOKEN (fallback: ~/services/vm-queue/.env)",
    "",
    "Subcommands:",
    "  submit-probe [--job-id <id>] [--ttl <sec>] [--wait <sec>]",
    "  submit-repo-check --repo <https://github.com/owner/repo> [--preset <preset>] [--ref <ref>] [--timeout <sec>] [--job-id <id>] [--ttl <sec>] [--wait <sec>]",
    "  offload --repo <https://github.com/owner/repo> [--preset <preset>] [--ref <ref>] [--timeout <sec>] [--job-id <id>] [--ttl <sec>] [--wait <sec>] [--window <sec>] [--public-url <url>]",
    "  workers [--window <sec>]",
    "  status <job_id>",
    "  list",
    "  requeue <job_id> [--ttl <sec>]",
  ].join("\n");
}

function loadConfig(
  parsed: ParsedArgs,
  env: Record<string, string | undefined>,
  homeDir: string,
): { baseUrl: string; publicUrl: string; adminToken: string } {
  let fileEnv: Record<string, string> = {};
  const explicitEnvPath = parsed.envFile;
  const fallbackEnvPath = join(homeDir, "services", "vm-queue", ".env");

  if (explicitEnvPath) {
    if (!existsSync(explicitEnvPath)) {
      throw new Error(`Env file not found: ${explicitEnvPath}`);
    }
    fileEnv = parseDotEnv(readFileSync(explicitEnvPath, "utf8"));
  } else if (!env.VM_QUEUE_ADMIN_TOKEN && existsSync(fallbackEnvPath)) {
    fileEnv = parseDotEnv(readFileSync(fallbackEnvPath, "utf8"));
  }

  const baseUrl = (
    parsed.url ??
    env.VM_QUEUE_URL ??
    fileEnv.VM_QUEUE_URL ??
    "http://127.0.0.1:8790"
  ).replace(/\/+$/, "");

  const publicUrl = (
    parsed.flags["public-url"] ??
    env.VM_QUEUE_PUBLIC_URL ??
    fileEnv.VM_QUEUE_PUBLIC_URL ??
    "http://<TAILSCALE_SERVER_IP>:8790"
  ).replace(/\/+$/, "");

  const adminToken = (
    env.VM_QUEUE_ADMIN_TOKEN ??
    fileEnv.VM_QUEUE_ADMIN_TOKEN ??
    ""
  ).trim();

  if (!adminToken) {
    throw new Error(
      "VM_QUEUE_ADMIN_TOKEN is not set (provide env var or --env-file)",
    );
  }

  return { baseUrl, publicUrl, adminToken };
}

async function apiRequest(
  fetchImpl: typeof fetch,
  baseUrl: string,
  adminToken: string,
  method: string,
  path: string,
  bodyObj?: Record<string, unknown>,
): Promise<{ ok: boolean; status: number; data: unknown; rawText: string }> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${adminToken}`,
  };
  if (bodyObj !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetchImpl(`${baseUrl}${path}`, {
    method,
    headers,
    ...(bodyObj !== undefined ? { body: JSON.stringify(bodyObj) } : {}),
  });
  const rawText = await res.text();
  let data: unknown = rawText;
  try {
    data = JSON.parse(rawText);
  } catch {
    // keep raw text
  }
  return { ok: res.ok, status: res.status, data, rawText };
}

async function waitForJobTerminal(
  fetchImpl: typeof fetch,
  baseUrl: string,
  adminToken: string,
  jobId: string,
  waitSec: number,
  pollIntervalMs: number,
  sleepFn: (ms: number) => Promise<void>,
): Promise<{ ok: boolean; timedOut: boolean; job: Record<string, unknown> }> {
  const deadline = Date.now() + waitSec * 1000;
  let lastJob: Record<string, unknown> = { job_id: jobId, status: "queued" };
  while (true) {
    const res = await apiRequest(
      fetchImpl,
      baseUrl,
      adminToken,
      "GET",
      `/jobs/${encodeURIComponent(jobId)}`,
    );
    if (!res.ok || !res.data || typeof res.data !== "object") {
      throw new Error(`HTTP ${res.status}: ${res.rawText}`);
    }
    lastJob = res.data as Record<string, unknown>;
    const st = lastJob.status;
    if (st === "completed" || st === "failed" || st === "expired") {
      return { ok: st === "completed", timedOut: false, job: lastJob };
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      return { ok: false, timedOut: true, job: lastJob };
    }
    await sleepFn(Math.min(pollIntervalMs, remaining));
  }
}

export async function runCli(argv: string[], io: CliIO = {}): Promise<number> {
  const env = io.env ?? process.env;
  const stdout = io.stdout ?? ((line: string) => console.log(line));
  const stderr = io.stderr ?? ((line: string) => console.error(line));
  const fetchImpl = io.fetchImpl ?? fetch;
  const homeDir = io.homeDir ?? homedir();
  const pollIntervalMs = io.pollIntervalMs ?? 2000;
  const sleepFn =
    io.sleepFn ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));

  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    stderr(`Error: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }

  if (parsed.flags.help === "true" || parsed.positionals.length === 0) {
    stdout(usageText());
    return parsed.flags.help === "true" ? 0 : 2;
  }

  const [cmd, ...rest] = parsed.positionals;

  let config: { baseUrl: string; publicUrl: string; adminToken: string };
  try {
    config = loadConfig(parsed, env, homeDir);
  } catch (err) {
    stderr(`Error: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }

  try {
    if (cmd === "offload") {
      const repoUrl = parsed.flags.repo;
      if (!repoUrl) {
        throw new Error("offload requires --repo");
      }
      const preset = parsed.flags.preset ?? "auto";
      const ttl = parseOptionalInt(parsed.flags.ttl, "ttl", 1, 86400);
      const timeoutSec = parseOptionalInt(parsed.flags.timeout, "timeout", 10, 600);
      const waitSec = parseOptionalInt(parsed.flags.wait, "wait", 1, 1800) ?? 180;
      const windowSec = parseOptionalInt(parsed.flags.window, "window", 5, 3600) ?? 90;

      const workerStatusRes = await apiRequest(
        fetchImpl,
        config.baseUrl,
        config.adminToken,
        "GET",
        `/workers/status?window_sec=${windowSec}`,
      );
      if (!workerStatusRes.ok || !workerStatusRes.data || typeof workerStatusRes.data !== "object") {
        stderr(`HTTP ${workerStatusRes.status}: ${workerStatusRes.rawText}`);
        return 1;
      }
      const workerStatus = workerStatusRes.data as {
        any_online?: boolean;
        online_count?: number;
      };

      const submitRes = await apiRequest(
        fetchImpl,
        config.baseUrl,
        config.adminToken,
        "POST",
        "/jobs",
        {
          kind: "repo_check",
          ...(parsed.flags["job-id"] ? { job_id: parsed.flags["job-id"] } : {}),
          ...(ttl !== undefined ? { ttl_sec: ttl } : {}),
          input: {
            repo_url: repoUrl,
            preset,
            ...(parsed.flags.ref ? { ref: parsed.flags.ref } : {}),
            ...(timeoutSec !== undefined ? { timeout_sec: timeoutSec } : {}),
          },
        },
      );
      if (!submitRes.ok || !submitRes.data || typeof submitRes.data !== "object") {
        stderr(`HTTP ${submitRes.status}: ${submitRes.rawText}`);
        return 1;
      }
      const createdJob = submitRes.data as Record<string, unknown>;
      const jobId = String(createdJob.job_id);

      if (!workerStatus.any_online) {
        const wakeCommand = `curl -fsSL https://raw.githubusercontent.com/gimso2x/vm-queue/main/worker/vm_worker.py -o /tmp/vm_worker.py && python3 /tmp/vm_worker.py --url ${config.publicUrl} --mode poll --max-idle-sec 1800`;
        stdout(
          JSON.stringify(
            {
              mode: "queued_worker_offline",
              worker_online: false,
              worker_status: workerStatus,
              job: createdJob,
              wake_command: wakeCommand,
            },
            null,
            2,
          ),
        );
        return 0;
      }

      const finalWait = await waitForJobTerminal(
        fetchImpl,
        config.baseUrl,
        config.adminToken,
        jobId,
        waitSec,
        pollIntervalMs,
        sleepFn,
      );
      const mode = finalWait.timedOut
        ? "auto_timeout"
        : finalWait.job.status === "completed"
          ? "auto_completed"
          : "auto_failed";
      stdout(
        JSON.stringify(
          {
            mode,
            worker_online: true,
            worker_status: workerStatus,
            job: finalWait.job,
          },
          null,
          2,
        ),
      );
      return finalWait.ok ? 0 : 1;
    }

    let method = "GET";
    let path = "";
    let bodyObj: Record<string, unknown> | undefined;
    let waitSec: number | undefined;

    if (cmd === "submit-probe") {
      method = "POST";
      path = "/jobs";
      const ttl = parseOptionalInt(parsed.flags.ttl, "ttl", 1, 86400);
      waitSec = parseOptionalInt(parsed.flags.wait, "wait", 1, 1800);
      bodyObj = {
        kind: "probe",
        ...(parsed.flags["job-id"] ? { job_id: parsed.flags["job-id"] } : {}),
        ...(ttl !== undefined ? { ttl_sec: ttl } : {}),
        input: { purpose: "cli-probe" },
      };
    } else if (cmd === "submit-repo-check") {
      const repoUrl = parsed.flags.repo;
      if (!repoUrl) {
        throw new Error("submit-repo-check requires --repo");
      }
      const preset = parsed.flags.preset ?? "auto";
      const ttl = parseOptionalInt(parsed.flags.ttl, "ttl", 1, 86400);
      const timeoutSec = parseOptionalInt(parsed.flags.timeout, "timeout", 10, 600);
      waitSec = parseOptionalInt(parsed.flags.wait, "wait", 1, 1800);
      method = "POST";
      path = "/jobs";
      bodyObj = {
        kind: "repo_check",
        ...(parsed.flags["job-id"] ? { job_id: parsed.flags["job-id"] } : {}),
        ...(ttl !== undefined ? { ttl_sec: ttl } : {}),
        input: {
          repo_url: repoUrl,
          preset,
          ...(parsed.flags.ref ? { ref: parsed.flags.ref } : {}),
          ...(timeoutSec !== undefined ? { timeout_sec: timeoutSec } : {}),
        },
      };
    } else if (cmd === "workers") {
      const windowSec = parseOptionalInt(parsed.flags.window, "window", 5, 3600);
      method = "GET";
      path =
        windowSec !== undefined
          ? `/workers/status?window_sec=${windowSec}`
          : "/workers/status";
    } else if (cmd === "status") {
      const jobId = rest[0];
      if (!jobId) {
        throw new Error("status requires <job_id>");
      }
      method = "GET";
      path = `/jobs/${encodeURIComponent(jobId)}`;
    } else if (cmd === "list") {
      method = "GET";
      path = "/jobs";
    } else if (cmd === "requeue") {
      const jobId = rest[0];
      if (!jobId) {
        throw new Error("requeue requires <job_id>");
      }
      const ttl = parseOptionalInt(parsed.flags.ttl, "ttl", 1, 86400);
      method = "POST";
      path = `/jobs/${encodeURIComponent(jobId)}/requeue`;
      if (ttl !== undefined) {
        bodyObj = { ttl_sec: ttl };
      }
    } else {
      throw new Error(`Unknown subcommand: ${cmd}`);
    }

    const res = await apiRequest(
      fetchImpl,
      config.baseUrl,
      config.adminToken,
      method,
      path,
      bodyObj,
    );
    if (!res.ok) {
      stderr(`HTTP ${res.status}: ${res.rawText}`);
      return 1;
    }

    if (
      waitSec !== undefined &&
      res.data &&
      typeof res.data === "object" &&
      "job_id" in res.data
    ) {
      const jobId = String((res.data as { job_id: unknown }).job_id);
      const finalWait = await waitForJobTerminal(
        fetchImpl,
        config.baseUrl,
        config.adminToken,
        jobId,
        waitSec,
        pollIntervalMs,
        sleepFn,
      );
      stdout(JSON.stringify(finalWait.job, null, 2));
      return finalWait.ok ? 0 : 1;
    }

    stdout(
      typeof res.data === "object"
        ? JSON.stringify(res.data, null, 2)
        : res.rawText,
    );
    return 0;
  } catch (err) {
    stderr(
      `${err instanceof Error ? err.message : String(err)}`,
    );
    return err instanceof Error && err.message.startsWith("HTTP ") ? 1 : 2;
  }
}

if (import.meta.main) {
  runCli(Bun.argv.slice(2)).then((code) => process.exit(code));
}
