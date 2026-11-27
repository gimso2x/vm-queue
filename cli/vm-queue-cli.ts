import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface CliIO {
  env?: Record<string, string | undefined>;
  stdout?: (line: string) => void;
  stderr?: (line: string) => void;
  fetchImpl?: typeof fetch;
  homeDir?: string;
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

function parseOptionalInt(raw: string | undefined, name: string): number | undefined {
  if (raw === undefined) return undefined;
  if (!/^-?\d+$/.test(raw)) {
    throw new Error(`Invalid integer for --${name}: ${raw}`);
  }
  return Number(raw);
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
    "  submit-probe [--job-id <id>] [--ttl <sec>]",
    "  submit-repo-check --repo <https://github.com/owner/repo> --preset <preset> [--ref <ref>] [--timeout <sec>] [--job-id <id>] [--ttl <sec>]",
    "  status <job_id>",
    "  list",
    "  requeue <job_id> [--ttl <sec>]",
  ].join("\n");
}

function loadConfig(
  parsed: ParsedArgs,
  env: Record<string, string | undefined>,
  homeDir: string,
): { baseUrl: string; adminToken: string } {
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

  return { baseUrl, adminToken };
}

export async function runCli(argv: string[], io: CliIO = {}): Promise<number> {
  const env = io.env ?? process.env;
  const stdout = io.stdout ?? ((line: string) => console.log(line));
  const stderr = io.stderr ?? ((line: string) => console.error(line));
  const fetchImpl = io.fetchImpl ?? fetch;
  const homeDir = io.homeDir ?? homedir();

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

  let config: { baseUrl: string; adminToken: string };
  try {
    config = loadConfig(parsed, env, homeDir);
  } catch (err) {
    stderr(`Error: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }

  let method = "GET";
  let path = "";
  let bodyObj: Record<string, unknown> | undefined;

  try {
    if (cmd === "submit-probe") {
      method = "POST";
      path = "/jobs";
      const ttl = parseOptionalInt(parsed.flags.ttl, "ttl");
      bodyObj = {
        kind: "probe",
        ...(parsed.flags["job-id"] ? { job_id: parsed.flags["job-id"] } : {}),
        ...(ttl !== undefined ? { ttl_sec: ttl } : {}),
        input: { purpose: "cli-probe" },
      };
    } else if (cmd === "submit-repo-check") {
      const repoUrl = parsed.flags.repo;
      const preset = parsed.flags.preset;
      if (!repoUrl || !preset) {
        throw new Error("submit-repo-check requires --repo and --preset");
      }
      const ttl = parseOptionalInt(parsed.flags.ttl, "ttl");
      const timeoutSec = parseOptionalInt(parsed.flags.timeout, "timeout");
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
      const ttl = parseOptionalInt(parsed.flags.ttl, "ttl");
      method = "POST";
      path = `/jobs/${encodeURIComponent(jobId)}/requeue`;
      if (ttl !== undefined) {
        bodyObj = { ttl_sec: ttl };
      }
    } else {
      throw new Error(`Unknown subcommand: ${cmd}`);
    }
  } catch (err) {
    stderr(`Error: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }

  const headers: Record<string, string> = {
    Authorization: `Bearer ${config.adminToken}`,
  };
  if (bodyObj !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  let res: Response;
  try {
    res = await fetchImpl(`${config.baseUrl}${path}`, {
      method,
      headers,
      ...(bodyObj !== undefined ? { body: JSON.stringify(bodyObj) } : {}),
    });
  } catch (err) {
    stderr(`Request failed: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }

  const text = await res.text();
  if (!res.ok) {
    stderr(`HTTP ${res.status}: ${text}`);
    return 1;
  }

  try {
    const parsedJson = JSON.parse(text);
    stdout(JSON.stringify(parsedJson, null, 2));
  } catch {
    stdout(text);
  }
  return 0;
}

if (import.meta.main) {
  runCli(Bun.argv.slice(2)).then((code) => process.exit(code));
}
