import { Database } from "bun:sqlite";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export interface AuthFailureInfo {
  method: string;
  path: string;
  status: 401 | 403;
  requiredRole: "admin" | "worker";
  reason:
    | "missing_auth_header"
    | "malformed_auth_header"
    | "token_mismatch"
    | "role_mismatch";
  scheme: "none" | "bearer" | "other";
  partCount: number;
  tokenLen: number;
  flags: string[];
}

export interface VmQueueOptions {
  dbPath: string;
  adminToken: string;
  workerToken: string;
  host?: string;
  port?: number;
  now?: () => number;
  onAuthFailure?: (info: AuthFailureInfo) => void;
}

export interface VmQueueApp {
  server: ReturnType<typeof Bun.serve>;
  db: Database;
  close: () => void;
}

export const ALLOWED_KINDS = new Set([
  "probe",
  "repo_check",
  "freqtrade_backtest",
  "qa_scenario",
]);
export const ALLOWED_REPO_CHECK_PRESETS = new Set([
  "auto",
  "git_info",
  "bun_test",
  "bun_check",
  "bun_build",
  "npm_test",
  "playwright_test",
  "repo_index",
  "pytest",
  "go_test",
  "cargo_test",
]);
export const ALLOWED_FREQTRADE_MODES = new Set(["backtest", "hyperopt"]);
export const ALLOWED_FREQTRADE_EXCHANGES = new Set([
  "binance",
  "okx",
  "bybit",
  "gate",
  "kraken",
]);
export const ALLOWED_FREQTRADE_TIMEFRAMES = new Set([
  "1m",
  "5m",
  "15m",
  "30m",
  "1h",
  "4h",
  "1d",
]);
export const ALLOWED_HYPEROPT_SPACES = new Set([
  "buy",
  "sell",
  "roi",
  "stoploss",
  "trailing",
]);
export const ALLOWED_HYPEROPT_LOSSES = new Set([
  "ShortTradeDurHyperOptLoss",
  "OnlyProfitHyperOptLoss",
  "SharpeHyperOptLoss",
  "SortinoHyperOptLoss",
  "CalmarHyperOptLoss",
]);
export const ALLOWED_QA_TOOLS = new Set([
  "read",
  "bash",
  "edit",
  "write",
  "grep",
  "glob",
  "todo",
]);
export const DEFAULT_MAX_INPUT_BYTES = 5 * 1024 * 1024;
export const HARD_MAX_INPUT_BYTES = 5 * 1024 * 1024;
export const DEFAULT_MAX_OUTPUT_BYTES = 1 * 1024 * 1024;
export const HARD_MAX_OUTPUT_BYTES = 1 * 1024 * 1024;
export const DEFAULT_TTL_SEC = 3600;
export const MAX_TTL_SEC = 86400;
export const DEFAULT_LEASE_SEC = 60;
export const MAX_LEASE_SEC = 600;
export const DEFAULT_WORKER_WINDOW_SEC = 90;
export const MAX_WORKER_WINDOW_SEC = 3600;

const JOB_ID_RE = /^[a-zA-Z0-9_-]{3,64}$/;
const WORKER_ID_RE = /^[a-zA-Z0-9._:-]{1,64}$/;
const WORKER_ARCH_RE = /^[a-zA-Z0-9._-]{1,32}$/;
const ALLOWED_REPO_CHECK_KEYS = new Set([
  "repo_url",
  "preset",
  "ref",
  "timeout_sec",
]);
const ALLOWED_FREQTRADE_KEYS = new Set([
  "repo_url",
  "ref",
  "strategy",
  "mode",
  "exchange",
  "timeframe",
  "timerange",
  "pairs",
  "epochs",
  "spaces",
  "hyperopt_loss",
  "stake_amount",
  "max_open_trades",
  "timeout_sec",
]);
const ALLOWED_QA_SCENARIO_KEYS = new Set([
  "repo_url",
  "ref",
  "scenario_id",
  "scenario_name",
  "brief",
  "task",
  "lessons",
  "model",
  "phase1_sec",
  "wrap_sec",
  "tools",
]);
const GITHUB_PUBLIC_REPO_RE =
  /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?$/;
const GIT_REF_RE = /^[A-Za-z0-9._\/-]{1,128}$/;
const STRATEGY_NAME_RE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const TIMERANGE_RE = /^(\d{8})-(\d{8})$/;
const PAIR_RE = /^[A-Z0-9]{2,12}\/[A-Z]{3,6}(?::[A-Z]{3,6})?$/;
const SCENARIO_ID_RE = /^[A-Za-z0-9._-]{1,32}$/;
const QA_MODEL_RE = /^[A-Za-z0-9._:\/-]{1,96}$/;
const PAID_MODEL_RE = /anthropic|claude|openai|gpt-4|gpt-5|\bo1\b|\bo3\b/i;

const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'none'",
};

const SECRET_PATTERNS: ReadonlyArray<[string, RegExp]> = [
  ["slack_token", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ["slack_app_token", /\bxapp-[A-Za-z0-9-]{10,}\b/],
  ["openai_or_anthropic_key", /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}\b/],
  ["tailscale_key", /\btskey-(?:auth|api|client)-[A-Za-z0-9_-]{10,}\b/],
  ["github_token", /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/],
  ["aws_access_key", /\bAKIA[0-9A-Z]{16}\b/],
  ["google_api_key", /\bAIza[0-9A-Za-z_-]{35}\b/],
  ["private_key_pem", /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/],
  ["bearer_header", /Bearer\s+[A-Za-z0-9._~+/=-]{16,}/i],
];

interface JobRow {
  job_id: string;
  kind: string;
  status: "queued" | "leased" | "completed" | "failed" | "expired";
  input_bytes: Uint8Array;
  input_content_type: string;
  max_input_bytes: number;
  max_output_bytes: number;
  ttl_sec: number;
  created_at: number;
  expires_at: number;
  worker_id: string | null;
  lease_token: string | null;
  lease_expires_at: number | null;
  attempts: number;
  output_json: string | null;
  error_text: string | null;
  completed_at: number | null;
}

interface WorkerRow {
  worker_id: string;
  last_seen_at: number;
  last_action: string;
  last_job_id: string | null;
  arch: string | null;
  cpus: number | null;
}

function sha256Digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

function classifyAuthHeader(authHeader: string | null): {
  scheme: "none" | "bearer" | "other";
  partCount: number;
  tokenLen: number;
  flags: string[];
} {
  if (!authHeader || !authHeader.trim()) {
    return { scheme: "none", partCount: 0, tokenLen: 0, flags: [] };
  }
  const trimmed = authHeader.trim();
  const parts = trimmed.split(/\s+/);
  const partCount = parts.length;
  const scheme = parts[0].toLowerCase() === "bearer" ? "bearer" : "other";
  const candidate =
    scheme === "bearer" && trimmed.length > parts[0].length
      ? trimmed.slice(parts[0].length).trimStart()
      : trimmed;
  const tokenLen = candidate.length;
  const flags: string[] = [];
  if (/^bearer\s+/i.test(candidate)) {
    flags.push("double_bearer");
  }
  if (/^VM_QUEUE_/i.test(candidate)) {
    flags.push("env_key_prefix");
  }
  if (candidate.includes("<") || candidate.includes(">")) {
    flags.push("angle_brackets");
  }
  if (/^["']|["']$/.test(candidate)) {
    flags.push("quoted");
  }
  if (/워커|REDACTED|\*\*\*|\$|\{|\}/.test(candidate)) {
    flags.push("placeholder_like");
  }
  if (/\s/.test(candidate)) {
    flags.push("contains_whitespace");
  }
  return { scheme, partCount, tokenLen, flags };
}

function constantTimeTokenMatch(provided: string, expected: string): boolean {
  if (!provided || !expected) return false;
  return timingSafeEqual(sha256Digest(provided), sha256Digest(expected));
}

export function detectSecretPattern(
  text: string,
  configuredTokens: ReadonlyArray<string>,
): string | null {
  for (const tok of configuredTokens) {
    if (tok && text.includes(tok)) {
      return "configured_token";
    }
  }
  for (const [name, pattern] of SECRET_PATTERNS) {
    if (pattern.test(text)) {
      return name;
    }
  }
  return null;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...SECURITY_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

function bytesResponse(
  bytes: Uint8Array,
  contentType: string,
  status = 200,
  extraHeaders?: Record<string, string>,
): Response {
  return new Response(bytes, {
    status,
    headers: {
      ...SECURITY_HEADERS,
      "Content-Type": contentType,
      ...(extraHeaders ?? {}),
    },
  });
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function validateStrictInputKeys(
  inputValue: Record<string, unknown>,
  allowedKeys: ReadonlySet<string>,
  errCode: string,
): { ok: true } | { ok: false; error: string; detail: string } {
  for (const key of Object.keys(inputValue)) {
    if (!allowedKeys.has(key)) {
      return {
        ok: false,
        error: errCode,
        detail: `unsupported field: ${key}`,
      };
    }
  }
  return { ok: true };
}

function validateGitHubRepoUrl(
  repoUrl: unknown,
  errCode: string,
): { ok: true } | { ok: false; error: string; detail: string } {
  if (typeof repoUrl !== "string") {
    return { ok: false, error: errCode, detail: "repo_url must be a string" };
  }
  const repoMatch = GITHUB_PUBLIC_REPO_RE.exec(repoUrl);
  if (!repoMatch) {
    return {
      ok: false,
      error: errCode,
      detail: "repo_url must be https://github.com/<owner>/<repo>",
    };
  }
  const [, owner, repo] = repoMatch;
  if (
    owner === "." ||
    owner === ".." ||
    repo === "." ||
    repo === ".." ||
    owner.includes("..") ||
    repo.includes("..") ||
    owner.startsWith("-") ||
    repo.startsWith("-")
  ) {
    return {
      ok: false,
      error: errCode,
      detail: "invalid owner or repository name",
    };
  }
  return { ok: true };
}

function validateGitRef(
  ref: unknown,
  errCode: string,
): { ok: true } | { ok: false; error: string; detail: string } {
  if (ref === undefined) return { ok: true };
  if (
    typeof ref !== "string" ||
    !GIT_REF_RE.test(ref) ||
    ref.startsWith("-") ||
    ref.startsWith("/") ||
    ref.endsWith("/") ||
    ref.includes("..") ||
    ref.includes("//")
  ) {
    return { ok: false, error: errCode, detail: "invalid git ref" };
  }
  return { ok: true };
}

function validateIntRange(
  value: unknown,
  errCode: string,
  field: string,
  min: number,
  max: number,
): { ok: true } | { ok: false; error: string; detail: string } {
  if (value === undefined) return { ok: true };
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < min ||
    value > max
  ) {
    return {
      ok: false,
      error: errCode,
      detail: `${field} must be an integer between ${min} and ${max}`,
    };
  }
  return { ok: true };
}

function validateStringArrayField(
  value: unknown,
  errCode: string,
  field: string,
  minLen: number,
  maxLen: number,
  itemValid: (item: string) => boolean,
): { ok: true } | { ok: false; error: string; detail: string } {
  if (value === undefined) return { ok: true };
  if (!Array.isArray(value) || value.length < minLen || value.length > maxLen) {
    return {
      ok: false,
      error: errCode,
      detail: `${field} must be an array of ${minLen}..${maxLen} items`,
    };
  }
  for (const item of value) {
    if (typeof item !== "string" || !itemValid(item)) {
      return {
        ok: false,
        error: errCode,
        detail: `invalid item in ${field}`,
      };
    }
  }
  return { ok: true };
}

function isValidTimerange(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const match = TIMERANGE_RE.exec(value);
  if (!match) return false;
  const [, startStr, endStr] = match;
  if (startStr >= endStr) return false;
  for (const d of [startStr, endStr]) {
    const month = Number(d.slice(4, 6));
    const day = Number(d.slice(6, 8));
    if (month < 1 || month > 12 || day < 1 || day > 31) {
      return false;
    }
  }
  return true;
}

export function validateJobInput(
  kind: string,
  inputValue: unknown,
): { ok: true } | { ok: false; error: string; detail?: string } {
  if (!isPlainObject(inputValue)) {
    const errMap: Record<string, string> = {
      repo_check: "invalid_repo_check_input",
      freqtrade_backtest: "invalid_freqtrade_backtest_input",
      qa_scenario: "invalid_qa_scenario_input",
    };
    return {
      ok: false,
      error: errMap[kind] ?? "invalid_input",
      detail: "input must be a JSON object",
    };
  }
  if (kind === "probe") {
    return { ok: true };
  }
  if (kind === "repo_check") {
    const errCode = "invalid_repo_check_input";
    const keyCheck = validateStrictInputKeys(inputValue, ALLOWED_REPO_CHECK_KEYS, errCode);
    if (!keyCheck.ok) return keyCheck;
    const repoCheck = validateGitHubRepoUrl(inputValue.repo_url, errCode);
    if (!repoCheck.ok) return repoCheck;

    const preset = inputValue.preset;
    if (
      preset !== undefined &&
      (typeof preset !== "string" || !ALLOWED_REPO_CHECK_PRESETS.has(preset))
    ) {
      return { ok: false, error: errCode, detail: "unsupported preset" };
    }
    const refCheck = validateGitRef(inputValue.ref, errCode);
    if (!refCheck.ok) return refCheck;
    return validateIntRange(inputValue.timeout_sec, errCode, "timeout_sec", 10, 1800);
  }
  if (kind === "freqtrade_backtest") {
    const errCode = "invalid_freqtrade_backtest_input";
    const keyCheck = validateStrictInputKeys(inputValue, ALLOWED_FREQTRADE_KEYS, errCode);
    if (!keyCheck.ok) return keyCheck;
    const repoCheck = validateGitHubRepoUrl(inputValue.repo_url, errCode);
    if (!repoCheck.ok) return repoCheck;
    const refCheck = validateGitRef(inputValue.ref, errCode);
    if (!refCheck.ok) return refCheck;

    if (
      typeof inputValue.strategy !== "string" ||
      !STRATEGY_NAME_RE.test(inputValue.strategy)
    ) {
      return { ok: false, error: errCode, detail: "invalid strategy name" };
    }
    if (
      inputValue.mode !== undefined &&
      (typeof inputValue.mode !== "string" ||
        !ALLOWED_FREQTRADE_MODES.has(inputValue.mode))
    ) {
      return { ok: false, error: errCode, detail: "unsupported mode" };
    }
    if (
      inputValue.exchange !== undefined &&
      (typeof inputValue.exchange !== "string" ||
        !ALLOWED_FREQTRADE_EXCHANGES.has(inputValue.exchange))
    ) {
      return { ok: false, error: errCode, detail: "unsupported exchange" };
    }
    if (
      inputValue.timeframe !== undefined &&
      (typeof inputValue.timeframe !== "string" ||
        !ALLOWED_FREQTRADE_TIMEFRAMES.has(inputValue.timeframe))
    ) {
      return { ok: false, error: errCode, detail: "unsupported timeframe" };
    }
    if (!isValidTimerange(inputValue.timerange)) {
      return {
        ok: false,
        error: errCode,
        detail: "timerange must be YYYYMMDD-YYYYMMDD with start < end",
      };
    }
    const pairsCheck = validateStringArrayField(
      inputValue.pairs,
      errCode,
      "pairs",
      1,
      20,
      (p) => PAIR_RE.test(p),
    );
    if (!pairsCheck.ok) return pairsCheck;
    const epochsCheck = validateIntRange(inputValue.epochs, errCode, "epochs", 1, 200);
    if (!epochsCheck.ok) return epochsCheck;
    const spacesCheck = validateStringArrayField(
      inputValue.spaces,
      errCode,
      "spaces",
      1,
      4,
      (s) => ALLOWED_HYPEROPT_SPACES.has(s),
    );
    if (!spacesCheck.ok) return spacesCheck;
    if (
      inputValue.hyperopt_loss !== undefined &&
      (typeof inputValue.hyperopt_loss !== "string" ||
        !ALLOWED_HYPEROPT_LOSSES.has(inputValue.hyperopt_loss))
    ) {
      return { ok: false, error: errCode, detail: "unsupported hyperopt_loss" };
    }
    if (
      inputValue.stake_amount !== undefined &&
      (typeof inputValue.stake_amount !== "number" ||
        !Number.isFinite(inputValue.stake_amount) ||
        inputValue.stake_amount < 10 ||
        inputValue.stake_amount > 100000)
    ) {
      return {
        ok: false,
        error: errCode,
        detail: "stake_amount must be a number between 10 and 100000",
      };
    }
    const tradesCheck = validateIntRange(
      inputValue.max_open_trades,
      errCode,
      "max_open_trades",
      1,
      20,
    );
    if (!tradesCheck.ok) return tradesCheck;
    return validateIntRange(inputValue.timeout_sec, errCode, "timeout_sec", 60, 3600);
  }
  if (kind === "qa_scenario") {
    const errCode = "invalid_qa_scenario_input";
    const keyCheck = validateStrictInputKeys(inputValue, ALLOWED_QA_SCENARIO_KEYS, errCode);
    if (!keyCheck.ok) return keyCheck;
    const repoCheck = validateGitHubRepoUrl(inputValue.repo_url, errCode);
    if (!repoCheck.ok) return repoCheck;
    const refCheck = validateGitRef(inputValue.ref, errCode);
    if (!refCheck.ok) return refCheck;

    if (
      typeof inputValue.scenario_id !== "string" ||
      !SCENARIO_ID_RE.test(inputValue.scenario_id)
    ) {
      return { ok: false, error: errCode, detail: "invalid scenario_id" };
    }
    if (
      typeof inputValue.scenario_name !== "string" ||
      inputValue.scenario_name.trim().length < 1 ||
      inputValue.scenario_name.length > 160
    ) {
      return { ok: false, error: errCode, detail: "invalid scenario_name" };
    }
    if (
      typeof inputValue.brief !== "string" ||
      inputValue.brief.trim().length < 1 ||
      inputValue.brief.length > 65536
    ) {
      return { ok: false, error: errCode, detail: "invalid brief" };
    }
    if (
      typeof inputValue.task !== "string" ||
      inputValue.task.trim().length < 1 ||
      inputValue.task.length > 32768
    ) {
      return { ok: false, error: errCode, detail: "invalid task" };
    }
    if (
      inputValue.lessons !== undefined &&
      (typeof inputValue.lessons !== "string" || inputValue.lessons.length > 65536)
    ) {
      return { ok: false, error: errCode, detail: "invalid lessons" };
    }
    if (inputValue.model !== undefined) {
      if (
        typeof inputValue.model !== "string" ||
        !QA_MODEL_RE.test(inputValue.model) ||
        PAID_MODEL_RE.test(inputValue.model)
      ) {
        return { ok: false, error: errCode, detail: "invalid or disallowed paid model" };
      }
    }
    const phase1Check = validateIntRange(
      inputValue.phase1_sec,
      errCode,
      "phase1_sec",
      30,
      3600,
    );
    if (!phase1Check.ok) return phase1Check;
    const wrapCheck = validateIntRange(inputValue.wrap_sec, errCode, "wrap_sec", 0, 900);
    if (!wrapCheck.ok) return wrapCheck;
    if (inputValue.tools !== undefined) {
      if (typeof inputValue.tools !== "string") {
        return { ok: false, error: errCode, detail: "tools must be a string" };
      }
      const parts = inputValue.tools.split(",").map((s) => s.trim());
      if (
        parts.length < 1 ||
        parts.length > 7 ||
        parts.some((p) => !p || !ALLOWED_QA_TOOLS.has(p))
      ) {
        return { ok: false, error: errCode, detail: "unsupported tools list" };
      }
    }
    return { ok: true };
  }
  return { ok: false, error: "unsupported_kind" };
}

function parseBoundedInt(
  value: unknown,
  defaultValue: number,
  min: number,
  max: number,
): number | null {
  if (value === undefined) return defaultValue;
  if (typeof value !== "number" || !Number.isInteger(value)) return null;
  if (value < min || value > max) return null;
  return value;
}

function withImmediateTx<T>(db: Database, fn: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const res = fn();
    db.exec("COMMIT");
    return res;
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // ignore rollback errors
    }
    throw err;
  }
}

function sweepExpiredAndLeased(db: Database, nowMs: number): void {
  db.query(
    `UPDATE jobs
     SET status = 'expired',
         worker_id = NULL,
         lease_token = NULL,
         lease_expires_at = NULL
     WHERE status IN ('queued', 'leased') AND expires_at <= ?`,
  ).run(nowMs);

  db.query(
    `UPDATE jobs
     SET status = 'queued',
         worker_id = NULL,
         lease_token = NULL,
         lease_expires_at = NULL
     WHERE status = 'leased' AND lease_expires_at <= ? AND expires_at > ?`,
  ).run(nowMs, nowMs);
}

type ReadBodyResult =
  | { ok: true; text: string }
  | { ok: false; reason: "too_large" | "read_error" };

async function readBodyCapped(
  req: Request,
  maxBytes: number,
): Promise<ReadBodyResult> {
  const clHeader = req.headers.get("content-length");
  if (clHeader !== null) {
    const cl = Number(clHeader);
    if (Number.isFinite(cl) && cl > maxBytes) {
      return { ok: false, reason: "too_large" };
    }
  }
  try {
    const buf = await req.arrayBuffer();
    if (buf.byteLength > maxBytes) {
      return { ok: false, reason: "too_large" };
    }
    return { ok: true, text: Buffer.from(buf).toString("utf8") };
  } catch {
    return { ok: false, reason: "read_error" };
  }
}

function serializeAdminJob(row: JobRow, includeOutput: boolean): Record<string, unknown> {
  const base: Record<string, unknown> = {
    job_id: row.job_id,
    kind: row.kind,
    status: row.status,
    ttl_sec: row.ttl_sec,
    max_input_bytes: row.max_input_bytes,
    max_output_bytes: row.max_output_bytes,
    created_at: row.created_at,
    expires_at: row.expires_at,
    worker_id: row.worker_id,
    lease_expires_at: row.lease_expires_at,
    attempts: row.attempts,
    completed_at: row.completed_at,
  };
  if (includeOutput) {
    base.output = row.output_json ? JSON.parse(row.output_json) : null;
    base.error = row.error_text;
  }
  return base;
}

function parseWorkerMeta(raw: unknown): { arch: string | null; cpus: number | null } {
  if (!isPlainObject(raw)) {
    return { arch: null, cpus: null };
  }
  const arch =
    typeof raw.arch === "string" && WORKER_ARCH_RE.test(raw.arch)
      ? raw.arch
      : null;
  const cpus =
    typeof raw.cpus === "number" &&
    Number.isInteger(raw.cpus) &&
    raw.cpus >= 1 &&
    raw.cpus <= 1024
      ? raw.cpus
      : null;
  return { arch, cpus };
}

function touchWorker(
  db: Database,
  workerId: string,
  nowMs: number,
  action: string,
  jobId: string | null,
  meta?: { arch: string | null; cpus: number | null },
): void {
  const arch = meta?.arch ?? null;
  const cpus = meta?.cpus ?? null;
  db.query(
    `INSERT INTO workers (worker_id, last_seen_at, last_action, last_job_id, arch, cpus)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(worker_id) DO UPDATE SET
       last_seen_at = excluded.last_seen_at,
       last_action = excluded.last_action,
       last_job_id = COALESCE(excluded.last_job_id, workers.last_job_id),
       arch = COALESCE(excluded.arch, workers.arch),
       cpus = COALESCE(excluded.cpus, workers.cpus)`,
  ).run(workerId, nowMs, action, jobId, arch, cpus);
}

export function createVmQueueApp(options: VmQueueOptions): VmQueueApp {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 8790;
  const now = options.now ?? (() => Date.now());
  const configuredTokens = [options.adminToken, options.workerToken];

  const db = new Database(options.dbPath);
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA busy_timeout = 5000;");
  db.exec("PRAGMA synchronous = NORMAL;");
  db.exec(`
    CREATE TABLE IF NOT EXISTS jobs (
      job_id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('queued','leased','completed','failed','expired')),
      input_bytes BLOB NOT NULL,
      input_content_type TEXT NOT NULL DEFAULT 'application/json',
      max_input_bytes INTEGER NOT NULL,
      max_output_bytes INTEGER NOT NULL,
      ttl_sec INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      worker_id TEXT,
      lease_token TEXT,
      lease_expires_at INTEGER,
      attempts INTEGER NOT NULL DEFAULT 0,
      output_json TEXT,
      error_text TEXT,
      completed_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_jobs_status_expires ON jobs(status, expires_at);
    CREATE INDEX IF NOT EXISTS idx_jobs_status_lease ON jobs(status, lease_expires_at);
    CREATE TABLE IF NOT EXISTS workers (
      worker_id TEXT PRIMARY KEY,
      last_seen_at INTEGER NOT NULL,
      last_action TEXT NOT NULL,
      last_job_id TEXT,
      arch TEXT,
      cpus INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_workers_last_seen ON workers(last_seen_at);
  `);

  function emitAuthFailure(
    req: Request,
    requiredRole: "admin" | "worker",
    status: 401 | 403,
    reason: AuthFailureInfo["reason"],
    authHeader: string | null,
  ): void {
    if (!options.onAuthFailure) return;
    let path = "/";
    try {
      path = new URL(req.url).pathname;
    } catch {
      path = "/";
    }
    const meta = classifyAuthHeader(authHeader);
    try {
      options.onAuthFailure({
        method: req.method,
        path,
        status,
        requiredRole,
        reason,
        ...meta,
      });
    } catch {
      // Diagnostic callback failures must not break auth handling
    }
  }

  function authenticate(
    req: Request,
    requiredRole: "admin" | "worker",
  ): Response | null {
    const authHeader = req.headers.get("authorization");
    if (!authHeader || !authHeader.trim()) {
      emitAuthFailure(req, requiredRole, 401, "missing_auth_header", authHeader);
      return jsonResponse({ error: "unauthorized" }, 401);
    }
    const match = /^Bearer\s+(\S+)$/i.exec(authHeader.trim());
    if (!match) {
      emitAuthFailure(req, requiredRole, 401, "malformed_auth_header", authHeader);
      return jsonResponse({ error: "unauthorized" }, 401);
    }
    const token = match[1];
    const isAdmin = constantTimeTokenMatch(token, options.adminToken);
    const isWorker = constantTimeTokenMatch(token, options.workerToken);

    if (!isAdmin && !isWorker) {
      emitAuthFailure(req, requiredRole, 401, "token_mismatch", authHeader);
      return jsonResponse({ error: "unauthorized" }, 401);
    }
    if (requiredRole === "admin" && !isAdmin) {
      emitAuthFailure(req, requiredRole, 403, "role_mismatch", authHeader);
      return jsonResponse({ error: "forbidden" }, 403);
    }
    if (requiredRole === "worker" && !isWorker) {
      emitAuthFailure(req, requiredRole, 403, "role_mismatch", authHeader);
      return jsonResponse({ error: "forbidden" }, 403);
    }
    return null;
  }

  async function handlePostJob(req: Request): Promise<Response> {
    const authErr = authenticate(req, "admin");
    if (authErr) return authErr;

    const bodyRes = await readBodyCapped(req, HARD_MAX_INPUT_BYTES + 65536);
    if (!bodyRes.ok) {
      if (bodyRes.reason === "too_large") {
        return jsonResponse({ error: "input_too_large" }, 413);
      }
      return jsonResponse({ error: "invalid_body" }, 400);
    }

    let payload: Record<string, unknown>;
    try {
      const parsed = JSON.parse(bodyRes.text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return jsonResponse({ error: "invalid_json" }, 400);
      }
      payload = parsed as Record<string, unknown>;
    } catch {
      return jsonResponse({ error: "invalid_json" }, 400);
    }

    const kind = payload.kind;
    if (typeof kind !== "string" || !ALLOWED_KINDS.has(kind)) {
      return jsonResponse(
        { error: "unsupported_kind", allowed: Array.from(ALLOWED_KINDS) },
        400,
      );
    }

    let jobId: string;
    if (payload.job_id === undefined) {
      jobId = `job_${randomBytes(8).toString("hex")}`;
    } else if (
      typeof payload.job_id === "string" &&
      JOB_ID_RE.test(payload.job_id)
    ) {
      jobId = payload.job_id;
    } else {
      return jsonResponse({ error: "invalid_job_id" }, 400);
    }

    const ttlSec = parseBoundedInt(
      payload.ttl_sec,
      DEFAULT_TTL_SEC,
      1,
      MAX_TTL_SEC,
    );
    if (ttlSec === null) {
      return jsonResponse({ error: "invalid_ttl_sec" }, 400);
    }

    const maxInputBytes = parseBoundedInt(
      payload.max_input_bytes,
      DEFAULT_MAX_INPUT_BYTES,
      1,
      HARD_MAX_INPUT_BYTES,
    );
    if (maxInputBytes === null) {
      return jsonResponse({ error: "invalid_max_input_bytes" }, 400);
    }

    const maxOutputBytes = parseBoundedInt(
      payload.max_output_bytes,
      DEFAULT_MAX_OUTPUT_BYTES,
      1,
      HARD_MAX_OUTPUT_BYTES,
    );
    if (maxOutputBytes === null) {
      return jsonResponse({ error: "invalid_max_output_bytes" }, 400);
    }

    const rawInputValue = payload.input === undefined ? {} : payload.input;
    const inputValidation = validateJobInput(kind, rawInputValue);
    if (!inputValidation.ok) {
      return jsonResponse(
        {
          error: inputValidation.error,
          ...(inputValidation.detail ? { detail: inputValidation.detail } : {}),
        },
        400,
      );
    }

    let inputValue: unknown = rawInputValue;
    if (kind === "repo_check" && isPlainObject(rawInputValue)) {
      inputValue =
        rawInputValue.preset === undefined
          ? { ...rawInputValue, preset: "auto" }
          : rawInputValue;
    } else if (kind === "freqtrade_backtest" && isPlainObject(rawInputValue)) {
      inputValue = {
        ...rawInputValue,
        mode: rawInputValue.mode ?? "backtest",
        exchange: rawInputValue.exchange ?? "binance",
        timeframe: rawInputValue.timeframe ?? "5m",
      };
    }

    const inputBuf = Buffer.from(JSON.stringify(inputValue), "utf8");
    if (inputBuf.byteLength > maxInputBytes) {
      return jsonResponse(
        {
          error: "input_too_large",
          max_input_bytes: maxInputBytes,
          actual_bytes: inputBuf.byteLength,
        },
        413,
      );
    }

    const inputSecretRule = detectSecretPattern(
      inputBuf.toString("utf8"),
      configuredTokens,
    );
    if (inputSecretRule !== null) {
      return jsonResponse(
        { error: "secret_pattern_detected", rule: inputSecretRule },
        422,
      );
    }

    const nowMs = now();
    const expiresAt = nowMs + ttlSec * 1000;

    try {
      withImmediateTx(db, () => {
        const existing = db
          .query("SELECT 1 FROM jobs WHERE job_id = ?")
          .get(jobId);
        if (existing) {
          throw new Error("JOB_EXISTS");
        }
        db.query(
          `INSERT INTO jobs (
             job_id, kind, status, input_bytes, input_content_type,
             max_input_bytes, max_output_bytes, ttl_sec, created_at, expires_at
           ) VALUES (?, ?, 'queued', ?, 'application/json', ?, ?, ?, ?, ?)`,
        ).run(
          jobId,
          kind,
          inputBuf,
          maxInputBytes,
          maxOutputBytes,
          ttlSec,
          nowMs,
          expiresAt,
        );
      });
    } catch (err) {
      if (err instanceof Error && err.message === "JOB_EXISTS") {
        return jsonResponse({ error: "job_exists" }, 409);
      }
      throw err;
    }

    return jsonResponse(
      {
        job_id: jobId,
        kind,
        status: "queued",
        ttl_sec: ttlSec,
        max_input_bytes: maxInputBytes,
        max_output_bytes: maxOutputBytes,
        created_at: nowMs,
        expires_at: expiresAt,
      },
      201,
    );
  }

  async function handleClaim(req: Request): Promise<Response> {
    const authErr = authenticate(req, "worker");
    if (authErr) return authErr;

    const bodyRes = await readBodyCapped(req, 65536);
    if (!bodyRes.ok) {
      return jsonResponse({ error: "invalid_body" }, 400);
    }

    let payload: Record<string, unknown>;
    try {
      const parsed = JSON.parse(bodyRes.text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return jsonResponse({ error: "invalid_json" }, 400);
      }
      payload = parsed as Record<string, unknown>;
    } catch {
      return jsonResponse({ error: "invalid_json" }, 400);
    }

    const workerId = payload.worker_id;
    if (typeof workerId !== "string" || !WORKER_ID_RE.test(workerId)) {
      return jsonResponse({ error: "invalid_worker_id" }, 400);
    }

    const leaseSec = parseBoundedInt(
      payload.lease_sec,
      DEFAULT_LEASE_SEC,
      1,
      MAX_LEASE_SEC,
    );
    if (leaseSec === null) {
      return jsonResponse({ error: "invalid_lease_sec" }, 400);
    }

    let claimKinds: string[] | null = null;
    if (payload.kinds !== undefined) {
      if (
        !Array.isArray(payload.kinds) ||
        payload.kinds.length === 0 ||
        payload.kinds.length > ALLOWED_KINDS.size
      ) {
        return jsonResponse({ error: "invalid_kinds" }, 400);
      }
      const uniqueKinds: string[] = [];
      for (const item of payload.kinds) {
        if (typeof item !== "string" || !ALLOWED_KINDS.has(item)) {
          return jsonResponse({ error: "invalid_kinds" }, 400);
        }
        if (!uniqueKinds.includes(item)) {
          uniqueKinds.push(item);
        }
      }
      claimKinds = uniqueKinds;
    }

    const meta = parseWorkerMeta(payload.meta);
    const nowMs = now();
    const claimed = withImmediateTx(db, () => {
      sweepExpiredAndLeased(db, nowMs);
      const next = (
        claimKinds === null
          ? db
              .query(
                `SELECT job_id, kind, max_input_bytes, max_output_bytes, expires_at, attempts
                 FROM jobs
                 WHERE status = 'queued'
                 ORDER BY created_at ASC, rowid ASC
                 LIMIT 1`,
              )
              .get()
          : db
              .query(
                `SELECT job_id, kind, max_input_bytes, max_output_bytes, expires_at, attempts
                 FROM jobs
                 WHERE status = 'queued'
                   AND kind IN (${claimKinds.map(() => "?").join(", ")})
                 ORDER BY created_at ASC, rowid ASC
                 LIMIT 1`,
              )
              .get(...claimKinds)
      ) as Pick<
        JobRow,
        | "job_id"
        | "kind"
        | "max_input_bytes"
        | "max_output_bytes"
        | "expires_at"
        | "attempts"
      > | null;

      if (!next) {
        touchWorker(db, workerId, nowMs, "claim_empty", null, meta);
        return null;
      }

      const leaseToken = randomBytes(16).toString("hex");
      const leaseExpiresAt = Math.min(next.expires_at, nowMs + leaseSec * 1000);
      const nextAttempts = next.attempts + 1;

      db.query(
        `UPDATE jobs
         SET status = 'leased',
             worker_id = ?,
             lease_token = ?,
             lease_expires_at = ?,
             attempts = ?
         WHERE job_id = ?`,
      ).run(workerId, leaseToken, leaseExpiresAt, nextAttempts, next.job_id);
      touchWorker(db, workerId, nowMs, "claim_hit", next.job_id, meta);

      return {
        job_id: next.job_id,
        kind: next.kind,
        worker_id: workerId,
        lease_token: leaseToken,
        lease_expires_at: leaseExpiresAt,
        max_input_bytes: next.max_input_bytes,
        max_output_bytes: next.max_output_bytes,
        attempts: nextAttempts,
      };
    });

    return jsonResponse({ job: claimed }, 200);
  }

  function handleGetInput(
    req: Request,
    url: URL,
    jobId: string,
  ): Response {
    const authErr = authenticate(req, "worker");
    if (authErr) return authErr;

    const workerId =
      req.headers.get("x-worker-id") ?? url.searchParams.get("worker_id");
    if (typeof workerId !== "string" || !WORKER_ID_RE.test(workerId)) {
      return jsonResponse({ error: "invalid_worker_id" }, 400);
    }

    const leaseToken =
      req.headers.get("x-lease-token") ?? url.searchParams.get("lease_token");

    const nowMs = now();
    const outcome = withImmediateTx(db, () => {
      sweepExpiredAndLeased(db, nowMs);
      const row = db
        .query("SELECT * FROM jobs WHERE job_id = ?")
        .get(jobId) as JobRow | null;
      if (!row) {
        return { kind: "not_found" as const };
      }
      if (
        row.status !== "leased" ||
        row.worker_id !== workerId ||
        row.lease_expires_at === null ||
        row.lease_expires_at <= nowMs ||
        row.expires_at <= nowMs ||
        (leaseToken !== null && row.lease_token !== leaseToken)
      ) {
        return { kind: "lease_invalid" as const };
      }
      if (row.input_bytes.byteLength > row.max_input_bytes) {
        return { kind: "too_large" as const };
      }
      return {
        kind: "ok" as const,
        jobKind: row.kind,
        bytes: row.input_bytes,
        contentType: row.input_content_type || "application/json",
      };
    });

    if (outcome.kind === "not_found") {
      return jsonResponse({ error: "job_not_found" }, 404);
    }
    if (outcome.kind === "lease_invalid") {
      return jsonResponse({ error: "lease_not_owned_or_expired" }, 409);
    }
    if (outcome.kind === "too_large") {
      return jsonResponse({ error: "input_too_large" }, 413);
    }
    return bytesResponse(outcome.bytes, outcome.contentType, 200, {
      "X-Job-Id": jobId,
      "X-Job-Kind": outcome.jobKind,
    });
  }

  async function handleHeartbeat(req: Request, jobId: string): Promise<Response> {
    const authErr = authenticate(req, "worker");
    if (authErr) return authErr;

    const bodyRes = await readBodyCapped(req, 65536);
    if (!bodyRes.ok) {
      return jsonResponse({ error: "invalid_body" }, 400);
    }

    let payload: Record<string, unknown>;
    try {
      const parsed = JSON.parse(bodyRes.text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return jsonResponse({ error: "invalid_json" }, 400);
      }
      payload = parsed as Record<string, unknown>;
    } catch {
      return jsonResponse({ error: "invalid_json" }, 400);
    }

    const workerId = payload.worker_id;
    if (typeof workerId !== "string" || !WORKER_ID_RE.test(workerId)) {
      return jsonResponse({ error: "invalid_worker_id" }, 400);
    }
    const leaseToken =
      payload.lease_token === undefined ? null : payload.lease_token;
    if (leaseToken !== null && typeof leaseToken !== "string") {
      return jsonResponse({ error: "invalid_lease_token" }, 400);
    }

    const leaseSec = parseBoundedInt(
      payload.lease_sec,
      DEFAULT_LEASE_SEC,
      1,
      MAX_LEASE_SEC,
    );
    if (leaseSec === null) {
      return jsonResponse({ error: "invalid_lease_sec" }, 400);
    }

    const nowMs = now();
    const outcome = withImmediateTx(db, () => {
      sweepExpiredAndLeased(db, nowMs);
      const row = db
        .query("SELECT * FROM jobs WHERE job_id = ?")
        .get(jobId) as JobRow | null;
      if (!row) {
        return { kind: "not_found" as const };
      }
      if (
        row.status !== "leased" ||
        row.worker_id !== workerId ||
        row.lease_expires_at === null ||
        row.lease_expires_at <= nowMs ||
        row.expires_at <= nowMs ||
        (leaseToken !== null && row.lease_token !== leaseToken)
      ) {
        return { kind: "lease_invalid" as const };
      }
      const nextLeaseExpiresAt = Math.min(
        row.expires_at,
        nowMs + leaseSec * 1000,
      );
      db.query("UPDATE jobs SET lease_expires_at = ? WHERE job_id = ?").run(
        nextLeaseExpiresAt,
        jobId,
      );
      touchWorker(db, workerId, nowMs, "heartbeat", jobId);
      return {
        kind: "ok" as const,
        lease_expires_at: nextLeaseExpiresAt,
      };
    });

    if (outcome.kind === "not_found") {
      return jsonResponse({ error: "job_not_found" }, 404);
    }
    if (outcome.kind === "lease_invalid") {
      return jsonResponse({ error: "lease_not_owned_or_expired" }, 409);
    }
    return jsonResponse(
      {
        job_id: jobId,
        status: "leased",
        worker_id: workerId,
        lease_expires_at: outcome.lease_expires_at,
      },
      200,
    );
  }

  async function handleFinish(
    req: Request,
    jobId: string,
    mode: "complete" | "fail",
  ): Promise<Response> {
    const authErr = authenticate(req, "worker");
    if (authErr) return authErr;

    const bodyRes = await readBodyCapped(req, HARD_MAX_OUTPUT_BYTES + 65536);
    if (!bodyRes.ok) {
      if (bodyRes.reason === "too_large") {
        return jsonResponse({ error: "output_too_large" }, 413);
      }
      return jsonResponse({ error: "invalid_body" }, 400);
    }

    let payload: Record<string, unknown>;
    try {
      const parsed = JSON.parse(bodyRes.text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return jsonResponse({ error: "invalid_json" }, 400);
      }
      payload = parsed as Record<string, unknown>;
    } catch {
      return jsonResponse({ error: "invalid_json" }, 400);
    }

    const workerId = payload.worker_id;
    if (typeof workerId !== "string" || !WORKER_ID_RE.test(workerId)) {
      return jsonResponse({ error: "invalid_worker_id" }, 400);
    }
    const leaseToken =
      payload.lease_token === undefined ? null : payload.lease_token;
    if (leaseToken !== null && typeof leaseToken !== "string") {
      return jsonResponse({ error: "invalid_lease_token" }, 400);
    }

    let serializedPayload: string;
    if (mode === "complete") {
      if (payload.output === undefined) {
        return jsonResponse({ error: "missing_output" }, 400);
      }
      serializedPayload = JSON.stringify(payload.output);
    } else {
      if (typeof payload.error !== "string" || payload.error.trim() === "") {
        return jsonResponse({ error: "missing_error" }, 400);
      }
      serializedPayload = payload.error;
    }

    const existingMeta = db
      .query("SELECT max_output_bytes FROM jobs WHERE job_id = ?")
      .get(jobId) as { max_output_bytes: number } | null;
    if (!existingMeta) {
      return jsonResponse({ error: "job_not_found" }, 404);
    }

    const actualBytes = Buffer.byteLength(serializedPayload, "utf8");
    if (actualBytes > existingMeta.max_output_bytes) {
      return jsonResponse(
        {
          error: "output_too_large",
          max_output_bytes: existingMeta.max_output_bytes,
          actual_bytes: actualBytes,
        },
        413,
      );
    }

    const secretRule = detectSecretPattern(serializedPayload, configuredTokens);
    if (secretRule !== null) {
      return jsonResponse(
        { error: "secret_pattern_detected", rule: secretRule },
        422,
      );
    }

    const nowMs = now();
    const outcome = withImmediateTx(db, () => {
      sweepExpiredAndLeased(db, nowMs);
      const row = db
        .query("SELECT * FROM jobs WHERE job_id = ?")
        .get(jobId) as JobRow | null;
      if (!row) {
        return { kind: "not_found" as const };
      }
      if (
        row.status !== "leased" ||
        row.worker_id !== workerId ||
        row.lease_expires_at === null ||
        row.lease_expires_at <= nowMs ||
        row.expires_at <= nowMs ||
        (leaseToken !== null && row.lease_token !== leaseToken)
      ) {
        return { kind: "lease_invalid" as const };
      }

      if (mode === "complete") {
        db.query(
          `UPDATE jobs
           SET status = 'completed',
               output_json = ?,
               error_text = NULL,
               completed_at = ?,
               lease_token = NULL
           WHERE job_id = ?`,
        ).run(serializedPayload, nowMs, jobId);
        touchWorker(db, workerId, nowMs, "complete", jobId);
        return { kind: "ok" as const, status: "completed" as const };
      } else {
        db.query(
          `UPDATE jobs
           SET status = 'failed',
               error_text = ?,
               completed_at = ?,
               lease_token = NULL
           WHERE job_id = ?`,
        ).run(serializedPayload, nowMs, jobId);
        touchWorker(db, workerId, nowMs, "fail", jobId);
        return { kind: "ok" as const, status: "failed" as const };
      }
    });

    if (outcome.kind === "not_found") {
      return jsonResponse({ error: "job_not_found" }, 404);
    }
    if (outcome.kind === "lease_invalid") {
      return jsonResponse({ error: "lease_not_owned_or_expired" }, 409);
    }

    return jsonResponse(
      {
        job_id: jobId,
        status: outcome.status,
        completed_at: nowMs,
      },
      200,
    );
  }

  function handleGetJob(req: Request, jobId: string): Response {
    const authErr = authenticate(req, "admin");
    if (authErr) return authErr;

    const nowMs = now();
    const row = withImmediateTx(db, () => {
      sweepExpiredAndLeased(db, nowMs);
      return db
        .query("SELECT * FROM jobs WHERE job_id = ?")
        .get(jobId) as JobRow | null;
    });

    if (!row) {
      return jsonResponse({ error: "job_not_found" }, 404);
    }
    return jsonResponse(serializeAdminJob(row, true), 200);
  }

  function handleListJobs(req: Request): Response {
    const authErr = authenticate(req, "admin");
    if (authErr) return authErr;

    const nowMs = now();
    const rows = withImmediateTx(db, () => {
      sweepExpiredAndLeased(db, nowMs);
      return db
        .query(
          `SELECT * FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT 50`,
        )
        .all() as JobRow[];
    });

    return jsonResponse(
      { jobs: rows.map((r) => serializeAdminJob(r, false)) },
      200,
    );
  }

  async function handleRequeue(req: Request, jobId: string): Promise<Response> {
    const authErr = authenticate(req, "admin");
    if (authErr) return authErr;

    const bodyRes = await readBodyCapped(req, 65536);
    if (!bodyRes.ok) {
      return jsonResponse({ error: "invalid_body" }, 400);
    }

    let requestedTtlSec: number | null = null;
    if (bodyRes.text.trim() !== "") {
      let payload: Record<string, unknown>;
      try {
        const parsed = JSON.parse(bodyRes.text);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          return jsonResponse({ error: "invalid_json" }, 400);
        }
        payload = parsed as Record<string, unknown>;
      } catch {
        return jsonResponse({ error: "invalid_json" }, 400);
      }
      if (payload.ttl_sec !== undefined) {
        const parsedTtl = parseBoundedInt(
          payload.ttl_sec,
          DEFAULT_TTL_SEC,
          1,
          MAX_TTL_SEC,
        );
        if (parsedTtl === null) {
          return jsonResponse({ error: "invalid_ttl_sec" }, 400);
        }
        requestedTtlSec = parsedTtl;
      }
    }

    const nowMs = now();
    const outcome = withImmediateTx(db, () => {
      sweepExpiredAndLeased(db, nowMs);
      const row = db
        .query("SELECT * FROM jobs WHERE job_id = ?")
        .get(jobId) as JobRow | null;
      if (!row) {
        return { kind: "not_found" as const };
      }
      if (row.status === "completed") {
        return { kind: "completed" as const };
      }
      const nextTtlSec = requestedTtlSec ?? row.ttl_sec;
      const nextExpiresAt =
        requestedTtlSec !== null
          ? nowMs + requestedTtlSec * 1000
          : row.expires_at <= nowMs
            ? nowMs + row.ttl_sec * 1000
            : row.expires_at;

      db.query(
        `UPDATE jobs
         SET status = 'queued',
             worker_id = NULL,
             lease_token = NULL,
             lease_expires_at = NULL,
             error_text = NULL,
             completed_at = NULL,
             ttl_sec = ?,
             expires_at = ?
         WHERE job_id = ?`,
      ).run(nextTtlSec, nextExpiresAt, jobId);

      const updated = db
        .query("SELECT * FROM jobs WHERE job_id = ?")
        .get(jobId) as JobRow;
      return { kind: "ok" as const, row: updated };
    });

    if (outcome.kind === "not_found") {
      return jsonResponse({ error: "job_not_found" }, 404);
    }
    if (outcome.kind === "completed") {
      return jsonResponse({ error: "cannot_requeue_completed" }, 409);
    }
    return jsonResponse(serializeAdminJob(outcome.row, false), 200);
  }

  async function handleWorkerPing(req: Request): Promise<Response> {
    const authErr = authenticate(req, "worker");
    if (authErr) return authErr;

    const bodyRes = await readBodyCapped(req, 16384);
    if (!bodyRes.ok) {
      return jsonResponse({ error: "invalid_body" }, 400);
    }

    let payload: Record<string, unknown>;
    try {
      const parsed = JSON.parse(bodyRes.text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return jsonResponse({ error: "invalid_json" }, 400);
      }
      payload = parsed as Record<string, unknown>;
    } catch {
      return jsonResponse({ error: "invalid_json" }, 400);
    }

    const workerId = payload.worker_id;
    if (typeof workerId !== "string" || !WORKER_ID_RE.test(workerId)) {
      return jsonResponse({ error: "invalid_worker_id" }, 400);
    }

    const meta = parseWorkerMeta(payload);
    const nowMs = now();
    withImmediateTx(db, () => {
      touchWorker(db, workerId, nowMs, "ping", null, meta);
    });

    return jsonResponse(
      {
        ok: true,
        worker_id: workerId,
        last_seen_at: nowMs,
      },
      200,
    );
  }

  function handleWorkersStatus(req: Request, url: URL): Response {
    const authErr = authenticate(req, "admin");
    if (authErr) return authErr;

    const rawWindow = url.searchParams.get("window_sec");
    let windowSec = DEFAULT_WORKER_WINDOW_SEC;
    if (rawWindow !== null) {
      if (!/^\d+$/.test(rawWindow)) {
        return jsonResponse({ error: "invalid_window_sec" }, 400);
      }
      const parsed = Number(rawWindow);
      if (parsed < 5 || parsed > MAX_WORKER_WINDOW_SEC) {
        return jsonResponse({ error: "invalid_window_sec" }, 400);
      }
      windowSec = parsed;
    }

    const nowMs = now();
    const cutoffMs = nowMs - windowSec * 1000;
    const rows = db
      .query("SELECT * FROM workers ORDER BY last_seen_at DESC LIMIT 50")
      .all() as WorkerRow[];

    const workers = rows.map((row) => ({
      worker_id: row.worker_id,
      last_seen_at: row.last_seen_at,
      idle_sec: Math.max(0, Math.floor((nowMs - row.last_seen_at) / 1000)),
      online: row.last_seen_at >= cutoffMs,
      last_action: row.last_action,
      last_job_id: row.last_job_id,
      arch: row.arch,
      cpus: row.cpus,
    }));
    const onlineCount = workers.filter((w) => w.online).length;

    return jsonResponse(
      {
        now: nowMs,
        window_sec: windowSec,
        online_count: onlineCount,
        any_online: onlineCount > 0,
        workers,
      },
      200,
    );
  }

  const server = Bun.serve({
    hostname: host,
    port,
    maxRequestBodySize: HARD_MAX_INPUT_BYTES + 65536,
    async fetch(req: Request): Promise<Response> {
      const url = new URL(req.url);
      const path = url.pathname;
      const method = req.method;

      if (method === "GET" && path === "/healthz") {
        return jsonResponse({ ok: true, service: "vm-queue" }, 200);
      }
      if (method === "POST" && path === "/jobs") {
        return handlePostJob(req);
      }
      if (method === "GET" && path === "/jobs") {
        return handleListJobs(req);
      }
      if (method === "POST" && path === "/jobs/claim") {
        return handleClaim(req);
      }
      if (method === "POST" && path === "/workers/ping") {
        return handleWorkerPing(req);
      }
      if (method === "GET" && path === "/workers/status") {
        return handleWorkersStatus(req, url);
      }

      const inputMatch = /^\/jobs\/([a-zA-Z0-9_-]{3,64})\/input$/.exec(path);
      if (method === "GET" && inputMatch) {
        return handleGetInput(req, url, inputMatch[1]);
      }

      const hbMatch = /^\/jobs\/([a-zA-Z0-9_-]{3,64})\/heartbeat$/.exec(path);
      if (method === "POST" && hbMatch) {
        return handleHeartbeat(req, hbMatch[1]);
      }

      const completeMatch = /^\/jobs\/([a-zA-Z0-9_-]{3,64})\/complete$/.exec(path);
      if (method === "POST" && completeMatch) {
        return handleFinish(req, completeMatch[1], "complete");
      }

      const failMatch = /^\/jobs\/([a-zA-Z0-9_-]{3,64})\/fail$/.exec(path);
      if (method === "POST" && failMatch) {
        return handleFinish(req, failMatch[1], "fail");
      }

      const requeueMatch = /^\/jobs\/([a-zA-Z0-9_-]{3,64})\/requeue$/.exec(path);
      if (method === "POST" && requeueMatch) {
        return handleRequeue(req, requeueMatch[1]);
      }

      const getMatch = /^\/jobs\/([a-zA-Z0-9_-]{3,64})$/.exec(path);
      if (method === "GET" && getMatch) {
        return handleGetJob(req, getMatch[1]);
      }

      return jsonResponse({ error: "not_found" }, 404);
    },
  });

  return {
    server,
    db,
    close: () => {
      server.stop(true);
      db.close();
    },
  };
}
