#!/usr/bin/env python3
"""Standalone, zero-dependency Python 3 worker for vm-queue."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Iterable, Optional

WORKER_ID_RE = re.compile(r"^[a-zA-Z0-9._:-]{1,64}$")
GITHUB_PUBLIC_REPO_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$"
)
GIT_REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,128}$")
ALLOWED_KINDS = frozenset({"probe", "repo_check", "freqtrade_backtest", "qa_scenario"})
ALLOWED_REPO_CHECK_KEYS = frozenset({"repo_url", "preset", "ref", "timeout_sec"})
ALLOWED_REPO_CHECK_PRESETS = frozenset(
    {
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
    }
)
ALLOWED_FREQTRADE_KEYS = frozenset(
    {
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
    }
)
ALLOWED_FREQTRADE_MODES = frozenset({"backtest", "hyperopt"})
ALLOWED_FREQTRADE_EXCHANGES = frozenset({"binance", "okx", "bybit", "gate", "kraken"})
ALLOWED_FREQTRADE_TIMEFRAMES = frozenset({"1m", "5m", "15m", "30m", "1h", "4h", "1d"})
ALLOWED_HYPEROPT_SPACES = frozenset({"buy", "sell", "roi", "stoploss", "trailing"})
ALLOWED_HYPEROPT_LOSSES = frozenset(
    {
        "ShortTradeDurHyperOptLoss",
        "OnlyProfitHyperOptLoss",
        "SharpeHyperOptLoss",
        "SortinoHyperOptLoss",
        "CalmarHyperOptLoss",
    }
)
STRATEGY_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
TIMERANGE_RE = re.compile(r"^(\d{8})-(\d{8})$")
PAIR_RE = re.compile(r"^[A-Z0-9]{2,12}/[A-Z]{3,6}(?::[A-Z]{3,6})?$")

ALLOWED_QA_SCENARIO_KEYS = frozenset(
    {
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
    }
)
ALLOWED_QA_TOOLS = frozenset({"read", "bash", "edit", "write", "grep", "glob", "todo"})
SCENARIO_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
QA_MODEL_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,96}$")
PAID_MODEL_RE = re.compile(r"anthropic|claude|openai|gpt-4|gpt-5|\bo1\b|\bo3\b", re.IGNORECASE)
LLM_PROVIDER_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")

FUNC_SYM_RE = re.compile(
    r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+\w+|def\s+\w+|func\s+(?:\([^)]+\)\s*)?\w+|(?:pub\s+)?(?:async\s+)?fn\s+\w+)",
    re.MULTILINE,
)
TYPE_SYM_RE = re.compile(
    r"^\s*(?:export\s+)?(?:class|interface|type|enum|struct)\s+\w+",
    re.MULTILINE,
)
INDEX_SOURCE_EXTS = frozenset({".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rs"})
SAFE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "TERM", "TMPDIR", "USER")


class WorkerInfraError(Exception):
    """Raised when a job cannot be executed because of worker/repo infra errors."""


def sanitize_worker_id(raw: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._:-]+", "-", raw).strip("-")
    if not cleaned:
        cleaned = "cue-worker"
    cleaned = cleaned[:64]
    if not WORKER_ID_RE.match(cleaned):
        return "cue-worker"
    return cleaned


def default_worker_id() -> str:
    host = socket.gethostname() or "vm"
    return sanitize_worker_id(f"cue-worker-{host}")


def validate_worker_token(raw: str) -> str:
    """Validate worker Bearer token without echoing its secret text in errors."""
    token = raw.rstrip("\r\n")
    if not token:
        raise ValueError("Worker token is empty")
    lower = token.lower()
    if lower.startswith("vm_queue_"):
        raise ValueError(
            "Worker token starts with env key prefix (VM_QUEUE_*); provide only the token value"
        )
    if lower.startswith("bearer "):
        raise ValueError(
            "Worker token starts with 'Bearer '; provide only the raw token value"
        )
    if (token.startswith("<") and token.endswith(">")) or "<" in token or ">" in token:
        raise ValueError(
            "Worker token contains angle brackets (< or >); remove placeholder brackets"
        )
    if (token.startswith('"') and token.endswith('"')) or (
        token.startswith("'") and token.endswith("'")
    ):
        raise ValueError(
            "Worker token is wrapped in quotes; provide the unquoted token value"
        )
    if any(ch.isspace() for ch in token):
        raise ValueError("Worker token contains whitespace")
    if len(token) < 24:
        raise ValueError(f"Worker token is too short (len={len(token)}, expected >= 24)")
    return token


def build_clean_env(source_env: Optional[dict[str, str]] = None) -> dict[str, str]:
    src = os.environ if source_env is None else source_env
    clean: dict[str, str] = {}
    for key in SAFE_ENV_KEYS:
        val = src.get(key)
        if val:
            clean[key] = val
    clean["GIT_TERMINAL_PROMPT"] = "0"
    clean["CI"] = "1"
    return clean


def redact_secrets(text: str, secrets: Iterable[str]) -> str:
    if not text:
        return text
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def redact_worker_token(text: str, token: str) -> str:
    return redact_secrets(text, [token])


def tail_text(text: str, max_chars: int = 12000) -> str:
    if len(text) <= max_chars:
        return text
    prefix = "...(truncated)\n"
    keep = max(0, max_chars - len(prefix))
    return prefix + text[-keep:]


def _validate_github_repo_url(repo_url: Any) -> str:
    if not isinstance(repo_url, str):
        raise WorkerInfraError("repo_url must be a string")
    match = GITHUB_PUBLIC_REPO_RE.match(repo_url)
    if not match:
        raise WorkerInfraError(
            "repo_url must match https://github.com/<owner>/<repo>"
        )
    owner, repo = match.group(1), match.group(2)
    if (
        owner in {".", ".."}
        or repo in {".", ".."}
        or ".." in owner
        or ".." in repo
        or owner.startswith("-")
        or repo.startswith("-")
    ):
        raise WorkerInfraError("Invalid GitHub owner or repository name")
    return repo_url


def _validate_git_ref(ref: Any) -> Optional[str]:
    if ref is None:
        return None
    if (
        not isinstance(ref, str)
        or not GIT_REF_RE.match(ref)
        or ref.startswith("-")
        or ref.startswith("/")
        or ref.endswith("/")
        or ".." in ref
        or "//" in ref
    ):
        raise WorkerInfraError("Invalid git ref")
    return ref


def _validate_int_range(
    value: Any, field: str, default: int, min_val: int, max_val: int
) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < min_val or value > max_val:
        raise WorkerInfraError(f"{field} must be an integer between {min_val} and {max_val}")
    return value


def validate_repo_check_input(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise WorkerInfraError("repo_check input must be a JSON object")
    unknown = set(data.keys()) - ALLOWED_REPO_CHECK_KEYS
    if unknown:
        raise WorkerInfraError(
            f"Unsupported repo_check input fields: {sorted(unknown)}"
        )
    repo_url = _validate_github_repo_url(data.get("repo_url"))

    preset = data.get("preset", "auto")
    if preset is None:
        preset = "auto"
    if not isinstance(preset, str) or preset not in ALLOWED_REPO_CHECK_PRESETS:
        raise WorkerInfraError(f"Unsupported repo_check preset: {preset!r}")

    ref = _validate_git_ref(data.get("ref"))
    timeout_sec = _validate_int_range(
        data.get("timeout_sec"), "timeout_sec", 180, 10, 1800
    )

    return {
        "repo_url": repo_url,
        "preset": preset,
        "ref": ref,
        "timeout_sec": timeout_sec,
    }


def validate_freqtrade_backtest_input(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise WorkerInfraError("freqtrade_backtest input must be a JSON object")
    unknown = set(data.keys()) - ALLOWED_FREQTRADE_KEYS
    if unknown:
        raise WorkerInfraError(
            f"Unsupported freqtrade_backtest input fields: {sorted(unknown)}"
        )
    repo_url = _validate_github_repo_url(data.get("repo_url"))
    ref = _validate_git_ref(data.get("ref"))

    strategy = data.get("strategy")
    if not isinstance(strategy, str) or not STRATEGY_NAME_RE.match(strategy):
        raise WorkerInfraError("Invalid freqtrade strategy name")

    mode = data.get("mode", "backtest")
    if mode is None:
        mode = "backtest"
    if not isinstance(mode, str) or mode not in ALLOWED_FREQTRADE_MODES:
        raise WorkerInfraError(f"Unsupported freqtrade mode: {mode!r}")

    exchange = data.get("exchange", "binance")
    if exchange is None:
        exchange = "binance"
    if not isinstance(exchange, str) or exchange not in ALLOWED_FREQTRADE_EXCHANGES:
        raise WorkerInfraError(f"Unsupported freqtrade exchange: {exchange!r}")

    timeframe = data.get("timeframe", "5m")
    if timeframe is None:
        timeframe = "5m"
    if not isinstance(timeframe, str) or timeframe not in ALLOWED_FREQTRADE_TIMEFRAMES:
        raise WorkerInfraError(f"Unsupported freqtrade timeframe: {timeframe!r}")

    timerange = data.get("timerange")
    if not isinstance(timerange, str):
        raise WorkerInfraError("timerange must be YYYYMMDD-YYYYMMDD")
    tr_match = TIMERANGE_RE.match(timerange)
    if not tr_match or tr_match.group(1) >= tr_match.group(2):
        raise WorkerInfraError("timerange must be YYYYMMDD-YYYYMMDD with start < end")
    for part in (tr_match.group(1), tr_match.group(2)):
        month, day = int(part[4:6]), int(part[6:8])
        if month < 1 or month > 12 or day < 1 or day > 31:
            raise WorkerInfraError("timerange contains invalid month or day")

    raw_pairs = data.get("pairs")
    if raw_pairs is None:
        pairs = ["BTC/USDT", "ETH/USDT"]
    else:
        if (
            not isinstance(raw_pairs, list)
            or len(raw_pairs) < 1
            or len(raw_pairs) > 20
            or any(not isinstance(p, str) or not PAIR_RE.match(p) for p in raw_pairs)
        ):
            raise WorkerInfraError("pairs must be 1..20 valid trading pairs")
        pairs = list(raw_pairs)

    epochs = _validate_int_range(data.get("epochs"), "epochs", 50, 1, 200)

    raw_spaces = data.get("spaces")
    if raw_spaces is None:
        spaces = ["buy", "sell"]
    else:
        if (
            not isinstance(raw_spaces, list)
            or len(raw_spaces) < 1
            or len(raw_spaces) > 4
            or any(
                not isinstance(s, str) or s not in ALLOWED_HYPEROPT_SPACES
                for s in raw_spaces
            )
        ):
            raise WorkerInfraError("spaces must be 1..4 valid hyperopt spaces")
        spaces = list(raw_spaces)

    hyperopt_loss = data.get("hyperopt_loss", "SharpeHyperOptLoss")
    if hyperopt_loss is None:
        hyperopt_loss = "SharpeHyperOptLoss"
    if (
        not isinstance(hyperopt_loss, str)
        or hyperopt_loss not in ALLOWED_HYPEROPT_LOSSES
    ):
        raise WorkerInfraError(f"Unsupported hyperopt_loss: {hyperopt_loss!r}")

    stake_amount = data.get("stake_amount", 100)
    if stake_amount is None:
        stake_amount = 100
    if (
        isinstance(stake_amount, bool)
        or not isinstance(stake_amount, (int, float))
        or stake_amount < 10
        or stake_amount > 100000
    ):
        raise WorkerInfraError("stake_amount must be between 10 and 100000")

    max_open_trades = _validate_int_range(
        data.get("max_open_trades"), "max_open_trades", 3, 1, 20
    )
    timeout_sec = _validate_int_range(
        data.get("timeout_sec"), "timeout_sec", 600, 60, 3600
    )

    return {
        "repo_url": repo_url,
        "ref": ref,
        "strategy": strategy,
        "mode": mode,
        "exchange": exchange,
        "timeframe": timeframe,
        "timerange": timerange,
        "pairs": pairs,
        "epochs": epochs,
        "spaces": spaces,
        "hyperopt_loss": hyperopt_loss,
        "stake_amount": float(stake_amount),
        "max_open_trades": max_open_trades,
        "timeout_sec": timeout_sec,
    }


def validate_qa_scenario_input(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise WorkerInfraError("qa_scenario input must be a JSON object")
    unknown = set(data.keys()) - ALLOWED_QA_SCENARIO_KEYS
    if unknown:
        raise WorkerInfraError(
            f"Unsupported qa_scenario input fields: {sorted(unknown)}"
        )
    repo_url = _validate_github_repo_url(data.get("repo_url"))
    ref = _validate_git_ref(data.get("ref"))

    scenario_id = data.get("scenario_id")
    if not isinstance(scenario_id, str) or not SCENARIO_ID_RE.match(scenario_id):
        raise WorkerInfraError("Invalid scenario_id")

    scenario_name = data.get("scenario_name")
    if (
        not isinstance(scenario_name, str)
        or len(scenario_name.strip()) < 1
        or len(scenario_name) > 160
    ):
        raise WorkerInfraError("Invalid scenario_name")

    brief = data.get("brief")
    if not isinstance(brief, str) or len(brief.strip()) < 1 or len(brief) > 65536:
        raise WorkerInfraError("Invalid brief")

    task = data.get("task")
    if not isinstance(task, str) or len(task.strip()) < 1 or len(task) > 32768:
        raise WorkerInfraError("Invalid task")

    lessons = data.get("lessons", "")
    if lessons is None:
        lessons = ""
    if not isinstance(lessons, str) or len(lessons) > 65536:
        raise WorkerInfraError("Invalid lessons")

    model = data.get("model")
    if model is not None:
        if (
            not isinstance(model, str)
            or not QA_MODEL_RE.match(model)
            or PAID_MODEL_RE.search(model)
        ):
            raise WorkerInfraError("Invalid or disallowed paid model")

    phase1_sec = _validate_int_range(data.get("phase1_sec"), "phase1_sec", 3000, 30, 3600)
    wrap_sec = _validate_int_range(data.get("wrap_sec"), "wrap_sec", 600, 0, 900)

    raw_tools = data.get("tools", "read,bash,edit,write,grep,glob,todo")
    if raw_tools is None:
        raw_tools = "read,bash,edit,write,grep,glob,todo"
    if not isinstance(raw_tools, str):
        raise WorkerInfraError("tools must be a comma-separated string")
    tool_parts = [p.strip() for p in raw_tools.split(",")]
    if (
        len(tool_parts) < 1
        or len(tool_parts) > 7
        or any(not p or p not in ALLOWED_QA_TOOLS for p in tool_parts)
    ):
        raise WorkerInfraError("Unsupported tools list in qa_scenario")

    return {
        "repo_url": repo_url,
        "ref": ref,
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "brief": brief,
        "task": task,
        "lessons": lessons,
        "model": model,
        "phase1_sec": phase1_sec,
        "wrap_sec": wrap_sec,
        "tools": ",".join(tool_parts),
    }


def _http_request(
    url: str,
    token: str,
    method: str = "GET",
    json_body: Optional[dict[str, Any]] = None,
    extra_headers: Optional[dict[str, str]] = None,
    timeout: int = 15,
) -> tuple[int, dict[str, str], bytes]:
    headers: dict[str, str] = {"Authorization": f"Bearer {token}"}
    if extra_headers:
        headers.update(extra_headers)
    data: Optional[bytes] = None
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(json_body).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp_headers, resp.read()
    except urllib.error.HTTPError as err:
        err_headers = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
        body = err.read()
        msg = body.decode("utf-8", "replace")
        raise WorkerInfraError(
            f"HTTP {err.code} from {url}: {redact_worker_token(msg, token)[:300]}"
        ) from err
    except urllib.error.URLError as err:
        raise WorkerInfraError(f"Network error calling {url}: {err.reason}") from err


def _run_subprocess(
    cmd: list[str],
    *,
    cwd: Optional[str] = None,
    env: dict[str, str],
    timeout_sec: int,
    token: str,
    secrets: Optional[Iterable[str]] = None,
    command_label: Optional[str] = None,
) -> dict[str, Any]:
    started = time.monotonic()
    timed_out = False
    secret_list = list(secrets) if secrets is not None else [token]
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        exit_code = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = -1
        stdout = (
            exc.stdout.decode("utf-8", "replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        stderr = (
            exc.stderr.decode("utf-8", "replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or "")
        )
    except OSError as exc:
        raise WorkerInfraError(f"Failed to execute {cmd[0]}: {exc}") from exc

    duration_ms = int((time.monotonic() - started) * 1000)
    return {
        "command": command_label or redact_secrets(" ".join(cmd), secret_list),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": duration_ms,
        "stdout": tail_text(redact_secrets(stdout, secret_list)),
        "stderr": tail_text(redact_secrets(stderr, secret_list)),
    }


def process_probe(clean_env: dict[str, str], token: str) -> dict[str, Any]:
    uname = _run_subprocess(["uname", "-m"], env=clean_env, timeout_sec=10, token=token)
    nproc = _run_subprocess(["nproc"], env=clean_env, timeout_sec=10, token=token)
    free_res = _run_subprocess(["free", "-h"], env=clean_env, timeout_sec=10, token=token)
    return {
        "uname_m": uname["stdout"].strip(),
        "nproc": nproc["stdout"].strip(),
        "free_h": free_res["stdout"].rstrip("\n"),
    }


def _resolve_tool(name: str, env: dict[str, str]) -> Optional[str]:
    search_paths = [env.get("PATH", "")]
    home = env.get("HOME") or str(Path.home())
    extra_dirs = [
        str(Path(home) / ".bun" / "bin"),
        str(Path(home) / ".local" / "bin"),
        "/tmp/vmq-ft-venv/bin",
        str(Path(home) / "ft-venv" / "bin"),
        "/usr/local/bin",
        str(Path(home) / ".cargo" / "bin"),
        "/usr/local/go/bin",
    ]
    combined = os.pathsep.join([p for p in search_paths + extra_dirs if p])
    return shutil.which(name, path=combined)


def _detect_available_tools(clean_env: dict[str, str], token: str) -> set[str]:
    found: set[str] = set()
    for tool in ("bun", "npm", "go", "cargo", "freqtrade", "omp"):
        if _resolve_tool(tool, clean_env):
            found.add(tool)
    if _resolve_tool("pytest", clean_env):
        found.add("pytest")
    else:
        probe_py = _run_subprocess(
            [sys.executable, "-m", "pytest", "--version"],
            env=clean_env,
            timeout_sec=10,
            token=token,
        )
        if probe_py["exit_code"] == 0:
            found.add("pytest")
    return found


def detect_auto_preset(
    repo_dir: str,
    clean_env: dict[str, str],
    token: str,
    *,
    available_tools: Optional[set[str]] = None,
) -> tuple[str, Optional[str], list[str]]:
    tools = (
        set(available_tools)
        if available_tools is not None
        else _detect_available_tools(clean_env, token)
    )
    sorted_tools = sorted(tools)
    root = Path(repo_dir)

    pkg_path = root / "package.json"
    if pkg_path.is_file():
        desired: Optional[str] = None
        scripts: Any = None
        has_bun_lock = (root / "bun.lock").is_file() or (root / "bun.lockb").is_file()
        try:
            pkg_data = json.loads(pkg_path.read_text(encoding="utf-8"))
        except Exception:
            pkg_data = {}
        if isinstance(pkg_data, dict):
            scripts = pkg_data.get("scripts")
            if isinstance(scripts, dict):
                if isinstance(scripts.get("check"), str) and scripts["check"].strip():
                    desired = "bun_check"
                elif isinstance(scripts.get("test"), str) and scripts["test"].strip():
                    desired = "bun_test"
        if desired is None and has_bun_lock:
            desired = "bun_test"
        if desired is not None:
            if "bun" in tools:
                return desired, None, sorted_tools
            if (
                not has_bun_lock
                and isinstance(scripts, dict)
                and isinstance(scripts.get("test"), str)
                and scripts["test"].strip()
                and "npm" in tools
            ):
                return "npm_test", None, sorted_tools
            return "git_info", "toolchain_not_installed:bun", sorted_tools

    tests_dir = root / "tests"
    has_py_manifest = (
        (root / "pyproject.toml").is_file()
        or (root / "pytest.ini").is_file()
        or (root / "setup.cfg").is_file()
        or (tests_dir.is_dir() and any(tests_dir.glob("test_*.py")))
    )
    if has_py_manifest:
        if "pytest" in tools:
            return "pytest", None, sorted_tools
        return "git_info", "toolchain_not_installed:pytest", sorted_tools

    if (root / "go.mod").is_file():
        if "go" in tools:
            return "go_test", None, sorted_tools
        return "git_info", "toolchain_not_installed:go", sorted_tools

    if (root / "Cargo.toml").is_file():
        if "cargo" in tools:
            return "cargo_test", None, sorted_tools
        return "git_info", "toolchain_not_installed:cargo", sorted_tools

    return "git_info", "no_recognized_test_manifest", sorted_tools


def clone_github_repo(
    repo_url: str,
    dest_dir: str,
    ref: Optional[str],
    clean_env: dict[str, str],
    timeout_sec: int,
    token: str,
) -> None:
    git_bin = _resolve_tool("git", clean_env)
    if not git_bin:
        raise WorkerInfraError("Required tool not found: git")

    if ref is None:
        res = _run_subprocess(
            [
                git_bin,
                "-c",
                "core.hooksPath=/dev/null",
                "clone",
                "--depth",
                "1",
                repo_url,
                dest_dir,
            ],
            env=clean_env,
            timeout_sec=timeout_sec,
            token=token,
        )
        if res["exit_code"] != 0 or res["timed_out"]:
            raise WorkerInfraError(
                f"git clone failed (exit={res['exit_code']}): {res['stderr'] or res['stdout']}"
            )
        return

    branch_res = _run_subprocess(
        [
            git_bin,
            "-c",
            "core.hooksPath=/dev/null",
            "clone",
            "--depth",
            "1",
            "--branch",
            ref,
            repo_url,
            dest_dir,
        ],
        env=clean_env,
        timeout_sec=timeout_sec,
        token=token,
    )
    if branch_res["exit_code"] == 0 and not branch_res["timed_out"]:
        return

    shutil.rmtree(dest_dir, ignore_errors=True)
    os.makedirs(dest_dir, exist_ok=True)
    for cmd in (
        [git_bin, "-c", "core.hooksPath=/dev/null", "init"],
        [git_bin, "remote", "add", "origin", repo_url],
        [
            git_bin,
            "-c",
            "core.hooksPath=/dev/null",
            "fetch",
            "--depth",
            "1",
            "origin",
            ref,
        ],
        [git_bin, "-c", "core.hooksPath=/dev/null", "checkout", "--detach", "FETCH_HEAD"],
    ):
        step = _run_subprocess(
            cmd,
            cwd=dest_dir,
            env=clean_env,
            timeout_sec=timeout_sec,
            token=token,
        )
        if step["exit_code"] != 0 or step["timed_out"]:
            raise WorkerInfraError(
                f"git ref fetch failed for {ref}: {step['stderr'] or step['stdout']}"
            )


REPO_MARKER_FILES = (
    "README.md",
    "package.json",
    "bun.lock",
    "bun.lockb",
    "package-lock.json",
    "pyproject.toml",
    "requirements.txt",
    "go.mod",
    "Cargo.toml",
)


def _list_repo_markers(repo_dir: str) -> list[str]:
    root = Path(repo_dir)
    return [name for name in REPO_MARKER_FILES if (root / name).exists()]


def _collect_git_info(repo_dir: str, clean_env: dict[str, str], token: str) -> dict[str, Any]:
    git_bin = _resolve_tool("git", clean_env) or "git"
    ls_res = _run_subprocess(
        [git_bin, "ls-files"], cwd=repo_dir, env=clean_env, timeout_sec=30, token=token
    )
    files = [line for line in ls_res["stdout"].splitlines() if line.strip()]
    ext_counts: Counter[str] = Counter()
    for rel in files:
        suffix = Path(rel).suffix.lower() or "(no_ext)"
        ext_counts[suffix] += 1
    top_exts = [{"ext": k, "count": v} for k, v in ext_counts.most_common(8)]
    return {
        "file_count": len(files),
        "top_extensions": top_exts,
        "markers": _list_repo_markers(repo_dir),
    }


def _collect_repo_index(repo_dir: str, clean_env: dict[str, str], token: str) -> dict[str, Any]:
    git_bin = _resolve_tool("git", clean_env) or "git"
    ls_res = _run_subprocess(
        [git_bin, "ls-files"], cwd=repo_dir, env=clean_env, timeout_sec=60, token=token
    )
    files = [line for line in ls_res["stdout"].splitlines() if line.strip()]
    root = Path(repo_dir).resolve()
    ext_counts: Counter[str] = Counter()
    dir_counts: Counter[str] = Counter()
    file_stats: list[dict[str, Any]] = []
    total_lines = 0
    total_bytes = 0
    symbol_counts = {"functions": 0, "classes_types": 0, "files_scanned": 0}

    for rel in files:
        p = root / rel
        if p.is_symlink() or not p.is_file():
            continue
        try:
            resolved = p.resolve()
            resolved.relative_to(root)
        except Exception:
            continue

        suffix = p.suffix.lower() or "(no_ext)"
        ext_counts[suffix] += 1
        parent_parts = Path(rel).parts[:-1][:2]
        dir_key = "/".join(parent_parts) if parent_parts else "(root)"
        dir_counts[dir_key] += 1

        try:
            size_bytes = p.stat().st_size
        except OSError:
            continue
        total_bytes += size_bytes

        lines_cnt = 0
        if size_bytes <= 2 * 1024 * 1024:
            try:
                raw_bytes = p.read_bytes()
                if b"\x00" not in raw_bytes[:1024]:
                    text = raw_bytes.decode("utf-8", "ignore")
                    lines_cnt = len(text.splitlines())
                    total_lines += lines_cnt
                    if suffix in INDEX_SOURCE_EXTS and size_bytes <= 512 * 1024:
                        symbol_counts["files_scanned"] += 1
                        symbol_counts["functions"] += len(FUNC_SYM_RE.findall(text))
                        symbol_counts["classes_types"] += len(TYPE_SYM_RE.findall(text))
            except OSError:
                pass

        file_stats.append({"path": rel, "lines": lines_cnt, "bytes": size_bytes})

    return {
        "file_count": len(files),
        "total_bytes": total_bytes,
        "total_lines": total_lines,
        "top_extensions": [{"ext": k, "count": v} for k, v in ext_counts.most_common(10)],
        "top_directories": [{"dir": k, "files": v} for k, v in dir_counts.most_common(12)],
        "largest_files": sorted(
            file_stats, key=lambda x: (-x["lines"], -x["bytes"], x["path"])
        )[:15],
        "symbol_counts": symbol_counts,
        "markers": _list_repo_markers(repo_dir),
    }


def _shrink_output_to_fit(
    output: dict[str, Any], max_output_bytes: int
) -> dict[str, Any]:
    encoded = json.dumps(output).encode("utf-8")
    if len(encoded) <= max_output_bytes:
        return output
    # Progressively shrink step stdout/stderr tails to stay under server cap
    for limit in (4000, 1500, 500, 120):
        for step in output.get("steps", []):
            if isinstance(step, dict):
                if isinstance(step.get("stdout"), str):
                    step["stdout"] = tail_text(step["stdout"], limit)
                if isinstance(step.get("stderr"), str):
                    step["stderr"] = tail_text(step["stderr"], limit)
        if len(json.dumps(output).encode("utf-8")) <= max_output_bytes:
            return output
    if isinstance(output.get("report_md"), str):
        for r_limit in (32000, 16000, 8000, 2000):
            output["report_md"] = tail_text(output["report_md"], r_limit)
            if len(json.dumps(output).encode("utf-8")) <= max_output_bytes:
                return output
    return output


def _collect_head_meta(
    repo_dir: str, clean_env: dict[str, str], token: str
) -> tuple[str, str]:
    git_bin = _resolve_tool("git", clean_env) or "git"
    sha_res = _run_subprocess(
        [git_bin, "rev-parse", "HEAD"],
        cwd=repo_dir,
        env=clean_env,
        timeout_sec=15,
        token=token,
    )
    subj_res = _run_subprocess(
        [git_bin, "log", "-1", "--format=%s"],
        cwd=repo_dir,
        env=clean_env,
        timeout_sec=15,
        token=token,
    )
    return sha_res["stdout"].strip(), subj_res["stdout"].strip()


def _install_bun_deps(
    bun_bin: str,
    repo_dir: str,
    clean_env: dict[str, str],
    timeout_sec: int,
    token: str,
    steps: list[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    if not (Path(repo_dir) / "package.json").exists():
        return None
    install_cmd = [bun_bin, "install", "--ignore-scripts"]
    if (Path(repo_dir) / "bun.lock").exists() or (Path(repo_dir) / "bun.lockb").exists():
        install_cmd.append("--frozen-lockfile")
    install_step = _run_subprocess(
        install_cmd,
        cwd=repo_dir,
        env=clean_env,
        timeout_sec=timeout_sec,
        token=token,
    )
    steps.append(install_step)
    if install_step["exit_code"] != 0 or install_step["timed_out"]:
        return install_step
    return None


def _install_npm_deps(
    npm_bin: str,
    repo_dir: str,
    clean_env: dict[str, str],
    timeout_sec: int,
    token: str,
    steps: list[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    if not (Path(repo_dir) / "package.json").exists():
        return None
    subcmd = "ci" if (Path(repo_dir) / "package-lock.json").exists() else "install"
    install_step = _run_subprocess(
        [npm_bin, subcmd, "--ignore-scripts"],
        cwd=repo_dir,
        env=clean_env,
        timeout_sec=timeout_sec,
        token=token,
    )
    steps.append(install_step)
    if install_step["exit_code"] != 0 or install_step["timed_out"]:
        return install_step
    return None


def process_repo_check(
    raw_input: Any,
    *,
    token: str,
    clean_env: dict[str, str],
    max_output_bytes: int = 1024 * 1024,
    clone_fn: Optional[
        Callable[[str, str, Optional[str], dict[str, str], int, str], None]
    ] = None,
    available_tools_override: Optional[set[str]] = None,
) -> dict[str, Any]:
    spec = validate_repo_check_input(raw_input)
    repo_url: str = spec["repo_url"]
    requested_preset: str = spec["preset"]
    ref: Optional[str] = spec["ref"]
    timeout_sec: int = spec["timeout_sec"]

    started = time.monotonic()
    arch_res = _run_subprocess(["uname", "-m"], env=clean_env, timeout_sec=10, token=token)
    arch = arch_res["stdout"].strip() or "unknown"
    cpus = os.cpu_count() or 1

    tmpdir = tempfile.mkdtemp(prefix="vmq-repo-")
    repo_dir = os.path.join(tmpdir, "repo")
    os.makedirs(repo_dir, exist_ok=True)
    steps: list[dict[str, Any]] = []

    try:
        cloner = clone_fn or clone_github_repo
        cloner(repo_url, repo_dir, ref, clean_env, timeout_sec, token)
        head_sha, commit_subject = _collect_head_meta(repo_dir, clean_env, token)

        fallback_reason: Optional[str] = None
        available_tools: Optional[list[str]] = None
        if requested_preset == "auto":
            preset, fallback_reason, available_tools = detect_auto_preset(
                repo_dir,
                clean_env,
                token,
                available_tools=available_tools_override,
            )
        else:
            preset = requested_preset

        info_meta: Optional[dict[str, Any]] = None
        index_meta: Optional[dict[str, Any]] = None
        custom_summary: Optional[str] = None

        if preset == "git_info":
            info_meta = _collect_git_info(repo_dir, clean_env, token)
            passed = True
            timed_out = False
        elif preset == "repo_index":
            index_meta = _collect_repo_index(repo_dir, clean_env, token)
            passed = True
            timed_out = False
        elif preset in {"bun_test", "bun_check", "bun_build"}:
            bun_bin = _resolve_tool("bun", clean_env)
            if not bun_bin:
                raise WorkerInfraError("Required tool not found for preset: bun")
            failed_install = _install_bun_deps(
                bun_bin, repo_dir, clean_env, timeout_sec, token, steps
            )
            if failed_install is not None:
                passed = False
                timed_out = bool(failed_install["timed_out"])
                custom_summary = (
                    f"{preset}: dependency install failed (exit={failed_install['exit_code']})"
                )
            elif preset == "bun_build":
                pkg_path = Path(repo_dir) / "package.json"
                has_build = False
                if pkg_path.is_file():
                    try:
                        pkg_data = json.loads(pkg_path.read_text(encoding="utf-8"))
                        scripts = pkg_data.get("scripts") if isinstance(pkg_data, dict) else None
                        has_build = isinstance(scripts, dict) and isinstance(scripts.get("build"), str) and bool(scripts["build"].strip())
                    except Exception:
                        has_build = False
                if not has_build:
                    passed = False
                    timed_out = False
                    custom_summary = "bun_build: package.json has no scripts.build"
                else:
                    run_step = _run_subprocess(
                        [bun_bin, "run", "build"],
                        cwd=repo_dir,
                        env=clean_env,
                        timeout_sec=timeout_sec,
                        token=token,
                    )
                    steps.append(run_step)
                    passed = run_step["exit_code"] == 0 and not run_step["timed_out"]
                    timed_out = bool(run_step["timed_out"])
            else:
                run_cmd = (
                    [bun_bin, "test"]
                    if preset == "bun_test"
                    else [bun_bin, "run", "check"]
                )
                run_step = _run_subprocess(
                    run_cmd,
                    cwd=repo_dir,
                    env=clean_env,
                    timeout_sec=timeout_sec,
                    token=token,
                )
                steps.append(run_step)
                passed = run_step["exit_code"] == 0 and not run_step["timed_out"]
                timed_out = bool(run_step["timed_out"])
        elif preset == "npm_test":
            npm_bin = _resolve_tool("npm", clean_env)
            if not npm_bin:
                raise WorkerInfraError("Required tool not found for preset: npm")
            failed_install = _install_npm_deps(
                npm_bin, repo_dir, clean_env, timeout_sec, token, steps
            )
            if failed_install is not None:
                passed = False
                timed_out = bool(failed_install["timed_out"])
                custom_summary = (
                    f"npm_test: dependency install failed (exit={failed_install['exit_code']})"
                )
            else:
                run_step = _run_subprocess(
                    [npm_bin, "test"],
                    cwd=repo_dir,
                    env=clean_env,
                    timeout_sec=timeout_sec,
                    token=token,
                )
                steps.append(run_step)
                passed = run_step["exit_code"] == 0 and not run_step["timed_out"]
                timed_out = bool(run_step["timed_out"])
        elif preset == "playwright_test":
            has_bun_lock = (Path(repo_dir) / "bun.lock").exists() or (
                Path(repo_dir) / "bun.lockb"
            ).exists()
            bun_bin = _resolve_tool("bun", clean_env)
            npm_bin = _resolve_tool("npm", clean_env)
            workers_flag = f"--workers={min(cpus, 8)}"
            runner_cmd: list[str]
            failed_install: Optional[dict[str, Any]] = None

            if bun_bin and (has_bun_lock or not npm_bin):
                bunx_bin = _resolve_tool("bunx", clean_env)
                if not bunx_bin:
                    raise WorkerInfraError("Required tool not found for preset: bunx")
                failed_install = _install_bun_deps(
                    bun_bin, repo_dir, clean_env, timeout_sec, token, steps
                )
                runner_cmd = [bunx_bin, "playwright", "test", workers_flag]
            elif npm_bin:
                npx_bin = _resolve_tool("npx", clean_env)
                if not npx_bin:
                    raise WorkerInfraError("Required tool not found for preset: npx")
                failed_install = _install_npm_deps(
                    npm_bin, repo_dir, clean_env, timeout_sec, token, steps
                )
                runner_cmd = [npx_bin, "--no-install", "playwright", "test", workers_flag]
            else:
                raise WorkerInfraError("Required tool not found for preset: bun or npm")

            if failed_install is not None:
                passed = False
                timed_out = bool(failed_install["timed_out"])
                custom_summary = (
                    f"playwright_test: dependency install failed (exit={failed_install['exit_code']})"
                )
            else:
                local_pw = Path(repo_dir) / "node_modules" / ".bin" / "playwright"
                if not (local_pw.exists() or _resolve_tool("playwright", clean_env)):
                    raise WorkerInfraError(
                        "Playwright binary not found in repository dependencies or PATH"
                    )
                run_step = _run_subprocess(
                    runner_cmd,
                    cwd=repo_dir,
                    env=clean_env,
                    timeout_sec=timeout_sec,
                    token=token,
                )
                steps.append(run_step)
                passed = run_step["exit_code"] == 0 and not run_step["timed_out"]
                timed_out = bool(run_step["timed_out"])
        elif preset == "pytest":
            pytest_bin = _resolve_tool("pytest", clean_env)
            if pytest_bin:
                pytest_cmd = [pytest_bin, "-q"]
            else:
                probe_py = _run_subprocess(
                    [sys.executable, "-m", "pytest", "--version"],
                    cwd=repo_dir,
                    env=clean_env,
                    timeout_sec=10,
                    token=token,
                )
                if probe_py["exit_code"] != 0:
                    raise WorkerInfraError("Required tool not found for preset: pytest")
                pytest_cmd = [sys.executable, "-m", "pytest", "-q"]
            run_step = _run_subprocess(
                pytest_cmd,
                cwd=repo_dir,
                env=clean_env,
                timeout_sec=timeout_sec,
                token=token,
            )
            steps.append(run_step)
            passed = run_step["exit_code"] == 0 and not run_step["timed_out"]
            timed_out = bool(run_step["timed_out"])
        elif preset == "go_test":
            go_bin = _resolve_tool("go", clean_env)
            if not go_bin:
                raise WorkerInfraError("Required tool not found for preset: go")
            run_step = _run_subprocess(
                [go_bin, "test", "./..."],
                cwd=repo_dir,
                env=clean_env,
                timeout_sec=timeout_sec,
                token=token,
            )
            steps.append(run_step)
            passed = run_step["exit_code"] == 0 and not run_step["timed_out"]
            timed_out = bool(run_step["timed_out"])
        elif preset == "cargo_test":
            cargo_bin = _resolve_tool("cargo", clean_env)
            if not cargo_bin:
                raise WorkerInfraError("Required tool not found for preset: cargo")
            run_step = _run_subprocess(
                [cargo_bin, "test"],
                cwd=repo_dir,
                env=clean_env,
                timeout_sec=timeout_sec,
                token=token,
            )
            steps.append(run_step)
            passed = run_step["exit_code"] == 0 and not run_step["timed_out"]
            timed_out = bool(run_step["timed_out"])
        else:
            raise WorkerInfraError(f"Unsupported preset: {preset}")

        duration_ms = int((time.monotonic() - started) * 1000)
        if custom_summary is not None:
            summary = custom_summary
        elif preset == "git_info" and info_meta is not None:
            summary = f"git_info: {info_meta['file_count']} tracked files at {head_sha[:12]}"
        elif preset == "repo_index" and index_meta is not None:
            summary = (
                f"repo_index: {index_meta['file_count']} files, "
                f"{index_meta['total_lines']} lines at {head_sha[:12]}"
            )
        elif timed_out:
            summary = f"{preset}: timed out after {timeout_sec}s"
        elif passed:
            summary = f"{preset}: passed in {duration_ms}ms ({arch}, {cpus} CPUs)"
        else:
            last_code = steps[-1]["exit_code"] if steps else -1
            summary = f"{preset}: failed (exit={last_code}) in {duration_ms}ms"

        output: dict[str, Any] = {
            "arch": arch,
            "cpus": cpus,
            "repo_url": repo_url,
            "preset": preset,
            "requested_preset": requested_preset,
            "resolved_preset": preset,
            "ref": ref,
            "head_sha": head_sha,
            "commit_subject": commit_subject,
            "passed": passed,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
            "steps": steps,
            "summary": summary,
        }
        if requested_preset == "auto":
            output["fallback_reason"] = fallback_reason
            output["available_tools"] = available_tools
        if info_meta is not None:
            output["file_count"] = info_meta["file_count"]
            output["top_extensions"] = info_meta["top_extensions"]
            output["markers"] = info_meta["markers"]
        if index_meta is not None:
            output["index"] = index_meta

        return _shrink_output_to_fit(output, max_output_bytes)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def process_freqtrade_backtest(
    raw_input: Any,
    *,
    token: str,
    clean_env: dict[str, str],
    max_output_bytes: int = 1024 * 1024,
    clone_fn: Optional[
        Callable[[str, str, Optional[str], dict[str, str], int, str], None]
    ] = None,
    freqtrade_bin_override: Optional[str] = None,
) -> dict[str, Any]:
    spec = validate_freqtrade_backtest_input(raw_input)
    freqtrade_bin = freqtrade_bin_override or _resolve_tool("freqtrade", clean_env)
    if not freqtrade_bin:
        raise WorkerInfraError("Required tool not found: freqtrade")

    started = time.monotonic()
    arch_res = _run_subprocess(["uname", "-m"], env=clean_env, timeout_sec=10, token=token)
    arch = arch_res["stdout"].strip() or "unknown"
    cpus = os.cpu_count() or 1

    tmpdir = tempfile.mkdtemp(prefix="vmq-ft-")
    repo_dir = os.path.join(tmpdir, "repo")
    datadir = os.path.join(tmpdir, "data")
    cfg_path = os.path.join(tmpdir, "config.json")
    os.makedirs(repo_dir, exist_ok=True)
    os.makedirs(datadir, exist_ok=True)
    steps: list[dict[str, Any]] = []

    try:
        cloner = clone_fn or clone_github_repo
        cloner(
            spec["repo_url"],
            repo_dir,
            spec["ref"],
            clean_env,
            spec["timeout_sec"],
            token,
        )
        head_sha, commit_subject = _collect_head_meta(repo_dir, clean_env, token)

        pairs: list[str] = spec["pairs"]
        stake_currency = pairs[0].split("/")[1].split(":")[0]
        ft_config = {
            "dry_run": True,
            "dry_run_wallet": max(1000, int(spec["stake_amount"] * spec["max_open_trades"] * 2)),
            "stake_currency": stake_currency,
            "stake_amount": spec["stake_amount"],
            "max_open_trades": spec["max_open_trades"],
            "timeframe": spec["timeframe"],
            "exchange": {
                "name": spec["exchange"],
                "key": "",
                "secret": "",
                "pair_whitelist": pairs,
                "pair_blacklist": [],
            },
            "pairlists": [{"method": "StaticPairList"}],
        }
        Path(cfg_path).write_text(json.dumps(ft_config, indent=2), encoding="utf-8")

        dl_cmd = [
            freqtrade_bin,
            "download-data",
            "--config",
            cfg_path,
            "--datadir",
            datadir,
            "--exchange",
            spec["exchange"],
            "--timeframes",
            spec["timeframe"],
            "--timerange",
            spec["timerange"],
            "--pairs",
            *pairs,
        ]
        dl_step = _run_subprocess(
            dl_cmd,
            cwd=tmpdir,
            env=clean_env,
            timeout_sec=spec["timeout_sec"],
            token=token,
        )
        steps.append(dl_step)

        if dl_step["exit_code"] != 0 or dl_step["timed_out"]:
            passed = False
            timed_out = bool(dl_step["timed_out"])
            summary = f"freqtrade download-data failed (exit={dl_step['exit_code']})"
        else:
            if spec["mode"] == "hyperopt":
                run_cmd = [
                    freqtrade_bin,
                    "hyperopt",
                    "--config",
                    cfg_path,
                    "--datadir",
                    datadir,
                    "--strategy-path",
                    repo_dir,
                    "--strategy",
                    spec["strategy"],
                    "--timeframe",
                    spec["timeframe"],
                    "--timerange",
                    spec["timerange"],
                    "--epochs",
                    str(spec["epochs"]),
                    "--spaces",
                    *spec["spaces"],
                    "--hyperopt-loss",
                    spec["hyperopt_loss"],
                    "-j",
                    str(min(cpus, 8)),
                ]
            else:
                run_cmd = [
                    freqtrade_bin,
                    "backtesting",
                    "--config",
                    cfg_path,
                    "--datadir",
                    datadir,
                    "--strategy-path",
                    repo_dir,
                    "--strategy",
                    spec["strategy"],
                    "--timeframe",
                    spec["timeframe"],
                    "--timerange",
                    spec["timerange"],
                    "--export",
                    "none",
                ]
            run_step = _run_subprocess(
                run_cmd,
                cwd=tmpdir,
                env=clean_env,
                timeout_sec=spec["timeout_sec"],
                token=token,
            )
            steps.append(run_step)
            passed = run_step["exit_code"] == 0 and not run_step["timed_out"]
            timed_out = bool(run_step["timed_out"])
            duration_ms = int((time.monotonic() - started) * 1000)
            if timed_out:
                summary = f"freqtrade {spec['mode']} timed out after {spec['timeout_sec']}s"
            elif passed:
                summary = (
                    f"freqtrade {spec['mode']} ({spec['strategy']}) passed in "
                    f"{duration_ms}ms ({arch}, {cpus} CPUs)"
                )
            else:
                summary = (
                    f"freqtrade {spec['mode']} ({spec['strategy']}) failed "
                    f"(exit={run_step['exit_code']})"
                )

        duration_ms = int((time.monotonic() - started) * 1000)
        output: dict[str, Any] = {
            "arch": arch,
            "cpus": cpus,
            "repo_url": spec["repo_url"],
            "ref": spec["ref"],
            "head_sha": head_sha,
            "commit_subject": commit_subject,
            "strategy": spec["strategy"],
            "mode": spec["mode"],
            "exchange": spec["exchange"],
            "timeframe": spec["timeframe"],
            "timerange": spec["timerange"],
            "pairs": pairs,
            "passed": passed,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
            "steps": steps,
            "summary": summary,
        }
        return _shrink_output_to_fit(output, max_output_bytes)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _resolve_llm_env(llm_env: Optional[dict[str, str]] = None) -> tuple[str, str, str]:
    src = os.environ if llm_env is None else llm_env
    api_key = (src.get("VM_QUEUE_LLM_API_KEY") or "").strip()
    base_url = (src.get("VM_QUEUE_LLM_BASE_URL") or "").strip()
    provider = (src.get("VM_QUEUE_LLM_PROVIDER") or "custom").strip()
    if not api_key:
        raise WorkerInfraError("VM_QUEUE_LLM_API_KEY is required for qa_scenario")
    if not base_url.startswith("https://"):
        raise WorkerInfraError("VM_QUEUE_LLM_BASE_URL must start with https://")
    if not LLM_PROVIDER_RE.match(provider):
        raise WorkerInfraError("Invalid VM_QUEUE_LLM_PROVIDER name")
    return api_key, base_url, provider


def process_qa_scenario(
    raw_input: Any,
    *,
    token: str,
    clean_env: dict[str, str],
    max_output_bytes: int = 1024 * 1024,
    clone_fn: Optional[
        Callable[[str, str, Optional[str], dict[str, str], int, str], None]
    ] = None,
    omp_bin_override: Optional[str] = None,
    llm_env: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    spec = validate_qa_scenario_input(raw_input)
    llm_api_key, llm_base_url, llm_provider = _resolve_llm_env(llm_env)
    omp_bin = omp_bin_override or _resolve_tool("omp", clean_env)
    if not omp_bin:
        raise WorkerInfraError("Required tool not found: omp")

    requested_model: Optional[str] = spec["model"]
    if requested_model is None:
        provider_name = llm_provider
        full_model = f"{provider_name}/deepseek-v4.1-flash:max"
    elif "/" in requested_model:
        candidate_provider, rest_model = requested_model.split("/", 1)
        provider_name = (
            candidate_provider
            if re.match(r"^[a-zA-Z0-9_-]{1,32}$", candidate_provider)
            else llm_provider
        )
        full_model = f"{provider_name}/{rest_model}"
    else:
        provider_name = llm_provider
        full_model = f"{provider_name}/{requested_model}"

    secrets = [s for s in (token, llm_api_key) if s]
    started = time.monotonic()
    arch_res = _run_subprocess(["uname", "-m"], env=clean_env, timeout_sec=10, token=token)
    arch = arch_res["stdout"].strip() or "unknown"
    cpus = os.cpu_count() or 1

    tmpdir = tempfile.mkdtemp(prefix="vmq-qa-")
    run_dir = os.path.join(tmpdir, "run")
    repo_dir = os.path.join(run_dir, "repo")
    qhome_dir = os.path.join(run_dir, "home")
    scratch_dir = os.path.join(run_dir, "scratch")
    agent_dir = os.path.join(tmpdir, "omp-agent")
    sessions_dir = os.path.join(tmpdir, "sessions")
    for d in (repo_dir, qhome_dir, scratch_dir, agent_dir, sessions_dir):
        os.makedirs(d, exist_ok=True)
    steps: list[dict[str, Any]] = []

    try:
        models_path = Path(agent_dir) / "models.yml"
        models_yaml = (
            "providers:\n"
            f"  {provider_name}:\n"
            f"    baseUrl: {json.dumps(llm_base_url)}\n"
            "    api: openai-completions\n"
            "    auth: apiKey\n"
            f"    apiKey: {json.dumps(llm_api_key)}\n"
            "    discovery:\n"
            "      type: openai-models-list\n"
        )
        models_path.write_text(models_yaml, encoding="utf-8")
        os.chmod(models_path, 0o600)

        overlay_path = Path(tmpdir) / "qa-omp-overlay.yml"
        overlay_path.write_text(
            "retry:\n"
            "  modelFallback: false\n"
            "memory:\n"
            '  backend: "off"\n'
            "prewalk:\n"
            '  auto: "off"\n'
            "advisor:\n"
            "  enabled: false\n",
            encoding="utf-8",
        )

        cloner = clone_fn or clone_github_repo
        cloner(
            spec["repo_url"],
            repo_dir,
            spec["ref"],
            clean_env,
            min(300, spec["phase1_sec"]),
            token,
        )
        head_sha, commit_subject = _collect_head_meta(repo_dir, clean_env, token)

        bun_bin = _resolve_tool("bun", clean_env)
        if bun_bin and (Path(repo_dir) / "package.json").exists():
            failed_install = _install_bun_deps(
                bun_bin, repo_dir, clean_env, 300, token, steps
            )
            if failed_install is not None:
                duration_ms = int((time.monotonic() - started) * 1000)
                return _shrink_output_to_fit(
                    {
                        "arch": arch,
                        "cpus": cpus,
                        "repo_url": spec["repo_url"],
                        "ref": spec["ref"],
                        "head_sha": head_sha,
                        "commit_subject": commit_subject,
                        "scenario_id": spec["scenario_id"],
                        "scenario_name": spec["scenario_name"],
                        "model": full_model,
                        "verdict": "미완료",
                        "findings_count": 0,
                        "report_md": "",
                        "passed": False,
                        "timed_out": bool(failed_install["timed_out"]),
                        "duration_ms": duration_ms,
                        "steps": steps,
                        "summary": f"qa_scenario {spec['scenario_id']}: dependency install failed",
                    },
                    max_output_bytes,
                )

        qa_env = dict(clean_env)
        qa_env["PI_CODING_AGENT_DIR"] = agent_dir
        report_path = os.path.join(run_dir, "report.md")
        lessons_part = f"\n\n{spec['lessons'].strip()}" if spec["lessons"].strip() else ""
        prompt = (
            f"{spec['brief'].strip()}{lessons_part}\n\n"
            f"# Your task: QA {spec['scenario_id']} — {spec['scenario_name']}\n"
            f"REPO={repo_dir}\n"
            f"QHOME={qhome_dir}\n"
            f"SCRATCH={scratch_dir}\n"
            f"REPORT={report_path}\n"
            "PORT=18741\n\n"
            f"{spec['task'].strip()}"
        )

        phase1_cmd = [
            omp_bin,
            "-p",
            "--config",
            str(overlay_path),
            "--model",
            full_model,
            "--tools",
            spec["tools"],
            "--no-tools",
            "--session-dir",
            sessions_dir,
            "--cwd",
            run_dir,
            "--no-title",
            prompt,
        ]
        phase1_step = _run_subprocess(
            phase1_cmd,
            cwd=run_dir,
            env=qa_env,
            timeout_sec=spec["phase1_sec"],
            token=token,
            secrets=secrets,
            command_label=f"{omp_bin} -p --model {full_model} --tools {spec['tools']} <prompt>",
        )
        steps.append(phase1_step)

        report_file = Path(report_path)
        report_text = (
            report_file.read_text(encoding="utf-8", errors="replace")
            if report_file.is_file()
            else ""
        )
        verdict_re = re.compile(r"^## 판정:\s*(통과|지적 있음)", re.MULTILINE)
        timed_out = bool(phase1_step["timed_out"])

        if not verdict_re.search(report_text) and spec["wrap_sec"] > 0:
            session_files = sorted(
                Path(sessions_dir).rglob("*.jsonl"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if session_files:
                wrap_prompt = (
                    "Time is up. Stop testing and run no commands except writing the file. "
                    f"Rewrite REPORT ({report_path}) in the required format from everything you "
                    "already ran and saw in this session, keeping every finding already in it. "
                    "Mark parts you did not reach as 미완료 and set the 판정 line."
                )
                wrap_cmd = [
                    omp_bin,
                    "-p",
                    "--config",
                    str(overlay_path),
                    "--model",
                    full_model,
                    "--tools",
                    spec["tools"],
                    "--no-tools",
                    "--session-dir",
                    sessions_dir,
                    "--cwd",
                    run_dir,
                    "--no-title",
                    "--resume",
                    str(session_files[0]),
                    wrap_prompt,
                ]
                wrap_step = _run_subprocess(
                    wrap_cmd,
                    cwd=run_dir,
                    env=qa_env,
                    timeout_sec=spec["wrap_sec"],
                    token=token,
                    secrets=secrets,
                    command_label=f"{omp_bin} -p --model {full_model} --resume <session>",
                )
                steps.append(wrap_step)
                if wrap_step["timed_out"]:
                    timed_out = True
                if report_file.is_file():
                    report_text = report_file.read_text(encoding="utf-8", errors="replace")

        report_md = redact_secrets(report_text, secrets)
        verdict_match = verdict_re.search(report_md)
        verdict = verdict_match.group(1) if verdict_match else "미완료"
        findings_count = len(re.findall(r"^### \[", report_md, re.MULTILINE))
        passed = verdict in {"통과", "지적 있음"}
        duration_ms = int((time.monotonic() - started) * 1000)
        summary = (
            f"qa_scenario {spec['scenario_id']}: {verdict} "
            f"(findings={findings_count}) in {duration_ms}ms"
        )

        output: dict[str, Any] = {
            "arch": arch,
            "cpus": cpus,
            "repo_url": spec["repo_url"],
            "ref": spec["ref"],
            "head_sha": head_sha,
            "commit_subject": commit_subject,
            "scenario_id": spec["scenario_id"],
            "scenario_name": spec["scenario_name"],
            "model": full_model,
            "verdict": verdict,
            "findings_count": findings_count,
            "report_md": report_md,
            "passed": passed,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
            "steps": steps,
            "summary": redact_secrets(summary, secrets),
        }
        return _shrink_output_to_fit(output, max_output_bytes)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def resolve_worker_kinds(
    raw_kinds: str,
    clean_env: dict[str, str],
    llm_env: Optional[dict[str, str]] = None,
) -> list[str]:
    if raw_kinds.strip() == "auto":
        kinds = ["probe", "repo_check"]
        if _resolve_tool("freqtrade", clean_env):
            kinds.append("freqtrade_backtest")
        src = os.environ if llm_env is None else llm_env
        if (
            _resolve_tool("omp", clean_env)
            and (src.get("VM_QUEUE_LLM_API_KEY") or "").strip()
            and (src.get("VM_QUEUE_LLM_BASE_URL") or "").strip().startswith("https://")
        ):
            kinds.append("qa_scenario")
        return kinds

    parts = [p.strip() for p in raw_kinds.split(",") if p.strip()]
    if not parts:
        raise ValueError("--kinds cannot be empty")
    unique: list[str] = []
    for part in parts:
        if part not in ALLOWED_KINDS:
            raise ValueError(f"Unsupported kind in --kinds: {part}")
        if part not in unique:
            unique.append(part)
    return unique


def claim_and_process_one(
    base_url: str,
    token: str,
    worker_id: str,
    lease_sec: int,
    *,
    kinds: Optional[list[str]] = None,
    clone_fn: Optional[
        Callable[[str, str, Optional[str], dict[str, str], int, str], None]
    ] = None,
    freqtrade_bin_override: Optional[str] = None,
    omp_bin_override: Optional[str] = None,
    llm_env: Optional[dict[str, str]] = None,
) -> Optional[dict[str, Any]]:
    base_url = base_url.rstrip("/")
    worker_meta = {
        "arch": platform.machine() or "unknown",
        "cpus": os.cpu_count() or 1,
    }
    claim_body: dict[str, Any] = {
        "worker_id": worker_id,
        "lease_sec": lease_sec,
        "meta": worker_meta,
    }
    if kinds is not None:
        claim_body["kinds"] = kinds

    _, _, claim_raw = _http_request(
        f"{base_url}/jobs/claim",
        token,
        method="POST",
        json_body=claim_body,
    )
    claim_payload = json.loads(claim_raw.decode("utf-8"))
    job = claim_payload.get("job")
    if job is None:
        return None

    job_id = str(job["job_id"])
    kind = str(job["kind"])
    lease_token = str(job["lease_token"])
    max_output_bytes = int(job.get("max_output_bytes", 1024 * 1024))

    stop_event = threading.Event()
    hb_thread: Optional[threading.Thread] = None

    def send_heartbeat() -> None:
        _http_request(
            f"{base_url}/jobs/{job_id}/heartbeat",
            token,
            method="POST",
            json_body={
                "worker_id": worker_id,
                "lease_token": lease_token,
                "lease_sec": lease_sec,
            },
        )

    def heartbeat_loop() -> None:
        interval = max(5, lease_sec // 2)
        while not stop_event.wait(interval):
            try:
                send_heartbeat()
            except Exception:
                # Best effort renewal; complete/fail handles expired leases
                break

    try:
        _, input_headers, input_raw = _http_request(
            f"{base_url}/jobs/{job_id}/input",
            token,
            method="GET",
            extra_headers={
                "X-Worker-Id": worker_id,
                "X-Lease-Token": lease_token,
            },
        )
        header_kind = input_headers.get("x-job-kind")
        if header_kind is not None and header_kind != kind:
            raise WorkerInfraError(
                f"Job kind mismatch: claim={kind}, header={header_kind}"
            )
        input_data = json.loads(input_raw.decode("utf-8"))

        send_heartbeat()
        hb_thread = threading.Thread(target=heartbeat_loop, daemon=True)
        hb_thread.start()

        clean_env = build_clean_env()
        if kind == "probe":
            output = process_probe(clean_env, token)
        elif kind == "repo_check":
            output = process_repo_check(
                input_data,
                token=token,
                clean_env=clean_env,
                max_output_bytes=max_output_bytes,
                clone_fn=clone_fn,
            )
        elif kind == "freqtrade_backtest":
            output = process_freqtrade_backtest(
                input_data,
                token=token,
                clean_env=clean_env,
                max_output_bytes=max_output_bytes,
                clone_fn=clone_fn,
                freqtrade_bin_override=freqtrade_bin_override,
            )
        elif kind == "qa_scenario":
            output = process_qa_scenario(
                input_data,
                token=token,
                clean_env=clean_env,
                max_output_bytes=max_output_bytes,
                clone_fn=clone_fn,
                omp_bin_override=omp_bin_override,
                llm_env=llm_env,
            )
        else:
            raise WorkerInfraError(f"Unsupported job kind for worker: {kind}")

        stop_event.set()
        if hb_thread is not None:
            hb_thread.join(timeout=2.0)

        _, _, complete_raw = _http_request(
            f"{base_url}/jobs/{job_id}/complete",
            token,
            method="POST",
            json_body={
                "worker_id": worker_id,
                "lease_token": lease_token,
                "output": output,
            },
            timeout=30,
        )
        complete_data = json.loads(complete_raw.decode("utf-8"))
        return {
            "job_id": job_id,
            "kind": kind,
            "status": complete_data.get("status", "completed"),
            "output": output,
        }
    except Exception as exc:
        stop_event.set()
        if hb_thread is not None:
            hb_thread.join(timeout=2.0)
        llm_key = ((os.environ if llm_env is None else llm_env).get("VM_QUEUE_LLM_API_KEY") or "").strip()
        err_msg = redact_secrets(str(exc), [token, llm_key]) or type(exc).__name__
        err_msg = err_msg[:2000]
        try:
            _http_request(
                f"{base_url}/jobs/{job_id}/fail",
                token,
                method="POST",
                json_body={
                    "worker_id": worker_id,
                    "lease_token": lease_token,
                    "error": err_msg,
                },
            )
        except Exception:
            pass
        return {
            "job_id": job_id,
            "kind": kind,
            "status": "failed",
            "error": err_msg,
        }


def _run_single_slot(
    *,
    base_url: str,
    token: str,
    worker_id: str,
    lease_sec: int,
    mode: str,
    poll_sec: int,
    max_idle_sec: int,
    kinds: Optional[list[str]],
    clone_fn: Optional[
        Callable[[str, str, Optional[str], dict[str, str], int, str], None]
    ],
    freqtrade_bin_override: Optional[str],
    omp_bin_override: Optional[str],
    llm_env: Optional[dict[str, str]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    if mode == "once":
        res = claim_and_process_one(
            base_url,
            token,
            worker_id,
            lease_sec,
            kinds=kinds,
            clone_fn=clone_fn,
            freqtrade_bin_override=freqtrade_bin_override,
            omp_bin_override=omp_bin_override,
            llm_env=llm_env,
        )
        if res is not None:
            results.append(res)
        return results

    if mode == "drain":
        while True:
            res = claim_and_process_one(
                base_url,
                token,
                worker_id,
                lease_sec,
                kinds=kinds,
                clone_fn=clone_fn,
                freqtrade_bin_override=freqtrade_bin_override,
                omp_bin_override=omp_bin_override,
                llm_env=llm_env,
            )
            if res is None:
                break
            results.append(res)
        return results

    if mode == "poll":
        last_work_at = time.monotonic()
        while True:
            res = claim_and_process_one(
                base_url,
                token,
                worker_id,
                lease_sec,
                kinds=kinds,
                clone_fn=clone_fn,
                freqtrade_bin_override=freqtrade_bin_override,
                omp_bin_override=omp_bin_override,
                llm_env=llm_env,
            )
            if res is not None:
                results.append(res)
                last_work_at = time.monotonic()
                continue
            if time.monotonic() - last_work_at >= max_idle_sec:
                break
            time.sleep(poll_sec)
        return results

    raise ValueError(f"Unsupported mode: {mode}")


def run_worker(
    *,
    base_url: str,
    token: str,
    worker_id: str,
    lease_sec: int,
    mode: str,
    poll_sec: int,
    max_idle_sec: int,
    kinds: Optional[list[str]] = None,
    concurrency: int = 1,
    clone_fn: Optional[
        Callable[[str, str, Optional[str], dict[str, str], int, str], None]
    ] = None,
    freqtrade_bin_override: Optional[str] = None,
    omp_bin_override: Optional[str] = None,
    llm_env: Optional[dict[str, str]] = None,
) -> list[dict[str, Any]]:
    if concurrency < 1 or concurrency > 16:
        raise ValueError("concurrency must be between 1 and 16")
    if concurrency == 1:
        return _run_single_slot(
            base_url=base_url,
            token=token,
            worker_id=worker_id,
            lease_sec=lease_sec,
            mode=mode,
            poll_sec=poll_sec,
            max_idle_sec=max_idle_sec,
            kinds=kinds,
            clone_fn=clone_fn,
            freqtrade_bin_override=freqtrade_bin_override,
            omp_bin_override=omp_bin_override,
            llm_env=llm_env,
        )

    all_results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [
            pool.submit(
                _run_single_slot,
                base_url=base_url,
                token=token,
                worker_id=sanitize_worker_id(f"{worker_id}-s{slot}"),
                lease_sec=lease_sec,
                mode=mode,
                poll_sec=poll_sec,
                max_idle_sec=max_idle_sec,
                kinds=kinds,
                clone_fn=clone_fn,
                freqtrade_bin_override=freqtrade_bin_override,
                omp_bin_override=omp_bin_override,
                llm_env=llm_env,
            )
            for slot in range(1, concurrency + 1)
        ]
        for fut in futures:
            all_results.extend(fut.result())
    return all_results


def _load_token(token_file: Optional[str]) -> str:
    if token_file:
        raw = Path(token_file).read_text(encoding="utf-8")
    else:
        raw = os.environ.get("VM_QUEUE_WORKER_TOKEN", "")
    return validate_worker_token(raw)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Standalone worker for vm-queue (probe, repo_check, freqtrade_backtest, qa_scenario)"
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("VM_QUEUE_URL", "").strip(),
        help="vm-queue server base URL (or VM_QUEUE_URL)",
    )
    parser.add_argument(
        "--worker-id",
        default=default_worker_id(),
        help="Worker ID sent to vm-queue",
    )
    parser.add_argument(
        "--lease-sec",
        type=int,
        default=60,
        help="Lease duration in seconds (1..600)",
    )
    parser.add_argument(
        "--mode",
        choices=("drain", "once", "poll"),
        default="drain",
        help="Execution mode (default: drain)",
    )
    parser.add_argument(
        "--poll-sec",
        type=int,
        default=5,
        help="Polling interval in seconds for --mode poll",
    )
    parser.add_argument(
        "--max-idle-sec",
        type=int,
        default=60,
        help="Idle timeout in seconds for --mode poll (1..3600)",
    )
    parser.add_argument(
        "--kinds",
        default="auto",
        help="Comma-separated job kinds to claim or 'auto' (default: auto)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Concurrent worker slots (1..16, default: 1)",
    )
    parser.add_argument(
        "--token-file",
        default=None,
        help="Optional file containing only the worker token (default: VM_QUEUE_WORKER_TOKEN env)",
    )
    args = parser.parse_args(argv)

    if not args.url:
        print("Error: --url or VM_QUEUE_URL is required", file=sys.stderr)
        return 2
    if args.lease_sec < 1 or args.lease_sec > 600:
        print("Error: --lease-sec must be between 1 and 600", file=sys.stderr)
        return 2
    if args.max_idle_sec < 1 or args.max_idle_sec > 3600:
        print(
            "Error: --max-idle-sec must be between 1 and 3600 (finite session polling only; 24/7 keepalive is disallowed)",
            file=sys.stderr,
        )
        return 2
    if args.concurrency < 1 or args.concurrency > 16:
        print("Error: --concurrency must be between 1 and 16", file=sys.stderr)
        return 2

    clean_env = build_clean_env()
    try:
        kinds = resolve_worker_kinds(args.kinds, clean_env)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    worker_id = sanitize_worker_id(args.worker_id)
    try:
        token = _load_token(args.token_file)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    llm_key = (os.environ.get("VM_QUEUE_LLM_API_KEY") or "").strip()
    try:
        results = run_worker(
            base_url=args.url,
            token=token,
            worker_id=worker_id,
            lease_sec=args.lease_sec,
            mode=args.mode,
            poll_sec=max(1, args.poll_sec),
            max_idle_sec=max(1, args.max_idle_sec),
            kinds=kinds,
            concurrency=args.concurrency,
        )
    except Exception as exc:
        print(
            f"Worker error: {redact_secrets(str(exc), [token, llm_key])}",
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            {
                "worker_id": worker_id,
                "mode": args.mode,
                "kinds": kinds,
                "concurrency": args.concurrency,
                "processed": len(results),
                "results": results,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
