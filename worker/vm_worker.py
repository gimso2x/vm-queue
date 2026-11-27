#!/usr/bin/env python3
"""Standalone, zero-dependency Python 3 worker for vm-queue."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
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
from typing import Any, Callable, Optional

WORKER_ID_RE = re.compile(r"^[a-zA-Z0-9._:-]{1,64}$")
GITHUB_PUBLIC_REPO_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$"
)
GIT_REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,128}$")
ALLOWED_REPO_CHECK_KEYS = frozenset({"repo_url", "preset", "ref", "timeout_sec"})
ALLOWED_REPO_CHECK_PRESETS = frozenset(
    {"git_info", "bun_test", "bun_check", "pytest", "go_test", "cargo_test"}
)
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


def redact_worker_token(text: str, token: str) -> str:
    if not text or not token:
        return text
    return text.replace(token, "[REDACTED]")


def tail_text(text: str, max_chars: int = 12000) -> str:
    if len(text) <= max_chars:
        return text
    prefix = "...(truncated)\n"
    keep = max(0, max_chars - len(prefix))
    return prefix + text[-keep:]


def validate_repo_check_input(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise WorkerInfraError("repo_check input must be a JSON object")
    unknown = set(data.keys()) - ALLOWED_REPO_CHECK_KEYS
    if unknown:
        raise WorkerInfraError(
            f"Unsupported repo_check input fields: {sorted(unknown)}"
        )
    repo_url = data.get("repo_url")
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

    preset = data.get("preset")
    if not isinstance(preset, str) or preset not in ALLOWED_REPO_CHECK_PRESETS:
        raise WorkerInfraError(f"Unsupported repo_check preset: {preset!r}")

    ref = data.get("ref")
    if ref is not None:
        if (
            not isinstance(ref, str)
            or not GIT_REF_RE.match(ref)
            or ref.startswith("-")
            or ref.startswith("/")
            or ref.endswith("/")
            or ".." in ref
            or "//" in ref
        ):
            raise WorkerInfraError("Invalid git ref in repo_check input")

    timeout_sec = data.get("timeout_sec", 180)
    if (
        isinstance(timeout_sec, bool)
        or not isinstance(timeout_sec, int)
        or timeout_sec < 10
        or timeout_sec > 600
    ):
        raise WorkerInfraError("timeout_sec must be an integer between 10 and 600")

    return {
        "repo_url": repo_url,
        "preset": preset,
        "ref": ref,
        "timeout_sec": timeout_sec,
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
) -> dict[str, Any]:
    started = time.monotonic()
    timed_out = False
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
        "command": " ".join(cmd),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": duration_ms,
        "stdout": tail_text(redact_worker_token(stdout, token)),
        "stderr": tail_text(redact_worker_token(stderr, token)),
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
        "/usr/local/bin",
        str(Path(home) / ".cargo" / "bin"),
        "/usr/local/go/bin",
    ]
    combined = os.pathsep.join([p for p in search_paths + extra_dirs if p])
    return shutil.which(name, path=combined)


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
    markers = [
        name
        for name in (
            "README.md",
            "package.json",
            "bun.lock",
            "bun.lockb",
            "pyproject.toml",
            "requirements.txt",
            "go.mod",
            "Cargo.toml",
        )
        if (Path(repo_dir) / name).exists()
    ]
    return {
        "file_count": len(files),
        "top_extensions": top_exts,
        "markers": markers,
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
    return output


def process_repo_check(
    raw_input: Any,
    *,
    token: str,
    clean_env: dict[str, str],
    max_output_bytes: int = 1024 * 1024,
    clone_fn: Optional[
        Callable[[str, str, Optional[str], dict[str, str], int, str], None]
    ] = None,
) -> dict[str, Any]:
    spec = validate_repo_check_input(raw_input)
    repo_url: str = spec["repo_url"]
    preset: str = spec["preset"]
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
        head_sha = sha_res["stdout"].strip()
        commit_subject = subj_res["stdout"].strip()

        info_meta: Optional[dict[str, Any]] = None
        if preset == "git_info":
            info_meta = _collect_git_info(repo_dir, clean_env, token)
            passed = True
            timed_out = False
        elif preset in {"bun_test", "bun_check"}:
            bun_bin = _resolve_tool("bun", clean_env)
            if not bun_bin:
                raise WorkerInfraError("Required tool not found for preset: bun")
            install_cmd = [bun_bin, "install", "--ignore-scripts"]
            if (Path(repo_dir) / "bun.lock").exists() or (
                Path(repo_dir) / "bun.lockb"
            ).exists():
                install_cmd.append("--frozen-lockfile")
            if (Path(repo_dir) / "package.json").exists():
                install_step = _run_subprocess(
                    install_cmd,
                    cwd=repo_dir,
                    env=clean_env,
                    timeout_sec=timeout_sec,
                    token=token,
                )
                steps.append(install_step)
                if install_step["exit_code"] != 0 or install_step["timed_out"]:
                    passed = False
                    timed_out = bool(install_step["timed_out"])
                    summary = f"{preset}: dependency install failed (exit={install_step['exit_code']})"
                    return _shrink_output_to_fit(
                        {
                            "arch": arch,
                            "cpus": cpus,
                            "repo_url": repo_url,
                            "preset": preset,
                            "ref": ref,
                            "head_sha": head_sha,
                            "commit_subject": commit_subject,
                            "passed": passed,
                            "timed_out": timed_out,
                            "duration_ms": int((time.monotonic() - started) * 1000),
                            "steps": steps,
                            "summary": summary,
                        },
                        max_output_bytes,
                    )
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
        if preset == "git_info" and info_meta is not None:
            summary = f"git_info: {info_meta['file_count']} tracked files at {head_sha[:12]}"
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
            "ref": ref,
            "head_sha": head_sha,
            "commit_subject": commit_subject,
            "passed": passed,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
            "steps": steps,
            "summary": summary,
        }
        if info_meta is not None:
            output["file_count"] = info_meta["file_count"]
            output["top_extensions"] = info_meta["top_extensions"]
            output["markers"] = info_meta["markers"]

        return _shrink_output_to_fit(output, max_output_bytes)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def claim_and_process_one(
    base_url: str,
    token: str,
    worker_id: str,
    lease_sec: int,
    *,
    clone_fn: Optional[
        Callable[[str, str, Optional[str], dict[str, str], int, str], None]
    ] = None,
) -> Optional[dict[str, Any]]:
    base_url = base_url.rstrip("/")
    _, _, claim_raw = _http_request(
        f"{base_url}/jobs/claim",
        token,
        method="POST",
        json_body={"worker_id": worker_id, "lease_sec": lease_sec},
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
        err_msg = redact_worker_token(str(exc), token) or type(exc).__name__
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


def run_worker(
    *,
    base_url: str,
    token: str,
    worker_id: str,
    lease_sec: int,
    mode: str,
    poll_sec: int,
    max_idle_sec: int,
    clone_fn: Optional[
        Callable[[str, str, Optional[str], dict[str, str], int, str], None]
    ] = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    if mode == "once":
        res = claim_and_process_one(
            base_url, token, worker_id, lease_sec, clone_fn=clone_fn
        )
        if res is not None:
            results.append(res)
        return results

    if mode == "drain":
        while True:
            res = claim_and_process_one(
                base_url, token, worker_id, lease_sec, clone_fn=clone_fn
            )
            if res is None:
                break
            results.append(res)
        return results

    if mode == "poll":
        last_work_at = time.monotonic()
        while True:
            res = claim_and_process_one(
                base_url, token, worker_id, lease_sec, clone_fn=clone_fn
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


def _load_token(token_file: Optional[str]) -> str:
    if token_file:
        raw = Path(token_file).read_text(encoding="utf-8")
    else:
        raw = os.environ.get("VM_QUEUE_WORKER_TOKEN", "")
    return validate_worker_token(raw)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Standalone worker for vm-queue (probe & repo_check)"
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
        help="Idle timeout in seconds for --mode poll",
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

    worker_id = sanitize_worker_id(args.worker_id)
    try:
        token = _load_token(args.token_file)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    try:
        results = run_worker(
            base_url=args.url,
            token=token,
            worker_id=worker_id,
            lease_sec=args.lease_sec,
            mode=args.mode,
            poll_sec=max(1, args.poll_sec),
            max_idle_sec=max(1, args.max_idle_sec),
        )
    except Exception as exc:
        print(f"Worker error: {redact_worker_token(str(exc), token)}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "worker_id": worker_id,
                "mode": args.mode,
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
