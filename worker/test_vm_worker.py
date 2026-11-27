import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.request

import vm_worker


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _find_bun() -> str:
    for candidate in (
        shutil.which("bun"),
        str(Path.home() / ".bun" / "bin" / "bun"),
        "/usr/local/bin/bun",
    ):
        if candidate and Path(candidate).exists():
            return candidate
    raise RuntimeError("bun binary not found for integration test")


class VmWorkerUnitTest(unittest.TestCase):
    def test_validate_worker_token_rejects_bad_formats_without_secret_echo(self) -> None:
        good = "abcdefghijklmnopqrstuvwxyz012345"
        self.assertEqual(vm_worker.validate_worker_token(good + "\n"), good)

        bad_cases = [
            "",
            "VM_QUEUE_WORKER_TOKEN=secret_value_0123456789abcdef",
            "Bearer secret_value_0123456789abcdef",
            "<secret_value_0123456789abcdef>",
            '"secret_value_0123456789abcdef"',
            "secret value 0123456789abcdef",
            "too-short-secret-123",
        ]
        for bad in bad_cases:
            with self.assertRaises(ValueError) as ctx:
                vm_worker.validate_worker_token(bad)
            if bad:
                self.assertNotIn("secret_value", str(ctx.exception))
                self.assertNotIn("too-short-secret", str(ctx.exception))

    def test_validate_repo_check_input(self) -> None:
        valid = vm_worker.validate_repo_check_input(
            {
                "repo_url": "https://github.com/example-org/sample-repo",
                "preset": "git_info",
                "ref": "main",
                "timeout_sec": 60,
            }
        )
        self.assertEqual(valid["preset"], "git_info")

        invalid_inputs = [
            {"repo_url": "https://gitlab.com/org/repo", "preset": "git_info"},
            {"repo_url": "file:///etc/passwd", "preset": "git_info"},
            {"repo_url": "ssh://git@github.com/org/repo.git", "preset": "git_info"},
            {"repo_url": "https://user:pass@github.com/org/repo", "preset": "git_info"},
            {"repo_url": "https://github.com/org/repo", "preset": "git_info", "cmd": "id"},
            {"repo_url": "https://github.com/org/repo", "preset": "arbitrary"},
            {"repo_url": "https://github.com/org/repo", "preset": "pytest", "ref": "-evil"},
            {"repo_url": "https://github.com/org/repo", "preset": "pytest", "ref": "a/../b"},
        ]
        for item in invalid_inputs:
            with self.assertRaises(vm_worker.WorkerInfraError):
                vm_worker.validate_repo_check_input(item)

    def test_build_clean_env_strips_secrets(self) -> None:
        fake_env = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/tmp/home",
            "VM_QUEUE_WORKER_TOKEN": "super-secret-worker-token",
            "AWS_SECRET_ACCESS_KEY": "aws-dummy-value",
            "GITHUB_TOKEN": "github-dummy-value",
            "OPENAI_API_KEY": "openai-dummy-value",
        }
        cleaned = vm_worker.build_clean_env(fake_env)
        self.assertEqual(cleaned["PATH"], "/usr/bin:/bin")
        self.assertEqual(cleaned["GIT_TERMINAL_PROMPT"], "0")
        self.assertNotIn("VM_QUEUE_WORKER_TOKEN", cleaned)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", cleaned)
        self.assertNotIn("GITHUB_TOKEN", cleaned)
        self.assertNotIn("OPENAI_API_KEY", cleaned)


class VmWorkerIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="vm-worker-int-")
        self.admin_token = "int-admin-token-0123456789abcdef"
        self.worker_token = "int-worker-token-fedcba9876543210"
        self.port = _free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"

        repo_root = Path(__file__).resolve().parent.parent
        bun_bin = _find_bun()
        env = dict(os.environ)
        env.update(
            {
                "VM_QUEUE_HOST": "127.0.0.1",
                "VM_QUEUE_PORT": str(self.port),
                "VM_QUEUE_DB_PATH": str(Path(self.tmpdir) / "queue.db"),
                "VM_QUEUE_ADMIN_TOKEN": self.admin_token,
                "VM_QUEUE_WORKER_TOKEN": self.worker_token,
            }
        )
        self.proc = subprocess.Popen(
            [bun_bin, "run", str(repo_root / "index.ts")],
            cwd=str(repo_root),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._wait_healthz()

    def tearDown(self) -> None:
        if hasattr(self, "proc") and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if hasattr(self, "proc"):
            for stream in (self.proc.stdout, self.proc.stderr):
                if stream:
                    stream.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _wait_healthz(self) -> None:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(f"{self.base_url}/healthz", timeout=1) as r:
                    if r.status == 200:
                        return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("vm-queue server failed to start in integration test")

    def _admin_req(self, path: str, body: dict | None = None) -> dict:
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method="POST" if body is not None else "GET",
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode("utf-8"))

    def _create_sample_local_git_repo(self) -> str:
        src = Path(self.tmpdir) / "sample-git"
        src.mkdir()
        (src / "README.md").write_text("# sample\n", encoding="utf-8")
        (src / "main.py").write_text("print('ok')\n", encoding="utf-8")
        subprocess.run(["git", "init", "-b", "main"], cwd=src, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=src,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test User"],
            cwd=src,
            check=True,
            capture_output=True,
        )
        subprocess.run(["git", "add", "README.md", "main.py"], cwd=src, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "initial commit"],
            cwd=src,
            check=True,
            capture_output=True,
        )
        return str(src)

    def test_probe_and_repo_check_and_failure_reporting(self) -> None:
        # 1. probe round-trip
        self._admin_req(
            "/jobs",
            {"job_id": "int-probe-1", "kind": "probe", "input": {"purpose": "test"}},
        )
        probe_res = vm_worker.run_worker(
            base_url=self.base_url,
            token=self.worker_token,
            worker_id="cue-int-1",
            lease_sec=60,
            mode="drain",
            poll_sec=1,
            max_idle_sec=5,
        )
        self.assertEqual(len(probe_res), 1)
        self.assertEqual(probe_res[0]["status"], "completed")
        job1 = self._admin_req("/jobs/int-probe-1")
        self.assertEqual(job1["status"], "completed")
        self.assertTrue(job1["output"]["uname_m"])
        self.assertTrue(job1["output"]["nproc"])

        # 2. repo_check git_info round-trip using offline local git repo
        sample_repo = self._create_sample_local_git_repo()

        def local_clone_fn(
            _repo_url: str,
            dest_dir: str,
            _ref: str | None,
            clean_env: dict[str, str],
            timeout_sec: int,
            token: str,
        ) -> None:
            vm_worker.clone_github_repo(
                sample_repo, dest_dir, None, clean_env, timeout_sec, token
            )

        self._admin_req(
            "/jobs",
            {
                "job_id": "int-repo-1",
                "kind": "repo_check",
                "input": {
                    "repo_url": "https://github.com/example-org/sample-repo",
                    "preset": "git_info",
                },
            },
        )
        repo_res = vm_worker.run_worker(
            base_url=self.base_url,
            token=self.worker_token,
            worker_id="cue-int-1",
            lease_sec=60,
            mode="drain",
            poll_sec=1,
            max_idle_sec=5,
            clone_fn=local_clone_fn,
        )
        self.assertEqual(len(repo_res), 1)
        self.assertEqual(repo_res[0]["status"], "completed")
        job2 = self._admin_req("/jobs/int-repo-1")
        self.assertEqual(job2["status"], "completed")
        self.assertTrue(job2["output"]["passed"])
        self.assertEqual(job2["output"]["file_count"], 2)
        self.assertTrue(len(job2["output"]["head_sha"]) >= 7)

        # 3. Infra failure path reports POST /fail instead of stranding in leased
        def failing_clone_fn(*_args, **_kwargs) -> None:
            raise vm_worker.WorkerInfraError("simulated missing toolchain or clone error")

        self._admin_req(
            "/jobs",
            {
                "job_id": "int-repo-fail-1",
                "kind": "repo_check",
                "input": {
                    "repo_url": "https://github.com/example-org/sample-repo",
                    "preset": "git_info",
                },
            },
        )
        fail_res = vm_worker.run_worker(
            base_url=self.base_url,
            token=self.worker_token,
            worker_id="cue-int-1",
            lease_sec=60,
            mode="once",
            poll_sec=1,
            max_idle_sec=5,
            clone_fn=failing_clone_fn,
        )
        self.assertEqual(len(fail_res), 1)
        self.assertEqual(fail_res[0]["status"], "failed")
        job3 = self._admin_req("/jobs/int-repo-fail-1")
        self.assertEqual(job3["status"], "failed")
        self.assertIn("simulated missing toolchain", job3["error"])


if __name__ == "__main__":
    unittest.main()
