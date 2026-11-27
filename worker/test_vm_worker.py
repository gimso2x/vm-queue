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

    def test_detect_auto_preset_and_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            # Plain repo -> git_info
            (root / "README.md").write_text("# plain\n", encoding="utf-8")
            p, reason, _ = vm_worker.detect_auto_preset(
                str(root), {}, "tok", available_tools={"bun", "pytest", "go", "cargo"}
            )
            self.assertEqual((p, reason), ("git_info", "no_recognized_test_manifest"))

            # package.json check -> bun_check when bun available, else git_info fallback
            (root / "package.json").write_text(
                json.dumps({"scripts": {"check": "bun test", "test": "bun test"}}),
                encoding="utf-8",
            )
            p, reason, _ = vm_worker.detect_auto_preset(
                str(root), {}, "tok", available_tools={"bun"}
            )
            self.assertEqual((p, reason), ("bun_check", None))
            p, reason, _ = vm_worker.detect_auto_preset(
                str(root), {}, "tok", available_tools=set()
            )
            self.assertEqual((p, reason), ("git_info", "toolchain_not_installed:bun"))
            p, reason, _ = vm_worker.detect_auto_preset(
                str(root), {}, "tok", available_tools={"npm"}
            )
            self.assertEqual((p, reason), ("npm_test", None))
            (root / "package.json").unlink()

            # pyproject.toml -> pytest or fallback
            (root / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
            p, reason, _ = vm_worker.detect_auto_preset(
                str(root), {}, "tok", available_tools={"pytest"}
            )
            self.assertEqual((p, reason), ("pytest", None))
            p, reason, _ = vm_worker.detect_auto_preset(
                str(root), {}, "tok", available_tools=set()
            )
            self.assertEqual((p, reason), ("git_info", "toolchain_not_installed:pytest"))
            (root / "pyproject.toml").unlink()

            # go.mod -> go_test or fallback
            (root / "go.mod").write_text("module example.com/m\n", encoding="utf-8")
            p, reason, _ = vm_worker.detect_auto_preset(
                str(root), {}, "tok", available_tools=set()
            )
            self.assertEqual((p, reason), ("git_info", "toolchain_not_installed:go"))
            (root / "go.mod").unlink()

            # Cargo.toml -> cargo_test or fallback
            (root / "Cargo.toml").write_text("[package]\nname='x'\n", encoding="utf-8")
            p, reason, _ = vm_worker.detect_auto_preset(
                str(root), {}, "tok", available_tools=set()
            )
            self.assertEqual((p, reason), ("git_info", "toolchain_not_installed:cargo"))

    def test_max_idle_sec_capped_at_3600(self) -> None:
        code = vm_worker.main(
            ["--url", "http://127.0.0.1:8790", "--max-idle-sec", "7200"]
        )
        self.assertEqual(code, 2)

    def test_validate_freqtrade_and_qa_inputs(self) -> None:
        valid_ft = vm_worker.validate_freqtrade_backtest_input(
            {
                "repo_url": "https://github.com/example-org/sample-strategy",
                "strategy": "SampleStrategy",
                "timerange": "20250101-20250201",
            }
        )
        self.assertEqual(valid_ft["mode"], "backtest")
        self.assertEqual(valid_ft["exchange"], "binance")

        for bad_ft in (
            {
                "repo_url": "https://github.com/org/repo",
                "strategy": "SampleStrategy",
                "timerange": "20250201-20250101",
            },
            {
                "repo_url": "https://github.com/org/repo",
                "strategy": "1bad",
                "timerange": "20250101-20250201",
            },
            {
                "repo_url": "https://github.com/org/repo",
                "strategy": "SampleStrategy",
                "timerange": "20250101-20250201",
                "pairs": ["bad_pair"],
            },
        ):
            with self.assertRaises(vm_worker.WorkerInfraError):
                vm_worker.validate_freqtrade_backtest_input(bad_ft)

        valid_qa = vm_worker.validate_qa_scenario_input(
            {
                "repo_url": "https://github.com/example-org/sample-repo",
                "scenario_id": "01",
                "scenario_name": "config test",
                "brief": "Brief",
                "task": "Task",
                "model": "deepseek-v4.1-flash:max",
                "tools": "read,bash,grep",
            }
        )
        self.assertEqual(valid_qa["tools"], "read,bash,grep")

        for bad_qa in (
            {
                "repo_url": "https://github.com/example-org/sample-repo",
                "scenario_id": "01",
                "scenario_name": "paid",
                "brief": "Brief",
                "task": "Task",
                "model": "anthropic/claude-sonnet-4-5",
            },
            {
                "repo_url": "https://github.com/example-org/sample-repo",
                "scenario_id": "01",
                "scenario_name": "disallowed tool",
                "brief": "Brief",
                "task": "Task",
                "tools": "read,task",
            },
        ):
            with self.assertRaises(vm_worker.WorkerInfraError):
                vm_worker.validate_qa_scenario_input(bad_qa)

    def test_repo_index_collects_stats_and_symbols(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            (repo / "src" / "core").mkdir(parents=True)
            (repo / "README.md").write_text("# Demo\nLine 2\n", encoding="utf-8")
            (repo / "src" / "core" / "app.ts").write_text(
                "export class App {}\nexport function runApp() {\n  return 1;\n}\n",
                encoding="utf-8",
            )
            (repo / "src" / "core" / "helper.ts").write_text(
                "export function ping() {\n  return 'ok';\n}\n",
                encoding="utf-8",
            )
            (repo / "src" / "worker.py").write_text(
                "def helper():\n    pass\n", encoding="utf-8"
            )
            subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "T"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

            out = vm_worker.process_repo_check(
                {"repo_url": "https://github.com/example-org/sample-repo", "preset": "repo_index"},
                token="tok-dummy-0123456789abcdef",
                clean_env=vm_worker.build_clean_env(),
                clone_fn=lambda _u, d, _r, e, t, k: vm_worker.clone_github_repo(
                    str(repo), d, None, e, t, k
                ),
            )
            self.assertTrue(out["passed"])
            self.assertEqual(out["resolved_preset"], "repo_index")
            idx = out["index"]
            self.assertEqual(idx["file_count"], 4)
            self.assertEqual(idx["total_lines"], 11)
            self.assertEqual(idx["symbol_counts"]["functions"], 3)
            self.assertEqual(idx["symbol_counts"]["classes_types"], 1)
            self.assertEqual(idx["top_directories"][0], {"dir": "src/core", "files": 2})

            # bun_build without scripts.build fails gracefully without crashing
            (repo / "package.json").write_text(json.dumps({"name": "demo"}), encoding="utf-8")
            subprocess.run(["git", "add", "package.json"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "pkg"], cwd=repo, check=True, capture_output=True)
            build_out = vm_worker.process_repo_check(
                {"repo_url": "https://github.com/example-org/sample-repo", "preset": "bun_build"},
                token="tok-dummy-0123456789abcdef",
                clean_env=vm_worker.build_clean_env(),
                clone_fn=lambda _u, d, _r, e, t, k: vm_worker.clone_github_repo(
                    str(repo), d, None, e, t, k
                ),
            )
            self.assertFalse(build_out["passed"])
            self.assertIn("no scripts.build", build_out["summary"])

    def test_resolve_worker_kinds(self) -> None:
        clean_env = {"PATH": "/nonexistent"}
        self.assertEqual(
            vm_worker.resolve_worker_kinds("auto", clean_env, llm_env={}),
            ["probe", "repo_check"],
        )
        self.assertEqual(
            vm_worker.resolve_worker_kinds("probe,qa_scenario,probe", clean_env),
            ["probe", "qa_scenario"],
        )
        with self.assertRaises(ValueError):
            vm_worker.resolve_worker_kinds("probe,bad_kind", clean_env)

    def test_freqtrade_and_qa_scenario_mock_execution(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "sample-repo"
            repo.mkdir()
            (repo / "README.md").write_text("# Sample\n", encoding="utf-8")
            subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "T"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "add", "README.md"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

            cloner = lambda _u, d, _r, e, t, k: vm_worker.clone_github_repo(
                str(repo), d, None, e, t, k
            )

            # Mock freqtrade executable verifying config.json dry_run & empty keys
            ft_bin = root / "mock_freqtrade.py"
            ft_bin.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "from pathlib import Path\n"
                "cmd = sys.argv[1]\n"
                "cfg_idx = sys.argv.index('--config') + 1\n"
                "cfg = json.loads(Path(sys.argv[cfg_idx]).read_text())\n"
                "assert cfg['dry_run'] is True\n"
                "assert cfg['exchange']['key'] == ''\n"
                "assert cfg['exchange']['secret'] == ''\n"
                "print(f'mock freqtrade {cmd} ok')\n",
                encoding="utf-8",
            )
            os.chmod(ft_bin, 0o755)

            ft_out = vm_worker.process_freqtrade_backtest(
                {
                    "repo_url": "https://github.com/example-org/sample-strategy",
                    "strategy": "SampleStrategy",
                    "mode": "hyperopt",
                    "timerange": "20250101-20250201",
                    "epochs": 5,
                },
                token="tok-dummy-0123456789abcdef",
                clean_env=vm_worker.build_clean_env(),
                clone_fn=cloner,
                freqtrade_bin_override=str(ft_bin),
            )
            self.assertTrue(ft_out["passed"])
            self.assertEqual(len(ft_out["steps"]), 2)
            self.assertIn("hyperopt", ft_out["summary"])

            # Mock omp executable testing isolated models.yml, secret redaction, and --resume wrap-up
            omp_bin = root / "mock_omp.py"
            omp_bin.write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "from pathlib import Path\n"
                "agent_dir = Path(os.environ['PI_CODING_AGENT_DIR'])\n"
                "models_file = agent_dir / 'models.yml'\n"
                "assert (models_file.stat().st_mode & 0o777) == 0o600\n"
                "assert 'VM_QUEUE_WORKER_TOKEN' not in os.environ\n"
                "assert 'VM_QUEUE_LLM_API_KEY' not in os.environ\n"
                "sdir_idx = sys.argv.index('--session-dir') + 1\n"
                "sdir = Path(sys.argv[sdir_idx])\n"
                "report = Path(os.getcwd()) / 'report.md'\n"
                "if '--resume' in sys.argv:\n"
                "    report.write_text('# QA 01\\n## 판정: 지적 있음\\n### [지적] leak local-llm-secret-12345\\n', encoding='utf-8')\n"
                "    print('wrap ok local-llm-secret-12345')\n"
                "else:\n"
                "    (sdir / 'run1.jsonl').write_text('{}\\n', encoding='utf-8')\n"
                "    report.write_text('# QA 01\\npartial only\\n', encoding='utf-8')\n"
                "    print('phase1 incomplete')\n",
                encoding="utf-8",
            )
            os.chmod(omp_bin, 0o755)

            qa_out = vm_worker.process_qa_scenario(
                {
                    "repo_url": "https://github.com/example-org/sample-repo",
                    "scenario_id": "01",
                    "scenario_name": "config test",
                    "brief": "Brief",
                    "task": "Task",
                    "model": "deepseek-v4.1-flash:max",
                    "phase1_sec": 60,
                    "wrap_sec": 30,
                },
                token="tok-dummy-0123456789abcdef",
                clean_env=vm_worker.build_clean_env(),
                clone_fn=cloner,
                omp_bin_override=str(omp_bin),
                llm_env={
                    "VM_QUEUE_LLM_API_KEY": "local-llm-secret-12345",
                    "VM_QUEUE_LLM_BASE_URL": "https://llm.example.com/v1",
                    "VM_QUEUE_LLM_PROVIDER": "custom",
                },
            )
            self.assertTrue(qa_out["passed"])
            self.assertEqual(qa_out["verdict"], "지적 있음")
            self.assertEqual(qa_out["findings_count"], 1)
            self.assertEqual(len(qa_out["steps"]), 2)
            self.assertIn("[REDACTED]", qa_out["report_md"])
            self.assertNotIn("local-llm-secret-12345", json.dumps(qa_out))


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

        # 4. preset=auto falls back safely when runtime absent & worker presence is recorded
        pkg_repo = Path(self.tmpdir) / "pkg-git"
        pkg_repo.mkdir()
        (pkg_repo / "package.json").write_text(
            json.dumps({"scripts": {"test": "echo ok"}}), encoding="utf-8"
        )
        subprocess.run(["git", "init", "-b", "main"], cwd=pkg_repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=pkg_repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "T"], cwd=pkg_repo, check=True, capture_output=True)
        subprocess.run(["git", "add", "package.json"], cwd=pkg_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "add pkg"], cwd=pkg_repo, check=True, capture_output=True)

        auto_out = vm_worker.process_repo_check(
            {"repo_url": "https://github.com/example-org/sample-repo", "preset": "auto"},
            token=self.worker_token,
            clean_env=vm_worker.build_clean_env(),
            clone_fn=lambda _u, d, _r, e, t, k: vm_worker.clone_github_repo(
                str(pkg_repo), d, None, e, t, k
            ),
            available_tools_override=set(),
        )
        self.assertTrue(auto_out["passed"])
        self.assertEqual(auto_out["requested_preset"], "auto")
        self.assertEqual(auto_out["resolved_preset"], "git_info")
        self.assertEqual(auto_out["fallback_reason"], "toolchain_not_installed:bun")

        # Worker presence recorded by previous claims
        workers_status = self._admin_req("/workers/status?window_sec=60")
        self.assertTrue(workers_status["any_online"])
        self.assertEqual(workers_status["workers"][0]["worker_id"], "cue-int-1")
        self.assertTrue(workers_status["workers"][0]["arch"])
        self.assertGreaterEqual(workers_status["workers"][0]["cpus"], 1)

    def test_kinds_filtering_and_concurrency(self) -> None:
        self._admin_req(
            "/jobs",
            {
                "job_id": "int-ft-skip-1",
                "kind": "freqtrade_backtest",
                "input": {
                    "repo_url": "https://github.com/example-org/sample-strategy",
                    "strategy": "SampleStrategy",
                    "timerange": "20250101-20250201",
                },
            },
        )
        for idx in (1, 2, 3):
            self._admin_req(
                "/jobs",
                {"job_id": f"int-conc-probe-{idx}", "kind": "probe", "input": {"idx": idx}},
            )

        res = vm_worker.run_worker(
            base_url=self.base_url,
            token=self.worker_token,
            worker_id="cue-conc",
            lease_sec=60,
            mode="drain",
            poll_sec=1,
            max_idle_sec=5,
            kinds=["probe"],
            concurrency=2,
        )
        self.assertEqual(len(res), 3)
        self.assertTrue(all(r["status"] == "completed" for r in res))
        # freqtrade job remains queued because worker only claimed probe
        ft_job = self._admin_req("/jobs/int-ft-skip-1")
        self.assertEqual(ft_job["status"], "queued")


if __name__ == "__main__":
    unittest.main()
