#!/usr/bin/env python3
"""Self-tests for the sandeval runner.

Structural checks need nothing; the end-to-end checks run only vectors with no
side effects (V8 reads for a git worktree, V10 reads cgroup files), so the suite
is safe to run anywhere. `python3 tests/test_harness.py`, or via
`tests/run-tests.sh`.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNNER = os.path.join(ROOT, "bin", "sandeval")
EXPECTED_IDS = [f"V{n}" for n in range(1, 25)]
SEVERITIES = {"ship-blocker", "high", "medium", "low", "info"}


def run(*args, **kwargs):
    return subprocess.run(
        [sys.executable, RUNNER, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **kwargs,
    )


class DiscoveryTests(unittest.TestCase):
    def test_list_shows_every_vector(self):
        out = run("list")
        self.assertEqual(out.returncode, 0, out.stderr)
        for vector_id in EXPECTED_IDS:
            self.assertIn(vector_id, out.stdout)

    def test_every_vector_has_metadata(self):
        sys.path.insert(0, os.path.join(ROOT, "sandeval"))
        from runner import discover_vectors  # noqa: E402

        vectors = discover_vectors(os.path.join(ROOT, "vectors"))
        ids = [v.id for v in vectors]
        self.assertEqual(len(ids), len(set(ids)), f"duplicate ids: {ids}")
        for vector in vectors:
            self.assertTrue(vector.title, vector.id)
            self.assertTrue(vector.maps_to, vector.id)
            self.assertIn(vector.severity, SEVERITIES, vector.id)
            self.assertTrue(callable(getattr(vector, "check", None)), vector.id)


class RefusalTests(unittest.TestCase):
    def test_run_refuses_without_replica(self):
        out = run("run", "--vector", "V8")
        self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        self.assertIn("refusing", out.stderr.lower())


class ReportTests(unittest.TestCase):
    def test_json_and_markdown_schema(self):
        with tempfile.TemporaryDirectory() as td:
            json_path = os.path.join(td, "report.json")
            md_path = os.path.join(td, "report.md")
            out = run(
                "run",
                "--replica",
                "--vector",
                "V8,V10",
                "--in",
                td,
                "--out",
                td,
                "--json",
                json_path,
                "--report",
                md_path,
            )
            self.assertIn(out.returncode, (0, 1), out.stdout + out.stderr)
            with open(json_path) as handle:
                data = json.load(handle)
            for key in ("version", "generated", "context", "summary", "results"):
                self.assertIn(key, data)
            self.assertEqual(len(data["results"]), 2)
            for record in data["results"]:
                self.assertIn(record["result"]["status"], ("PASS", "FAIL", "SUSPECTED", "SKIP", "INFO"))
                self.assertTrue(record["result"]["evidence"])
            self.assertTrue(os.path.exists(md_path))
            with open(md_path) as handle:
                self.assertIn("sandeval report", handle.read())

    def test_clean_is_safe(self):
        with tempfile.TemporaryDirectory() as td:
            out = run("run", "--replica", "--clean", "--vector", "V1", "--in", td, "--out", td)
            self.assertIn(out.returncode, (0, 1), out.stdout + out.stderr)


class AutomationTests(unittest.TestCase):
    def test_auto_writes_a_combined_report(self):
        with tempfile.TemporaryDirectory() as td:
            json_path = os.path.join(td, "auto.json")
            out = run(
                "auto",
                "--replica",
                "--no-sweep",
                "--vector",
                "V8,V15",
                "--in",
                td,
                "--out",
                td,
                "--json",
                json_path,
            )
            self.assertIn(out.returncode, (0, 1), out.stdout + out.stderr)
            with open(json_path) as handle:
                data = json.load(handle)
            self.assertEqual(len(data["results"]), 2)

    def test_diff_classifies_regressions(self):
        with tempfile.TemporaryDirectory() as td:
            old = os.path.join(td, "old.json")
            new = os.path.join(td, "new.json")
            with open(old, "w") as handle:
                json.dump({"results": [{"id": "V1", "result": {"status": "PASS", "evidence": ""}}]}, handle)
            with open(new, "w") as handle:
                json.dump({"results": [{"id": "V1", "result": {"status": "FAIL", "evidence": ""}}]}, handle)
            out = run("diff", old, new)
            self.assertEqual(out.returncode, 1)
            self.assertIn("REGRESSION", out.stdout)

    def test_diff_reports_improvement(self):
        with tempfile.TemporaryDirectory() as td:
            old = os.path.join(td, "o.json")
            new = os.path.join(td, "n.json")
            with open(old, "w") as handle:
                json.dump({"results": [{"id": "V1", "result": {"status": "FAIL", "evidence": ""}}]}, handle)
            with open(new, "w") as handle:
                json.dump({"results": [{"id": "V1", "result": {"status": "PASS", "evidence": ""}}]}, handle)
            out = run("diff", old, new)
            self.assertEqual(out.returncode, 0)
            self.assertIn("IMPROVED", out.stdout)


class RunnerFeatureTests(unittest.TestCase):
    """Exit-code threshold, machine-readable diff and catalogue."""

    def test_exit_code_thresholds(self):
        sys.path.insert(0, os.path.join(ROOT, "sandeval"))
        import runner  # noqa: E402

        fail_only = type("A", (), {"fail_on": "FAIL"})()
        strict = type("A", (), {"fail_on": "SUSPECTED"})()
        self.assertEqual(runner._exit_code({"FAIL": 1}, fail_only), 1)
        self.assertEqual(runner._exit_code({"SUSPECTED": 1}, fail_only), 0)
        self.assertEqual(runner._exit_code({"SUSPECTED": 1}, strict), 1)
        self.assertEqual(runner._exit_code({"PASS": 2}, strict), 0)
        self.assertEqual(runner._exit_code({}, fail_only), 0)

    def test_diff_writes_machine_readable_json(self):
        with tempfile.TemporaryDirectory() as td:
            old, new, out = (
                os.path.join(td, "old.json"),
                os.path.join(td, "new.json"),
                os.path.join(td, "diff.json"),
            )
            with open(old, "w") as handle:
                json.dump(
                    {"results": [
                        {"id": "V1", "result": {"status": "PASS", "evidence": ""}},
                        {"id": "V9", "result": {"status": "FAIL", "evidence": ""}},
                    ]},
                    handle,
                )
            with open(new, "w") as handle:
                json.dump(
                    {"results": [
                        {"id": "V1", "result": {"status": "FAIL", "evidence": ""}},
                        {"id": "V9", "result": {"status": "PASS", "evidence": ""}},
                        {"id": "V21", "result": {"status": "FAIL", "evidence": ""}},
                    ]},
                    handle,
                )
            out_proc = run("diff", old, new, "--json", out)
            self.assertEqual(out_proc.returncode, 1, out_proc.stdout + out_proc.stderr)
            with open(out) as handle:
                data = json.load(handle)
            self.assertEqual(data["regressions"], 1)  # V1 PASS->FAIL; NEW is not a regression
            self.assertEqual(data["movements"], 1)  # V9 FAIL->PASS
            verdicts = {c["id"]: c["verdict"] for c in data["changes"]}
            self.assertEqual(verdicts["V1"], "REGRESSION")
            self.assertEqual(verdicts["V9"], "IMPROVED")
            self.assertEqual(verdicts["V21"], "NEW")

    def test_list_writes_catalogue_json(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "catalogue.json")
            out_proc = run("list", "--json", out)
            self.assertEqual(out_proc.returncode, 0, out_proc.stderr)
            with open(out) as handle:
                data = json.load(handle)
            self.assertEqual(len(data), len(EXPECTED_IDS))
            ids = {entry["id"] for entry in data}
            self.assertEqual(ids, set(EXPECTED_IDS))
            for entry in data:
                self.assertIn("host_global", entry)
                self.assertIn(entry["severity"], SEVERITIES)


class SafeGateTests(unittest.TestCase):
    """--safe must SKIP host-global vectors (V8 arms a host-side trap)."""

    def test_safe_skips_host_global_vector(self):
        with tempfile.TemporaryDirectory() as td:
            out = run(
                "run", "--replica", "--safe", "--vector", "V8",
                "--in", td, "--out", td,
            )
            self.assertIn(out.returncode, (0, 1), out.stdout + out.stderr)
            self.assertIn("[V8]", out.stdout.replace("[ V8]", "[V8]"))
            self.assertIn("host-global", out.stdout)

    def test_skip_safe_excludes_host_global_vector(self):
        with tempfile.TemporaryDirectory() as td:
            out = run(
                "run", "--replica", "--skip-safe", "--vector", "V8",
                "--in", td, "--out", td,
            )
            self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
            self.assertIn("no vectors selected", out.stderr)

    def test_v8_is_tagged_host_global(self):
        sys.path.insert(0, os.path.join(ROOT, "sandeval"))
        from runner import discover_vectors  # noqa: E402

        vectors = {v.id: v for v in discover_vectors(os.path.join(ROOT, "vectors"))}
        self.assertTrue(getattr(vectors["V8"], "host_global", False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
