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
EXPECTED_IDS = [f"V{n}" for n in range(1, 21)]
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
