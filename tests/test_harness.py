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
EXPECTED_IDS = [f"V{n}" for n in range(1, 38)]
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


class ReportTests(unittest.TestCase):
    def test_json_and_markdown_schema(self):
        with tempfile.TemporaryDirectory() as td:
            json_path = os.path.join(td, "report.json")
            md_path = os.path.join(td, "report.md")
            out = run(
                "run",
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
            out = run("run", "--clean", "--vector", "V1", "--in", td, "--out", td)
            self.assertIn(out.returncode, (0, 1), out.stdout + out.stderr)


class AutomationTests(unittest.TestCase):
    def test_auto_writes_a_combined_report(self):
        with tempfile.TemporaryDirectory() as td:
            json_path = os.path.join(td, "auto.json")
            out = run(
                "auto",
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


class ReportActionTests(unittest.TestCase):
    """The report must be actionable: ranked findings, why/fix, reproduce cmd."""

    @staticmethod
    def _rec(vid, status, severity="high", evidence="x"):
        return {
            "id": vid,
            "title": f"title {vid}",
            "severity": severity,
            "maps_to": "P1",
            "host_verify": "host-verify/verify.sh",
            "duration_ms": 5,
            "result": {"status": status, "evidence": evidence},
            "remediation": {"why": "why text", "fix": "fix text"},
        }

    def _render(self, records):
        sys.path.insert(0, os.path.join(ROOT, "sandeval"))
        import runner  # noqa: E402
        from base import Context  # noqa: E402

        ctx = Context(in_dir="/in", out_dir="/out", scratch="/in/.s")
        return runner.render_markdown(records, ctx, {"FAIL": 1, "PASS": 1})

    def test_fail_gets_actionable_block(self):
        md = self._render(
            [self._rec("V1", "FAIL"), self._rec("V9", "PASS", severity="ship-blocker")]
        )
        self.assertIn("## Action required: FAIL", md)
        self.assertIn("- **why it matters:**", md)
        self.assertIn("- **fix:**", md)
        self.assertIn("run --vector V1 --in /in --out /out", md)
        self.assertIn("## Next steps", md)
        self.assertIn("Process exit code: **exit 1", md)

    def test_long_evidence_is_bounded(self):
        md = self._render([self._rec("V2", "FAIL", evidence="p" * 800)])
        self.assertIn("full text in the JSON report", md)

    def test_advice_fallback_for_unknown_vector(self):
        sys.path.insert(0, os.path.join(ROOT, "sandeval"))
        import advice  # noqa: E402

        self.assertTrue(advice.for_id("V999")["fix"])
        self.assertIn("why", advice.for_id("V21"))

    def test_records_carry_duration_and_remediation(self):
        with tempfile.TemporaryDirectory() as td:
            json_path = os.path.join(td, "r.json")
            out = run("run", "--vector", "V8,V10", "--in", td, "--out", td, "--json", json_path)
            self.assertIn(out.returncode, (0, 1), out.stdout + out.stderr)
            with open(json_path) as handle:
                data = json.load(handle)
            self.assertGreater(data["context"]["runtime_s"], 0)
            for record in data["results"]:
                self.assertIsInstance(record["duration_ms"], int)
                self.assertIn("fix", record["remediation"])

    def test_auto_removes_scratch(self):
        """Regression: auto-mode used to leave .sandeval-* scratch dirs behind."""
        with tempfile.TemporaryDirectory() as td:
            out = run("auto", "--no-sweep", "--vector", "V8", "--in", td, "--out", td)
            self.assertIn(out.returncode, (0, 1), out.stdout + out.stderr)
            residue = [n for n in os.listdir(td) if n.startswith(".sandeval-")]
            self.assertEqual(residue, [])

    def test_compare_reports_improvement(self):
        with tempfile.TemporaryDirectory() as td:
            old = os.path.join(td, "old.json")
            with open(old, "w") as handle:
                json.dump(
                    {"results": [{"id": "V15", "result": {"status": "FAIL", "evidence": ""}}]},
                    handle,
                )
            out = run("run", "--vector", "V15", "--in", td, "--out", td, "--compare", old)
            self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
            self.assertIn("IMPROVED", out.stdout)


class ImpactLayerTests(unittest.TestCase):
    """V29-V37: helpers, metadata, and the cleanup guarantees."""

    def test_common_helpers(self):
        sys.path.insert(0, os.path.join(ROOT, "vectors"))
        import _common  # noqa: E402

        line = _common.marker_line("V29", "target=x")
        self.assertTrue(line.startswith("SAND_EVAL_POC V29 "))
        self.assertTrue(line.endswith("target=x\n"))
        self.assertEqual(_common.errno_name(1), "EPERM")
        self.assertEqual(_common.errno_name(0), "ok")
        self.assertFalse(_common.is_regular_path("socket:[123]"))
        self.assertFalse(_common.is_regular_path("pipe:[1]"))
        self.assertTrue(_common.is_regular_path(os.__file__))
        inv = _common.fd_inventory(os.getpid())
        self.assertTrue(any(e["fd"] == 0 or e["fd"] == 1 for e in inv))
        with tempfile.NamedTemporaryFile() as handle:
            self.assertTrue(_common.writable_by_us(os.fstat(handle.fileno())))

    def test_new_vectors_have_advice_and_metadata(self):
        sys.path.insert(0, os.path.join(ROOT, "sandeval"))
        sys.path.insert(0, os.path.join(ROOT, "vectors"))
        import advice  # noqa: E402
        from runner import discover_vectors  # noqa: E402

        vectors = {v.id: v for v in discover_vectors(os.path.join(ROOT, "vectors"))}
        for vid in ("V29", "V30", "V31", "V32", "V33", "V34", "V35", "V36", "V37"):
            self.assertIn(vid, vectors, vid)
            self.assertTrue(advice.for_id(vid)["why"], f"advice why missing for {vid}")
            self.assertTrue(advice.for_id(vid)["fix"], f"advice fix missing for {vid}")
            self.assertTrue(vectors[vid].description, vid)

    def test_v35_xattr_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            policy = os.path.join(td, "policy.toml")
            with open(policy, "w") as handle:
                handle.write("[resources]\n")
            out = run(
                "run", "--clean", "--vector", "V35",
                "--in", td, "--out", td, "--policy", policy, "--state-dir", td,
            )
            self.assertIn(out.returncode, (0, 1), out.stdout + out.stderr)
            try:
                os.getxattr(policy, "user.sandeval.V35")
                self.fail("xattr marker survived --clean")
            except OSError:
                pass

    def test_v30_leaves_no_links(self):
        with tempfile.TemporaryDirectory() as td:
            out = run("run", "--clean", "--vector", "V30", "--in", td, "--out", td)
            self.assertIn(out.returncode, (0, 1), out.stdout + out.stderr)
            residue = [n for n in os.listdir(td) if n.startswith("ingest-")]
            self.assertEqual(residue, [])


class SafeGateTests(unittest.TestCase):
    """--safe must SKIP host-global vectors (V8 arms a host-side trap)."""

    def test_safe_skips_host_global_vector(self):
        with tempfile.TemporaryDirectory() as td:
            out = run(
                "run", "--safe", "--vector", "V8",
                "--in", td, "--out", td,
            )
            self.assertIn(out.returncode, (0, 1), out.stdout + out.stderr)
            self.assertIn("[V8]", out.stdout.replace("[ V8]", "[V8]"))
            self.assertIn("host-global", out.stdout)

    def test_skip_safe_excludes_host_global_vector(self):
        with tempfile.TemporaryDirectory() as td:
            out = run(
                "run", "--skip-safe", "--vector", "V8",
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
