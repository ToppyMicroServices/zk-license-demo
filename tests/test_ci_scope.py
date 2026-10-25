"""Check CI routing without installing dependencies or starting the demo."""
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.ci_scope import changed_paths, main, select_scope, test_modules, ROOT


class ScopeTests(unittest.TestCase):
    def test_documentation_and_beads_do_not_start_checks(self):
        result = select_scope(["README.md", "AGENTS.md", "docs/evidence/log.json",
                               ".beads/issues.jsonl", ".gitignore"])
        self.assertEqual(result["tests"], "")
        self.assertEqual(set(result.values()), {"", "false"})

    def test_unknown_config_and_selection_contract_require_full_checks(self):
        for path in (".github/workflows/test.yml", "requirements-ingestion.txt",
                     "scripts/ci_scope.py", "new_runtime.py", "pyproject.toml",
                     "tests/__init__.py", "tests/deleted_test.py"):
            with self.subTest(path=path):
                result = select_scope([path])
                self.assertEqual(set(result["tests"].split()), test_modules(ROOT))
                self.assertEqual({value for key, value in result.items() if key != "tests"}, {"true"})

    def test_card_changes_include_enrollment_crash_without_demo_checks(self):
        result = select_scope(["card_signature.py"])
        self.assertEqual(set(result["tests"].split()),
                         {"test_card_signature", "test_enrollment_gate", "test_enrollment_crash"})
        self.assertEqual(result["python"], "true")
        self.assertEqual(result["browser"], "false")
        self.assertEqual(result["proof"], "false")

    def test_subprocess_entry_points_select_consumers(self):
        result = select_scope(["split_demo.py", "demo.py"])
        self.assertEqual(set(result["tests"].split()), {"test_split_wallet", "test_crypto", "test_policy"})
        self.assertEqual(result["proof"], "true")
        result = select_scope(["split_service.py"])
        self.assertIn("test_split_service", result["tests"].split())
        self.assertEqual(result["browser"], "true")
        self.assertEqual(result["concurrent"], "true")

    def test_shared_enrollment_fixture_selects_its_consumer(self):
        result = select_scope(["tests/test_enrollment_gate.py"])
        self.assertEqual(set(result["tests"].split()), {"test_enrollment_gate", "test_enrollment_crash"})

    def test_test_only_change_does_not_run_measurements(self):
        result = select_scope(["tests/test_split_benchmark.py"])
        self.assertEqual(result["tests"], "test_split_benchmark")
        self.assertEqual(result["concurrent"], "false")
        self.assertEqual(select_scope(["tests/test_ci_scope.py"])["tests"], "test_ci_scope")

    def test_shared_assets_select_both_services_and_browser(self):
        for path in ("web/brand.css", "web/toppy-logo.png"):
            with self.subTest(path=path):
                result = select_scope([path])
                self.assertEqual(set(result["tests"].split()), {"test_service", "test_split_service"})
                self.assertEqual(result["browser"], "true")
        self.assertEqual(select_scope(["web/app.js"])["browser"], "false")

    def test_js_and_browser_only_tests_do_not_start_python_job(self):
        for path, flag in (("tests/test_split_web.mjs", "js"),
                           ("tests/browser_split_web.py", "browser")):
            with self.subTest(path=path):
                result = select_scope([path])
                self.assertEqual(result[flag], "true")
                self.assertEqual(result["python"], "false")

    def test_split_assets_and_union_preserve_all_related_checks(self):
        result = select_scope(["split_web/wallet.js", "enrollment_gate.py"])
        self.assertEqual(set(result["tests"].split()),
                         {"test_split_service", "test_enrollment_gate", "test_enrollment_crash"})
        self.assertEqual(result["js"], "true")
        self.assertEqual(result["browser"], "true")
        self.assertEqual(result["serial"], "false")

    def test_missing_zero_or_unavailable_base_requires_full_checks(self):
        with patch("scripts.ci_scope.subprocess.run") as run:
            for base in (None, "", "0" * 40, "--help", "HEAD"):
                self.assertIsNone(changed_paths(base))
            run.assert_not_called()
        with patch("scripts.ci_scope.subprocess.run", side_effect=subprocess.CalledProcessError(128, "git")):
            self.assertIsNone(changed_paths("a" * 40))

    def test_diff_retains_deleted_paths_and_uses_nul_delimiters(self):
        result = subprocess.CompletedProcess([], 0, b"docs/a b.md\0old.py\0new.py\0")
        with patch("scripts.ci_scope.subprocess.run", return_value=result) as run:
            self.assertEqual(changed_paths("a" * 40), ["docs/a b.md", "old.py", "new.py"])
        self.assertEqual(run.call_args.args[0],
                         ["git", "diff", "--name-only", "--no-renames", "-z", "a" * 40, "HEAD"])

    def test_full_outputs_are_written_without_replacing_previous_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "outputs"
            output.write_text("previous=value\n", encoding="utf-8")
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), redirect_stdout(io.StringIO()), \
                    patch("scripts.ci_scope.changed_paths") as diff:
                main(["--full"])
            diff.assert_not_called()
            content = output.read_text(encoding="utf-8")
            self.assertTrue(content.startswith("previous=value\n"))
            self.assertIn("python=true\n", content)
            self.assertIn("browser=true\n", content)


if __name__ == "__main__":
    unittest.main()
