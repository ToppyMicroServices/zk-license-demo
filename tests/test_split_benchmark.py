"""Evidence-writing failure cases; the real HTTP measurements run separately in CI."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from split_benchmark import MeasurementFailure, run


class SplitBenchmarkEvidenceTests(unittest.TestCase):
    def test_invalid_counts_and_existing_evidence_do_not_start_measurement(self):
        with TemporaryDirectory() as temporary, patch("split_benchmark.measure") as measure:
            out = Path(temporary) / "result.json"
            for options in ({"warmups": 5}, {"flows": 0}, {"flows": 29},
                            {"flows": 27}, {"warmups": 3},
                            {"concurrency": [8]}, {"concurrency": [1, 1]},
                            {"concurrency": [True]}, {"concurrency": []}):
                with self.subTest(options=options), self.assertRaises(MeasurementFailure):
                    run(out, **options)
            self.assertFalse(out.exists())
            out.write_text("existing evidence", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                run(out)
            self.assertEqual(out.read_text(encoding="utf-8"), "existing evidence")
            measure.assert_not_called()

    def test_failed_measurement_retains_partial_results_without_exception_secrets(self):
        def failed(report, *_):
            report["scenarios"].append({"concurrency": 1, "status": "FAILED", "measured_batches": []})
            raise RuntimeError("Bearer never-publish-this")

        with TemporaryDirectory() as temporary, patch("split_benchmark.measure", side_effect=failed):
            out = Path(temporary) / "result.json"
            result = run(out)
            saved = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(saved, result)
            self.assertEqual(saved["status"], "FAILED")
            self.assertEqual(saved["failure"], "measurement_exception")
            self.assertEqual(len(saved["scenarios"]), 1)
            self.assertNotIn("never-publish-this", out.read_text(encoding="utf-8"))

    def test_expected_failure_is_not_relabelled_as_success(self):
        with TemporaryDirectory() as temporary, patch(
                "split_benchmark.measure", side_effect=MeasurementFailure("flow_failed")):
            result = run(Path(temporary) / "result.json")
            self.assertEqual(result["status"], "FAILED")
            self.assertEqual(result["failure"], "flow_failed")
