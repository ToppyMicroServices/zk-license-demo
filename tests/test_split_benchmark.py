"""Evidence-writing failure cases; the real HTTP measurements run separately in CI."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from split_benchmark import MeasurementFailure, concurrent_rate_boundary, run


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

    def test_one_failed_quota_probe_preserves_all_probe_observations(self):
        class FailingClient:
            def __init__(self):
                self.calls = 0
                self.lock = threading.Lock()

            def call(self, steps, *_args, **_kwargs):
                with self.lock:
                    self.calls += 1
                    ordinal = self.calls
                steps.append({"http_status": None if ordinal == 1 else 200,
                              "elapsed_ms": 1.0})
                if ordinal == 1:
                    raise RuntimeError("Bearer never-publish-this")

        client, evidence = FailingClient(), {}
        with self.assertRaisesRegex(MeasurementFailure, "concurrent_quota_probe_failed"):
            concurrent_rate_boundary(client, evidence)
        self.assertEqual(client.calls, 4)
        probes = evidence["concurrent_boundary"]
        self.assertEqual(len(probes), 4)
        self.assertEqual(sum(probe["status"] == "FAILED" for probe in probes), 1)
        self.assertTrue(all(len(probe["steps"]) == 1 for probe in probes))
        self.assertTrue(all(probe["elapsed_ms"] >= 0 for probe in probes))
        self.assertNotIn("never-publish-this", json.dumps(evidence))
