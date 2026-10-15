"""Check statistics and evidence preservation without substituting crypto results."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from benchmark import run, summarize


class BenchmarkTests(unittest.TestCase):
    def test_nearest_rank_and_median(self):
        result = summarize(list(range(30, 0, -1)))
        self.assertEqual(result, {"count": 30, "min": 1, "median": 15.5,
                                  "p95": 29, "max": 30, "mean": 15.5})
        self.assertEqual(summarize([7])["p95"], 7)

    def test_invalid_samples_rejected(self):
        for values in ([], [-1], [float("nan")], [float("inf")]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                summarize(values)

    def test_existing_evidence_and_invalid_counts_fail_before_measurement(self):
        with TemporaryDirectory() as tmp, patch("benchmark.measure") as measure:
            out = Path(tmp) / "result.json"
            out.write_text("previous evidence", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                run(out)
            self.assertEqual(out.read_text(encoding="utf-8"), "previous evidence")
            for counts in ({"runs": 0}, {"runs": 1001}, {"warmups": -1}, {"warmups": 101}):
                with self.subTest(counts=counts), self.assertRaises(ValueError):
                    run(Path(tmp) / "new.json", **counts)
            measure.assert_not_called()

    def test_failed_measurement_does_not_write_success_report(self):
        with TemporaryDirectory() as tmp, patch("benchmark.measure", side_effect=RuntimeError("invalid_proof")):
            out = Path(tmp) / "result.json"
            with self.assertRaisesRegex(RuntimeError, "invalid_proof"):
                run(out)
            self.assertFalse(out.exists())
