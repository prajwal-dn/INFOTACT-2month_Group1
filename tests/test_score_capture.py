#!/usr/bin/env python3
"""Regression tests for CAN-Sentinel saved-model inference."""

import csv
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "src" / "score_capture.py"

CASES = [
    {
        "capture": "data/normal_baseline_60s.csv",
        "expected_rows": 59,
        "expected_normal": 58,
        "expected_anomalies": 1,
    },
    {
        "capture": "data/high_frequency_capture.csv",
        "expected_rows": 43,
        "expected_normal": 0,
        "expected_anomalies": 43,
    },
    {
        "capture": "data/unexpected_id_capture.csv",
        "expected_rows": 28,
        "expected_normal": 0,
        "expected_anomalies": 28,
    },
]

REQUIRED_COLUMNS = {
    "capture_file",
    "window_index",
    "window_start_utc",
    "prediction",
    "anomaly_score",
    "total_frames",
    "unique_can_ids",
}


class ScoreCaptureTests(unittest.TestCase):
    def test_saved_model_inference(self):
        with tempfile.TemporaryDirectory(prefix="can-sentinel-test-") as tmp:
            for case in CASES:
                with self.subTest(capture=case["capture"]):
                    output = Path(tmp) / (
                        Path(case["capture"]).stem + "_inference.csv"
                    )

                    result = subprocess.run(
                        [
                            sys.executable,
                            str(SCRIPT),
                            str(ROOT / case["capture"]),
                            "--output",
                            str(output),
                        ],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                    )

                    self.assertEqual(
                        result.returncode,
                        0,
                        msg=result.stdout + "\n" + result.stderr,
                    )
                    self.assertTrue(output.is_file())

                    with output.open(newline="", encoding="utf-8") as handle:
                        reader = csv.DictReader(handle)
                        self.assertTrue(
                            REQUIRED_COLUMNS.issubset(
                                set(reader.fieldnames or [])
                            )
                        )
                        rows = list(reader)

                    self.assertEqual(len(rows), case["expected_rows"])
                    self.assertTrue(
                        all(
                            row["prediction"] in {"NORMAL", "ANOMALY"}
                            for row in rows
                        )
                    )
                    self.assertTrue(
                        all(row["anomaly_score"] != "" for row in rows)
                    )

                    normal_count = sum(
                        row["prediction"] == "NORMAL" for row in rows
                    )
                    anomaly_count = sum(
                        row["prediction"] == "ANOMALY" for row in rows
                    )

                    self.assertEqual(normal_count, case["expected_normal"])
                    self.assertEqual(
                        anomaly_count, case["expected_anomalies"]
                    )

                    print(
                        f"PASS: {case['capture']} — "
                        f"{normal_count} normal, "
                        f"{anomaly_count} anomalous"
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
