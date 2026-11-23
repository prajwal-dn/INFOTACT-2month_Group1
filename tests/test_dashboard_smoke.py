#!/usr/bin/env python3
"""Smoke tests for the CAN-Sentinel desktop dashboard."""

import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from PySide6.QtWidgets import QApplication
from dashboard import Dashboard


class DashboardSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_dashboard_initializes_with_capture_presets(self):
        window = Dashboard()
        self.addCleanup(window.close)

        self.assertEqual(
            window.windowTitle(),
            "CAN-Sentinel | Intrusion Detection Console",
        )
        self.assertEqual(window.capture_combo.count(), 3)

        for index in range(window.capture_combo.count()):
            relative_path = window.capture_combo.itemData(index)
            self.assertTrue((ROOT / relative_path).is_file())

        self.assertTrue((ROOT / "src" / "score_capture.py").is_file())
        self.assertTrue(
            (ROOT / "models" / "isolation_forest_baseline.joblib").is_file()
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
