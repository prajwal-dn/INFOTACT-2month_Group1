#!/usr/bin/env python3
"""CAN-Sentinel desktop dashboard for saved virtual-CAN captures."""

import csv
import shutil
import signal
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

ROOT = Path(__file__).resolve().parents[1]
SCORER = ROOT / "src" / "score_capture.py"
OUTPUT = ROOT / "reports" / "dashboard_inference_latest.csv"

PRESETS = [
    ("Normal baseline — 60 seconds", "data/normal_baseline_60s.csv"),
    ("High-frequency attack", "data/high_frequency_capture.csv"),
    ("Unexpected extended ID", "data/unexpected_id_capture.csv"),
]


class InferenceWorker(QThread):
    succeeded = Signal(str, str)
    failed = Signal(str)

    def __init__(self, capture_path):
        super().__init__()
        self.capture_path = Path(capture_path)

    def run(self):
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCORER),
                    str(self.capture_path),
                    "--output",
                    str(OUTPUT),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                message = result.stderr.strip() or result.stdout.strip()
                self.failed.emit(message or "Inference failed.")
                return

            self.succeeded.emit(str(OUTPUT), result.stdout)

        except subprocess.TimeoutExpired:
            self.failed.emit("Inference timed out after 120 seconds.")
        except OSError as exc:
            self.failed.emit(str(exc))


class MetricCard(QFrame):
    def __init__(self, caption, value="—"):
        super().__init__()
        self.setObjectName("metricCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)

        self.caption = QLabel(caption.upper())
        self.caption.setObjectName("metricCaption")

        self.value = QLabel(value)
        self.value.setObjectName("metricValue")

        layout.addWidget(self.caption)
        layout.addWidget(self.value)


class Dashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CAN-Sentinel | Intrusion Detection Console")
        self.resize(1120, 760)
        self.worker = None
        self.sniffer_process = None
        self.capture_output_handle = None
        self.capture_log_handle = None
        self.active_capture_path = None

        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(24, 20, 24, 18)
        root_layout.setSpacing(16)

        # Header
        header = QHBoxLayout()
        title_area = QVBoxLayout()

        title = QLabel("CAN-SENTINEL")
        title.setObjectName("mainTitle")

        subtitle = QLabel(
            "AUTOMOTIVE ECU INTRUSION DETECTION  /  OFFLINE ANALYSIS"
        )
        subtitle.setObjectName("subtitle")

        title_area.addWidget(title)
        title_area.addWidget(subtitle)
        header.addLayout(title_area)
        header.addStretch()

        self.status_label = QLabel("● READY")
        self.status_label.setObjectName("statusReady")
        header.addWidget(self.status_label, alignment=Qt.AlignmentFlag.AlignTop)

        root_layout.addLayout(header)

        # Capture selection
        select_frame = QFrame()
        select_frame.setObjectName("panel")
        select_layout = QVBoxLayout(select_frame)

        section_title = QLabel("CAPTURE SOURCE")
        section_title.setObjectName("sectionTitle")
        select_layout.addWidget(section_title)

        selection_row = QHBoxLayout()
        self.capture_combo = QComboBox()

        for label, relative_path in PRESETS:
            self.capture_combo.addItem(label, relative_path)

        self.capture_combo.currentIndexChanged.connect(self.update_path)
        selection_row.addWidget(self.capture_combo, 2)

        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Path to a CAN sniffer CSV")
        selection_row.addWidget(self.path_edit, 3)

        browse_button = QPushButton("Browse…")
        browse_button.clicked.connect(self.browse_capture)
        selection_row.addWidget(browse_button)

        select_layout.addLayout(selection_row)

        capture_row = QHBoxLayout()

        self.start_capture_button = QPushButton("●  Start vcan0 capture")
        self.start_capture_button.clicked.connect(self.start_capture)
        capture_row.addWidget(self.start_capture_button)

        self.stop_capture_button = QPushButton("■  Stop & Analyze")
        self.stop_capture_button.setEnabled(False)
        self.stop_capture_button.clicked.connect(self.stop_capture_and_analyze)
        capture_row.addWidget(self.stop_capture_button)

        select_layout.addLayout(capture_row)

        capture_hint = QLabel(
            "Capture uses vcan0 only. Generate traffic in another terminal, "
            "then select Stop & Analyze."
        )
        capture_hint.setObjectName("mutedText")
        select_layout.addWidget(capture_hint)

        self.run_button = QPushButton("▶  Analyze capture")
        self.run_button.setObjectName("primaryButton")
        self.run_button.clicked.connect(self.run_inference)
        select_layout.addWidget(
            self.run_button, alignment=Qt.AlignmentFlag.AlignLeft
        )

        root_layout.addWidget(select_frame)
        self.update_path(0)

        # Summary cards
        cards = QHBoxLayout()
        self.total_card = MetricCard("Windows scored")
        self.normal_card = MetricCard("Normal windows")
        self.anomaly_card = MetricCard("Anomalous windows")
        self.rate_card = MetricCard("Anomaly rate")

        for card in (
            self.total_card,
            self.normal_card,
            self.anomaly_card,
            self.rate_card,
        ):
            cards.addWidget(card)

        root_layout.addLayout(cards)

        # Results table
        results_panel = QFrame()
        results_panel.setObjectName("panel")
        results_layout = QVBoxLayout(results_panel)

        results_header = QHBoxLayout()
        results_title = QLabel("WINDOW-LEVEL DETECTION RESULTS")
        results_title.setObjectName("sectionTitle")

        self.result_count = QLabel("No analysis loaded")
        self.result_count.setObjectName("mutedText")

        results_header.addWidget(results_title)
        results_header.addStretch()
        results_header.addWidget(self.result_count)
        results_layout.addLayout(results_header)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "Window",
            "Start time (UTC)",
            "Prediction",
            "Frames",
            "Unique IDs",
            "Extended",
            "Anomaly score",
        ])
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setStretchLastSection(True)

        results_layout.addWidget(self.table)
        root_layout.addWidget(results_panel, 1)

        # Footer
        self.footer = QLabel(
            "Prototype • Saved virtual-CAN captures • "
            "Model accuracy is not independently validated"
        )
        self.footer.setObjectName("mutedText")
        root_layout.addWidget(self.footer)

        self.setStyleSheet("""
            QMainWindow, QWidget {
                background: #0c1220;
                color: #e6edf7;
                font-family: "Noto Sans", "DejaVu Sans", sans-serif;
                font-size: 10pt;
            }
            QLabel#mainTitle {
                font-size: 23pt;
                font-weight: 800;
                color: #f4f7ff;
                letter-spacing: 1px;
            }
            QLabel#subtitle, QLabel#metricCaption, QLabel#mutedText {
                color: #95a5bb;
                font-size: 8pt;
            }
            QLabel#sectionTitle {
                color: #dce8f7;
                font-size: 10pt;
                font-weight: 700;
            }
            QLabel#statusReady {
                color: #50d5a0;
                font-weight: 700;
                padding: 7px 10px;
                background: #14362f;
                border-radius: 7px;
            }
            QLabel#statusBusy {
                color: #f4ca67;
                font-weight: 700;
                padding: 7px 10px;
                background: #3b3018;
                border-radius: 7px;
            }
            QFrame#panel, QFrame#metricCard {
                background: #131d2d;
                border: 1px solid #26374d;
                border-radius: 10px;
            }
            QLabel#metricValue {
                font-size: 22pt;
                font-weight: 700;
                color: #f2f7ff;
            }
            QLineEdit, QComboBox {
                background: #0c1524;
                border: 1px solid #30435c;
                border-radius: 6px;
                padding: 9px;
                color: #edf4ff;
                min-height: 20px;
            }
            QComboBox QAbstractItemView {
                background: #131d2d;
                color: #edf4ff;
                selection-background-color: #235d86;
            }
            QPushButton {
                background: #23334a;
                color: #edf4ff;
                border: 1px solid #3a4e68;
                border-radius: 6px;
                padding: 9px 13px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #304762;
            }
            QPushButton:disabled {
                color: #8290a4;
                background: #182234;
            }
            QPushButton#primaryButton {
                background: #087e8b;
                border-color: #1499a5;
                color: white;
                padding: 11px 17px;
            }
            QPushButton#primaryButton:hover {
                background: #0996a3;
            }
            QTableWidget {
                background: #0e1726;
                alternate-background-color: #121f31;
                border: 1px solid #26374d;
                border-radius: 6px;
                gridline-color: #26374d;
                selection-background-color: #214d70;
            }
            QHeaderView::section {
                background: #1b2a3e;
                color: #c7d7ec;
                padding: 9px 7px;
                border: none;
                font-weight: 700;
            }
        """)

    def update_path(self, index):
        relative_path = self.capture_combo.itemData(index)
        if relative_path:
            self.path_edit.setText(str(ROOT / relative_path))

    def browse_capture(self):
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select a CAN sniffer CSV",
            str(ROOT / "data"),
            "CSV files (*.csv);;All files (*)",
        )
        if filename:
            self.path_edit.setText(filename)

    def start_capture(self):
        if self.worker is not None:
            QMessageBox.information(
                self, "Analysis running",
                "Wait for the current analysis to finish before recording."
            )
            return

        if self.sniffer_process is not None:
            QMessageBox.warning(
                self, "Capture active", "A capture is already running."
            )
            return

        sniffer = ROOT / "build" / "can_sniffer"
        if not sniffer.is_file():
            QMessageBox.critical(
                self, "Sniffer missing",
                f"Build the CAN sniffer first:\n{sniffer}"
            )
            return

        # Confirm that the virtual interface exists and is UP.
        try:
            check = subprocess.run(
                ["ip", "-details", "link", "show", "vcan0"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            QMessageBox.critical(self, "Interface check failed", str(exc))
            return

        first_line = check.stdout.splitlines()[0] if check.stdout else ""
        if check.returncode != 0 or "UP" not in first_line.split(">")[0]:
            QMessageBox.warning(
                self, "vcan0 unavailable",
                "The virtual CAN interface vcan0 is not UP.\n\n"
                "Bring it up in a terminal before recording:\n"
                "sudo modprobe vcan\n"
                "sudo ip link add dev vcan0 type vcan  # only if absent\n"
                "sudo ip link set up vcan0"
            )
            return

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        capture_path = ROOT / "data" / f"dashboard_capture_{stamp}.csv"
        log_path = ROOT / "data" / f"dashboard_capture_{stamp}.log"
        capture_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            output_handle = capture_path.open(
                "w", newline="", encoding="utf-8"
            )
            log_handle = log_path.open(
                "w", encoding="utf-8"
            )

            stdbuf = shutil.which("stdbuf")
            command = (
                [stdbuf, "-oL", str(sniffer)]
                if stdbuf else [str(sniffer)]
            )

            process = subprocess.Popen(
                command,
                cwd=ROOT,
                stdout=output_handle,
                stderr=log_handle,
                text=True,
            )
        except OSError as exc:
            try:
                output_handle.close()
            except (UnboundLocalError, OSError):
                pass
            try:
                log_handle.close()
            except (UnboundLocalError, OSError):
                pass
            QMessageBox.critical(
                self, "Capture failed",
                f"Could not start the CAN sniffer:\n{exc}"
            )
            return

        self.capture_output_handle = output_handle
        self.capture_log_handle = log_handle
        self.sniffer_process = process
        self.active_capture_path = capture_path

        self.start_capture_button.setEnabled(False)
        self.stop_capture_button.setEnabled(True)
        self.run_button.setEnabled(False)
        self.status_label.setText("● CAPTURING vcan0")
        self.status_label.setObjectName("statusBusy")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        self.footer.setText(
            f"Recording to {capture_path.name}. Generate traffic on vcan0 "
            "from another terminal, then click Stop & Analyze."
        )

    def stop_capture_and_analyze(self):
        process = self.sniffer_process
        if process is None:
            return

        capture_path = self.active_capture_path
        self.stop_capture_button.setEnabled(False)
        self.status_label.setText("● STOPPING CAPTURE")
        self.status_label.setObjectName("statusBusy")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

        try:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        except OSError as exc:
            QMessageBox.warning(
                self, "Stop warning",
                f"Could not stop the sniffer cleanly:\n{exc}"
            )
        finally:
            for handle in (
                self.capture_output_handle,
                self.capture_log_handle,
            ):
                if handle is not None:
                    handle.close()

            self.sniffer_process = None
            self.capture_output_handle = None
            self.capture_log_handle = None
            self.active_capture_path = None

        self.start_capture_button.setEnabled(True)
        self.run_button.setEnabled(True)

        if capture_path is None or not capture_path.is_file():
            self.status_label.setText("● ERROR")
            self.footer.setText("No capture file was produced.")
            return

        self.path_edit.setText(str(capture_path))
        self.capture_combo.setCurrentIndex(-1)
        self.footer.setText(
            f"Capture saved: {capture_path.name}. Starting analysis…"
        )

        # Reuse the existing inference workflow on the new capture.
        self.run_inference()

    def run_inference(self):
        if self.worker is not None:
            return
        if (
            self.sniffer_process is not None
            and self.sniffer_process.poll() is None
        ):
            QMessageBox.warning(
                self, "Capture active",
                "Stop the current capture before analyzing a file."
            )
            return

        capture = self.path_edit.text().strip()
        if not capture:
            QMessageBox.warning(self, "Missing capture", "Select a CSV file.")
            return

        if not Path(capture).is_file():
            QMessageBox.warning(
                self, "File not found", f"Cannot find:\n{capture}"
            )
            return

        self.run_button.setEnabled(False)
        self.status_label.setText("● ANALYZING")
        self.status_label.setObjectName("statusBusy")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        self.footer.setText("Running saved-model inference…")

        self.worker = InferenceWorker(capture)
        self.worker.succeeded.connect(self.show_results)
        self.worker.failed.connect(self.show_error)
        self.worker.finished.connect(self.worker_finished)
        self.worker.start()

    def show_results(self, report_path, stdout):
        try:
            with open(report_path, newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
        except (OSError, csv.Error) as exc:
            self.show_error(f"Could not read inference report: {exc}")
            return

        total = len(rows)
        anomaly_count = sum(
            row["prediction"] == "ANOMALY" for row in rows
        )
        normal_count = total - anomaly_count
        anomaly_rate = (100 * anomaly_count / total) if total else 0

        self.total_card.value.setText(str(total))
        self.normal_card.value.setText(str(normal_count))
        self.anomaly_card.value.setText(str(anomaly_count))
        self.rate_card.value.setText(f"{anomaly_rate:.1f}%")

        self.table.setRowCount(total)

        for index, row in enumerate(rows):
            values = [
                row["window_index"],
                row["window_start_utc"],
                row["prediction"],
                row["total_frames"],
                row["unique_can_ids"],
                row["extended_frame_count"],
                row["anomaly_score"],
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))

                if column in (0, 3, 4, 5, 6):
                    item.setTextAlignment(
                        Qt.AlignmentFlag.AlignCenter
                    )

                if row["prediction"] == "ANOMALY":
                    item.setForeground(QColor("#ff9b9b"))
                    if column == 2:
                        item.setText("⚠ ANOMALY")

                self.table.setItem(index, column, item)

        self.table.resizeRowsToContents()
        self.result_count.setText(f"{total} windows")
        self.status_label.setText("● ANALYSIS COMPLETE")
        self.status_label.setObjectName("statusReady")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

        capture_name = rows[0]["capture_file"] if rows else "capture"
        self.footer.setText(
            f"Analyzed {capture_name} • Report saved to "
            f"{report_path} • Prototype predictions"
        )

    def show_error(self, message):
        self.status_label.setText("● ERROR")
        self.footer.setText("Analysis failed.")
        QMessageBox.critical(self, "Inference error", message)

    def worker_finished(self):
        self.run_button.setEnabled(True)
        if self.status_label.text() == "● ANALYZING":
            self.status_label.setText("● READY")
            self.status_label.setObjectName("statusReady")
            self.status_label.style().unpolish(self.status_label)
            self.status_label.style().polish(self.status_label)
        self.worker = None


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    window = Dashboard()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
