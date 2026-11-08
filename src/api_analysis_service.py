#!/usr/bin/env python3
"""Analysis service for CAN-Sentinel.

Provides genuine capture scoring and frequency analysis using the original
saved Isolation Forest baseline model and CAN-Sentinel feature pipeline.
"""

import csv
from collections import Counter, defaultdict
from copy import deepcopy
import io
import math
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib

if __package__:
    from .incident_engine import correlate_incidents
else:
    from incident_engine import correlate_incidents

if __package__:
    from .alert_explainer import explain_window
else:
    from alert_explainer import explain_window

if __package__:
    from .frequency_analyzer import (
        EXPECTED_HEADER,
        KNOWN_IDS,
        build_frequency_summary,
        build_window_features,
        load_capture,
        ns_to_timestamp,
        timestamp_to_ns,
    )
    from .isolation_forest_detector import FEATURE_COLUMNS
else:
    from frequency_analyzer import (
        EXPECTED_HEADER,
        KNOWN_IDS,
        build_frequency_summary,
        build_window_features,
        load_capture,
        ns_to_timestamp,
        timestamp_to_ns,
    )
    from isolation_forest_detector import FEATURE_COLUMNS

ROOT = Path(__file__).resolve().parents[1]
WINDOW_MS = 1000
DEFAULT_MODEL_PATH = ROOT / "models/isolation_forest_baseline.joblib"


def get_model_info(model_path: Optional[Path] = None) -> Dict[str, Any]:
    """Inspect and return metadata for the saved Isolation Forest model."""
    path = model_path or DEFAULT_MODEL_PATH
    if not path.is_file():
        return {
            "loaded": False,
            "path": str(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path),
            "algorithm": "IsolationForest",
            "contamination": None,
            "training_windows": None,
            "window_ms": WINDOW_MS,
            "feature_columns": list(FEATURE_COLUMNS),
            "sklearn_version": None,
        }

    try:
        bundle = joblib.load(path)
        model = bundle.get("model")
        feature_cols = bundle.get("feature_columns", list(FEATURE_COLUMNS))
        contamination = bundle.get("contamination", 0.02)
        training_windows = bundle.get("training_windows")
        sklearn_ver = bundle.get("sklearn_version")

        algo_name = "IsolationForest"
        if model is not None:
            n_est = getattr(model, "n_estimators", 200)
            rand_state = getattr(model, "random_state", 42)
            algo_name = f"IsolationForest (n_estimators={n_est}, random_state={rand_state})"

        return {
            "loaded": True,
            "path": str(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path).replace("\\", "/"),
            "algorithm": algo_name,
            "contamination": float(contamination) if contamination is not None else 0.02,
            "training_windows": int(training_windows) if training_windows is not None else None,
            "window_ms": WINDOW_MS,
            "feature_columns": list(feature_cols),
            "sklearn_version": str(sklearn_ver) if sklearn_ver else None,
        }
    except Exception:
        return {
            "loaded": False,
            "path": str(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path).replace("\\", "/"),
            "algorithm": "IsolationForest",
            "contamination": None,
            "training_windows": None,
            "window_ms": WINDOW_MS,
            "feature_columns": list(FEATURE_COLUMNS),
            "sklearn_version": None,
        }


def format_frequency_row(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw frequency row into frontend Zod FrequencyRow format."""
    def clean_float(val: Any) -> Optional[float]:
        if val is None or val == "":
            return None
        try:
            f = float(val)
            return None if math.isnan(f) else round(f, 6)
        except (ValueError, TypeError):
            return None

    return {
        "can_id": str(raw["can_id"]),
        "frame_format": str(raw["frame_format"]),
        "frame_count": int(raw["frame_count"]),
        "percentage_of_total": round(float(raw["percentage_of_total"]), 4),
        "unique_payload_count": int(raw["unique_payload_count"]),
        "mean_interarrival_ms": clean_float(raw.get("mean_interarrival_ms")),
        "median_interarrival_ms": clean_float(raw.get("median_interarrival_ms")),
        "min_interarrival_ms": clean_float(raw.get("min_interarrival_ms")),
        "max_interarrival_ms": clean_float(raw.get("max_interarrival_ms")),
    }


def parse_csv_records(csv_text_or_path: Any) -> List[Dict[str, Any]]:
    """Parse CSV text or Path, enforcing canonical header and non-empty rows."""
    if isinstance(csv_text_or_path, (str, Path)) and Path(csv_text_or_path).is_file():
        path = Path(csv_text_or_path)
        with path.open("r", newline="", encoding="utf-8") as handle:
            return _parse_reader(csv.DictReader(handle))
    else:
        text = str(csv_text_or_path)
        handle = io.StringIO(text)
        return _parse_reader(csv.DictReader(handle))


def _parse_reader(reader: csv.DictReader) -> List[Dict[str, Any]]:
    if reader.fieldnames != EXPECTED_HEADER:
        raise ValueError(
            f"Invalid CSV header. Expected {EXPECTED_HEADER}, got {reader.fieldnames}"
        )

    records = []
    for line_num, row in enumerate(reader, start=2):
        if None in row or any(v is None for v in row.values()):
            raise ValueError(f"Malformed CSV row at line {line_num}")

        ts_raw = row["timestamp_utc"].strip()
        ts_ns = timestamp_to_ns(ts_raw)
        can_id_raw = row["can_id"].strip()
        fmt = row["frame_format"].strip()
        iface = row["interface"].strip()
        flags = row["flags"].strip()
        dlc_val = int(row["dlc"].strip())
        payload = row["payload"].strip().upper()

        if iface != "vcan0":
            raise ValueError(
                f"Interface {iface!r} at line {line_num} is not allowed. Prototype accepts virtual CAN (vcan0) only."
            )

        if fmt not in ("standard", "extended"):
            raise ValueError(f"Invalid frame format {fmt!r} at line {line_num}")

        id_int = int(can_id_raw, 16)
        normalized_id = f"0x{id_int:x}"

        records.append({
            "timestamp_ns": ts_ns,
            "timestamp_utc": ts_raw,
            "interface": iface,
            "can_id": normalized_id,
            "frame_format": fmt,
            "flags": flags,
            "dlc": dlc_val,
            "payload": payload,
        })

    if not records:
        raise ValueError("Capture file contains no frame records.")

    return records


class ApiAnalysisService:
    """Service to score captures, produce reports, and store analysis results."""

    def __init__(self, model_path: Optional[Path] = None, reports_dir: Optional[Path] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.reports_dir = reports_dir or (ROOT / "reports")
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self._analyses: Dict[str, Dict[str, Any]] = {}
        self._report_files: Dict[str, Path] = {}
        self._capture_records: Dict[str, List[Dict[str, Any]]] = {}

    def score_records(
        self,
        records: List[Dict[str, Any]],
        capture_name: str,
        origin: str = "preset",
        analysis_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Score CAN records using the original 14-feature Isolation Forest pipeline."""
        if not self.model_path.is_file():
            raise FileNotFoundError(f"Original model not found at {self.model_path}")

        bundle = joblib.load(self.model_path)
        model = bundle["model"]
        feature_columns = bundle["feature_columns"]

        if list(feature_columns) != FEATURE_COLUMNS:
            raise ValueError("Model feature columns mismatch original schema")

        # Build 1000ms fixed windows anchored to the first frame
        windows = build_window_features(records, WINDOW_MS)
        excluded_partial_window: Optional[int] = None
        if windows:
            discarded = windows.pop()
            excluded_partial_window = int(discarded["window_index"])

        if not windows:
            raise ValueError("Not enough complete windows to score this capture.")

        X = [[float(w[col]) for col in feature_columns] for w in windows]
        predictions = model.predict(X)
        scores = model.score_samples(X)

        # Build exact per-ID evidence using the same window boundaries.
        first_ns = min(record["timestamp_ns"] for record in records)
        window_ns = WINDOW_MS * 1_000_000
        response_counts_by_window = defaultdict(Counter)

        for record in records:
            index = (record["timestamp_ns"] - first_ns) // window_ns
            response_counts_by_window[index][record["can_id"]] += 1

        scored_windows = []
        report_rows = []
        normal_count = 0
        anomaly_count = 0

        for w, pred, score in zip(windows, predictions, scores):
            is_anomaly = (pred == -1)
            pred_label = "ANOMALY" if is_anomaly else "NORMAL"
            anom_score = round(-float(score), 8)

            if is_anomaly:
                anomaly_count += 1
            else:
                normal_count += 1

            window_feats = {col: float(w[col]) for col in FEATURE_COLUMNS}

            id_counts = response_counts_by_window[int(w["window_index"])]
            can_id_counts = dict(sorted(id_counts.items()))
            unexpected_ids = sorted(
                can_id for can_id in id_counts
                if can_id not in KNOWN_IDS
            )

            dominant_id = (
                max(id_counts, key=lambda can_id: (id_counts[can_id], can_id))
                if id_counts else None
            )
            dominant_share = (
                round(id_counts[dominant_id] / sum(id_counts.values()) * 100, 4)
                if dominant_id is not None else 0.0
            )

            response_evidence = {
                "can_id_counts": can_id_counts,
                "unexpected_can_ids": unexpected_ids,
                "dominant_can_id": dominant_id,
                "dominant_can_id_share_pct": dominant_share,
            }

            scored_windows.append({
                "window_index": int(w["window_index"]),
                "window_start_utc": str(w["window_start_utc"]),
                "prediction": pred_label,
                "anomaly_score": anom_score,
                "features": window_feats,
                "explanation": explain_window(window_feats, pred_label),
                "response_evidence": response_evidence,
            })

            # For reports/<capture>_inference.csv
            row_dict = {
                "capture_file": capture_name,
                "window_index": w["window_index"],
                "window_start_utc": w["window_start_utc"],
                "prediction": pred_label,
                "anomaly_score": anom_score,
            }
            row_dict.update(window_feats)
            report_rows.append(row_dict)

        # Generate report CSV file
        aid = analysis_id or f"analysis_{uuid.uuid4().hex[:12]}"
        report_path = self.reports_dir / f"{aid}_inference.csv"
        report_fields = [
            "capture_file",
            "window_index",
            "window_start_utc",
            "prediction",
            "anomaly_score",
            *FEATURE_COLUMNS,
        ]
        with report_path.open("w", newline="", encoding="utf-8") as h:
            writer = csv.DictWriter(h, fieldnames=report_fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(report_rows)

        self._report_files[aid] = report_path

        # Generate frequency summary
        raw_freq = build_frequency_summary(records)
        freq_summary = [format_frequency_row(r) for r in raw_freq]

        model_info = get_model_info(self.model_path)
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        notes = [
            f"Isolation Forest inference on {capture_name} ({origin}).",
            "Prototype predictions on virtual-CAN traffic; detection-only.",
        ]
        if excluded_partial_window is not None:
            notes.append(f"Excluded partial final window index {excluded_partial_window}.")

        result = {
            "id": aid,
            "data_source": "backend",
            "capture_file": capture_name,
            "origin": origin,
            "created_at": created_at,
            "frames_loaded": len(records),
            "windows_scored": len(scored_windows),
            "normal_count": normal_count,
            "anomaly_count": anomaly_count,
            "excluded_partial_window": excluded_partial_window,
            "model": model_info,
            "windows": scored_windows,
            "incidents": correlate_incidents(scored_windows),
            "frequency_summary": freq_summary,
            "notes": notes,
        }

        self._analyses[aid] = result
        self._capture_records[aid] = deepcopy(records)
        return result

    def get_analysis(self, aid: str) -> Optional[Dict[str, Any]]:
        return self._analyses.get(aid)

    def get_capture_records(self, aid: str) -> Optional[List[Dict[str, Any]]]:
        """Return a protected copy of the original capture records."""
        records = self._capture_records.get(aid)
        return deepcopy(records) if records is not None else None

    def list_analyses(self) -> List[Dict[str, Any]]:
        """List summary objects in reverse chronological order."""
        summaries = []
        for a in reversed(list(self._analyses.values())):
            summaries.append({
                "id": a["id"],
                "data_source": a["data_source"],
                "capture_file": a["capture_file"],
                "origin": a["origin"],
                "created_at": a["created_at"],
                "frames_loaded": a["frames_loaded"],
                "windows_scored": a["windows_scored"],
                "normal_count": a["normal_count"],
                "anomaly_count": a["anomaly_count"],
            })
        return summaries

    def get_report_csv_path(self, aid: str) -> Optional[Path]:
        return self._report_files.get(aid)
