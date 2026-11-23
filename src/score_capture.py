#!/usr/bin/env python3
"""Score a saved CAN capture using the trained Isolation Forest model."""

import argparse
import csv
import sys
from pathlib import Path

import joblib

from frequency_analyzer import load_capture, build_window_features

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(
        description="Score a saved CAN capture without retraining."
    )
    parser.add_argument(
        "capture",
        help="Path to a saved CAN sniffer CSV capture",
    )
    parser.add_argument(
        "--model",
        default=str(ROOT / "models/isolation_forest_baseline.joblib"),
        help="Saved Isolation Forest model bundle",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output CSV path (default: reports/<capture>_inference.csv)",
    )
    parser.add_argument(
        "--window-ms",
        type=int,
        default=1000,
        help="Feature window size in milliseconds; trained model uses 1000",
    )
    args = parser.parse_args()

    if args.window_ms != 1000:
        parser.error(
            "This model was trained with 1000 ms windows. "
            "Use --window-ms 1000."
        )

    capture_path = Path(args.capture)
    if not capture_path.is_absolute():
        capture_path = Path.cwd() / capture_path

    model_path = Path(args.model)
    if not model_path.is_absolute():
        model_path = Path.cwd() / model_path

    if not capture_path.is_file():
        parser.error(f"Capture file not found: {capture_path}")

    if not model_path.is_file():
        parser.error(f"Model file not found: {model_path}")

    try:
        bundle = joblib.load(model_path)
        model = bundle["model"]
        feature_columns = bundle["feature_columns"]

        if bundle.get("contamination") != 0.02:
            print(
                "WARNING: Model contamination is "
                f"{bundle.get('contamination')}; expected 0.02.",
                file=sys.stderr,
            )

        records = load_capture(capture_path)

        if any(record["interface"] != "vcan0" for record in records):
            raise ValueError(
                "Capture includes an interface other than vcan0. "
                "This prototype accepts virtual-CAN captures only."
            )

        windows = build_window_features(records, args.window_ms)

        if len(windows) > 1:
            discarded = windows.pop()
            print(
                "INFO: Excluding possible partial final window "
                f"{discarded['window_index']}"
            )

        if not windows:
            raise ValueError(
                "Not enough complete windows to score this capture."
            )

        X = [
            [float(window[column]) for column in feature_columns]
            for window in windows
        ]

        predictions = model.predict(X)
        scores = model.score_samples(X)

        output_path = (
            Path(args.output)
            if args.output
            else ROOT / "reports" / f"{capture_path.stem}_inference.csv"
        )
        if not output_path.is_absolute():
            output_path = Path.cwd() / output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_fields = [
            "capture_file",
            "window_index",
            "window_start_utc",
            "prediction",
            "anomaly_score",
            *feature_columns,
        ]

        rows = []
        for window, prediction, score in zip(
            windows, predictions, scores
        ):
            row = {
                "capture_file": capture_path.name,
                "window_index": window["window_index"],
                "window_start_utc": window["window_start_utc"],
                "prediction": (
                    "ANOMALY" if prediction == -1 else "NORMAL"
                ),
                "anomaly_score": round(-float(score), 8),
            }
            row.update({
                column: window[column] for column in feature_columns
            })
            rows.append(row)

        with output_path.open(
            "w", newline="", encoding="utf-8"
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=output_fields,
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(rows)

        anomaly_count = sum(
            row["prediction"] == "ANOMALY" for row in rows
        )

        print("=" * 60)
        print("CAN-SENTINEL — CAPTURE INFERENCE")
        print("=" * 60)
        print(f"Capture: {capture_path}")
        print(f"Model: {model_path}")
        print(f"Frames loaded: {len(records)}")
        print(f"Windows scored: {len(rows)}")
        print(f"Anomalous windows: {anomaly_count}")
        print(f"Normal windows: {len(rows) - anomaly_count}")
        print(f"Report: {output_path}")
        print(
            "NOTE: Prototype predictions on saved virtual-CAN data; "
            "not validated real-world detection accuracy."
        )

    except (OSError, KeyError, ValueError, csv.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
