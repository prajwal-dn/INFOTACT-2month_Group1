#!/usr/bin/env python3
"""Train an Isolation Forest baseline and score CAN traffic windows."""

import argparse
import csv
import math
import sys
from pathlib import Path

import joblib
import sklearn
from sklearn.ensemble import IsolationForest

ROOT = Path(__file__).resolve().parents[1]

FEATURE_COLUMNS = [
    "total_frames",
    "unique_can_ids",
    "extended_frame_count",
    "unique_payload_count",
    "max_id_share_pct",
    "id_0x100_count",
    "id_0x100_share_pct",
    "id_0x101_count",
    "id_0x101_share_pct",
    "id_0x102_count",
    "id_0x102_share_pct",
    "id_0x999_count",
    "id_0x999_share_pct",
    "other_id_count",
]


def load_features(path):
    """Read and validate numeric window features."""
    rows = []

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)

        missing = set(FEATURE_COLUMNS) - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"{path} is missing columns: {sorted(missing)}"
            )

        for line_number, row in enumerate(reader, start=2):
            values = []

            for column in FEATURE_COLUMNS:
                try:
                    value = float(row[column])
                except (ValueError, TypeError):
                    raise ValueError(
                        f"{path}, line {line_number}: invalid {column}"
                    )

                if not math.isfinite(value):
                    raise ValueError(
                        f"{path}, line {line_number}: non-finite {column}"
                    )

                values.append(value)

            rows.append({
                "window_index": row.get("window_index", ""),
                "features": values,
            })

    if not rows:
        raise ValueError(f"No feature windows found in {path}")

    # The capture stop time is not stored in the feature CSV.
    # Exclude the last observed window because it may be incomplete.
    if len(rows) > 1:
        discarded = rows.pop()
        print(
            f"INFO: Excluding possible partial final window "
            f"{discarded['window_index']} from {path}"
        )

    return rows


def score_rows(model, records, scenario, source):
    predictions = model.predict(
        [record["features"] for record in records]
    )
    scores = model.score_samples(
        [record["features"] for record in records]
    )

    output = []

    for record, prediction, score in zip(records, predictions, scores):
        output.append({
            "scenario": scenario,
            "source_file": source,
            "window_index": record["window_index"],
            "prediction": (
                "ANOMALY" if prediction == -1 else "NORMAL"
            ),
            # Higher anomaly_score means more unusual to this model.
            "anomaly_score": round(-float(score), 8),
        })

    return output


def main():
    parser = argparse.ArgumentParser(
        description="CAN-Sentinel Isolation Forest prototype"
    )
    parser.add_argument(
        "--normal",
        default="reports/normal_baseline_60s_window_features.csv",
    )
    parser.add_argument(
        "--high-frequency",
        default="reports/high_frequency_capture_window_features.csv",
    )
    parser.add_argument(
        "--unexpected-id",
        default="reports/unexpected_id_capture_window_features.csv",
    )
    parser.add_argument("--contamination", type=float, default=0.02)
    args = parser.parse_args()

    if not 0.0 < args.contamination <= 0.5:
        parser.error("--contamination must be greater than 0 and at most 0.5")

    try:
        normal = load_features(ROOT / args.normal)
        high_frequency = load_features(ROOT / args.high_frequency)
        unexpected_id = load_features(ROOT / args.unexpected_id)

        if len(normal) < 10:
            raise ValueError(
                "At least 10 normal windows are required for this prototype"
            )

        # Preserve chronological order: first 80% trains, final 20% tests.
        split = int(len(normal) * 0.8)
        split = max(1, min(split, len(normal) - 1))

        train_rows = normal[:split]
        normal_test_rows = normal[split:]

        model = IsolationForest(
            n_estimators=200,
            contamination=args.contamination,
            random_state=42,
        )

        model.fit([row["features"] for row in train_rows])

        results = []
        results.extend(score_rows(
            model, normal_test_rows, "normal_holdout", args.normal
        ))
        results.extend(score_rows(
            model, high_frequency, "simulated_high_frequency",
            args.high_frequency
        ))
        results.extend(score_rows(
            model, unexpected_id, "simulated_unexpected_id",
            args.unexpected_id
        ))

        report_path = ROOT / "reports/isolation_forest_scored_windows.csv"
        report_path.parent.mkdir(parents=True, exist_ok=True)

        with report_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "scenario", "source_file",
                    "window_index", "prediction", "anomaly_score",
                ],
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(results)

        model_path = ROOT / "models/isolation_forest_baseline.joblib"
        model_path.parent.mkdir(parents=True, exist_ok=True)

        joblib.dump({
            "model": model,
            "feature_columns": FEATURE_COLUMNS,
            "training_source": args.normal,
            "training_windows": len(train_rows),
            "contamination": args.contamination,
            "sklearn_version": sklearn.__version__,
        }, model_path)

        print("=" * 65)
        print("CAN-SENTINEL ISOLATION FOREST — INITIAL EXPERIMENT")
        print("=" * 65)
        print(f"scikit-learn: {sklearn.__version__}")
        print(f"Normal training windows: {len(train_rows)}")
        print(f"Normal held-out windows: {len(normal_test_rows)}")
        print(f"Contamination setting: {args.contamination}")

        for scenario in (
            "normal_holdout",
            "simulated_high_frequency",
            "simulated_unexpected_id",
        ):
            group = [row for row in results if row["scenario"] == scenario]
            flagged = sum(row["prediction"] == "ANOMALY" for row in group)
            print(
                f"{scenario}: {flagged}/{len(group)} "
                f"windows flagged as anomalous"
            )

        print("\nSaved scored windows:", report_path)
        print("Saved model:", model_path)
        print("\nNOTE: These are preliminary results, not validated accuracy.")

    except (OSError, ValueError, csv.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
