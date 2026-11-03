#!/usr/bin/env python3
"""Live CAN inference using the original CAN-Sentinel Isolation Forest."""

import argparse
import json
import socket
import sys
from pathlib import Path

import joblib

if __package__:
    from .frequency_analyzer import (
        build_window_features,
        ns_to_timestamp,
        timestamp_to_ns,
    )
    from .isolation_forest_detector import FEATURE_COLUMNS
    from .socket_receiver import (
        SOCKET_PATH,
        remove_stale_socket,
        validate_event,
    )
else:
    from frequency_analyzer import (
        build_window_features,
        ns_to_timestamp,
        timestamp_to_ns,
    )
    from isolation_forest_detector import FEATURE_COLUMNS
    from socket_receiver import (
        SOCKET_PATH,
        remove_stale_socket,
        validate_event,
    )


ROOT = Path(__file__).resolve().parents[1]
WINDOW_MS = 1000
WINDOW_NS = WINDOW_MS * 1_000_000


def load_model(model_path):
    """Load and validate the existing model bundle without retraining."""
    path = Path(model_path)

    if not path.is_absolute():
        path = ROOT / path

    if not path.is_file():
        raise FileNotFoundError(f"Model not found: {path}")

    bundle = joblib.load(path)

    if not isinstance(bundle, dict):
        raise ValueError("Unexpected model bundle format")

    model = bundle.get("model")
    columns = bundle.get("feature_columns")

    if model is None or columns is None:
        raise ValueError("Model bundle is missing model or feature_columns")

    if list(columns) != FEATURE_COLUMNS:
        raise ValueError(
            "Model feature columns do not match the original 14-feature schema"
        )

    if bundle.get("contamination") != 0.02:
        raise ValueError("Expected original model contamination of 0.02")

    return model, list(columns), path


def event_to_record(event):
    """Convert a validated socket event to the analyzer's record format."""
    timestamp_ns = timestamp_to_ns(event["timestamp_utc"])

    identifier = int(event["can_id"], 16)

    return {
        "timestamp_ns": timestamp_ns,
        "timestamp_utc": event["timestamp_utc"],
        "interface": event["interface"],
        "can_id": f"0x{identifier:x}",
        "frame_format": event["frame_format"],
        "payload": event["payload"],
    }


def score_window(model, feature_columns, records, window_index, anchor_ns):
    """Score one completed one-second window using original features."""
    windows = build_window_features(records, WINDOW_MS)

    if len(windows) != 1:
        raise ValueError(
            f"Expected one feature row for live window, received {len(windows)}"
        )

    features = windows[0]

    X = [[float(features[column]) for column in feature_columns]]

    prediction = int(model.predict(X)[0])
    raw_score = float(model.score_samples(X)[0])
    anomaly_score = -raw_score

    label = "ANOMALY" if prediction == -1 else "NORMAL"
    window_start = ns_to_timestamp(anchor_ns + window_index * WINDOW_NS)

    print(
        f"Window {window_index:04d} | "
        f"{label:7s} | "
        f"frames={features['total_frames']:4d} | "
        f"anomaly_score={anomaly_score:.8f} | "
        f"start={window_start}",
        flush=True,
    )

    return label


def run_receiver(model, feature_columns, expected_count):
    """Receive, validate, bucket and score live CAN events."""
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    accepted = 0
    scored = 0
    anomalies = 0
    normal = 0

    anchor_ns = None
    current_index = None
    current_records = []
    previous_timestamp_ns = None

    try:
        remove_stale_socket(SOCKET_PATH)
        server.bind(SOCKET_PATH)
        Path(SOCKET_PATH).chmod(0o600)
        server.listen(1)

        print(f"Live inference listening on {SOCKET_PATH}")
        print("Interface restriction: vcan0")
        print(f"Feature window: {WINDOW_MS} ms")
        print(f"Model: original 14-feature Isolation Forest")
        print("Waiting for production C sniffer...\n", flush=True)

        connection, _ = server.accept()

        with connection:
            buffer = b""

            while expected_count == 0 or accepted < expected_count:
                chunk = connection.recv(4096)

                if not chunk:
                    if buffer:
                        raise ValueError(
                            "Connection ended with incomplete JSON line"
                        )
                    break

                buffer += chunk

                if len(buffer) > 1_048_576:
                    raise ValueError("Unprocessed socket buffer exceeded 1 MB")

                while b"\n" in buffer and (
                    expected_count == 0 or accepted < expected_count
                ):
                    raw_line, buffer = buffer.split(b"\n", 1)

                    if not raw_line:
                        raise ValueError("Empty JSON message received")

                    event = validate_event(json.loads(raw_line))
                    record = event_to_record(event)

                    timestamp_ns = record["timestamp_ns"]

                    if (
                        previous_timestamp_ns is not None
                        and timestamp_ns < previous_timestamp_ns
                    ):
                        raise ValueError(
                            "CAN event timestamps moved backwards; "
                            "cannot safely construct fixed windows"
                        )

                    previous_timestamp_ns = timestamp_ns
                    accepted += 1

                    if anchor_ns is None:
                        anchor_ns = timestamp_ns
                        current_index = 0

                    window_index = (timestamp_ns - anchor_ns) // WINDOW_NS

                    if window_index < current_index:
                        raise ValueError("Out-of-order window received")

                    if window_index > current_index:
                        # A timestamp in the next window proves that the
                        # previous window has finished.
                        label = score_window(
                            model,
                            feature_columns,
                            current_records,
                            current_index,
                            anchor_ns,
                        )

                        scored += 1

                        if label == "ANOMALY":
                            anomalies += 1
                        else:
                            normal += 1

                        current_index = window_index
                        current_records = []

                    current_records.append(record)

        print("\n" + "=" * 60)
        print("CAN-SENTINEL — LIVE INFERENCE SUMMARY")
        print("=" * 60)
        print(f"Events received:       {accepted}")
        print(f"Completed windows:     {scored}")
        print(f"Normal windows:        {normal}")
        print(f"Anomalous windows:     {anomalies}")

        if current_records:
            print(
                f"Final possible partial window discarded: {current_index}"
            )

        if scored:
            print("Inference completed using the original saved model.")
        else:
            print("No complete one-second windows were available.")

        print(
            "NOTE: Prototype predictions on isolated virtual-CAN traffic; "
            "not validated real-world detection accuracy."
        )

    finally:
        server.close()
        Path(SOCKET_PATH).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(
        description="Live CAN-Sentinel Isolation Forest inference"
    )

    parser.add_argument(
        "--model",
        default=str(ROOT / "models/isolation_forest_baseline.joblib"),
        help="Original saved model bundle",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Maximum events to receive; 0 means unlimited",
    )

    args = parser.parse_args()

    if args.count < 0:
        parser.error("--count must be zero or a positive integer")

    try:
        model, feature_columns, model_path = load_model(args.model)

        print(f"Loaded model: {model_path}")
        print(f"Feature count: {len(feature_columns)}")

        run_receiver(model, feature_columns, args.count)

    except KeyboardInterrupt:
        print("\nLive inference interrupted.", file=sys.stderr)
        return 130

    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
