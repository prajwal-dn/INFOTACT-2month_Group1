#!/usr/bin/env python3

import argparse
import csv
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_HEADER = [
    "timestamp_utc",
    "interface",
    "can_id",
    "frame_format",
    "flags",
    "dlc",
    "payload",
]

KNOWN_IDS = ["0x100", "0x101", "0x102", "0x999"]

TIMESTAMP_PATTERN = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?Z$"
)


def timestamp_to_ns(value):
    """Convert a UTC ISO timestamp to integer nanoseconds."""
    match = TIMESTAMP_PATTERN.fullmatch(value.strip())
    if not match:
        raise ValueError(f"Invalid UTC timestamp: {value!r}")

    dt = datetime.strptime(
        match.group("base"), "%Y-%m-%dT%H:%M:%S"
    ).replace(tzinfo=timezone.utc)

    import calendar
    seconds = calendar.timegm(dt.utctimetuple())
    fraction = (match.group("fraction") or "").ljust(9, "0")

    return seconds * 1_000_000_000 + int(fraction or "0")


def ns_to_timestamp(value):
    """Format integer nanoseconds as an ISO UTC timestamp."""
    seconds, nanoseconds = divmod(value, 1_000_000_000)
    base = datetime.fromtimestamp(
        seconds, tz=timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%S")

    return f"{base}.{nanoseconds:09d}Z"


def load_capture(path):
    """Load and validate the expected CAN sniffer CSV format."""
    records = []

    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)

        if reader.fieldnames != EXPECTED_HEADER:
            raise ValueError(
                f"Unexpected CSV header in {path}: {reader.fieldnames}"
            )

        for line_number, row in enumerate(reader, start=2):
            if None in row or any(value is None for value in row.values()):
                raise ValueError(
                    f"Malformed CSV row at line {line_number}"
                )

            try:
                ts_ns = timestamp_to_ns(row["timestamp_utc"])
                can_id_raw = row["can_id"].strip()

                if not re.fullmatch(r"0[xX][0-9a-fA-F]+", can_id_raw):
                    raise ValueError("Invalid CAN ID")

                identifier = int(can_id_raw, 16)
                frame_format = row["frame_format"].strip().lower()

                if frame_format not in {"standard", "extended"}:
                    raise ValueError("Invalid frame format")

                if frame_format == "standard" and identifier > 0x7FF:
                    raise ValueError("Standard CAN ID exceeds 11 bits")

                if frame_format == "extended" and identifier > 0x1FFFFFFF:
                    raise ValueError("Extended CAN ID exceeds 29 bits")

                payload = row["payload"].strip().upper()

                if not re.fullmatch(r"(?:[0-9A-F]{2})*", payload):
                    raise ValueError("Invalid hexadecimal payload")

                dlc = int(row["dlc"])

                if not 0 <= dlc <= 8:
                    raise ValueError("DLC outside classic CAN range 0–8")

                if dlc != len(payload) // 2:
                    raise ValueError("DLC does not match payload length")

                records.append({
                    "timestamp_ns": ts_ns,
                    "timestamp_utc": row["timestamp_utc"].strip(),
                    "interface": row["interface"].strip(),
                    "can_id": f"0x{identifier:x}",
                    "frame_format": frame_format,
                    "payload": payload,
                })

            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"{path}, line {line_number}: {exc}"
                ) from exc

    if not records:
        raise ValueError(f"No data frames found in {path}")

    return records


def write_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def build_frequency_summary(records):
    by_id = defaultdict(list)

    for record in records:
        by_id[record["can_id"]].append(record)

    total_frames = len(records)
    rows = []

    for can_id in sorted(by_id, key=lambda value: int(value, 16)):
        frames = sorted(
            by_id[can_id], key=lambda record: record["timestamp_ns"]
        )

        timestamps = [frame["timestamp_ns"] for frame in frames]
        gaps_ms = [
            (timestamps[i] - timestamps[i - 1]) / 1_000_000
            for i in range(1, len(timestamps))
        ]

        formats = sorted({frame["frame_format"] for frame in frames})
        rows.append({
            "can_id": can_id,
            "frame_format": formats[0] if len(formats) == 1 else "mixed",
            "frame_count": len(frames),
            "percentage_of_total": round(
                len(frames) / total_frames * 100, 4
            ),
            "unique_payload_count": len({
                frame["payload"] for frame in frames
            }),
            "mean_interarrival_ms": (
                round(mean(gaps_ms), 6) if gaps_ms else ""
            ),
            "median_interarrival_ms": (
                round(median(gaps_ms), 6) if gaps_ms else ""
            ),
            "min_interarrival_ms": (
                round(min(gaps_ms), 6) if gaps_ms else ""
            ),
            "max_interarrival_ms": (
                round(max(gaps_ms), 6) if gaps_ms else ""
            ),
        })

    return rows


def build_window_features(records, window_ms):
    """Create fixed-width feature rows anchored to the first frame."""
    window_ns = window_ms * 1_000_000
    first_ns = min(record["timestamp_ns"] for record in records)
    windows = defaultdict(list)

    for record in records:
        index = (record["timestamp_ns"] - first_ns) // window_ns
        windows[index].append(record)

    rows = []

    for index in sorted(windows):
        frames = windows[index]
        total = len(frames)
        counts = Counter(frame["can_id"] for frame in frames)

        row = {
            "window_index": int(index),
            "window_start_utc": ns_to_timestamp(
                first_ns + index * window_ns
            ),
            "window_size_ms": window_ms,
            "total_frames": total,
            "unique_can_ids": len(counts),
            "extended_frame_count": sum(
                frame["frame_format"] == "extended" for frame in frames
            ),
            "unique_payload_count": len({
                frame["payload"] for frame in frames
            }),
            "max_id_share_pct": round(
                max(counts.values()) / total * 100, 4
            ),
        }

        for can_id in KNOWN_IDS:
            count = counts.get(can_id, 0)
            row[f"id_{can_id}_count"] = count
            row[f"id_{can_id}_share_pct"] = round(
                count / total * 100, 4
            )

        row["other_id_count"] = sum(
            count for can_id, count in counts.items()
            if can_id not in KNOWN_IDS
        )

        rows.append(row)

    return rows


def main():
    parser = argparse.ArgumentParser(
        description="Analyze CAN capture frequency and timing."
    )
    parser.add_argument(
        "csv_file", help="Path to a CAN sniffer CSV capture"
    )
    parser.add_argument(
        "--window-ms",
        type=int,
        default=1000,
        help="Feature window size in milliseconds (default: 1000)",
    )
    parser.add_argument(
        "--output-dir",
        default=str(ROOT / "reports"),
        help="Directory for generated reports",
    )
    args = parser.parse_args()

    if args.window_ms <= 0:
        parser.error("--window-ms must be greater than zero")

    input_path = Path(args.csv_file)
    if not input_path.is_absolute():
        input_path = Path.cwd() / input_path

    if not input_path.is_file():
        parser.error(f"Input file not found: {input_path}")

    try:
        records = load_capture(input_path)

        summary = build_frequency_summary(records)
        features = build_window_features(records, args.window_ms)

        output_dir = Path(args.output_dir)
        if not output_dir.is_absolute():
            output_dir = Path.cwd() / output_dir

        summary_path = output_dir / (
            f"{input_path.stem}_frequency_summary.csv"
        )
        features_path = output_dir / (
            f"{input_path.stem}_window_features.csv"
        )

        summary_fields = [
            "can_id", "frame_format", "frame_count",
            "percentage_of_total", "unique_payload_count",
            "mean_interarrival_ms", "median_interarrival_ms",
            "min_interarrival_ms", "max_interarrival_ms",
        ]

        feature_fields = [
            "window_index", "window_start_utc", "window_size_ms",
            "total_frames", "unique_can_ids", "extended_frame_count",
            "unique_payload_count", "max_id_share_pct",
        ]

        for can_id in KNOWN_IDS:
            feature_fields.extend([
                f"id_{can_id}_count",
                f"id_{can_id}_share_pct",
            ])

        feature_fields.append("other_id_count")

        write_csv(summary_path, summary, summary_fields)
        write_csv(features_path, features, feature_fields)

        print("=" * 65)
        print("CAN-SENTINEL FREQUENCY ANALYSIS")
        print("=" * 65)
        print(f"Input: {input_path}")
        print(f"Frames analyzed: {len(records)}")
        print(f"Unique CAN IDs: {len(summary)}")
        print(f"Window size: {args.window_ms} ms")
        print("\nPER-ID SUMMARY")

        for row in summary:
            avg = row["mean_interarrival_ms"]
            avg_text = f"{avg} ms" if avg != "" else "N/A (one frame)"

            print(
                f"{row['can_id']} [{row['frame_format']}]: "
                f"{row['frame_count']} frames, "
                f"{row['percentage_of_total']}%, "
                f"average gap: {avg_text}"
            )

        print("\nReports written:")
        print(f"  Summary: {summary_path}")
        print(f"  Window features: {features_path}")

    except (OSError, ValueError, csv.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
