#!/usr/bin/env python3

import csv
import re
import sys
from datetime import datetime
from pathlib import Path

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

# Normal traffic must contain all three expected standard CAN IDs.
NORMAL_IDS = {"0x100", "0x101", "0x102"}

TESTS = [
    {
        "file": "data/fresh_clone_normal.csv",
        "scenario": "Normal traffic",
        "profile": "normal",
    },
    {
        "file": "data/normal_regression.csv",
        "scenario": "Normal regression",
        "profile": "normal",
    },
    {
        "file": "data/fresh_clone_high_frequency.csv",
        "scenario": "High-frequency attack",
        "profile": "high_frequency",
    },
    {
        "file": "data/high_frequency_regression.csv",
        "scenario": "High-frequency regression",
        "profile": "high_frequency",
    },
    {
        "file": "data/fresh_clone_unexpected_id.csv",
        "scenario": "Unexpected extended ID",
        "profile": "unexpected_id",
    },
    {
        "file": "data/unexpected_id_regression.csv",
        "scenario": "Unexpected-ID regression",
        "profile": "unexpected_id",
    },
]


def validate_capture(test):
    path = ROOT / test["file"]
    profile = test["profile"]
    errors = []
    frame_ids = set()
    frames = 0

    if not path.is_file():
        return False, 0, [f"File not found: {test['file']}"], set()

    try:
        with path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)

            if reader.fieldnames != EXPECTED_HEADER:
                return False, 0, [
                    f"Unexpected CSV header: {reader.fieldnames}"
                ], set()

            for line_number, row in enumerate(reader, start=2):
                frames += 1

                if None in row or any(value is None for value in row.values()):
                    errors.append(
                        f"Line {line_number}: malformed row or wrong column count"
                    )
                    continue

                timestamp = row["timestamp_utc"].strip()
                interface = row["interface"].strip()
                can_id = row["can_id"].strip().lower()
                frame_format = row["frame_format"].strip().lower()
                payload = row["payload"].strip().upper()

                # Timestamp must be UTC ISO format ending in Z.
                if not re.fullmatch(
                    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
                    r"(?:\.\d{1,9})?Z",
                    timestamp,
                ):
                    errors.append(
                        f"Line {line_number}: invalid UTC timestamp"
                    )
                else:
                    try:
                        datetime.fromisoformat(
                            timestamp[:-1] + "+00:00"
                        )
                    except ValueError:
                        errors.append(
                            f"Line {line_number}: invalid timestamp value"
                        )

                if interface != "vcan0":
                    errors.append(
                        f"Line {line_number}: unexpected interface {interface!r}"
                    )

                # Validate CAN identifier and frame format.
                if not re.fullmatch(r"0x[0-9a-f]+", can_id):
                    errors.append(
                        f"Line {line_number}: invalid CAN ID {can_id!r}"
                    )
                else:
                    identifier = int(can_id, 16)
                    frame_ids.add(can_id)

                    if frame_format == "standard" and identifier > 0x7FF:
                        errors.append(
                            f"Line {line_number}: standard CAN ID exceeds 11 bits"
                        )
                    elif frame_format == "extended" and identifier > 0x1FFFFFFF:
                        errors.append(
                            f"Line {line_number}: extended CAN ID exceeds 29 bits"
                        )
                    elif frame_format not in {"standard", "extended"}:
                        errors.append(
                            f"Line {line_number}: invalid frame format"
                        )

                # Validate classic CAN DLC and hexadecimal payload.
                try:
                    dlc = int(row["dlc"])
                    if not 0 <= dlc <= 8:
                        errors.append(
                            f"Line {line_number}: DLC must be between 0 and 8"
                        )
                    if not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", payload):
                        errors.append(
                            f"Line {line_number}: payload is not valid hexadecimal bytes"
                        )
                    elif len(payload) // 2 != dlc:
                        errors.append(
                            f"Line {line_number}: DLC does not match payload length"
                        )
                except ValueError:
                    errors.append(
                        f"Line {line_number}: DLC is not an integer"
                    )

                # Validate the expected traffic scenario.
                if profile == "normal":
                    if can_id not in NORMAL_IDS:
                        errors.append(
                            f"Line {line_number}: unexpected normal-traffic ID {can_id}"
                        )
                    if frame_format != "standard":
                        errors.append(
                            f"Line {line_number}: normal traffic should use standard IDs"
                        )

                elif profile == "high_frequency":
                    if can_id != "0x100":
                        errors.append(
                            f"Line {line_number}: expected CAN ID 0x100"
                        )
                    if frame_format != "standard":
                        errors.append(
                            f"Line {line_number}: expected standard frame"
                        )
                    if payload != "FFFF":
                        errors.append(
                            f"Line {line_number}: expected payload FFFF"
                        )

                elif profile == "unexpected_id":
                    if can_id != "0x999":
                        errors.append(
                            f"Line {line_number}: expected CAN ID 0x999"
                        )
                    if frame_format != "extended":
                        errors.append(
                            f"Line {line_number}: expected extended frame"
                        )
                    if payload != "DEAD":
                        errors.append(
                            f"Line {line_number}: expected payload DEAD"
                        )

    except (OSError, csv.Error) as exc:
        return False, frames, [f"Unable to read CSV: {exc}"], frame_ids

    if frames == 0:
        errors.append("Capture contains no data frames")

    if profile == "normal":
        missing_ids = NORMAL_IDS - frame_ids
        if missing_ids:
            errors.append(
                "Missing expected normal IDs: "
                + ", ".join(sorted(missing_ids))
            )

    return not errors, frames, errors, frame_ids


def main():
    total_pass = 0
    total_fail = 0

    print("=" * 68)
    print("CAN-SENTINEL CAPTURE REGRESSION VALIDATOR")
    print("=" * 68)

    for test in TESTS:
        passed, frames, errors, frame_ids = validate_capture(test)

        print(f"\n[{ 'PASS' if passed else 'FAIL' }] {test['scenario']}")
        print(f"  File:   {test['file']}")
        print(f"  Frames: {frames}")
        print(
            "  IDs:    " + (", ".join(sorted(frame_ids)) if frame_ids else "none")
        )

        if errors:
            for error in errors[:10]:
                print(f"  ERROR:  {error}")
            if len(errors) > 10:
                print(f"  ... and {len(errors) - 10} more error(s)")
            total_fail += 1
        else:
            total_pass += 1

    print("\n" + "=" * 68)
    print(f"RESULT: {total_pass} passed, {total_fail} failed")
    print("=" * 68)

    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
