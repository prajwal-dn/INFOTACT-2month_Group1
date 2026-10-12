"""Main entry: parse a candump log and write to CSV."""

import argparse
import sys
from pathlib import Path

from .candump_parser import parse_file
from .csv_logger import CSVLogger


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse candump output into structured CSV."
    )
    parser.add_argument("input", help="Path to candump log file")
    parser.add_argument(
        "-o", "--output",
        default="data/can_log.csv",
        help="Output CSV path (default: data/can_log.csv)",
    )
    parser.add_argument(
        "--show-errors", action="store_true",
        help="Print malformed line details to stderr",
    )
    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"ERROR: input file not found: {args.input}", file=sys.stderr)
        return 1

    frames, errors = parse_file(args.input)
    logger = CSVLogger(args.output)
    written = logger.write(frames)

    print(f"Parsed {len(frames)} frames, {len(errors)} malformed lines.")
    print(f"Wrote {written} rows to {args.output}")

    if errors and args.show_errors:
        print("\nMalformed lines:", file=sys.stderr)
        for lineno, raw, reason in errors:
            print(f"  Line {lineno}: {reason}", file=sys.stderr)
            print(f"    {raw}", file=sys.stderr)

    return 0 if not errors else 2


if __name__ == "__main__":
    sys.exit(main())
