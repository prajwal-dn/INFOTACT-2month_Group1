"""Write parsed CAN frames to CSV with proper headers and append mode."""

import csv
from pathlib import Path
from .candump_parser import CANFrame


CSV_HEADERS = ["timestamp", "interface", "can_id", "dlc", "payload", "raw_line"]


class CSVLogger:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _needs_header(self) -> bool:
        return not self.path.exists() or self.path.stat().st_size == 0

    def write(self, frames: list[CANFrame]) -> int:
        if not frames:
            return 0

        with open(self.path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            if self._needs_header():
                writer.writeheader()
            for frame in frames:
                writer.writerow({
                    "timestamp": frame.timestamp,
                    "interface": frame.interface,
                    "can_id": frame.can_id,
                    "dlc": frame.dlc,
                    "payload": frame.payload,
                    "raw_line": frame.raw_line,
                })
        return len(frames)

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        with open(self.path, "r", newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))
