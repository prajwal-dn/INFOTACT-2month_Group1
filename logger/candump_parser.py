"""Parse raw candump output lines into structured CAN frame records."""

from dataclasses import dataclass
from datetime import datetime
import re


CANDUMP_PATTERN = re.compile(
    r"^\s*(?P<iface>\w+)\s+"
    r"(?P<can_id>[0-9A-Fa-f]{3,8})\s+"
    r"\[(?P<dlc>\d)\]\s+"
    r"(?P<payload>(?:[0-9A-Fa-f]{2}\s*)*)$"
)


@dataclass
class CANFrame:
    timestamp: str
    interface: str
    can_id: str
    dlc: int
    payload: str
    raw_line: str


class CandumpParseError(ValueError):
    pass


def parse_line(line: str, timestamp: str | None = None) -> CANFrame:
    if not line or not line.strip():
        raise CandumpParseError("Empty line")

    match = CANDUMP_PATTERN.match(line.strip())
    if not match:
        raise CandumpParseError(f"Malformed candump line: {line!r}")

    can_id = match.group("can_id").upper()
    dlc = int(match.group("dlc"))

    raw_payload = match.group("payload").split()
    payload_bytes = [b.upper().zfill(2) for b in raw_payload]

    if len(payload_bytes) != dlc:
        raise CandumpParseError(
            f"DLC mismatch: declared {dlc}, found {len(payload_bytes)} bytes"
        )

    if dlc > 8:
        raise CandumpParseError(f"Invalid DLC {dlc} (max 8 for classic CAN)")

    return CANFrame(
        timestamp=timestamp or datetime.utcnow().isoformat(timespec="milliseconds"),
        interface=match.group("iface"),
        can_id=can_id,
        dlc=dlc,
        payload=" ".join(payload_bytes),
        raw_line=line.rstrip("\n"),
    )


def parse_file(path: str):
    frames = []
    errors = []

    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                frames.append(parse_line(line))
            except CandumpParseError as e:
                errors.append((lineno, line.rstrip("\n"), str(e)))

    return frames, errors
