#!/usr/bin/env python3

import argparse
import json
import re
import socket
import stat
from datetime import datetime
from pathlib import Path

SOCKET_PATH = "/tmp/can_sentinel.sock"

EXPECTED_FIELDS = {
    "schema_version",
    "event_type",
    "timestamp_utc",
    "interface",
    "can_id",
    "frame_format",
    "flags",
    "dlc",
    "payload",
}

TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,9})?Z$"
)


def validate_event(event):
    if not isinstance(event, dict):
        raise ValueError("Event must be a JSON object")

    if set(event) != EXPECTED_FIELDS:
        raise ValueError("Unexpected or missing event fields")

    if type(event["schema_version"]) is not int or event["schema_version"] != 1:
        raise ValueError("Unsupported schema version")

    if event["event_type"] != "can_frame":
        raise ValueError("Unsupported event type")

    timestamp = event["timestamp_utc"]
    if not isinstance(timestamp, str) or not TIMESTAMP_PATTERN.fullmatch(timestamp):
        raise ValueError("Invalid UTC timestamp format")

    try:
        datetime.strptime(timestamp[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise ValueError("Invalid UTC timestamp value") from exc

    if event["interface"] != "vcan0":
        raise ValueError("Only vcan0 is permitted")

    can_id = event["can_id"]
    if not isinstance(can_id, str) or not re.fullmatch(
        r"0[xX][0-9a-fA-F]+", can_id
    ):
        raise ValueError("Invalid CAN identifier")

    identifier = int(can_id, 16)
    frame_format = event["frame_format"]

    if frame_format == "standard":
        if identifier > 0x7FF:
            raise ValueError("Standard CAN ID exceeds 11 bits")
    elif frame_format == "extended":
        if identifier > 0x1FFFFFFF:
            raise ValueError("Extended CAN ID exceeds 29 bits")
    else:
        raise ValueError("Unsupported frame format")

    if event["flags"] != "none":
        raise ValueError("Version 1 supports flags=none only")

    dlc = event["dlc"]
    if type(dlc) is not int or not 0 <= dlc <= 8:
        raise ValueError("DLC must be an integer from 0 to 8")

    payload = event["payload"]
    if not isinstance(payload, str) or not re.fullmatch(
        r"(?:[0-9A-F]{2})*", payload
    ):
        raise ValueError("Payload must contain uppercase hexadecimal bytes")

    if len(payload) != dlc * 2:
        raise ValueError("Payload length does not match DLC")

    return event


def remove_stale_socket(path):
    socket_file = Path(path)

    if socket_file.exists():
        if not stat.S_ISSOCK(socket_file.lstat().st_mode):
            raise RuntimeError(f"Refusing to remove non-socket path: {path}")
        socket_file.unlink()


def run_receiver(expected_count):
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    try:
        remove_stale_socket(SOCKET_PATH)
        server.bind(SOCKET_PATH)
        Path(SOCKET_PATH).chmod(0o600)
        server.listen(1)

        print(f"Listening on {SOCKET_PATH}")
        print("Waiting for C sample producer...")

        accepted = 0
        with server.accept()[0] as connection:
            buffer = b""

            while accepted < expected_count:
                chunk = connection.recv(4096)

                if not chunk:
                    if buffer:
                        raise ValueError("Connection ended with incomplete JSON line")
                    break

                buffer += chunk

                while b"\n" in buffer and accepted < expected_count:
                    raw_line, buffer = buffer.split(b"\n", 1)

                    if not raw_line:
                        raise ValueError("Empty message received")

                    event = validate_event(json.loads(raw_line))
                    accepted += 1

                    print(
                        f"ACCEPTED {accepted}: "
                        f"{event['can_id']} "
                        f"{event['frame_format']} "
                        f"payload={event['payload']} "
                        f"timestamp={event['timestamp_utc']}"
                    )

            if accepted != expected_count:
                raise RuntimeError(
                    f"Expected {expected_count} events, received {accepted}"
                )

        print(f"SUCCESS: received and validated {accepted} events")

    finally:
        server.close()
        Path(SOCKET_PATH).unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=2)
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be at least 1")

    run_receiver(args.count)
