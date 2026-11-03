# CAN-Sentinel C-to-Python Integration Contract

## 1. Purpose

Define a local communication interface between the C CAN sniffer
(producer) and the Python processing pipeline (consumer).

Transport: Unix domain stream socket (AF_UNIX, SOCK_STREAM).
Message framing: One JSON object per line, terminated by '\n'.
Contract version: 1.
Socket path: /tmp/can_sentinel.sock.

## 2. Message schema

Each message represents one CAN data frame.

{
  "schema_version": 1,
  "event_type": "can_frame",
  "timestamp_utc": "2026-10-31T18:20:30.123456789Z",
  "interface": "vcan0",
  "can_id": "0x100",
  "frame_format": "standard",
  "flags": "none",
  "dlc": 2,
  "payload": "FFFF"
}

## 3. Field definitions

- schema_version: Integer. Must be 1.
- event_type: String. Must be "can_frame".
- timestamp_utc: UTC ISO-8601 timestamp with nanosecond precision.
- interface: String. Must be "vcan0".
- can_id: Hexadecimal string, such as "0x100".
- frame_format: "standard" or "extended".
- flags: String. Version 1 supports "none".
- dlc: Integer from 0 to 8.
- payload: Uppercase hexadecimal bytes. Length must equal dlc * 2.

## 4. Validation

The receiver must reject:
- Unsupported schema versions or event types.
- Interfaces other than vcan0.
- Invalid UTC timestamps.
- Invalid CAN identifiers or identifier ranges.
- Unsupported frame formats.
- Unsupported flags.
- DLC values outside 0-8.
- Invalid payload characters or payload/DLC mismatches.
- Malformed JSON messages.

Version 1 supports standard and extended data frames only.
CAN error frames and remote-transmission frames are outside
the initial contract.

## 5. Transport behavior

- One JSON event per newline.
- A stream may contain multiple consecutive events.
- The receiver must handle messages split across recv() calls.
- The receiver must not assume one recv() equals one event.
- A connection ending with an incomplete JSON line is invalid.
- The receiver uses a local socket with restricted permissions.

## 6. CSV compatibility

The seven CAN fields preserve the existing analyzer's CSV schema:

timestamp_utc,interface,can_id,frame_format,flags,dlc,payload

The Python integration layer can convert validated JSON events
into this existing CSV format without changing the detector.

## 7. Safety and scope

- All CAN traffic testing is restricted to vcan0.
- Initial IPC testing uses synthetic sample events only.
- No physical vehicle interface is used.
- This contract does not implement CAN blocking or prevention.

## 8. Initial acceptance test

A C test client sends two valid sample events through the Unix socket.
The Python receiver validates and displays both events.
The original CAN sniffer, CSV parser, and ML model remain unchanged.
