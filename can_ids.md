# CAN-Sentinel — CAN ID Mapping

**Contributor:** Prajwal Dn  
**Purpose:** Define the initial CAN messages used by the virtual traffic simulator.

## 1. Signal Mapping

| CAN ID | Signal | Payload Size | Frequency | Encoding |
|---|---|---|---|---|
| 0x100 | Engine RPM | 2 bytes | 10 Hz | Unsigned, big-endian |
| 0x101 | Vehicle Speed | 2 bytes | 10 Hz | Unsigned, big-endian |
| 0x102 | Coolant Temperature | 2 bytes | 1 Hz | Unsigned, big-endian |
| 0x200 | Brake Status | 1 byte | 10 Hz | 00 = released, 01 = pressed |
| 0x201 | Steering Angle | 2 bytes | 10 Hz | Signed, big-endian |

## 2. Example Values

| Signal | Example Value | Payload Bytes |
|---|---:|---|
| Engine RPM | 3000 RPM | 0B B8 |
| Vehicle Speed | 60 km/h | 00 3C |
| Coolant Temperature | 90 C | 00 5A |

## 3. Initial Implementation Scope

The first C traffic generator will implement:

- CAN ID 0x100 for engine RPM.
- CAN ID 0x101 for vehicle speed.
- CAN ID 0x102 for coolant temperature.

RPM and speed messages will be sent every 100 milliseconds.
Coolant temperature will be sent every second.

## 4. Planned Virtual Test Scenarios

- High-frequency messages on CAN ID 0x100.
- Unexpected CAN ID 0x999.
- Repeated brake-status messages on CAN ID 0x200.

These are planned tests on the virtual vcan0 interface only.

## 5. Notes

These identifiers and formats are the initial conventions for this
project's simulator, not universal automotive CAN standards.
Steering-angle scaling and units will be defined before that signal
is implemented.
