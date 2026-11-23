# Day 6 — Automated CAN Capture Validation
Date: 27 October 2026

## Objective
Create a repeatable Python validator for saved CAN capture CSV files.

## Implementation
Created `tests/validate_captures.py`.

The validator checks:
- Expected CSV header and row structure
- UTC timestamp format and validity
- Capture interface is `vcan0`
- CAN identifier syntax and frame format
- Classic CAN DLC and hexadecimal payload length
- Expected IDs and payloads for each test scenario
- Presence of all three expected IDs in normal traffic

## Test Results

| Scenario | Frames checked | Result |
|---|---:|---|
| Fresh-clone normal traffic | 103 | PASS |
| Normal regression | 104 | PASS |
| Fresh-clone high-frequency attack | 977 | PASS |
| High-frequency regression | 2167 | PASS |
| Fresh-clone unexpected extended ID | 52 | PASS |
| Unexpected-ID regression | 87 | PASS |

**Total: 6 passed, 0 failed.**

## Scope and Limitations
The validator checks saved CSV structure and expected scenario content.
It does not train or evaluate an ML detector, verify precise attack timing,
or prove detection accuracy.

All attack simulations and captures referenced by this work used the
virtual CAN interface `vcan0`, not a physical vehicle network.

## Reproduce
Run from the repository root:

`python3 tests/validate_captures.py`
