# CAN-Sentinel — Day 5 Regression Testing

**Date:** 24 October 2026
**Owner:** Prajwal
**Branch:** prajwal
**Environment:** Kali Linux / isolated virtual SocketCAN (vcan0)

## Objective
Regression-test the normal traffic generator, C CAN sniffer,
and simulated anomaly traffic after implementation.

## Test 1: Normal Traffic
- Result: Basic CSV validation passed.
- The capture contains normal traffic from the virtual CAN generator.
- The CSV header, rows, timestamps, and captured CAN IDs were checked.
- Evidence: data/normal_regression.csv
- Generator log: data/normal_generator_regression.log

## Test 2: High-Frequency Traffic
- Mode: 1
- Target interval: 1 ms
- CAN ID: 0x100
- Payload: FFFF
- Frames sent: 2167
- Frames captured: 2167
- Write errors: 0
- Invalid rows: 0
- Missing timestamps: 0
- Average observed interval: 2.307 ms
- Median observed interval: 2.074 ms
- Validation: PASS
- Evidence: data/high_frequency_regression.csv
- Generator log: data/high_frequency_generator.log

## Test 3: Unexpected Extended CAN ID
- Mode: 2
- Target interval: 50 ms
- CAN ID: 0x999
- Frame format: extended
- Payload: DEAD
- Frames sent: 87
- Frames captured: 87
- Write errors: 0
- Invalid rows: 0
- Missing timestamps: 0
- Average observed interval: 58.323 ms
- Median observed interval: 52.344 ms
- Minimum observed interval: 49.659 ms
- Maximum observed interval: 128.340 ms
- Validation: PASS
- Evidence: data/unexpected_id_regression.csv
- Generator log: data/unexpected_id_generator.log

## Limitations
The simulator's target intervals are not guaranteed transmission
intervals. Observed timing can vary because of virtual-machine
scheduling and user-space capture timing. Results are reported as
measured, not as proof of exact timing.

These tests validate traffic generation, capture, and CSV structure.
They do not by themselves prove that a machine-learning detector
can accurately classify attacks.

## Safety
All regression tests were performed on the isolated virtual
vcan0 interface. No physical vehicle or production CAN network
was used.

## Next Steps
- Review test evidence and preserve screenshots.
- Run the existing regression checks again if code changes.
- Continue anomaly-detector integration and evaluation.
- Commit and push the results to the prajwal branch.
