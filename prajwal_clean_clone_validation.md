# CAN-Sentinel — Clean-Clone Validation

**Date:** 25 October 2026
**Owner:** Prajwal
**Branch:** prajwal
**Environment:** Kali Linux / virtual SocketCAN (`vcan0`)

## Objective

Verify that the pushed repository can be cloned, compiled, and used
to capture normal CAN traffic in a separate checkout.

## Build Verification

Cloned the `prajwal` branch into a separate directory and successfully
compiled all three C programs:

- `src/normal_traffic.c`
- `src/can_sniffer.c`
- `src/attack_simulator.c`

The README was present in the clean clone.

## Normal Traffic Capture

After recreating and bringing up the virtual `vcan0` interface,
ran the normal traffic generator for approximately five seconds
while the C sniffer captured frames.

Observed frame counts:

- CAN ID 0x100: 49 frames
- CAN ID 0x101: 49 frames
- CAN ID 0x102: 5 frames
- Total: 103 frames

CSV validation result:

- Required CSV header: correct
- Malformed/invalid rows: 0
- Missing timestamps: 0
- Expected CAN IDs present: yes
- Result: PASS

## Evidence Files

- `data/fresh_clone_normal.csv`
- `data/fresh_clone_generator.log`

## Conclusion

The code compiled successfully and the normal traffic capture worked
from a separate Git clone after the virtual CAN interface was set up.

The virtual interface is a Linux runtime resource and must be created
and brought up separately on a new environment.

## Safety

All traffic was generated and captured on the isolated virtual
`vcan0` interface. No physical vehicle or production CAN network
was used.

## Fresh-Clone Attack Regression Tests — 26 October 2026

Both attack regression tests were executed from a separate fresh clone of the repository, using the virtual CAN interface `vcan0`.

### High-Frequency Standard-ID Test

- Simulator mode: 1
- Expected CAN ID: `0x100` (standard)
- Expected payload: `FFFF`
- Frames captured: 977
- Simulator-reported frames sent: 977
- Invalid CSV rows: 0
- Missing timestamps: 0
- Write errors: 0
- Result: PASS

### Unexpected Extended-ID Test

- Simulator mode: 2
- Expected CAN ID: `0x999` (extended)
- Expected payload: `DEAD`
- Frames captured: 52
- Simulator-reported frames sent: 52
- Invalid CSV rows: 0
- Missing timestamps: 0
- Write errors: 0
- Result: PASS

### Evidence Files

- `data/fresh_clone_high_frequency.csv`
- `data/fresh_clone_high_frequency.log`
- `data/fresh_clone_unexpected_id.csv`
- `data/fresh_clone_unexpected_id.log`

Both captures were validated with Python CSV checks. All tests were performed on `vcan0`, not on a physical vehicle network. The observed timing is subject to Linux userspace scheduling and virtual-machine overhead.
