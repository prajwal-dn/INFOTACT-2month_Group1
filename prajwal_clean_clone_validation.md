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
