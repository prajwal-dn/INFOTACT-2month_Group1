# CAN-Sentinel — Day 3 Timing Improvement

**Contributor:** Prajwal Dn
**Date:** 14 October 2026
**Environment:** Kali Linux in VirtualBox
**Interface:** Virtual SocketCAN `vcan0`

## 1. Objective

Improve the timing scheduler of the normal CAN traffic generator
and measure the intervals between transmitted CAN frames.

## 2. Implementation

The C generator uses Linux SocketCAN, `CLOCK_MONOTONIC`,
and absolute-deadline scheduling.

Each CAN message maintains its own deadline. When the scheduler
wakes up late, expired periods are skipped rather than sending
multiple catch-up frames in a burst.

## 3. Target Traffic

| CAN ID | Signal | Target Interval |
|---|---|---:|
| 0x100 | Engine RPM: 3000 | 100 ms |
| 0x101 | Vehicle speed: 60 km/h | 100 ms |
| 0x102 | Coolant temperature: 90 C | 1000 ms |

## 4. Measured Results

| CAN ID | Frames Captured | Target | Average Interval | Median Interval | Min–Max Interval | Std. Deviation |
|---|---:|---:|---:|---:|---:|---:|
| 0x100 | 100 | 100 ms | 100.16 ms | 99.94 ms | 46.23–152.74 ms | 19.92 ms |
| 0x101 | 100 | 100 ms | 100.16 ms | 99.95 ms | 45.95–153.01 ms | 20.03 ms |
| 0x102 | 10 | 1000 ms | 999.89 ms | 999.08 ms | 952.53–1048.36 ms | 29.92 ms |

## 5. Conclusion

The observed average and median intervals were close to the
configured target intervals for all three message types.

Individual RPM and speed intervals still showed timing variation.
These results demonstrate improved scheduling behaviour during
this test, but do not establish a hard real-time guarantee.

## 6. Evidence and Logs

- `data/day3_claude_timing.log`
- `data/day3_claude_generator.log`
- `screenshots/prajwal_day3_timing_test.png`

## 7. Safety Scope

All testing was performed on the virtual `vcan0` interface.
No physical vehicle or production automotive network was used.

## 8. Generator Diagnostic Summary

A separate diagnostic run of the updated generator reported:

| CAN Signal | Frames Sent | Skipped Periods | Send Errors |
|---|---:|---:|---:|
| Engine RPM (0x100) | 340 | 9 | 0 |
| Vehicle speed (0x101) | 340 | 9 | 0 |
| Coolant temperature (0x102) | 35 | 0 | 0 |

No CAN write errors were reported in this run. RPM and speed missed
periods were skipped rather than sent as catch-up bursts.

These counters represent a separate diagnostic run from the
timing-statistics sample in Section 4.
