# Prajwal — Day 3 Notes (14 October 2026)

## Task: Improve Normal CAN Traffic Generator

### Features Implemented
- Configurable transmission interval through command-line arguments.
- Randomized RPM values from 2000 to 4000.
- Randomized vehicle speed values from 0 to 120 km/h.
- Randomized coolant temperature from 80 to 100 C.
- Absolute-deadline scheduling using CLOCK_MONOTONIC.
- Error handling for CAN socket operations and writes.
- Graceful shutdown using Ctrl+C.
- Diagnostic counters for sent frames, skipped periods, and send errors.

### CAN Message Configuration

| CAN ID | Signal | Payload | Default Interval |
|---|---|---|---|
| 0x100 | RPM | 2-byte unsigned big-endian | 100 ms |
| 0x101 | Vehicle Speed | 2-byte unsigned big-endian | 100 ms |
| 0x102 | Coolant Temperature | 2-byte unsigned big-endian | 1000 ms |

The coolant interval is configured as ten times the RPM/speed interval.

### Build Command

    gcc -std=gnu11 -Wall -Wextra -Wpedantic -O2 \
      src/normal_traffic.c -o build/normal_traffic

### Run Commands

    ./build/normal_traffic
    ./build/normal_traffic 10
    ./build/normal_traffic 500

The optional interval must be an integer between 1 and 60000 milliseconds.

### Test Results

**Default interval run**
- RPM frames sent: 741
- Speed frames sent: 741
- Coolant frames sent: 77
- RPM/speed skipped periods: 21 each
- Send errors: 0

**10 ms interval test (approximately 3 seconds)**
- RPM frames sent: 240
- Speed frames sent: 240
- Coolant frames sent: 30
- RPM/speed skipped periods: 61 each
- Coolant skipped periods: 1
- Send errors: 0

**500 ms interval test (approximately 6 seconds)**
- RPM frames sent: 12
- Speed frames sent: 12
- Coolant frames sent: 2
- Skipped periods: 0
- Send errors: 0

Counts are from individual test runs. Scheduling delays in a virtual machine
can cause missed periods, which the scheduler skips rather than sending
catch-up bursts.

### Evidence
- screenshots/prajwal_candump_test.png
- screenshots/prajwal_normal_traffic.png
- screenshots/prajwal_day3_timing_test.png
- screenshots/prajwal_day3_generator_summary.png
- screenshots/prajwal_improved_generator.png

### Safety Scope
All testing was performed on the virtual vcan0 interface.
No physical vehicle or production automotive network was used.

### Next Steps
- Verify the generated traffic using candump.
- Continue the CAN-Sentinel project according to the assigned plan.
