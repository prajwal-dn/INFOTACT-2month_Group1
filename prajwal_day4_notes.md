# Prajwal — Day 4 Notes (15 October 2026)

## Task: Virtual CAN Attack Simulator

### Objective
Create a C program to generate simulated abnormal CAN traffic
on the isolated virtual vcan0 interface.

### Implementation
Source file: src/attack_simulator.c
Executable: build/attack_simulator

The program supports two modes:

1. High-frequency mode
   - CAN ID: 0x100
   - Payload: FF FF
   - Target interval: 1 ms

2. Unexpected extended-ID mode
   - CAN ID: 0x999 (extended identifier)
   - Payload: DE AD
   - Target interval: 50 ms

The identifier 0x999 is represented as an extended CAN frame because
it exceeds the maximum standard 11-bit CAN identifier.

### Build Command

    gcc -std=gnu11 -Wall -Wextra -Wpedantic -O2 \
      src/attack_simulator.c -o build/attack_simulator

### Run Commands

    ./build/attack_simulator 1
    ./build/attack_simulator 2

Press Ctrl+C to stop either mode. The program prints sent-frame
and write-error counters when it stops.

### Observed Test Results

High-frequency mode:
- Frames sent: 59,756
- Write errors: 0

Unexpected extended-ID mode:
- Frames sent: 260
- Write errors: 0

These are the counters from the observed runs. They do not by
themselves prove the exact transmission interval or receiver-side
capture count.

### Evidence

Screenshot: screenshots/prajwal_attack_simulator.png

### Safety Scope

All testing is restricted to the virtual vcan0 interface.
No physical vehicle or production automotive network was used.

### Next Steps

- Capture attack traffic and convert it to CSV for analysis.
- Train the anomaly-detection model using normal and attack data.
