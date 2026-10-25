# CAN-Sentinel Mid-Review Checklist

**Owner:** Prajwal
**Branch:** prajwal
**Project:** CAN-Sentinel — Automotive ECU Intrusion Detection System
**Review window:** 27–30 October 2026 (confirm exact slot)
**Environment:** Kali Linux / isolated virtual CAN (vcan0)

## 1. What Is Implemented

- Virtual CAN interface setup and verification.
- C normal traffic generator for RPM, speed and coolant values.
- C-based SocketCAN sniffer with UTC timestamps and CSV output.
- High-frequency anomaly simulator.
- Unexpected extended CAN ID simulator.
- Regression tests, CSV validation, and test documentation.

## 2. Pre-Demo Checks

Confirm the correct branch and a clean working tree:

    git branch --show-current
    git status --short
    git log -5 --oneline

Verify the virtual interface:

    ip -details link show vcan0

Compile all three C programs:

    mkdir -p build data

    gcc -std=gnu11 -Wall -Wextra -Wpedantic -O2 \
      src/normal_traffic.c -o build/normal_traffic

    gcc -std=gnu11 -Wall -Wextra -Wpedantic -O2 \
      src/can_sniffer.c -o build/can_sniffer

    gcc -std=gnu11 -Wall -Wextra -Wpedantic -O2 \
      src/attack_simulator.c -o build/attack_simulator

## 3. Demo A — Normal CAN Traffic

Run the following commands in the same terminal:

    stdbuf -oL ./build/can_sniffer > data/review_normal.csv &
    SNIFFER_PID=$!

    sleep 1

    timeout 5s stdbuf -oL ./build/normal_traffic \
      > data/review_normal_generator.log 2>&1

    sleep 1
    kill -TERM "$SNIFFER_PID"
    wait "$SNIFFER_PID"

The normal generator runs continuously; timeout after five seconds is
expected. If timeout reports exit code 124, that normally means its
time limit was reached.

Inspect the capture:

    head data/review_normal.csv
    wc -l data/review_normal.csv

Expected CAN IDs include 0x100 (RPM), 0x101 (speed) and 0x102 (coolant).

## 4. Demo B — High-Frequency Scenario

Run in the same terminal:

    stdbuf -oL ./build/can_sniffer > data/review_high_frequency.csv &
    SNIFFER_PID=$!

    sleep 1

    stdbuf -oL ./build/attack_simulator 1 \
      > data/review_high_frequency.log 2>&1 &
    ATTACK_PID=$!

    sleep 5
    kill -INT "$ATTACK_PID"
    wait "$ATTACK_PID"

    sleep 1
    kill -TERM "$SNIFFER_PID"
    wait "$SNIFFER_PID"

Inspect results:

    head data/review_high_frequency.csv
    tail data/review_high_frequency.log
    wc -l data/review_high_frequency.csv

Expected: CAN ID 0x100 with payload FFFF. Target interval is 1 ms;
actual observed timing may differ in a virtual machine.

## 5. Demo C — Unexpected Extended CAN ID

Run in the same terminal:

    stdbuf -oL ./build/can_sniffer > data/review_extended_id.csv &
    SNIFFER_PID=$!

    sleep 1

    stdbuf -oL ./build/attack_simulator 2 \
      > data/review_extended_id.log 2>&1 &
    ATTACK_PID=$!

    sleep 5
    kill -INT "$ATTACK_PID"
    wait "$ATTACK_PID"

    sleep 1
    kill -TERM "$SNIFFER_PID"
    wait "$SNIFFER_PID"

Inspect results:

    head data/review_extended_id.csv
    tail data/review_extended_id.log
    wc -l data/review_extended_id.csv

Expected: CAN ID 0x999, extended frame format, payload DEAD.
Target interval is 50 ms; actual observed timing may vary.

## 6. Explain the Architecture

Current implemented pipeline:

Normal traffic generator or simulated anomaly traffic
    -> Linux SocketCAN virtual interface (vcan0)
    -> C CAN sniffer
    -> Timestamped CSV capture

Planned integration:

CSV/structured frame events
    -> Python feature extraction and anomaly detector
    -> Dashboard displaying traffic and detection evidence

Do not claim that the planned ML detector or dashboard is integrated
until the team can demonstrate that it actually works.

## 7. Technical Viva Questions

Q: Why use vcan0?
A: It allows repeatable CAN-frame simulations without connecting to a
physical vehicle or production CAN network.

Q: What does the sniffer record?
A: UTC timestamp, interface, CAN ID, frame format, flags, DLC and
payload.

Q: What does DLC mean?
A: Data Length Code; for the classic CAN frames used here, it indicates
the payload length in bytes.

Q: Why is 0x999 an extended ID?
A: It is greater than the largest 11-bit standard identifier, 0x7FF.
The simulator sets the extended-frame flag.

Q: Does a successful capture prove the attack was detected?
A: No. It proves the frame was generated and captured. Detection must
be evaluated separately using a working detector and measured results.

Q: Why do observed intervals differ from the target?
A: The simulator and sniffer run in user space, and virtual-machine
scheduling introduces timing variation.

Q: What remains?
A: Verify the team's Python logger/model status, agree the C-to-Python
integration contract, integrate detection, and demonstrate dashboard
alerts once available.

## 8. Evidence to Keep Ready

- Screenshot of vcan0 in the UP state.
- Screenshot of normal traffic generation and capture.
- Screenshot of the high-frequency scenario and its summary.
- Screenshot of the unexpected extended-ID scenario and its summary.
- CSV files and regression notes.
- GitHub branch and commit history.
- README and architecture explanation.

## 9. Safety and Reporting

All attack-like tests must remain on isolated vcan0. No physical
vehicle or live automotive network may be targeted.

Report observed results honestly. Capture success and CSV validation
do not establish ML precision, recall, or detection accuracy.

Keep work on branch prajwal. Do not merge to main before the team
receives permission to merge.
