# CAN-Sentinel
## Automotive ECU Intrusion Detection System

CAN-Sentinel is a cybersecurity project for generating and monitoring
simulated Controller Area Network (CAN) traffic. The current C modules
run on Linux SocketCAN using the isolated virtual interface `vcan0`.

The project establishes a foundation for testing unusual CAN message
frequency and unexpected CAN identifiers.

## Current Implementation

- `src/normal_traffic.c`: generates simulated RPM, vehicle speed and
  coolant-temperature messages.
- `src/can_sniffer.c`: captures CAN frames and writes CSV records with
  UTC timestamps, interface, CAN ID, frame format, flags, DLC and payload.
- `src/attack_simulator.c`: generates two controlled anomaly scenarios.
- `can_ids.md`: documents the project's simulated CAN message conventions.
- `prajwal_day5_regression.md`: records regression test results and
  measured timing limitations.

The Python machine-learning detector and graphical dashboard are
future integration components; do not assume they are already connected
to this C pipeline.

## Architecture

Normal traffic generator or controlled anomaly simulator
    -> Linux SocketCAN virtual interface (`vcan0`)
    -> C CAN sniffer
    -> timestamped CSV capture
    -> planned Python analysis and detection
    -> planned PyQt dashboard and alerts

## Requirements

- Linux with SocketCAN and virtual CAN (`vcan`) support
- GCC compiler
- `iproute2` utilities
- `can-utils` for optional `candump` and `cansend` smoke tests

## 1. Set Up the Virtual CAN Interface

Load the virtual CAN module:

    sudo modprobe vcan

Create `vcan0` if it does not already exist:

    ip link show vcan0

If the preceding command reports that `vcan0` does not exist, run:

    sudo ip link add dev vcan0 type vcan

Bring the interface up:

    sudo ip link set up vcan0

Verify it:

    ip -details link show vcan0

The interface should display the `UP` flag.

## 2. Compile the C Programs

From the repository root, run:

    mkdir -p build data

    gcc -std=gnu11 -Wall -Wextra -Wpedantic -O2 \
      src/normal_traffic.c -o build/normal_traffic

    gcc -std=gnu11 -Wall -Wextra -Wpedantic -O2 \
      src/can_sniffer.c -o build/can_sniffer

    gcc -std=gnu11 -Wall -Wextra -Wpedantic -O2 \
      src/attack_simulator.c -o build/attack_simulator

The `build/` directory contains local compiled binaries and is ignored
by Git.

## 3. Normal Traffic Generator

Run with the default interval:

    ./build/normal_traffic

Stop with Ctrl+C.

Optionally specify the RPM and speed interval in milliseconds:

    ./build/normal_traffic 100
    ./build/normal_traffic 500

The accepted interval is 1 through 60000 milliseconds. Coolant
messages are scheduled every ten intervals.

Simulated message conventions:

| CAN ID | Signal | Payload size | Default interval |
|---|---|---:|---:|
| `0x100` | RPM | 2 bytes | 100 ms |
| `0x101` | Vehicle speed | 2 bytes | 100 ms |
| `0x102` | Coolant temperature | 2 bytes | 1000 ms |

Values are encoded as unsigned big-endian two-byte integers. The
generator uses simulated ranges: RPM 2000-4000, speed 0-120 km/h,
and coolant temperature 80-100 C.

## 4. Capture Normal Traffic

Start the sniffer and save its output:

    stdbuf -oL ./build/can_sniffer > data/normal_demo.csv &
    SNIFFER_PID=$!

Give it a moment to start, then run the generator for five seconds:

    sleep 1
    timeout 5s stdbuf -oL ./build/normal_traffic \
      > data/normal_generator_demo.log 2>&1
    sleep 1

Stop the sniffer gracefully:

    kill -TERM "$SNIFFER_PID"
    wait "$SNIFFER_PID"

The generator is designed to run until stopped, so a timeout after five
seconds is expected. Check the capture:

    head data/normal_demo.csv
    wc -l data/normal_demo.csv

The first CSV line is the header; subsequent lines are captured frames.

## 5. Simulated Anomaly Scenarios

All scenarios below run exclusively on the isolated virtual interface
`vcan0`. Each example starts and stops the sniffer and simulator from
the same terminal so that their process IDs remain available.

### Mode 1: High-frequency messages

Run a five-second capture:

    rm -f data/high_frequency_demo.csv data/high_frequency_demo.log

    stdbuf -oL ./build/can_sniffer \
      > data/high_frequency_demo.csv &
    SNIFFER_PID=$!

    sleep 1

    stdbuf -oL ./build/attack_simulator 1 \
      > data/high_frequency_demo.log 2>&1 &
    ATTACK_PID=$!

    sleep 5
    kill -INT "$ATTACK_PID"
    wait "$ATTACK_PID"
    sleep 1

    kill -TERM "$SNIFFER_PID"
    wait "$SNIFFER_PID"

Mode 1 sends CAN ID `0x100`, payload `FFFF`, with a target interval
of 1 ms.

### Mode 2: Unexpected extended CAN ID

Run a five-second capture:

    rm -f data/unexpected_id_demo.csv data/unexpected_id_demo.log

    stdbuf -oL ./build/can_sniffer \
      > data/unexpected_id_demo.csv &
    SNIFFER_PID=$!

    sleep 1

    stdbuf -oL ./build/attack_simulator 2 \
      > data/unexpected_id_demo.log 2>&1 &
    ATTACK_PID=$!

    sleep 5
    kill -INT "$ATTACK_PID"
    wait "$ATTACK_PID"
    sleep 1

    kill -TERM "$SNIFFER_PID"
    wait "$SNIFFER_PID"

Mode 2 sends CAN ID `0x999`, payload `DEAD`, with a target interval
of 50 ms. It uses an extended CAN frame because `0x999` is larger
than the maximum 11-bit standard identifier `0x7FF`.

After each test, inspect the capture with:

    head data/high_frequency_demo.csv
    head data/unexpected_id_demo.csv
    wc -l data/high_frequency_demo.csv data/unexpected_id_demo.csv

## 6. CSV Format

The sniffer emits these columns:

    timestamp_utc,interface,can_id,frame_format,flags,dlc,payload

- `timestamp_utc`: UTC wall-clock timestamp generated when the frame
  is processed in user space.
- `interface`: the virtual interface (`vcan0`).
- `can_id`: decoded CAN identifier.
- `frame_format`: standard, extended or error.
- `flags`: frame flags recorded by the sniffer.
- `dlc`: payload length.
- `payload`: payload bytes formatted as uppercase hexadecimal.

## 7. Recorded Regression Results

Results from the recorded run on 24 October 2026:

| Scenario | Frames captured | Validation |
|---|---:|---|
| Normal traffic | See `data/normal_regression.csv` | Basic CSV checks passed |
| High-frequency | 2167 | Passed |
| Unexpected extended ID | 87 | Passed |

High-frequency run: all captured frames used ID `0x100` and payload
`FFFF`. Average observed interval was 2.307 ms; median was 2.074 ms.

Unexpected extended-ID run: all captured frames used extended ID
`0x999` and payload `DEAD`. Average observed interval was 58.323 ms;
median was 52.344 ms.

See `prajwal_day5_regression.md` and the corresponding files in `data/`
for details.

## 8. Saved-Model Inference and Live Dashboard

### Run inference on a saved capture

Activate the virtual environment and analyze a recorded virtual-CAN capture.
Run these commands from the repository root:

    source .venv/bin/activate
    python src/score_capture.py data/normal_baseline_60s.csv

The default report is written to
`reports/normal_baseline_60s_inference.csv`. It contains per-window
predictions, anomaly scores and feature values.

Inference loads `models/isolation_forest_baseline.joblib` without
retraining. The model uses 1,000 ms windows and may exclude a potentially
incomplete final window. Only virtual-CAN captures from `vcan0` are accepted.

### Launch the desktop dashboard

    source .venv/bin/activate
    python src/dashboard.py

The dashboard supports capture presets, browsing for a CSV, analyzing
saved captures and starting a capture on virtual `vcan0`.

While capture is running, completed one-second windows are incrementally
scored with the saved model. Results and summary metrics are updated, and
an alert is displayed when a window is classified as anomalous. The newest
potentially incomplete window remains pending. Use **Stop & Analyze** to
finish capture and perform final inference.

### Run the regression checks

Run the following from the repository root:

    python tests/validate_captures.py
    python tests/test_score_capture.py
    QT_QPA_PLATFORM=offscreen python tests/test_dashboard_smoke.py
    python -m compileall -q src tests

Passing these tests does not establish independently validated real-world
detection accuracy.

## 9. Limitations

The target sending intervals are not exact timing guarantees. Virtual
machine scheduling and user-space capture timing can cause delays and
outliers. The timestamps are not hardware-level bus timestamps.

Successful frame capture and CSV validation do not, by themselves,
prove that a machine-learning detector accurately classifies attacks.
Detection metrics and dashboard integration must be measured separately.

## 10. Safety

This project uses simulated traffic on the isolated virtual `vcan0`
interface. Never run attack simulations against a physical vehicle,
live automotive bus or network without explicit authorization.

## 11. Contributor Workflow

Prajwal's working branch is `prajwal`. Commit meaningful source code,
tests, documentation and evidence to the assigned branch. Do not merge
to `main` before the project review instruction allows it.

