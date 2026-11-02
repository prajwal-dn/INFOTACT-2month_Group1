# CAN-Sentinel Live Integration

Kali-tested integration package for the CAN-Sentinel project.

## Included files

- src/can_sniffer.c
  - Existing CSV mode remains the default.
  - Optional --socket mode sends JSON events to Python.
- src/socket_receiver.py
  - Validates version 1 CAN events.
  - Supports --count 0 for unlimited reception.
- src/live_inference.py
  - Receives live socket events.
  - Extracts the original 14 features.
  - Runs the original saved Isolation Forest.
- docs/c_to_python_socket_contract.md
- verification_report.md

## Requirements

- Linux with SocketCAN
- GCC
- Python virtual environment
- scikit-learn 1.9.1
- Original models/isolation_forest_baseline.joblib

The original model is intentionally not included. Reuse the existing project model.

## Compile

From the project root:

gcc -Wall -Wextra -Wpedantic -O2 src/can_sniffer.c -o build/can_sniffer

## Start live inference

Activate the existing Python environment:

source .venv/bin/activate

Terminal 1:
python src/live_inference.py

Terminal 2:
./build/can_sniffer --socket

Terminal 3:
./build/normal_traffic 100

Stop the traffic generator first, then the sniffer.
The Python process will print the final inference summary.

## Attack simulation

High-frequency attack:

./build/attack_simulator 1

Unexpected extended-ID attack:

./build/attack_simulator 2

Use the same Python inference and C sniffer startup sequence.

## CSV compatibility

Running ./build/can_sniffer without arguments retains CSV output.

## Safety and limitations

- Testing is restricted to vcan0.
- No physical vehicle interface is used.
- Socket mode supports standard and extended data frames.
- RTR and CAN error frames are skipped in socket mode.
- The original model is not retrained or modified.
- The live inference module prints predictions to the terminal.
- Dashboard integration is not included.
- Simulation results do not establish real-world detection accuracy.
