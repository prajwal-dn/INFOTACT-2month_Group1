# Day 8 — Saved-Model Inference
Date: 28 October 2026

## Objective
Create a reusable inference script that scores saved CAN captures
using the trained Isolation Forest model without retraining it.

## Implementation

Created `src/score_capture.py`.

The script:
- Loads `models/isolation_forest_baseline.joblib`
- Validates and reads a saved CAN sniffer CSV capture
- Generates the same 1-second window features used by training
- Scores windows using the saved Isolation Forest
- Writes predictions and anomaly scores to a CSV report
- Excludes the possible partial final window
- Reports the number of normal and anomalous windows

Created `tests/test_score_capture.py` to test inference against
three existing virtual-CAN captures.

## Test Results

| Capture | Windows scored | Normal | Anomalous |
|---|---:|---:|---:|
| Normal baseline | 59 | 58 | 1 |
| High-frequency attack | 43 | 0 | 43 |
| Unexpected-ID attack | 28 | 0 | 28 |

Automated test result: PASS.

## Generated Reports

- `reports/normal_baseline_60s_inference.csv`
- `reports/high_frequency_capture_inference.csv`
- `reports/unexpected_id_capture_inference.csv`

## Reproduction

Activate the project environment:

`source .venv/bin/activate`

Run inference:

`python src/score_capture.py data/normal_baseline_60s.csv`

Run the automated inference test:

`python tests/test_score_capture.py`

## Limitations

These tests use previously captured virtual-CAN traffic. The normal
baseline contains one window flagged as anomalous. The two simulated
attack captures were fully flagged in this experiment.

The datasets are limited and do not establish independently validated
real-world detection accuracy. Live stream processing, dashboard
integration, additional normal sessions, and broader attack testing
remain future work.

All testing described here used `vcan0`, not a physical vehicle network.
