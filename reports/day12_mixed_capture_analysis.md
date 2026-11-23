# Day 12 — Mixed CAN Capture Investigation

## Objective
Investigate a dashboard capture containing multiple traffic phases,
validate its data integrity, and evaluate the saved Isolation Forest model.

## Capture integrity
Original capture:
data/dashboard_capture_20261029T152724_167664Z.csv

- Original file size: 704,512 bytes
- Null bytes: 2,474
- First null byte: offset 702,038
- Valid CSV records: 10,636
- Invalid trailing row: 1

A cleaned copy was created by removing only the trailing null-byte
padding after the final complete CSV record.

Cleaned capture:
data/dashboard_capture_20261029T152724_167664Z.cleaned.csv

The cleaned copy contains 10,636 valid records and zero null bytes.
The original file was preserved.

## Capture summary

- Total frames: 10,636
- Standard frames: 10,450
- Extended frames: 186
- CAN ID 0x100: 10,181
- CAN ID 0x101: 244
- CAN ID 0x102: 25
- CAN ID 0x999: 186

## Observed traffic phases

### Phase 1 — Unexpected extended identifier

- Relative time: 0–10 seconds
- Frames: 186
- CAN ID: 0x999
- Frame format: Extended
- Payload: DEAD
- Scored windows: 10
- Anomalous windows: 10

### Phase 2 — Normal-pattern traffic

- Relative time: approximately 770–810 seconds
- CAN IDs: 0x100, 0x101 and 0x102
- Frames: 513
- 0x100: 244
- 0x101: 244
- 0x102: 25

The model classified 25 windows as NORMAL.
One additional window (778) was classified as ANOMALY.
That window contained 9 frames across the expected standard IDs.
It is a possible startup/transition false positive; ground truth was
not independently confirmed.

### Phase 3 — High-frequency traffic

- Relative time: approximately 820–860 seconds
- CAN ID: 0x100
- Frames in this phase: 9,937
- Payload observed: FFFF
- Scored anomalous windows: 21

The traffic reached hundreds of frames per second in several intervals,
well above the project's normal simulated rate.

## Saved-model inference

Model:
models/isolation_forest_baseline.joblib

Inference report:
reports/dashboard_capture_20261029T152724_167664Z.cleaned_inference.csv

- Frames loaded: 10,636
- Populated one-second intervals: 58
- Windows scored: 57
- Anomalous windows: 32
- Normal windows: 25

The final populated interval, index 856, contained 229 frames and
was excluded by the scorer as a possible partial final window.

The 32 anomalous predictions consist of:
- 10 windows associated with the 0x999 phase
- 21 windows associated with high-frequency 0x100 traffic
- 1 possible false positive in the normal-pattern phase

All 31 scored attack-pattern windows were flagged in this capture.

## Findings and limitations

1. The saved model flagged both observed attack-like traffic patterns.
2. It classified 25 normal-pattern windows as NORMAL.
3. One low-volume normal-pattern window was flagged and requires
   ground-truth confirmation.
4. The final partial window was not scored.
5. This is a simulated virtual-CAN capture, not real-world vehicle data.
6. These observations are not a measurement of real-world detection
   accuracy or a comprehensive false-positive rate.

No model retraining or detector changes were made during this investigation.
All testing was performed on virtual CAN data.

## Conclusion

The mixed capture demonstrates detection of both the unexpected
extended-ID traffic pattern and high-frequency CAN-ID traffic.
The possible startup-window false positive and excluded final window
are documented for further evaluation.
