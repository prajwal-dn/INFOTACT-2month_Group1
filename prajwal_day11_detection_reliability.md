# CAN-Sentinel — Day 11 Detection Reliability Investigation

**Date:** 29 October 2026
**Branch:** `prajwal`
**Model:** `models/isolation_forest_baseline.joblib`

## 1. Objective

Investigate an anomalous window in the original normal-baseline capture,
collect additional normal traffic, evaluate the saved model against the
new captures, and rerun the project regression tests.

All captures in this investigation use the virtual CAN interface `vcan0`.
The saved model was not retrained or modified.

## 2. Fresh Normal-Traffic Captures

Two 60-second normal-traffic captures were collected.

| Capture | Frames | Generator results | Scored windows | Anomalies |
|---|---:|---|---:|---:|
| `data/day11_normal_20261029T101225Z.csv` | 1,256 | 598 ID `0x100`, 598 ID `0x101`, 60 ID `0x102`; zero reported send errors | 59 | 0 |
| `data/day11_normal_repeat_20261029T101626Z.csv` | 1,260 | 600 ID `0x100`, 600 ID `0x101`, 60 ID `0x102`; zero reported send errors | 59 | 0 |

The first capture was scored to
`reports/day11_normal_20261029T101225Z_inference.csv`.

The repeat capture was scored to
`reports/day11_normal_repeat_20261029T101626Z_inference.csv`.

The inference script excluded the potentially incomplete final window
from each capture. Across both captures, 118 windows were scored and
none were classified as anomalous.

The first fresh capture contained 10 windows without ID `0x102`.
All 10 were classified as normal. Therefore, the absence of `0x102`
alone does not explain the anomaly in the original baseline.

## 3. Investigation of Original Baseline Window 18

The report `reports/normal_baseline_60s_inference.csv` contains 59
scored windows: 58 classified as normal and one classified as anomalous.

Window 18 had an anomaly score of `0.71522442` and contained:

- 19 total frames
- 10 frames with ID `0x100`
- 9 frames with ID `0x101`
- 0 frames with ID `0x102`
- 0 extended frames
- 19 unique payloads
- Maximum CAN ID share of 52.6316%

The neighboring windows 17 and 19 were classified as normal.

### Timing observation

An ID `0x102` frame arrived at
`2026-10-27T14:28:22.736198769Z`, approximately 0.291 milliseconds
before window 18 started at
`2026-10-27T14:28:22.736489714Z`.

The next recorded ID `0x102` frame arrived at
`2026-10-27T14:28:23.737050126Z`, approximately 1.001 seconds after
window 18 started. The gap between those two ID `0x102` frames was
approximately 1.000851 seconds.

This timing supports the possibility of a window-boundary effect.

### Feature comparison

Compared with the 59 windows in the first fresh normal capture, the
original anomalous window's `max_id_share_pct` and
`id_0x100_share_pct` were outside that capture's observed ranges.
Its other reported features were within those observed ranges.

A slight imbalance between IDs `0x100` and `0x101` may have contributed
to the alert. However, Isolation Forest evaluates multiple features,
and this comparison does not establish the exact cause. The original
alert remains unresolved.

## 4. Regression-Test Results

The following checks passed on 29 October 2026:

| Check | Result |
|---|---|
| Capture regression validator | 6 passed, 0 failed |
| Saved-model inference regression | Passed |
| Original normal baseline | 58 normal, 1 anomalous |
| High-frequency simulated attack | 43 of 43 scored windows anomalous |
| Unexpected-ID simulated attack | 28 of 28 scored windows anomalous |
| Dashboard smoke test | Passed |
| Python syntax check | Passed |
| Git whitespace check | Passed |

The attack results are from existing simulated virtual-CAN test captures.
They do not establish detection accuracy on real vehicle networks.

## 5. Conclusions and Limitations

The two fresh normal captures were classified without anomalous windows.
This is encouraging preliminary evidence that the saved model recognizes
these additional examples of simulated normal traffic.

The original baseline anomaly has not been conclusively explained.
Two fresh captures are insufficient to establish a reliable overall
false-positive rate or real-world detection accuracy.

The model was left unchanged during this investigation. Additional
diverse normal captures and further controlled evaluation are needed
before deciding whether model or feature changes are justified.

All experiments were conducted on virtual `vcan0` only. The system has
not been validated on a physical vehicle CAN network.

## 6. Evidence Files

Fresh captures and generator/sniffer logs:

- `data/day11_normal_20261029T101225Z.csv`
- `data/day11_normal_20261029T101225Z_generator.log`
- `data/day11_normal_20261029T101225Z_sniffer.log`
- `data/day11_normal_repeat_20261029T101626Z.csv`
- `data/day11_normal_repeat_20261029T101626Z_generator.log`
- `data/day11_normal_repeat_20261029T101626Z_sniffer.log`

Inference reports:

- `reports/day11_normal_20261029T101225Z_inference.csv`
- `reports/day11_normal_repeat_20261029T101626Z_inference.csv`
