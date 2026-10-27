# Day 7 — CAN Frequency Analysis and Anomaly Detection
Date: 27 October 2026

## 1. Objective

Analyze captured CAN traffic and build a preliminary Isolation Forest
model using window-level features derived from normal traffic.

## 2. Frequency Analyzer

Created `src/frequency_analyzer.py`.

The analyzer validates CAN CSV records and produces:
- Per-ID frame counts and percentage distribution
- Unique payload counts
- Mean, median, minimum and maximum inter-arrival times
- Fixed-width window features for subsequent ML experiments

## 3. Normal Baseline Capture

Capture: `data/normal_baseline_60s.csv`

- Frames analyzed: 1,230
- Standard IDs observed: 0x100, 0x101 and 0x102
- RPM frames: 585
- Speed frames: 585
- Coolant frames: 60
- RPM mean inter-arrival time: approximately 102.43 ms
- Speed mean inter-arrival time: approximately 102.43 ms
- Coolant mean inter-arrival time: approximately 1,000.60 ms
- One-second feature windows generated: 60

The generator reported zero errors. It reported 14 skipped periods
for each of the RPM and speed streams, so the observed cadence differs
slightly from the nominal schedule.

## 4. Isolation Forest Prototype

Created `src/isolation_forest_detector.py`.

The model:
- Uses numeric window-level features from the frequency analyzer
- Fits on normal traffic windows only
- Uses a chronological 80/20 split of the available baseline windows
- Scores held-out normal and simulated attack windows
- Saves the fitted model and scored-window report

The final observed window is excluded from each feature file because
the capture stop time is not recorded in the feature CSV and that
window may be incomplete.

For the current baseline, 47 windows were used for training and
12 were held out.

## 5. Exploratory Results

Using `contamination=0.02`:

- Held-out normal baseline: 0/12 windows flagged
- Fresh-clone normal capture: 0/4 flagged
- Normal regression capture: 0/5 flagged
- Normal sniffer capture: 0/4 flagged
- High-frequency fresh-clone capture: 3/3 flagged
- High-frequency regression capture: 4/4 flagged
- Larger high-frequency capture: 43/43 flagged
- Unexpected-ID fresh-clone capture: 2/2 flagged
- Unexpected-ID regression capture: 5/5 flagged
- Larger unexpected-ID capture: 28/28 flagged

These counts are exploratory results from the available captures.
They are not an independent test set and must not be presented as
validated real-world detection accuracy.

## 6. Limitations and Next Improvements

- The normal training baseline is small and comes from a single
  recording session.
- The attack captures represent only two simulated scenarios.
- The contamination setting was selected after inspecting results
  from these same captures, which can make the observed performance
  optimistic.
- Similar or benign traffic patterns may still be flagged.
- Capture timing depends on Linux userspace scheduling and VM overhead.
- No real-vehicle CAN network was used.

Next steps:
1. Collect additional normal recordings across separate sessions.
2. Test with varied and mixed normal/attack traffic.
3. Establish a separate evaluation dataset before tuning thresholds.
4. Measure false alarms as well as attack detection.
5. Integrate the detector with a live or replay-based dashboard.

## 7. Reproduction

Activate the project environment first:

`source .venv/bin/activate`

Analyze the baseline:

`python3 src/frequency_analyzer.py data/normal_baseline_60s.csv`

Run the initial detector:

`python src/isolation_forest_detector.py --contamination 0.02`

Main outputs:
- `reports/normal_baseline_60s_frequency_summary.csv`
- `reports/normal_baseline_60s_window_features.csv`
- `reports/isolation_forest_scored_windows.csv`
- `models/isolation_forest_baseline.joblib`

All capture and attack testing described here used the virtual interface
`vcan0`, not a physical vehicle network.
