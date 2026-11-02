# CAN-Sentinel — Final Architecture

**Branch:** prajwal  
**Date:** 2026-11-01  
**Status:** Complete prototype; pending hardware validation

---

## 1. System Overview

CAN-Sentinel is a virtual-CAN intrusion detection prototype that combines:
- C SocketCAN modules for traffic generation and capture on Linux.
- A Python ML pipeline using a trained Isolation Forest for anomaly detection.
- A PySide6 desktop dashboard for interactive analysis and live capture.
- A versioned Unix-domain socket contract for C-to-Python integration.

All traffic is restricted to the isolated virtual CAN interface `vcan0`.

---

## 2. Pipeline Architecture

```
┌─────────────────────────────────────────────────┐
│                   C MODULES (Linux)             │
│                                                 │
│  normal_traffic.c       attack_simulator.c      │
│  (RPM/speed/coolant)    (mode 1: high-freq,     │
│                          mode 2: unexpected ID) │
│          │                      │               │
│          └──────────┬───────────┘               │
│                     ▼                           │
│            Linux SocketCAN vcan0                │
│                     │                           │
│                     ▼                           │
│              can_sniffer.c                      │
│         (timestamped CSV capture)               │
└─────────────────────────┬───────────────────────┘
                          │
              ┌───────────┴──────────────┐
              │  OPTIONAL: socket mode   │
              │  (Unix domain socket)    │
              │  socket_receiver.py      │
              └───────────┬──────────────┘
                          │
          ┌───────────────▼──────────────────┐
          │         PYTHON PIPELINE          │
          │                                  │
          │  frequency_analyzer.py           │
          │  • load_capture()                │
          │  • build_window_features()       │
          │    → 14 feature columns          │
          │    → 1000 ms windows             │
          │                                  │
          │  score_capture.py                │
          │  • loads saved model bundle      │
          │  • calls model.predict()         │
          │  • calls model.score_samples()   │
          │  • excludes partial final window │
          │                                  │
          │  isolation_forest_baseline.joblib│
          │  (scikit-learn 1.9.1,            │
          │   contamination=0.02,            │
          │   n_estimators=200,              │
          │   random_state=42,               │
          │   trained on 47 normal windows)  │
          └───────────────┬──────────────────┘
                          │
              ┌───────────▼──────────────────┐
              │         OUTPUTS              │
              │                             │
              │  reports/*_inference.csv    │
              │  reports/*_window_features  │
              │  reports/*_frequency_summary│
              │                             │
              │  src/dashboard.py (PySide6) │
              │  • offline file analysis    │
              │  • live capture + scoring   │
              │  • anomaly alerts           │
              └─────────────────────────────┘
```

---

## 3. C Module Details

### src/normal_traffic.c

Generates simulated vehicle CAN frames on `vcan0`:

| CAN ID | Signal | Interval | Encoding |
|---|---|---|---|
| 0x100 | Engine RPM | 100 ms (configurable) | 2-byte big-endian unsigned |
| 0x101 | Vehicle Speed | 100 ms (configurable) | 2-byte big-endian unsigned |
| 0x102 | Coolant Temperature | 10× interval (≈1000 ms) | 2-byte big-endian unsigned |

Compile: `gcc -std=gnu11 -Wall -Wextra -O2 src/normal_traffic.c -o build/normal_traffic`

### src/can_sniffer.c

Reads raw CAN frames from `vcan0` using `PF_CAN / SOCK_RAW / CAN_RAW`.

Outputs the canonical 7-column CSV to stdout:
```
timestamp_utc,interface,can_id,frame_format,flags,dlc,payload
```

Timestamps are generated via `clock_gettime(CLOCK_REALTIME)` — user-space
precision, not hardware bus timestamps.

Compile: `gcc -std=gnu11 -Wall -Wextra -O2 src/can_sniffer.c -o build/can_sniffer`

### src/attack_simulator.c

Two anomaly simulation modes:

| Mode | CAN ID | Payload | Interval | Frame type |
|---|---|---|---|---|
| 1 (high-frequency) | 0x100 | FFFF | 1 ms target | Standard |
| 2 (unexpected ID) | 0x999 | DEAD | 50 ms target | Extended |

Compile: `gcc -std=gnu11 -Wall -Wextra -O2 src/attack_simulator.c -o build/attack_simulator`

---

## 4. Python Module Details

### src/frequency_analyzer.py

- `load_capture(path)`: loads and validates the canonical CSV
- `build_window_features(records, window_ms)`: creates 14-feature rows per window
- `build_frequency_summary(records)`: per-ID statistics

**14 feature columns** (canonical order):

| # | Column | Description |
|---|---|---|
| 1 | `total_frames` | Total CAN frames in the window |
| 2 | `unique_can_ids` | Number of distinct CAN IDs observed |
| 3 | `extended_frame_count` | Frames using extended (29-bit) format |
| 4 | `unique_payload_count` | Distinct payload byte strings |
| 5 | `max_id_share_pct` | Share (%) of the most frequent CAN ID |
| 6 | `id_0x100_count` | Frame count for CAN ID 0x100 (RPM) |
| 7 | `id_0x100_share_pct` | Share (%) for 0x100 |
| 8 | `id_0x101_count` | Frame count for 0x101 (speed) |
| 9 | `id_0x101_share_pct` | Share (%) for 0x101 |
| 10 | `id_0x102_count` | Frame count for 0x102 (coolant temp) |
| 11 | `id_0x102_share_pct` | Share (%) for 0x102 |
| 12 | `id_0x999_count` | Frame count for 0x999 (unexpected ID) |
| 13 | `id_0x999_share_pct` | Share (%) for 0x999 |
| 14 | `other_id_count` | Frames with IDs not in the known set |

### src/score_capture.py

Offline inference tool. Loads the saved model bundle and scores a CSV capture.
- Rejects non-vcan0 captures.
- Excludes the final (potentially incomplete) window.
- Outputs `reports/<stem>_inference.csv`.

### src/isolation_forest_detector.py

Training script (run once to produce the model). Not needed for inference.
Model is already saved at `models/isolation_forest_baseline.joblib`.

### src/socket_receiver.py

Python side of the C-to-Python Unix socket integration.
- Validates JSON-line events per the contract in `docs/c_to_python_socket_contract.md`.
- Handles partial `recv()` reads via a line buffer.
- Restricts to `vcan0`.
- Linux-only (AF_UNIX sockets not available on Windows).

### src/dashboard.py

PySide6 desktop application:
- Capture preset selector (3 pre-loaded captures).
- Manual CSV file browser.
- Background inference worker thread.
- Summary cards: total windows, normal, anomalies, anomaly rate.
- Sortable results table.
- Anomaly score chart.
- Live capture with incremental scoring.
- Event log panel.

---

## 5. Model Bundle

**File:** `models/isolation_forest_baseline.joblib`  
**SHA-256:** `28a0feb7d886ff95e6e3ffb1ba34d209fc55081d9ba02269d6677b56a8c8f825`

Bundle contents:
```python
{
    "model":             IsolationForest(n_estimators=200, contamination=0.02, random_state=42),
    "feature_columns":   [14 columns listed above],
    "training_source":   "reports/normal_baseline_60s_window_features.csv",
    "training_windows":  47,
    "contamination":     0.02,
    "sklearn_version":   "1.9.1",
}
```

---

## 6. Regression Results (must remain reproducible)

| Capture | Scored windows | NORMAL | ANOMALY |
|---|---|---|---|
| data/normal_baseline_60s.csv | 59 | 58 | 1 |
| data/high_frequency_capture.csv | 43 | 0 | 43 |
| data/unexpected_id_capture.csv | 28 | 0 | 28 |

---

## 7. Socket Integration Contract (C-to-Python)

Transport: Unix domain stream socket (`AF_UNIX SOCK_STREAM`)  
Path: `/tmp/can_sentinel.sock`  
Framing: one JSON object per line, terminated by `\n`  
Schema version: 1

Message schema:
```json
{
  "schema_version": 1,
  "event_type": "can_frame",
  "timestamp_utc": "2026-10-31T18:20:30.123456789Z",
  "interface": "vcan0",
  "can_id": "0x100",
  "frame_format": "standard",
  "flags": "none",
  "dlc": 2,
  "payload": "FFFF"
}
```

**Status:** Contract and Python receiver implemented and tested.
The production `can_sniffer.c` currently writes to stdout (CSV mode) only.
Socket mode is an optional integration layer that does not modify
the existing sniffer behaviour.

---

## 8. Known Limitations

1. Timestamps are user-space wall-clock (`clock_gettime`), not hardware bus timestamps.
2. Target sending intervals are not guaranteed; OS scheduling causes jitter.
3. The model was trained on 47 windows from one 60-second normal capture.
4. Detection accuracy has not been independently validated on real automotive traffic.
5. The socket integration requires Linux (AF_UNIX); Windows testing uses Python-only contract tests.
6. Dashboard live-capture features require a Linux host with `vcan0` configured.
7. The model contamination (0.02) was chosen empirically; it flags approximately 2% of normal traffic as anomalous.

---

## 9. Safety Restrictions

- All testing uses the isolated virtual interface `vcan0` only.
- No physical vehicle or live automotive bus has been used.
- Attack simulations must never be run against physical vehicles or real CAN networks without explicit authorization.
