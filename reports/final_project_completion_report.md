# CAN-Sentinel — Final Project Completion Report

**Project:** CAN-Sentinel — Automotive ECU Intrusion Detection System\
**Contributor:** Prajwal Dn (branch: `prajwal`)\
**Date completed:** 2026-11-01\
**Environment:** Kali Linux / isolated virtual CAN (`vcan0`) for C modules;\
Windows for Python analysis and dashboard\

---

## 1. Project Objective

CAN-Sentinel detects anomalous Controller Area Network (CAN) traffic
on a simulated automotive bus using an Isolation Forest model trained
on normal virtual traffic patterns.

The project is a cybersecurity research prototype. It does **not** make
validated real-world detection accuracy claims.

---

## 2. Implementation Status

### Completed

| Component | Status |
|---|---|
| C normal traffic generator (`src/normal_traffic.c`) | Complete |
| C CAN sniffer to CSV (`src/can_sniffer.c`) | Complete |
| C attack simulator — high-frequency mode | Complete |
| C attack simulator — unexpected extended ID mode | Complete |
| Python frequency analyzer — 14-feature extraction | Complete |
| Python Isolation Forest training script | Complete |
| Python saved-model inference (`score_capture.py`) | Complete |
| Trained model bundle (`models/isolation_forest_baseline.joblib`) | Saved; do not retrain |
| Python socket receiver (C-to-Python contract) | Complete |
| PySide6 desktop dashboard | Complete |
| Regression capture datasets | Complete (3 captures) |
| Automated test suite | Complete (14 tests passing) |
| C-to-Python socket contract documentation | Complete |
| CAN ID mapping documentation | Complete |
| Aman replacement package | Complete |
| Final documentation | Complete |

### Not Completed (Remaining Deliverables)

| Item | Reason |
|---|---|
| Production `can_sniffer.c` socket integration | Implemented as optional `--socket` mode using Unix sockets |
| Lovable web frontend | Source ZIP not available in this workspace |
| Independent ML detection accuracy validation | Requires validated real-world automotive data |
| Hardware-timestamp precision | Out of scope for SocketCAN virtual interface |

---

## 3. Architecture Summary

See `docs/final_architecture.md` for the full diagram and module descriptions.

**Pipeline:**

```
C traffic generator / attack simulator
    → vcan0 (Linux SocketCAN)
    → can_sniffer.c (CSV capture)
    → frequency_analyzer.py (14-feature windows)
    → isolation_forest_baseline.joblib
    → predictions + anomaly scores
    → reports/ + dashboard.py
```

---

## 4. Canonical Model Configuration

| Parameter | Value |
|---|---|
| Algorithm | Isolation Forest |
| n_estimators | 200 |
| contamination | 0.02 |
| random_state | 42 |
| Feature count | 14 |
| Window size | 1000 ms |
| Training windows | 47 |
| sklearn version | 1.9.1 |
| Model file SHA-256 | `28a0feb7d886ff95e6e3ffb1ba34d209fc55081d9ba02269d6677b56a8c8f825` |

**The model must not be retrained.** The training script is preserved in
`src/isolation_forest_detector.py` for reference only.

---

## 5. The 14 Feature Columns

| # | Column | Description |
|---|---|---|
| 1 | `total_frames` | Total CAN frames in the 1000 ms window |
| 2 | `unique_can_ids` | Distinct CAN IDs observed |
| 3 | `extended_frame_count` | Frames using 29-bit extended format |
| 4 | `unique_payload_count` | Distinct payload byte strings |
| 5 | `max_id_share_pct` | Share (%) of the dominant CAN ID |
| 6 | `id_0x100_count` | Frame count for RPM signal |
| 7 | `id_0x100_share_pct` | Share (%) for RPM signal |
| 8 | `id_0x101_count` | Frame count for vehicle speed signal |
| 9 | `id_0x101_share_pct` | Share (%) for speed signal |
| 10 | `id_0x102_count` | Frame count for coolant temperature |
| 11 | `id_0x102_share_pct` | Share (%) for coolant temperature |
| 12 | `id_0x999_count` | Frame count for unexpected extended ID |
| 13 | `id_0x999_share_pct` | Share (%) for unexpected ID |
| 14 | `other_id_count` | Frames with IDs outside the known set |

---

## 6. CSV Schema

```
timestamp_utc,interface,can_id,frame_format,flags,dlc,payload
```

| Column | Example | Description |
|---|---|---|
| `timestamp_utc` | `2026-10-28T12:25:02.777520000Z` | ISO 8601 UTC, 9 nanosecond digits |
| `interface` | `vcan0` | Always `vcan0` |
| `can_id` | `0x100` | Hexadecimal with 0x prefix, lowercase |
| `frame_format` | `standard` | `standard` or `extended` |
| `flags` | `none` | Frame flags; `none` for normal data frames |
| `dlc` | `2` | Payload byte count (0–8) |
| `payload` | `0BB8` | Uppercase hexadecimal bytes |

---

## 7. Regression Test Results

These results confirm the original model inference is reproducible:

| Capture | Total windows | NORMAL | ANOMALY | Test status |
|---|---|---|---|---|
| `data/normal_baseline_60s.csv` | 59 | 58 | 1 | PASSED |
| `data/high_frequency_capture.csv` | 43 | 0 | 43 | PASSED |
| `data/unexpected_id_capture.csv` | 28 | 0 | 28 | PASSED |

---

## 8. Test Execution Summary

### Tests Passed (Windows, Python 3.11.9)

| Test | Result |
|---|---|
| `tests/test_socket_contract.py` — 13 contract validation tests | 13/13 PASSED |
| `tests/test_score_capture.py` — 3 regression subtests | 3/3 PASSED |
| `python -m compileall -q src tests` | PASSED (exit 0) |
| Model bundle loads with expected keys and configuration | PASSED |
| `handoff/aman_replacement/tests/test_candump_converter.py` | (see Part 6) |
| `handoff/aman_replacement/tests/test_logger.py` | (see Part 6) |

### Tests Not Executed (Linux-only)

| Test | Reason not executed |
|---|---|
| `tests/validate_captures.py` (partial) | Requires Linux data files |
| `tests/test_dashboard_smoke.py` | Requires PySide6 display server |
| GCC compilation of C modules | Requires Linux GCC |
| Live `vcan0` capture | Requires Linux SocketCAN |
| C socket producer + Python receiver integration | Requires Linux AF_UNIX |

**No Linux-only test results have been fabricated.**

---

## 9. Contribution Breakdown

### Prajwal Dn (branch: `prajwal`)

- `src/normal_traffic.c` — configurable CAN traffic generator
- `src/can_sniffer.c` — CSV-producing SocketCAN sniffer
- `src/attack_simulator.c` — high-frequency and unexpected-ID attack modes
- `src/frequency_analyzer.py` — 14-feature window extractor (canonical)
- `src/isolation_forest_detector.py` — Isolation Forest training script
- `src/score_capture.py` — saved-model offline inference
- `src/dashboard.py` — PySide6 desktop dashboard
- `src/socket_receiver.py` — Unix socket JSON event receiver
- `models/isolation_forest_baseline.joblib` — trained model bundle
- `data/normal_baseline_60s.csv` — 60-second normal traffic capture
- `data/high_frequency_capture.csv` — high-frequency attack capture
- `data/unexpected_id_capture.csv` — unexpected extended ID capture
- `tests/validate_captures.py` — multi-scenario CSV validator
- `tests/test_score_capture.py` — inference regression tests
- `tests/test_dashboard_smoke.py` — dashboard smoke test
- `tests/test_socket_contract.py` — socket contract unit tests
- `tests/socket_sample_producer.c` — C socket test client
- `docs/c_to_python_socket_contract.md` — socket integration contract
- `docs/final_architecture.md` — complete architecture document
- `can_ids.md` — CAN ID mapping
- All `prajwal_*.md` progress notes

### Aman Gaikwad (branch: `Aman-Gaikwad`) — Replacement Package

Aman's original contribution used an incompatible ML architecture (12 features,
sklearn 1.3.2, contamination 0.05). A replacement package has been prepared at
`handoff/aman_replacement/` that provides:

- `candump_converter.py` — candump log → canonical 7-column CSV
- `logger.py` — structured logger
- Complete test suite
- Replacement manifest with instructions
- Design documentation

Aman's original progress notes and experiment results are preserved as historical
evidence and must not be deleted without his review.

---

## 10. Known Limitations

1. Timestamps are user-space `clock_gettime`, not hardware bus timestamps.
2. Target CAN message intervals are not guaranteed; OS scheduling causes jitter.
3. The model was trained on 47 windows from a single 60-second capture.
4. Detection accuracy has not been validated on real automotive traffic.
5. The candump converter does not recover RTR frames or extended flags.
6. Dashboard live capture requires a Linux host with `vcan0` configured.
7. The web frontend (Lovable) is a remaining deliverable; its source ZIP was not available.
8. The C sniffer supports CSV capture and optional Unix-socket JSON event output through `--socket`. End-to-end runtime validation must be confirmed separately.

---

## 11. Safety Restrictions

- All tests run on the isolated virtual interface `vcan0` only.
- No physical vehicle or live automotive bus has been used.
- Attack simulation must never be run against physical vehicles or real CAN networks.

---

## 12. Git Status

Git status is dynamic and should be checked using `git status` when reviewing
this report. Project contributions are maintained on the `prajwal` branch.
