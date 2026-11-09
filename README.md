# CAN-Sentinel
## Automotive ECU Intrusion Detection System

CAN-Sentinel is a virtual automotive security laboratory that simulates
Controller Area Network (CAN) bus traffic, detects anomalies with a
machine-learning Isolation Forest model, and responds automatically to
controlled attack simulations — all inside the isolated virtual interface
`vcan0`.

> **Safety Note:** This is a research and demonstration project running
> entirely on a virtual CAN interface. It does **not** protect real
> vehicles. Never connect this software to a physical automotive bus or
> vehicle network without explicit, authorised testing arrangements.

---

## Features

| Phase | Feature |
|---|---|
| 1 | Isolation Forest anomaly detection trained on baseline CAN traffic |
| 2 | Virtual CAN bus with normal and malicious traffic C generators |
| 3 | Real-time live monitoring, windowed scoring, incident creation, and alert popup |
| 4 | Attack Prevention Analytics dashboard with live metrics and charts |
| 5 | Detailed incident reports with evidence, timeline, PDF print, and CSV export |
| 6 | SOC overview, real-time traffic charts, threat panel, and system health monitor |
| 7 | Automated response validation, resilience testing, and structured audit trail |
| 8 | End-to-end integration, full documentation, and demo readiness |

---

## Architecture

```
Normal traffic generator (C)  ──┐
Attack simulator (C)           ──┼──► vcan0 (Linux virtual CAN interface)
                                 │          │
                                 │    C CAN sniffer
                                 │          │
                                 │    timestamped CSV capture
                                 │          │
                                 │    Python FastAPI backend
                                 │       ├─ Isolation Forest scorer
                                 │       ├─ Incident engine
                                 │       ├─ Live session manager
                                 │       ├─ Automated response worker
                                 │       └─ Resilience tester
                                 │          │
                                 └──────────┴──► TanStack Start React frontend
                                                  ├─ SOC overview dashboard
                                                  ├─ Real-time traffic charts
                                                  ├─ Security alert modal
                                                  ├─ Incident history & reports
                                                  ├─ Attack prevention analytics
                                                  └─ Response reliability dashboard
```

---

## Technology Stack

| Component | Technology |
|---|---|
| Traffic generators | C (Linux SocketCAN `AF_CAN`) |
| CAN sniffer | C (Linux SocketCAN, CSV output) |
| ML detection | Python, scikit-learn Isolation Forest |
| Backend API | Python FastAPI, Uvicorn |
| Frontend | TypeScript, React, TanStack Start, TanStack Query |
| Charts | Recharts |
| Styling | Tailwind CSS, shadcn/ui |
| Testing (backend) | pytest |
| Testing (frontend) | Vitest, React Testing Library |

---

## Requirements

### System (Kali Linux recommended)

- Linux kernel with SocketCAN and virtual CAN (`vcan`) module support
- GCC compiler (`gcc`)
- `iproute2` utilities (`ip link`)
- `can-utils` for optional smoke tests (`candump`, `cansend`)
- Python 3.11+
- Node.js 20+ and pnpm (or npm)

### Python packages

```
pip install -r requirements.txt
pip install -r requirements-api.txt
pip install -r requirements-ml.txt
```

---

## 1. Set Up the Virtual CAN Interface

Load the virtual CAN kernel module:

```bash
sudo modprobe vcan
```

Create `vcan0` if it does not already exist:

```bash
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

Verify the interface:

```bash
ip -details link show vcan0
# Should display the UP flag and type vcan
```

---

## 2. Compile the C Programs

From the repository root:

```bash
mkdir -p build data

gcc -std=gnu11 -Wall -Wextra -Wpedantic -O2 \
  src/normal_traffic.c -o build/normal_traffic

gcc -std=gnu11 -Wall -Wextra -Wpedantic -O2 \
  src/can_sniffer.c -o build/can_sniffer

gcc -std=gnu11 -Wall -Wextra -Wpedantic -O2 \
  src/attack_simulator.c -o build/attack_simulator
```

The `build/` directory contains local compiled binaries and is excluded by `.gitignore`.

---

## 3. Set Up the Python Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-api.txt -r requirements-ml.txt
```

---

## 4. Set Up the Frontend

```bash
cd frontend
npm install          # or: pnpm install
```

---

## 5. Start the Backend

```bash
source .venv/bin/activate
python src/api_server.py
```

The FastAPI server starts on `http://localhost:8000` by default.

Override host and port with environment variables:

```bash
CAN_SENTINEL_HOST=0.0.0.0 CAN_SENTINEL_PORT=8000 python src/api_server.py
```

---

## 6. Start the Frontend (Development)

```bash
cd frontend
npm run dev
```

Open `http://localhost:5173` in your browser.

### Production Build

```bash
cd frontend
npm run build
```

The compiled output is placed in `frontend/.output/`.

---

## 7. CAN Message Conventions

Defined in `can_ids.md`.

| CAN ID | Signal | Payload size | Default interval |
|---|---|---:|---:|
| `0x100` | RPM (normal) | 2 bytes | 100 ms |
| `0x101` | Vehicle speed | 2 bytes | 100 ms |
| `0x102` | Coolant temperature | 2 bytes | 1 000 ms |
| `0x100` | High-frequency attack (Mode 1) | 2 bytes `FFFF` | 1 ms |
| `0x999` | Unexpected extended ID (Mode 2) | 2 bytes `DEAD` | 50 ms |

> **Attribution note:** Normal RPM and Mode 1 both use CAN ID `0x100`.
> Per-frame attribution between normal and attack traffic is not possible
> from sniffed data alone. The dashboard clearly labels such counts as
> estimated where generator-side evidence is unavailable.

---

## 8. Live Demonstration Sequence

This sequence demonstrates the full detection and response lifecycle.

### Prerequisites

- `vcan0` is UP.
- Backend is running (`python src/api_server.py`).
- Frontend is running (`npm run dev` inside `frontend/`).
- C binaries are compiled in `build/`.

### Step-by-step

1. Open `http://localhost:5173` → **Live Monitor**.
2. Click **Start Monitoring** to begin live capture on `vcan0`.
3. Verify system health panel shows CAN interface UP, sniffer RUNNING.
4. Click **Start Normal Traffic** to begin baseline CAN traffic.
5. Observe the real-time traffic chart. CAN IDs `0x100`, `0x101`, `0x102` appear.
6. Select **Mode 1** (high-frequency) or **Mode 2** (unexpected ID) attack.
7. Click **Start Attack** to launch the controlled attack simulator.
8. Watch anomaly scores rise in the detection window table.
9. A **Security Alert** popup appears when the incident is confirmed.
10. The backend **automatically terminates the attack process**.
11. Observe **Normal Traffic Continues** — the sniffer and generator remain active.
12. Recovery verification starts: 2 consecutive normal windows are required.
13. When recovery completes, status changes to **RECOVERED**.
14. Open the **Incident Investigation Report** for full evidence and timeline.
15. Navigate to **Incident History** to view all recorded incidents.
16. Use **Export CSV** to download the filtered incident list.
17. Use **Print / Save as PDF** to produce a formatted incident report.
18. Repeat steps 6–17 for Mode 2 to demonstrate both attack types.

---

## 9. Mode 1: High-Frequency Attack (Manual CLI)

```bash
# Terminal 1 — Sniffer
stdbuf -oL ./build/can_sniffer > data/mode1_demo.csv &
SNIFFER_PID=$!

# Terminal 2 — Normal traffic
./build/normal_traffic 100 &
NORMAL_PID=$!

# Terminal 3 — Mode 1 attack
./build/attack_simulator 1 &
ATTACK_PID=$!

# After ~10 seconds, stop the attack
kill -INT "$ATTACK_PID"
wait "$ATTACK_PID"

# After observing recovery, stop normal traffic and sniffer
kill -INT "$NORMAL_PID"
kill -TERM "$SNIFFER_PID"
wait "$NORMAL_PID" "$SNIFFER_PID"
```

Mode 1 sends CAN ID `0x100`, payload `FFFF`, at approximately 1 ms intervals (much higher frequency than the 100 ms normal rate).

---

## 10. Mode 2: Unexpected Extended CAN ID (Manual CLI)

```bash
stdbuf -oL ./build/can_sniffer > data/mode2_demo.csv &
SNIFFER_PID=$!

./build/normal_traffic 100 &
NORMAL_PID=$!

./build/attack_simulator 2 &
ATTACK_PID=$!

sleep 10
kill -INT "$ATTACK_PID"
wait "$ATTACK_PID"

kill -INT "$NORMAL_PID"
kill -TERM "$SNIFFER_PID"
wait "$NORMAL_PID" "$SNIFFER_PID"
```

Mode 2 sends CAN ID `0x999`, payload `DEAD`, at approximately 50 ms intervals using an extended CAN frame (29-bit identifier, `0x999 > 0x7FF`).

---

## 11. Offline Capture Analysis

Analyse a previously recorded CSV capture:

```bash
source .venv/bin/activate
python src/score_capture.py data/normal_baseline_60s.csv
```

The inference report is written to `reports/normal_baseline_60s_inference.csv`.

The model uses 1 000 ms windows. The last incomplete window is excluded unless `--include-partial` is specified.

---

## 12. API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/status` | System health and version |
| GET | `/api/presets` | Available capture preset list |
| GET | `/api/analyses` | All stored analysis results |
| GET | `/api/incidents` | All incidents across all analyses |
| POST | `/api/analyses` | Analyse a preset or path capture |
| GET | `/api/analyses/{id}` | Single analysis result |
| POST | `/api/analyses/upload` | Upload and analyse a CSV file |
| GET | `/api/analyses/{id}/report.csv` | Download per-window inference CSV |
| POST | `/api/live/start` | Start live capture session |
| GET | `/api/live/{id}` | Poll live session state |
| POST | `/api/live/{id}/stop` | Stop live capture and score |
| POST | `/api/live/{id}/attack` | Start controlled attack simulator |
| POST | `/api/live/{id}/attack/stop` | Stop attack simulator |
| POST | `/api/live/{id}/normal` | Start normal traffic generator |
| POST | `/api/live/{id}/normal/stop` | Stop normal traffic generator |
| POST | `/api/live/{id}/simulations/stop` | Stop all simulation generators |
| POST | `/api/analyses/{id}/incidents/{inc}/response/plan` | Plan response for a captured incident |
| POST | `/api/analyses/{id}/incidents/{inc}/response/activate` | Activate planned response |
| POST | `/api/analyses/{id}/incidents/{inc}/response/verify` | Verify post-mitigation recovery |
| GET | `/api/resilience/scenarios` | Run and return 8 resilience scenario results |
| POST | `/api/resilience/scenarios/run` | Re-run resilience scenarios on demand |

Full request and response schemas are documented in `docs/api_contract.md`.

---

## 13. Testing

### Backend unit tests

```bash
# From repository root, with the virtual environment active
export PYTHONPATH=src
python -m pytest tests/test_api_analysis_service.py \
                 tests/test_concurrent_traffic.py \
                 tests/test_live_incident_worker.py \
                 tests/test_incident_engine.py \
                 tests/test_resilience_scenarios.py \
                 tests/test_response_engine.py \
                 tests/test_score_capture.py \
                 tests/test_replay_mitigator.py \
                 -v
```

Expected: **90 passed**.

### Frontend tests

```bash
cd frontend
npm test -- --run
```

Expected: **74 passed** across 10 test files.

### TypeScript check

```bash
cd frontend
npx tsc --noEmit
```

### Production build check

```bash
cd frontend
npm run build
```

### Resilience scenario tests

Executed automatically as part of the backend test suite
(`tests/test_resilience_scenarios.py`). The 8 scenarios cover:

1. Unexpected attack process exit.
2. Attack simulator timeout with signal escalation.
3. Normal traffic generator crash.
4. Sniffer process crash.
5. Backend API unavailable.
6. Recovery interrupted by a new anomaly.
7. Multiple incidents in rapid succession.
8. Session stop while mitigation is in progress.

---

## 14. CSV Capture Format

The sniffer writes these columns:

```
timestamp_utc,interface,can_id,frame_format,flags,dlc,payload
```

| Column | Description |
|---|---|
| `timestamp_utc` | UTC wall-clock timestamp (user-space) |
| `interface` | Virtual interface (`vcan0`) |
| `can_id` | Decoded CAN identifier (decimal) |
| `frame_format` | `standard`, `extended`, or `error` |
| `flags` | Frame flags recorded by the sniffer |
| `dlc` | Payload byte length |
| `payload` | Payload bytes in uppercase hexadecimal |

---

## 15. Isolation Forest Model

The model is stored in `models/isolation_forest_baseline.joblib`.

- Trained on normal CAN traffic baseline captured on `vcan0`.
- Uses 1 000 ms sliding windows of per-window features (frame count, unique IDs, payload entropy, etc.).
- Contamination parameter set to reflect expected anomaly rate in baseline.
- **Do not retrain or modify the model** during evaluation. The saved model is the reference artefact.

---

## 16. Known Limitations

| Area | Limitation |
|---|---|
| Frame attribution | CAN ID `0x100` is shared by normal RPM and Mode 1. Exact frame counts cannot be attributed per-generator from sniffed data alone. Counts labelled **estimated** in the UI. |
| Timestamps | CAN frame timestamps are user-space UTC, not hardware bus timestamps. Scheduling jitter may cause ±few-ms drift. |
| Timing intervals | Target sending intervals (1 ms Mode 1, 50 ms Mode 2) are not hard real-time guarantees. Observed intervals may vary with system load. |
| False positives | No ground-truth labelling mechanism exists in the current build. False-positive counts are not claimed. |
| vcan0 only | All simulation and attack testing is restricted to the isolated virtual interface `vcan0`. Physical CAN hardware is not supported. |
| Windows | C generators require Linux SocketCAN. The Python backend and frontend build on Windows but live capture requires a Linux environment. |
| Session history | Session attack history and analytics are retained for the active session only. History is not persisted across backend restarts. |
| Recovery threshold | Recovery requires 2 consecutive normal-scoring windows after the attack process exits. This threshold is configurable via `required_normal_windows` in the session state. |

---

## 17. Project Layout

```
.
├── src/
│   ├── api_server.py           # FastAPI backend
│   ├── live_session_manager.py # Live capture, scoring, incident dispatch
│   ├── incident_engine.py      # Incident grouping and severity
│   ├── api_analysis_service.py # Offline capture analysis service
│   ├── isolation_forest_detector.py  # ML scorer
│   ├── response_engine.py      # Offline response planning
│   ├── resilience_tester.py    # Controlled failure scenario harness
│   ├── replay_mitigator.py     # Offline replay mitigation
│   ├── score_capture.py        # CLI inference tool
│   ├── normal_traffic.c        # Normal CAN traffic generator
│   ├── can_sniffer.c           # CAN frame sniffer and CSV writer
│   └── attack_simulator.c      # Controlled attack simulator (Mode 1 & 2)
├── frontend/
│   └── src/
│       ├── routes/live.tsx           # Live monitor page
│       ├── components/app/           # All dashboard components
│       └── lib/api/                  # API client, schemas, queries
├── tests/                     # pytest backend test suite
├── models/
│   └── isolation_forest_baseline.joblib
├── data/                      # Captured CSV files (git-ignored)
├── reports/                   # Inference report CSVs
├── docs/
│   ├── api_contract.md
│   └── final_architecture.md
├── can_ids.md                  # CAN message convention reference
├── requirements.txt
├── requirements-api.txt
├── requirements-ml.txt
└── README.md
```

---

## 18. Contributor Workflow

Working branch: `prajwal`.

Commit source code, tests, documentation, and evidence to the assigned branch.
Do not merge to `main` before the project review instruction allows it.
Do not push to remote without explicit instruction.
