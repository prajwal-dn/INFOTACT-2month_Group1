# CAN-Sentinel — API Integration Validation Report

**Date:** 2026-11-02  
**Branch:** `prajwal`  
**Service:** FastAPI Backend (`src/api_server.py`)  
**Frontend:** Lovable React Frontend (`lovable-frontend`)  
**Status:** VALIDATED & COMPLIANT

---

## 1. Executive Summary

The CAN-Sentinel intrusion detection system has been integrated with a production-grade FastAPI backend service that implements the exact REST contract expected by the Lovable React frontend. The service exposes all real inference results using the unmodified original 14-feature Isolation Forest baseline model (`models/isolation_forest_baseline.joblib`).

All operations adhere strictly to safety rules:
- Strictly detection-only (no CAN frame blocking or prevention).
- Strictly virtual CAN (`vcan0`).
- No modifications, retraining, or alterations to the baseline model.
- Zero Git modifications to remote branches or GitHub.

---

## 2. API Contract & Schema Compliance

The backend implements all 10 frontend endpoints with 100% schema compliance against the frontend's Zod definitions (`src/lib/api/schemas.ts`):

| Endpoint | Method | Response Zod Schema | Verified |
|---|---|---|:---:|
| `/api/status` | GET | `SystemStatus` | PASSED |
| `/api/presets` | GET | `array(CapturePreset)` | PASSED |
| `/api/analyses` | GET | `array(AnalysisSummary)` | PASSED |
| `/api/analyses` | POST | `AnalysisResult` | PASSED |
| `/api/analyses/{id}` | GET | `AnalysisResult` | PASSED |
| `/api/analyses/upload` | POST | `AnalysisResult` | PASSED |
| `/api/analyses/{id}/report.csv` | GET | Text CSV with `Content-Disposition` | PASSED |
| `/api/live/start` | POST | `LiveSession` | PASSED |
| `/api/live/{id}` | GET | `LiveSession` | PASSED |
| `/api/live/{id}/stop` | POST | `AnalysisResult` | PASSED |

---

## 3. Automated Test Verification Results

The automated test suite in `tests/test_api_contract.py` validates the end-to-end functionality using FastAPI's test client:

```
tests/test_api_contract.py::test_system_status_contract PASSED           [ 12%]
tests/test_api_contract.py::test_presets_contract PASSED                 [ 25%]
tests/test_api_contract.py::test_analyze_preset_normal PASSED            [ 37%]
tests/test_api_contract.py::test_analyze_attack_presets PASSED           [ 50%]
tests/test_api_contract.py::test_analyze_path_traversal_blocked PASSED   [ 62%]
tests/test_api_contract.py::test_upload_csv_analysis PASSED              [ 75%]
tests/test_api_contract.py::test_upload_invalid_csv_rejected PASSED      [ 87%]
tests/test_api_contract.py::test_live_session_flow_mock_direct PASSED    [100%]

======================== 8 passed in 6.23s =========================
```

Combined regression and socket contract tests:
```
=================== 22 passed, 3 subtests passed in 23.81s ===================
```

---

## 4. Live Capture & Inference Architecture

1. **Thread-Safe Session Lifecycle:**
   - Handled via `LiveSessionManager` using recursive locking (`threading.RLock`) to guarantee isolation and thread safety.
   - Prevents concurrent live sessions (returns HTTP 409 Conflict if a session is already capturing).
2. **Socket Handling:**
   - Single-process ownership of `/tmp/can_sentinel.sock`.
   - Cleans up stale sockets before binding with permissions `0600`.
3. **Window Construction & Incremental Scoring:**
   - Incoming frames are validated against the CAN-Sentinel version 1 socket contract.
   - Frames are bucketed into 1000ms fixed windows anchored to the first accepted frame.
   - When a frame in window $N+1$ arrives, window $N$ is finalized, features extracted, and scored via `model.predict()` and `model.score_samples()`.
4. **Stop & Analyze Exclusion:**
   - On `/api/live/{id}/stop`, the sniffer process is sent `SIGINT`, socket closed, and the final incomplete window is excluded from inference reports matching the project's standard offline scoring rules.
