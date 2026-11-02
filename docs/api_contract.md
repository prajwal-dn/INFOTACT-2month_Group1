# CAN-Sentinel — FastAPI Backend REST Contract

**Version:** 0.9.0-fastapi  
**Base Path:** `/api`  
**Host Port:** `8000` (FastAPI / Uvicorn)  
**Consumer:** Lovable AI Frontend (`src/lib/api/schemas.ts`, `src/lib/api/endpoints.ts`)

---

## 1. Overview

The CAN-Sentinel FastAPI service exposes the automotive ECU intrusion detection backend to the Lovable React frontend. All real backend responses use `data_source: "backend"`.

All errors return JSON in standard FastAPI format:
```json
{
  "detail": "Error description string"
}
```

---

## 2. Endpoints Specification

### 2.1 System Status
- **Method:** `GET`
- **Path:** `/api/status`
- **Description:** Real-time inspection of the Linux host environment (`vcan0` status, C sniffer binary, original Isolation Forest model bundle).
- **Response Schema:** `SystemStatus`
```json
{
  "data_source": "backend",
  "backend_version": "0.9.0-fastapi",
  "interface": {
    "name": "vcan0",
    "state": "UP"
  },
  "sniffer": {
    "built": true,
    "path": "build/can_sniffer"
  },
  "model": {
    "loaded": true,
    "path": "models/isolation_forest_baseline.joblib",
    "algorithm": "IsolationForest (n_estimators=200, random_state=42)",
    "contamination": 0.02,
    "training_windows": 47,
    "window_ms": 1000,
    "feature_columns": [
      "total_frames",
      "unique_can_ids",
      "extended_frame_count",
      "unique_payload_count",
      "max_id_share_pct",
      "id_0x100_count",
      "id_0x100_share_pct",
      "id_0x101_count",
      "id_0x101_share_pct",
      "id_0x102_count",
      "id_0x102_share_pct",
      "id_0x999_count",
      "id_0x999_share_pct",
      "other_id_count"
    ],
    "sklearn_version": "1.9.1"
  },
  "checked_at": "2026-11-02T00:00:00.000000Z"
}
```

---

### 2.2 Capture Presets
- **Method:** `GET`
- **Path:** `/api/presets`
- **Response:** Array of `CapturePreset` objects.
```json
[
  {
    "id": "normal_baseline_60s",
    "label": "Normal baseline — 60 seconds",
    "path": "data/normal_baseline_60s.csv",
    "available": true
  },
  {
    "id": "high_frequency_capture",
    "label": "High-frequency attack",
    "path": "data/high_frequency_capture.csv",
    "available": true
  },
  {
    "id": "unexpected_id_capture",
    "label": "Unexpected extended ID",
    "path": "data/unexpected_id_capture.csv",
    "available": true
  }
]
```

---

### 2.3 List Analyses
- **Method:** `GET`
- **Path:** `/api/analyses`
- **Response:** Array of `AnalysisSummary` objects in reverse chronological order.

---

### 2.4 Analyze Capture (Preset or Host Path)
- **Method:** `POST`
- **Path:** `/api/analyses`
- **Request Body:**
```json
{
  "capture_path": "data/normal_baseline_60s.csv",
  "origin": "preset"
}
```
- **Response Schema:** `AnalysisResult` (containing 14-feature scored 1-second windows, `frequency_summary`, `excluded_partial_window`, and `notes`).

---

### 2.5 Analysis Detail
- **Method:** `GET`
- **Path:** `/api/analyses/{id}`
- **Response Schema:** `AnalysisResult`

---

### 2.6 Upload Capture CSV
- **Method:** `POST`
- **Path:** `/api/analyses/upload`
- **Form Data:** `file: <multipart file>`
- **Response Schema:** `AnalysisResult`

---

### 2.7 Download Report CSV
- **Method:** `GET`
- **Path:** `/api/analyses/{id}/report.csv`
- **Response Headers:** `Content-Type: text/csv`, `Content-Disposition: attachment; filename="{id}_inference.csv"`

---

### 2.8 Start Live Capture
- **Method:** `POST`
- **Path:** `/api/live/start`
- **Description:** Binds `/tmp/can_sentinel.sock` on Linux, launches `build/can_sniffer --socket`, initializes live receiver state. Only one active live session is permitted.
- **Response Schema:** `LiveSession`
```json
{
  "id": "live_a1b2c3d4",
  "data_source": "backend",
  "state": "capturing",
  "interface": "vcan0",
  "capture_file": ".../data/live_capture_live_a1b2c3d4_20261102T000000Z.csv",
  "started_at": "2026-11-02T00:00:00.000000Z",
  "frames_captured": 0,
  "windows": [],
  "pending_window_index": null,
  "message": "Live capture initialized"
}
```

---

### 2.9 Poll Live Session
- **Method:** `GET`
- **Path:** `/api/live/{id}`
- **Description:** Frontend polls this endpoint every 1000ms. Returns snapshot of completed windows scored incrementally by the Isolation Forest model and the current pending window index.
- **Response Schema:** `LiveSession`

---

### 2.10 Stop Live Capture ("Stop & Analyze")
- **Method:** `POST`
- **Path:** `/api/live/{id}/stop`
- **Description:** Sends `SIGINT` to the C sniffer, unbinds `/tmp/can_sentinel.sock`, discards the final incomplete window, performs full scoring and frequency analysis on all recorded frames, and saves the final report.
- **Response Schema:** `AnalysisResult`
