#!/usr/bin/env python3
"""CAN-Sentinel Automotive ECU Intrusion Detection System — FastAPI Backend.

Provides standard REST endpoints matching the Lovable React frontend contracts:
  - GET  /api/status
  - GET  /api/presets
  - GET  /api/analyses
  - POST /api/analyses
  - GET  /api/analyses/{id}
  - POST /api/analyses/upload
  - GET  /api/analyses/{id}/report.csv
  - POST /api/live/start
  - GET  /api/live/{id}
  - POST /api/live/{id}/stop
"""

import os
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import uvicorn
from fastapi import FastAPI, File, HTTPException, Response, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

if __package__:
    from .api_analysis_service import (
        ApiAnalysisService,
        DEFAULT_MODEL_PATH,
        get_model_info,
        parse_csv_records,
    )
    from .live_session_manager import LiveSessionManager
    from .response_engine import ResponseEngine
    from .replay_mitigator import ReplayMitigator


else:
    from api_analysis_service import (
        ApiAnalysisService,
        DEFAULT_MODEL_PATH,
        get_model_info,
        parse_csv_records,
    )
    from live_session_manager import LiveSessionManager
    from response_engine import ResponseEngine
    from replay_mitigator import ReplayMitigator
ROOT = Path(__file__).resolve().parents[1]
BACKEND_VERSION = "0.9.0-fastapi"

app = FastAPI(
    title="CAN-Sentinel IDS Backend",
    version=BACKEND_VERSION,
    description="FastAPI service for CAN-Sentinel automotive intrusion detection system",
)

# CORS configuration
default_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
]
env_origins = os.getenv("CAN_SENTINEL_CORS_ORIGINS", "")
if env_origins:
    origins = [orig.strip() for orig in env_origins.split(",") if orig.strip()]
else:
    origins = default_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

# Shared singletons
analysis_service = ApiAnalysisService(
    model_path=DEFAULT_MODEL_PATH,
    reports_dir=ROOT / "reports",
)
live_manager = LiveSessionManager(
    analysis_service=analysis_service,
    model_path=DEFAULT_MODEL_PATH,
    captures_dir=ROOT / "data",
    sniffer_path=ROOT / "build" / "can_sniffer",
)
response_engine = ResponseEngine()
replay_mitigator = ReplayMitigator()
response_replays = {}


# Pydantic request models
class AnalyzeCaptureRequest(BaseModel):
    capture_path: str
    origin: Optional[Literal["preset", "path"]] = "preset"


def check_interface_state(iface_name: str = "vcan0") -> str:
    """Inspect the host Linux network interface state (UP, DOWN, MISSING, UNKNOWN)."""
    # Check via sysfs
    operstate_path = Path(f"/sys/class/net/{iface_name}/operstate")
    flags_path = Path(f"/sys/class/net/{iface_name}/flags")

    if not operstate_path.exists() and not flags_path.exists():
        return "MISSING"

    try:
        if operstate_path.exists():
            state_str = operstate_path.read_text(encoding="utf-8").strip().lower()
            if state_str == "up":
                return "UP"
            elif state_str in ("down", "lowerlayerdown"):
                return "DOWN"

        if flags_path.exists():
            flags_hex = flags_path.read_text(encoding="utf-8").strip()
            flags = int(flags_hex, 16)
            # IFF_UP is bit 0 (0x1)
            if flags & 0x1:
                return "UP"
            else:
                return "DOWN"
    except Exception:
        pass

    return "UNKNOWN"


def check_sniffer_status() -> Dict[str, Any]:
    """Check whether build/can_sniffer exists and is executable."""
    sniffer_path = ROOT / "build" / "can_sniffer"
    built = sniffer_path.is_file() and os.access(sniffer_path, os.X_OK)
    return {
        "built": built,
        "path": "build/can_sniffer",
    }


# =====================================================================
# REST Endpoints
# =====================================================================

@app.get("/api/status")
def get_system_status():
    """Inspect actual Linux environment, interface, sniffer binary, and ML model."""
    iface_state = check_interface_state("vcan0")
    sniffer_stat = check_sniffer_status()
    model_info = get_model_info(DEFAULT_MODEL_PATH)

    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    return {
        "data_source": "backend",
        "backend_version": BACKEND_VERSION,
        "interface": {
            "name": "vcan0",
            "state": iface_state,
        },
        "sniffer": sniffer_stat,
        "model": model_info,
        "checked_at": now_utc,
    }


@app.get("/api/presets")
def get_presets():
    """Return genuine capture presets available in the repository."""
    candidate_presets = [
        ("normal_baseline_60s", "Normal baseline — 60 seconds", "data/normal_baseline_60s.csv"),
        ("high_frequency_capture", "High-frequency attack", "data/high_frequency_capture.csv"),
        ("unexpected_id_capture", "Unexpected extended ID", "data/unexpected_id_capture.csv"),
        ("fresh_clone_normal", "Fresh clone normal capture", "data/fresh_clone_normal.csv"),
        ("fresh_clone_high_frequency", "Fresh clone high frequency", "data/fresh_clone_high_frequency.csv"),
        ("fresh_clone_unexpected_id", "Fresh clone unexpected extended ID", "data/fresh_clone_unexpected_id.csv"),
    ]

    results = []
    for pid, label, rel_path in candidate_presets:
        full_path = ROOT / rel_path
        results.append({
            "id": pid,
            "label": label,
            "path": rel_path,
            "available": full_path.is_file(),
        })
    return results


@app.get("/api/analyses")
def list_analyses():
    """List all completed analyses in reverse chronological order."""
    return analysis_service.list_analyses()


@app.post("/api/analyses")
def analyze_capture(req: AnalyzeCaptureRequest):
    """Score a capture file located on the backend host."""
    path_str = req.capture_path.strip()
    if not path_str:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="capture_path must not be empty",
        )

    cand_path = Path(path_str)
    if not cand_path.is_absolute():
        cand_path = ROOT / cand_path

    # Security check: must reside inside project root
    try:
        cand_path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: capture file must reside within the project directory.",
        )

    if not cand_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Capture file not found: {path_str}",
        )

    try:
        records = parse_csv_records(cand_path)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid capture file: {exc}",
        )

    try:
        res = analysis_service.score_records(
            records=records,
            capture_name=cand_path.name,
            origin=req.origin or "preset",
        )
        return res
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {exc}",
        )


@app.get("/api/analyses/{analysis_id}")
def get_analysis_detail(analysis_id: str):
    """Retrieve full analysis details including windows, frequency summary, and notes."""
    res = analysis_service.get_analysis(analysis_id)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis {analysis_id} not found",
        )
    return res

@app.post(
    "/api/analyses/{analysis_id}/incidents/{incident_id}/response/plan"
)
def plan_incident_response(analysis_id: str, incident_id: str):
    """Create an evidence-backed offline response plan."""

    incident = get_stored_incident(analysis_id, incident_id)

    try:
        return response_engine.plan(incident)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

@app.post(
    "/api/analyses/{analysis_id}/incidents/{incident_id}/response/activate"
)
def activate_incident_response(analysis_id: str, incident_id: str):
    """Activate an evidence-backed response in offline replay only."""

    incident = get_stored_incident(analysis_id, incident_id)
    storage_key = get_response_storage_key(analysis_id, incident_id)

    try:
        existing = response_engine.get_response(storage_key)

        if existing and existing.get("replay_result"):
            existing["incident_id"] = incident_id
            return existing

        scoped_incident = {
            **incident,
            "incident_id": storage_key,
        }

        response = response_engine.activate(scoped_incident)

        if response["action"] == "MANUAL_REVIEW":
            response["incident_id"] = incident_id
            return response

        records = analysis_service.get_capture_records(analysis_id)

        if not records:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Original capture records are unavailable.",
            )

        replay_result = replay_mitigator.apply(
            records=records,
            response=response,
            target_can_ids=response["target_can_ids"],
        )

        result = response_engine.attach_replay_result(
            storage_key,
            replay_result,
        )

        response_replays[storage_key] = replay_result
        result["incident_id"] = incident_id

        return result

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
def get_response_storage_key(analysis_id: str, incident_id: str) -> str:
    """Create an analysis-scoped key for response state."""
    return f"{analysis_id}:{incident_id}"
@app.post(
    "/api/analyses/{analysis_id}/incidents/{incident_id}/response/verify"
)
def verify_incident_recovery(analysis_id: str, incident_id: str):
    """Verify recovery using original and offline replay capture records."""

    incident = get_stored_incident(analysis_id, incident_id)
    storage_key = get_response_storage_key(analysis_id, incident_id)

    response = response_engine.get_response(storage_key)

    if not response:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Response not found. Activate a response first.",
        )

    if response.get("status") != "SIMULATED_ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Response is not awaiting recovery verification.",
        )

    replay_result = response_replays.get(storage_key)

    if not replay_result:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Offline replay result is unavailable.",
        )

    original_records = analysis_service.get_capture_records(analysis_id)

    if not original_records:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Original capture records are unavailable.",
        )

    replay_records = replay_result.get("replay_records", [])
    target_ids = set(response.get("target_can_ids", []))

    timestamps = [r["timestamp_ns"] for r in original_records]
    duration_seconds = max(
        1.0,
        (max(timestamps) - min(timestamps)) / 1_000_000_000,
    )

    baseline_count = sum(
        1 for r in original_records if r["can_id"] in target_ids
    )
    post_count = sum(
        1 for r in replay_records if r["can_id"] in target_ids
    )

    baseline_rate = baseline_count / duration_seconds
    post_rate = post_count / duration_seconds

    unexpected_targets = set(
        incident.get("response_evidence", {}).get(
            "unexpected_can_ids", []
        )
    )

    remaining_unexpected_ids = len({
        r["can_id"]
        for r in replay_records
        if r["can_id"] in unexpected_targets
    })

    try:
        result = response_engine.verify_recovery(
            incident_id=storage_key,
            baseline_frame_rate=baseline_rate,
            post_mitigation_frame_rate=post_rate,
            remaining_unexpected_ids=remaining_unexpected_ids,
        )
        result["incident_id"] = incident_id
        return result

    except (ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )

def get_stored_incident(analysis_id: str, incident_id: str):
    """Retrieve an incident belonging to a stored backend analysis."""

    analysis = analysis_service.get_analysis(analysis_id)

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found.",
        )

    incidents = analysis.get("incidents", [])

    for incident in incidents:
        if incident.get("incident_id") == incident_id:
            return incident

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Incident not found in this analysis.",
    )

@app.post("/api/analyses/upload")
async def upload_capture(file: UploadFile = File(...)):
    """Upload a CAN sniffer CSV file, validate schema, and run model scoring."""
    if not file.filename.endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must be a .csv file.",
        )

    content_bytes = await file.read()
    try:
        text = content_bytes.decode("utf-8")
        records = parse_csv_records(text)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Uploaded CSV validation failed: {exc}",
        )

    # Persist uploaded file in data/uploads
    uploads_dir = ROOT / "data" / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    clean_name = f"upload_{uuid.uuid4().hex[:6]}_{file.filename}"
    upload_dest = uploads_dir / clean_name
    upload_dest.write_bytes(content_bytes)

    try:
        res = analysis_service.score_records(
            records=records,
            capture_name=file.filename,
            origin="upload",
        )
        return res
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to score uploaded capture: {exc}",
        )


@app.get("/api/analyses/{analysis_id}/report.csv")
def download_analysis_report(analysis_id: str):
    """Download inference CSV report for an analysis."""
    report_path = analysis_service.get_report_csv_path(analysis_id)
    if not report_path or not report_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report CSV for analysis {analysis_id} not found",
        )

    filename = f"{analysis_id}_inference.csv"
    return FileResponse(
        path=report_path,
        media_type="text/csv",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/live/start")
def start_live_capture():
    """Start live capture session, binding /tmp/can_sentinel.sock and launching sniffer."""
    try:
        session = live_manager.start_session(interface="vcan0")
        return session
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not start live capture: {exc}",
        )


@app.get("/api/live/{session_id}")
def get_live_session(session_id: str):
    """Poll live session state, captured frames count, and scored windows."""
    session = live_manager.get_active_session_snapshot(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Live session {session_id} not found or inactive",
        )
    return session


@app.post("/api/live/{session_id}/stop")
def stop_live_capture(session_id: str):
    """Stop live capture, gracefully terminate sniffer, discard partial window, and score."""
    try:
        analysis_result = live_manager.stop_session(session_id)
        return analysis_result
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error stopping live session: {exc}",
        )


def main():
    """CLI entrypoint to start FastAPI uvicorn server."""
    host = os.getenv("CAN_SENTINEL_HOST", "0.0.0.0")
    port = int(os.getenv("CAN_SENTINEL_PORT", "8000"))
    uvicorn.run("api_server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
