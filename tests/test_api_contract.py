#!/usr/bin/env python3
"""Contract and integration tests for CAN-Sentinel FastAPI backend."""

import io
import os
import shutil
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from api_server import app, check_interface_state, check_sniffer_status
from isolation_forest_detector import FEATURE_COLUMNS


@pytest.fixture
def client():
    return TestClient(app)


def test_system_status_contract(client):
    """Test GET /api/status matches the frontend SystemStatus Zod schema."""
    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.json()

    assert data["data_source"] == "backend"
    assert isinstance(data["backend_version"], str)
    assert isinstance(data["interface"], dict)
    assert data["interface"]["name"] == "vcan0"
    assert data["interface"]["state"] in ("UP", "DOWN", "MISSING", "UNKNOWN")

    assert isinstance(data["sniffer"], dict)
    assert isinstance(data["sniffer"]["built"], bool)
    assert isinstance(data["sniffer"]["path"], str)

    model = data["model"]
    assert isinstance(model, dict)
    assert model["loaded"] is True
    assert model["window_ms"] == 1000
    assert model["contamination"] == 0.02
    assert model["feature_columns"] == FEATURE_COLUMNS
    assert "checked_at" in data


def test_presets_contract(client):
    """Test GET /api/presets returns list of genuine presets."""
    resp = client.get("/api/presets")
    assert resp.status_code == 200
    presets = resp.json()
    assert isinstance(presets, list)
    assert len(presets) > 0

    for p in presets:
        assert "id" in p
        assert "label" in p
        assert "path" in p
        assert "available" in p
        assert isinstance(p["available"], bool)


def test_analyze_preset_normal(client):
    """Test POST /api/analyses on normal_baseline_60s.csv."""
    resp = client.post("/api/analyses", json={
        "capture_path": "data/normal_baseline_60s.csv",
        "origin": "preset"
    })
    assert resp.status_code == 200
    data = resp.json()

    # Verify AnalysisResult schema
    assert data["data_source"] == "backend"
    assert data["origin"] == "preset"
    assert data["capture_file"] == "normal_baseline_60s.csv"
    assert data["frames_loaded"] > 0
    assert data["windows_scored"] > 0
    assert data["normal_count"] > 0
    # Normal baseline should be predominantly normal
    assert data["normal_count"] >= data["anomaly_count"]

    assert "model" in data
    assert "windows" in data
    assert len(data["windows"]) == data["windows_scored"]
    first_w = data["windows"][0]
    assert first_w["prediction"] in ("NORMAL", "ANOMALY")
    assert isinstance(first_w["anomaly_score"], float)
    for col in FEATURE_COLUMNS:
        assert col in first_w["features"]

    assert "frequency_summary" in data
    assert len(data["frequency_summary"]) > 0
    first_f = data["frequency_summary"][0]
    assert "can_id" in first_f
    assert "frame_format" in first_f
    assert "frame_count" in first_f
    assert "percentage_of_total" in first_f
    assert "unique_payload_count" in first_f
    assert "mean_interarrival_ms" in first_f

    # Test GET /api/analyses/{id}
    aid = data["id"]
    detail = client.get(f"/api/analyses/{aid}")
    assert detail.status_code == 200
    assert detail.json()["id"] == aid

    # Test GET /api/analyses
    listing = client.get("/api/analyses")
    assert listing.status_code == 200
    ids = [item["id"] for item in listing.json()]
    assert aid in ids

    # Test GET /api/analyses/{id}/report.csv
    rep = client.get(f"/api/analyses/{aid}/report.csv")
    assert rep.status_code == 200
    assert "text/csv" in rep.headers["content-type"]
    assert f'filename="{aid}_inference.csv"' in rep.headers["content-disposition"]
    csv_text = rep.text
    assert "capture_file,window_index,window_start_utc,prediction,anomaly_score" in csv_text


def test_analyze_attack_presets(client):
    """Test POST /api/analyses on high_frequency and unexpected_id captures."""
    # High frequency
    resp_hf = client.post("/api/analyses", json={
        "capture_path": "data/high_frequency_capture.csv",
        "origin": "preset"
    })
    assert resp_hf.status_code == 200
    data_hf = resp_hf.json()
    assert data_hf["anomaly_count"] > 0

    # Unexpected ID
    resp_uid = client.post("/api/analyses", json={
        "capture_path": "data/unexpected_id_capture.csv",
        "origin": "preset"
    })
    assert resp_uid.status_code == 200
    data_uid = resp_uid.json()
    assert data_uid["anomaly_count"] > 0


def test_analyze_path_traversal_blocked(client):
    """Test security restriction on unauthorized file paths."""
    resp = client.post("/api/analyses", json={
        "capture_path": "../../../Windows/System32/drivers/etc/hosts",
        "origin": "path"
    })
    assert resp.status_code in (403, 404)
    assert "detail" in resp.json()


def test_upload_csv_analysis(client):
    """Test POST /api/analyses/upload."""
    normal_csv = (ROOT / "data/fresh_clone_normal.csv").read_bytes()
    resp = client.post(
        "/api/analyses/upload",
        files={"file": ("test_upload_normal.csv", normal_csv, "text/csv")}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["origin"] == "upload"
    assert data["data_source"] == "backend"
    assert data["windows_scored"] > 0


def test_upload_invalid_csv_rejected(client):
    """Test invalid CSV upload fails with 400."""
    bad_csv = b"col1,col2\n1,2\n"
    resp = client.post(
        "/api/analyses/upload",
        files={"file": ("bad.csv", bad_csv, "text/csv")}
    )
    assert resp.status_code == 400
    assert "detail" in resp.json()


def test_live_session_flow_mock_direct(client):
    """Test live session start, event feeding, polling, and stopping."""
    from api_server import live_manager

    # Start live capture
    start_resp = client.post("/api/live/start")
    assert start_resp.status_code == 200
    session = start_resp.json()
    sid = session["id"]
    assert session["state"] == "capturing"
    assert session["data_source"] == "backend"

    # Concurrent start must fail with 409
    dup_resp = client.post("/api/live/start")
    assert dup_resp.status_code == 409
    assert "in progress" in dup_resp.json()["detail"]

    # Poll live session
    poll_resp = client.get(f"/api/live/{sid}")
    assert poll_resp.status_code == 200
    assert poll_resp.json()["id"] == sid

    # Feed events across 2 windows directly
    base_ts = 1730000000_000000000
    for w in range(2):
        for f in range(10):
            ts_str = f"2024-10-27T03:33:2{w}.{f:02d}0000000Z"
            event = {
                "schema_version": 1,
                "event_type": "can_frame",
                "timestamp_utc": ts_str,
                "interface": "vcan0",
                "can_id": "0x100",
                "frame_format": "standard",
                "flags": "none",
                "dlc": 8,
                "payload": "0102030405060708",
            }
            live_manager.feed_event_direct(event, sid)

    # Trigger window transition with a 3rd window event
    live_manager.feed_event_direct({
        "schema_version": 1,
        "event_type": "can_frame",
        "timestamp_utc": "2024-10-27T03:33:23.000000000Z",
        "interface": "vcan0",
        "can_id": "0x100",
        "frame_format": "standard",
        "flags": "none",
        "dlc": 8,
        "payload": "0102030405060708",
    }, sid)

    poll2 = client.get(f"/api/live/{sid}")
    assert poll2.status_code == 200
    assert len(poll2.json()["windows"]) >= 1

    # Stop live capture
    stop_resp = client.post(f"/api/live/{sid}/stop")
    assert stop_resp.status_code == 200
    final_res = stop_resp.json()
    assert final_res["origin"] == "live"
    assert final_res["data_source"] == "backend"
    assert "windows" in final_res
    assert "frequency_summary" in final_res
