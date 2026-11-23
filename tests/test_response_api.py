import pytest
from pathlib import Path
import subprocess
from fastapi.testclient import TestClient

from src import api_server
from src.response_engine import ResponseEngine
from src.replay_mitigator import ReplayMitigator


@pytest.fixture
def client(monkeypatch):
    """Provide isolated response components for every test."""

    monkeypatch.setattr(api_server, "response_engine", ResponseEngine())
    monkeypatch.setattr(api_server, "replay_mitigator", ReplayMitigator())
    monkeypatch.setattr(api_server, "response_replays", {})

    return TestClient(api_server.app)


def make_incident(
    incident_id="INC-0001",
    reason="HIGH_TRAFFIC_VOLUME",
    can_id="0x100",
):
    if reason == "HIGH_TRAFFIC_VOLUME":
        evidence = {
            "can_id_counts": {can_id: 120},
            "unexpected_can_ids": [],
        }
    elif reason == "UNEXPECTED_CAN_ID":
        evidence = {
            "can_id_counts": {can_id: 5},
            "unexpected_can_ids": [can_id],
        }
    else:
        evidence = {
            "can_id_counts": {},
            "unexpected_can_ids": [],
        }

    return {
        "incident_id": incident_id,
        "severity": "HIGH",
        "status": "OPEN",
        "affected_can_ids": [can_id],
        "reasons": [{"code": reason}],
        "response_evidence": evidence,
    }


def make_records(can_id="0x100", count=150):
    """Create deterministic offline vcan0 capture records."""

    return [
        {
            "timestamp_ns": i * 5_000_000,
            "can_id": can_id,
            "interface": "vcan0",
            "frame_format": "standard",
            "payload": "0102030405060708",
            "dlc": 8,
        }
        for i in range(count)
    ]


def setup_analysis(
    monkeypatch,
    analysis_id="ANALYSIS-A",
    incident=None,
    records=None,
):
    if incident is None:
        incident = make_incident()

    if records is None:
        records = make_records()

    analysis = {
        "id": analysis_id,
        "incidents": [incident],
    }

    monkeypatch.setattr(
        api_server.analysis_service,
        "get_analysis",
        lambda aid: analysis if aid == analysis_id else None,
    )

    monkeypatch.setattr(
        api_server.analysis_service,
        "get_capture_records",
        lambda aid: records if aid == analysis_id else None,
    )

    return incident


def response_url(analysis_id, incident_id="INC-0001"):
    return (
        f"/api/analyses/{analysis_id}/incidents/"
        f"{incident_id}/response"
    )


def test_plan_high_frequency_incident(client, monkeypatch):
    setup_analysis(monkeypatch)

    response = client.post(
        response_url("ANALYSIS-A") + "/plan"
    )

    assert response.status_code == 200
    data = response.json()

    assert data["classification"] == "HIGH_FREQUENCY_FLOOD"
    assert data["action"] == "SIMULATED_RATE_LIMIT"
    assert data["target_can_ids"] == ["0x100"]


def test_invalid_analysis_rejected(client):
    response = client.post(
        response_url("MISSING") + "/plan"
    )

    assert response.status_code == 404


def test_invalid_incident_rejected(client, monkeypatch):
    setup_analysis(monkeypatch)

    response = client.post(
        response_url("ANALYSIS-A", "INC-MISSING") + "/plan"
    )

    assert response.status_code == 404


def test_activation_runs_offline_replay(client, monkeypatch):
    setup_analysis(monkeypatch)

    response = client.post(
        response_url("ANALYSIS-A") + "/activate"
    )

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "SIMULATED_ACTIVE"
    assert data["action"] == "SIMULATED_RATE_LIMIT"
    assert data["mode"] == "SIMULATION"

    replay = data["replay_result"]

    assert replay["mode"] == "OFFLINE_SIMULATION"
    assert replay["original_preserved"] is True
    assert replay["removed_frames"] > 0


def test_manual_review_does_not_activate_mitigation(
    client,
    monkeypatch,
):
    incident = make_incident(
        reason="SOME_UNKNOWN_REASON"
    )
    setup_analysis(monkeypatch, incident=incident)

    response = client.post(
        response_url("ANALYSIS-A") + "/activate"
    )

    assert response.status_code == 200
    data = response.json()

    assert data["action"] == "MANUAL_REVIEW"
    assert data["status"] == "REVIEW_REQUIRED"
    assert "replay_result" not in data


def test_recovery_verification_after_activation(
    client,
    monkeypatch,
):
    setup_analysis(monkeypatch)

    activation = client.post(
        response_url("ANALYSIS-A") + "/activate"
    )

    assert activation.status_code == 200

    verification = client.post(
        response_url("ANALYSIS-A") + "/verify"
    )

    assert verification.status_code == 200

    data = verification.json()

    assert data["incident_id"] == "INC-0001"
    assert data["status"] in ("MITIGATED", "RECOVERY_FAILED")
    assert "recovery" in data


def test_verification_without_activation_rejected(
    client,
    monkeypatch,
):
    setup_analysis(monkeypatch)

    response = client.post(
        response_url("ANALYSIS-A") + "/verify"
    )

    assert response.status_code == 404


def test_unexpected_id_quarantine(client, monkeypatch):
    incident = make_incident(
        reason="UNEXPECTED_CAN_ID",
        can_id="0x555",
    )

    records = make_records("0x555", 10)
    setup_analysis(
        monkeypatch,
        incident=incident,
        records=records,
    )

    response = client.post(
        response_url("ANALYSIS-A") + "/activate"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["action"] == "SIMULATED_ID_QUARANTINE"
    assert data["target_can_ids"] == ["0x555"]
    assert data["replay_result"]["after"]["total_frames"] == 0


def test_same_incident_id_isolated_between_analyses(
    client,
    monkeypatch,
):
    incident_a = make_incident(can_id="0x100")
    incident_b = make_incident(can_id="0x101")

    records_a = make_records("0x100", 150)
    records_b = make_records("0x101", 150)

    analyses = {
        "ANALYSIS-A": {
            "id": "ANALYSIS-A",
            "incidents": [incident_a],
        },
        "ANALYSIS-B": {
            "id": "ANALYSIS-B",
            "incidents": [incident_b],
        },
    }

    captures = {
        "ANALYSIS-A": records_a,
        "ANALYSIS-B": records_b,
    }

    monkeypatch.setattr(
        api_server.analysis_service,
        "get_analysis",
        lambda aid: analyses.get(aid),
    )

    monkeypatch.setattr(
        api_server.analysis_service,
        "get_capture_records",
        lambda aid: captures.get(aid),
    )

    response_a = client.post(
        response_url("ANALYSIS-A") + "/activate"
    )
    response_b = client.post(
        response_url("ANALYSIS-B") + "/activate"
    )

    assert response_a.status_code == 200
    assert response_b.status_code == 200

    assert response_a.json()["incident_id"] == "INC-0001"
    assert response_b.json()["incident_id"] == "INC-0001"

    assert response_a.json()["target_can_ids"] == ["0x100"]
    assert response_b.json()["target_can_ids"] == ["0x101"]

    assert (
        response_a.json()["replay_result"]["before"]["frames_by_can_id"]
        != response_b.json()["replay_result"]["before"]["frames_by_can_id"]
    )


def test_repeated_activation_is_idempotent(
    client,
    monkeypatch,
):
    setup_analysis(monkeypatch)

    first = client.post(
        response_url("ANALYSIS-A") + "/activate"
    )

    second = client.post(
        response_url("ANALYSIS-A") + "/activate"
    )

    assert first.status_code == 200
    assert second.status_code == 200

    assert first.json() == second.json()


def test_recovery_uses_original_capture_time_span(
    client,
    monkeypatch,
):
    records = make_records("0x100", 150)
    setup_analysis(monkeypatch, records=records)

    activation = client.post(
        response_url("ANALYSIS-A") + "/activate"
    )
    assert activation.status_code == 200

    verification = client.post(
        response_url("ANALYSIS-A") + "/verify"
    )
    assert verification.status_code == 200

    recovery = verification.json()["recovery"]

    assert recovery["baseline_frame_rate"] > 0
    assert recovery["post_mitigation_frame_rate"] >= 0


def test_automatic_live_incident_response_end_to_end(
    client,
    monkeypatch,
):
    """Verify registration-backed automatic plan, replay, and recovery."""
    setup_analysis(monkeypatch)

    result = api_server.process_live_incident_automatically(
        "ANALYSIS-A",
        "INC-0001",
    )

    assert result["plan"]["classification"] == "HIGH_FREQUENCY_FLOOD"
    assert result["plan"]["action"] == "SIMULATED_RATE_LIMIT"

    assert result["activation"]["status"] == "SIMULATED_ACTIVE"
    assert result["activation"]["mode"] == "SIMULATION"
    assert result["activation"]["replay_result"]["mode"] == "OFFLINE_SIMULATION"
    assert result["activation"]["replay_result"]["original_preserved"] is True

    assert result["verification"]["status"] in (
        "MITIGATED",
        "RECOVERY_FAILED",
    )
    assert result["status"] == result["verification"]["status"]
    assert "recovery" in result["verification"]


def test_live_normal_traffic_api_lifecycle(client, monkeypatch):
    """Test start, duplicate, and stop for normal traffic and all simulations."""
    class MockProcess:
        pid = 3344
        returncode = None
        def poll(self):
            return self.returncode
        def send_signal(self, sig):
            pass
        def wait(self, timeout=None):
            self.returncode = 0
            return 0

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: MockProcess())

    manager = api_server.live_manager
    manager._active_session = {
        "id": "live_api_sim_test",
        "interface": "vcan0",
        "state": "capturing",
        "capture_file": "/tmp/test.csv",
        "started_at": "2026-11-09T10:00:00Z",
        "frames_captured": 100,
        "windows": [],
        "pending_window_index": None,
        "message": None,
        "normal": {"state": "NOT_STARTED"},
        "attack": {"state": "NOT_STARTED"},
        "recovery": {"state": "NOT_STARTED", "normal_windows": 0, "required_normal_windows": 2},
    }
    # Mock normal_path and attack_path as executable
    manager.normal_path = Path(__file__)
    manager.attack_path = Path(__file__)

    # Start normal traffic
    start_resp = client.post("/api/live/live_api_sim_test/normal", json={"interval_ms": 100})
    assert start_resp.status_code == 200
    assert start_resp.json()["state"] == "RUNNING"
    assert start_resp.json()["pid"] == 3344

    # Duplicate normal start should return 409
    dup_resp = client.post("/api/live/live_api_sim_test/normal", json={"interval_ms": 100})
    assert dup_resp.status_code == 409

    # Snapshot poll should show normal is RUNNING
    poll_resp = client.get("/api/live/live_api_sim_test")
    assert poll_resp.status_code == 200
    assert poll_resp.json()["normal"]["state"] == "RUNNING"

    # Stop normal traffic independently
    stop_resp = client.post("/api/live/live_api_sim_test/normal/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.json()["state"] == "STOPPED"

    # Start both and test stop_all_simulations
    manager._normal_proc = MockProcess()
    manager._attack_proc = MockProcess()
    manager._active_session["normal"] = {"state": "RUNNING", "pid": 3344}
    manager._active_session["attack"] = {"state": "RUNNING", "pid": 3345, "mode": 1}

    stop_all = client.post("/api/live/live_api_sim_test/simulations/stop")
    assert stop_all.status_code == 200
    assert stop_all.json()["normal"]["state"] == "STOPPED"
    assert stop_all.json()["attack"]["state"] == "STOPPED"
    assert manager._normal_proc is None
    assert manager._attack_proc is None

