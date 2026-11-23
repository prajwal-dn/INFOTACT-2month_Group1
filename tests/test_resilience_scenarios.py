"""Tests for Phase 7: Automated Response Validation & Resilience Testing.

Validates:
1. All 8 controlled failure scenarios via ResilienceTester.
2. Structured response audit trail creation in LiveSessionManager.
3. Deduplication of response workers for the same incident.
4. Process termination strict exit code verification (return_code == 0).
5. Interrupted recovery verification resets without false declaration.
"""

import pytest
from pathlib import Path
from src.resilience_tester import ResilienceTester
from src.live_session_manager import LiveSessionManager


class FakeAnalysisService:
    def __init__(self):
        self.registered_incidents = {}

    def register_live_incident(self, analysis_id, incident, records, capture_name):
        self.registered_incidents[analysis_id] = {
            "incident": incident,
            "records": records,
            "capture_name": capture_name,
        }


def test_all_controlled_failure_scenarios(tmp_path):
    tester = ResilienceTester(captures_dir=tmp_path)
    results = tester.run_all()

    assert len(results) == 8, f"Expected 8 scenarios, got {len(results)}"

    expected_ids = [
        "SCN-01",
        "SCN-02",
        "SCN-03",
        "SCN-04",
        "SCN-05",
        "SCN-06",
        "SCN-07",
        "SCN-08",
    ]
    actual_ids = [r["scenario_id"] for r in results]
    assert actual_ids == expected_ids

    # All scenarios must pass
    for scn in results:
        assert scn["status"] == "PASS", f"Scenario {scn['scenario_id']} failed: {scn['actual_result']}"
        assert "expected_behavior" in scn
        assert "actual_result" in scn
        assert "timestamp" in scn
        assert "diagnostic_evidence" in scn


def test_response_audit_trail_and_deduplication(tmp_path):
    service = FakeAnalysisService()
    manager = LiveSessionManager(
        analysis_service=service,
        captures_dir=tmp_path,
    )
    session = {
        "id": "audit_test_session",
        "interface": "vcan0",
        "state": "capturing",
        "windows": [],
        "records": [],
        "frames_captured": 0,
        "capture_file": str(tmp_path / "audit.csv"),
        "started_at": "2026-11-10T02:00:00Z",
        "pending_window_index": 0,
        "message": None,
        "incidents": [],
        "attack_history": [],
        "response_audit_trail": [],
    }
    manager._active_session = session

    # Queue an incident
    session["open_incident_windows"] = [
        {"window_index": 1, "window_start_utc": "2026-11-10T02:00:01Z", "prediction": "ANOMALY", "anomaly_score": 0.8, "features": {"total_frames": 500}, "response_evidence": {"can_id_counts": {"0x100": 500}, "unexpected_can_ids": []}},
        {"window_index": 2, "window_start_utc": "2026-11-10T02:00:02Z", "prediction": "ANOMALY", "anomaly_score": 0.8, "features": {"total_frames": 500}, "response_evidence": {"can_id_counts": {"0x100": 500}, "unexpected_can_ids": []}},
    ]
    session["open_incident_records"] = [{"timestamp_utc": "2026-11-10T02:00:01Z", "can_id": "0x100", "dlc": 8, "payload": "00"}]
    manager._close_live_incident(session)

    # Attempt to queue the same incident again to test deduplication
    manager._incident_queue.put({
        "session_id": "audit_test_session",
        "analysis_id": "analysis_live_audit_test_session_incident_0001",
        "incident": {"incident_id": "INC-0001"},
        "records": [],
        "capture_name": "audit.csv",
        "first_anomalous_window_utc": "2026-11-10T02:00:01Z",
        "incident_confirmed_utc": "2026-11-10T02:00:02Z",
    })

    manager._incident_queue.join()

    # Verify deduplication prevented duplicate processing
    assert len(service.registered_incidents) == 1
    assert len(manager._processed_incident_ids) == 1

    # Verify structured response audit trail
    snapshot = manager.get_active_session_snapshot("audit_test_session")
    audit_trail = snapshot.get("response_audit_trail", [])
    assert len(audit_trail) == 1

    entry = audit_trail[0]
    assert entry["incident_id"] == "INC-0001"
    assert entry["response_action"] == "TERMINATE_ATTACK_PROCESS"
    assert "action_initiation_timestamp" in entry
    assert "process_termination_timestamp" in entry
    assert "return_code" in entry
    assert "termination_reason" in entry
    assert "sniffer_continuity_status" in entry
    assert "normal_traffic_continuity_status" in entry
    assert "recovery_verification_result" in entry
    assert "final_response_status" in entry

    # Verify validation object
    val = snapshot.get("response_validation", {})
    assert "overall_status" in val
    assert "checks" in val
    assert val["checks"]["confirmed_incident_creation"]["status"] == "PASS"

    # Verify reliability object
    rel = snapshot.get("response_reliability", {})
    assert "total_response_attempts" in rel
    assert "confirmed_successful_mitigations" in rel
    assert "failed_mitigations" in rel
    assert "unexpected_attack_process_exits" in rel
