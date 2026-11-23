"""Tests for Phase 3: Concurrent Normal and Malicious CAN Traffic Simulation."""

import subprocess
import pytest
from pathlib import Path

from src.live_session_manager import LiveSessionManager
from src.incident_engine import correlate_incidents
from src.response_engine import ResponseEngine


class FakeAnalysisService:
    def __init__(self):
        self.registered = {}

    def register_live_incident(self, analysis_id, incident, records, capture_name):
        self.registered[analysis_id] = {
            "incident": incident,
            "records": records,
            "capture_name": capture_name,
        }


class FakeProcess:
    def __init__(self, pid=12345):
        self.pid = pid
        self.returncode = None
        self.signal_sent = None

    def poll(self):
        return self.returncode

    def send_signal(self, sig):
        self.signal_sent = sig

    def wait(self, timeout=None):
        self.returncode = 0
        return 0


def _prepare_scoring(monkeypatch, predictions):
    import src.live_session_manager as live_module

    class FakeModel:
        def predict(self, _features):
            return [predictions.pop(0)]

        def score_samples(self, _features):
            return [-0.9]

    monkeypatch.setattr(
        live_module,
        "build_window_features",
        lambda records, window_ms: [
            {column: 0.0 for column in live_module.FEATURE_COLUMNS}
        ],
    )
    monkeypatch.setattr(
        live_module,
        "explain_window",
        lambda features, label: {"severity": "HIGH", "reasons": []},
    )

    return live_module, FakeModel()


# ─── 1. Normal traffic alone ─────────────────────────────────────────────────

def test_start_normal_traffic_alone(tmp_path, monkeypatch):
    manager = LiveSessionManager(
        analysis_service=FakeAnalysisService(),
        captures_dir=tmp_path,
        normal_path=tmp_path / "fake_normal",
    )
    fake_binary = tmp_path / "fake_normal"
    fake_binary.write_text("#!/bin/sh\nexit 0\n")
    fake_binary.chmod(0o755)

    fake_proc = FakeProcess(pid=1001)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: fake_proc)

    manager._active_session = {
        "id": "live_normal_test",
        "interface": "vcan0",
        "state": "capturing",
        "windows": [],
    }

    result = manager.start_normal("live_normal_test", interval_ms=100)

    assert result["state"] == "RUNNING"
    assert result["pid"] == 1001
    assert result["interval_ms"] == 100
    assert manager._normal_proc is fake_proc
    assert manager._attack_proc is None


# ─── 2. Attack traffic alone ─────────────────────────────────────────────────

def test_start_attack_traffic_alone(tmp_path, monkeypatch):
    manager = LiveSessionManager(
        analysis_service=FakeAnalysisService(),
        captures_dir=tmp_path,
        attack_path=tmp_path / "fake_attack",
    )
    fake_binary = tmp_path / "fake_attack"
    fake_binary.write_text("#!/bin/sh\nexit 0\n")
    fake_binary.chmod(0o755)

    fake_proc = FakeProcess(pid=2001)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: fake_proc)

    manager._active_session = {
        "id": "live_attack_test",
        "interface": "vcan0",
        "state": "capturing",
        "windows": [],
    }

    result = manager.start_attack("live_attack_test", mode=1)

    assert result["state"] == "RUNNING"
    assert result["pid"] == 2001
    assert result["mode"] == 1
    assert manager._attack_proc is fake_proc
    assert manager._normal_proc is None


# ─── 3. Normal and Mode 1 simultaneously ─────────────────────────────────────

def test_simultaneous_normal_and_mode1_aggregate_detection():
    """Verify that aggregate traffic of normal + Mode 1 (flood) is classified as HIGH_FREQUENCY_FLOOD."""
    # Normal: 0x100 (10/s), 0x101 (10/s), 0x102 (1/s)
    # Mode 1 attack: 0x100 (1000/s)
    # Combined window has 1010 frames of 0x100 out of 1021 total frames (>98%)
    combined_window = {
        "window_index": 1,
        "window_start_utc": "2026-11-09T10:00:01.000000000Z",
        "prediction": "ANOMALY",
        "anomaly_score": -0.85,
        "features": {
            "total_frames": 1021,
            "unique_can_ids": 3,
            "id_0x100_count": 1010,
            "id_0x101_count": 10,
            "id_0x102_count": 1,
            "id_0x999_count": 0,
            "other_id_count": 0,
        },
        "response_evidence": {
            "can_id_counts": {"0x100": 1010, "0x101": 10, "0x102": 1},
            "unexpected_can_ids": [],
            "dominant_can_id": "0x100",
            "dominant_can_id_share_pct": 98.92,
        },
        "explanation": {
            "severity": "HIGH",
            "reasons": [{
                "code": "HIGH_TRAFFIC_VOLUME",
                "message": "High traffic volume",
                "evidence": {"total_frames": 1021},
            }],
        },
    }

    w1 = {**combined_window, "window_index": 1}
    w2 = {**combined_window, "window_index": 2}
    incidents = correlate_incidents([w1, w2])
    assert len(incidents) == 1
    incident = incidents[0]

    engine = ResponseEngine()
    plan = engine.plan(incident)

    assert plan["classification"] == "HIGH_FREQUENCY_FLOOD"
    assert plan["action"] == "SIMULATED_RATE_LIMIT"
    assert plan["target_can_ids"] == ["0x100"]


# ─── 4. Normal and Mode 2 simultaneously ─────────────────────────────────────

def test_simultaneous_normal_and_mode2_aggregate_detection():
    """Verify aggregate traffic of normal + Mode 2 (extended 0x999).
    0x999 is tracked in KNOWN_IDS features (id_0x999_count); an unknown injection triggers quarantine.
    """
    # Normal: 0x100 (10/s), 0x101 (10/s), 0x102 (1/s)
    # Mode 2 attack: 0x999 (20/s)
    combined_window = {
        "window_index": 1,
        "window_start_utc": "2026-11-09T10:00:01.000000000Z",
        "prediction": "ANOMALY",
        "anomaly_score": -0.72,
        "features": {
            "total_frames": 41,
            "unique_can_ids": 4,
            "extended_frame_count": 20,
            "id_0x100_count": 10,
            "id_0x101_count": 10,
            "id_0x102_count": 1,
            "id_0x999_count": 20,
            "other_id_count": 0,
        },
        "response_evidence": {
            "can_id_counts": {"0x100": 10, "0x101": 10, "0x102": 1, "0x999": 20},
            "unexpected_can_ids": [],
            "dominant_can_id": "0x999",
            "dominant_can_id_share_pct": 48.78,
        },
        "explanation": {
            "severity": "HIGH",
            "reasons": [{
                "code": "EXTENDED_CAN_FRAME",
                "message": "Unexpected extended CAN frames detected",
                "evidence": {"extended_frame_count": 20},
            }],
        },
    }

    w1 = {**combined_window, "window_index": 1}
    w2 = {**combined_window, "window_index": 2}
    incidents = correlate_incidents([w1, w2])
    assert len(incidents) == 1
    incident = incidents[0]

    # Verify incident captures aggregate features correctly
    assert incident["severity"] == "HIGH"
    assert "0x999" in incident["affected_can_ids"]
    assert "0x100" in incident["affected_can_ids"]
    assert incident["response_evidence"]["dominant_can_id"] == "0x999"

    engine = ResponseEngine()
    plan = engine.plan(incident)
    # Unclassified anomaly / manual review because 0x999 is in KNOWN_IDS and not >90% share
    assert plan["action"] in ("MANUAL_REVIEW", "SIMULATED_RATE_LIMIT")


def test_simultaneous_normal_and_unexpected_id_quarantine():
    """Verify that an unexpected ID (e.g. 0x555) injected with normal traffic triggers quarantine."""
    combined_window = {
        "window_index": 1,
        "window_start_utc": "2026-11-09T10:00:01.000000000Z",
        "prediction": "ANOMALY",
        "anomaly_score": -0.80,
        "features": {
            "total_frames": 26,
            "unique_can_ids": 4,
            "id_0x100_count": 10,
            "id_0x101_count": 10,
            "id_0x102_count": 1,
            "id_0x999_count": 0,
            "other_id_count": 5,
        },
        "response_evidence": {
            "can_id_counts": {"0x100": 10, "0x101": 10, "0x102": 1, "0x555": 5},
            "unexpected_can_ids": ["0x555"],
            "dominant_can_id": "0x100",
            "dominant_can_id_share_pct": 38.46,
        },
        "explanation": {
            "severity": "HIGH",
            "reasons": [{
                "code": "UNEXPECTED_CAN_ID",
                "message": "Unexpected CAN ID detected",
                "evidence": {"can_id": "0x555"},
            }],
        },
    }

    w1 = {**combined_window, "window_index": 1}
    w2 = {**combined_window, "window_index": 2}
    incidents = correlate_incidents([w1, w2])
    assert len(incidents) == 1

    engine = ResponseEngine()
    plan = engine.plan(incidents[0])
    assert plan["classification"] == "UNEXPECTED_CAN_ID"
    assert plan["action"] == "SIMULATED_ID_QUARANTINE"
    assert plan["target_can_ids"] == ["0x555"]


# ─── 5. Automatic attack termination while normal traffic continues ─────────

def test_automatic_attack_termination_preserves_normal_traffic(tmp_path):
    service = FakeAnalysisService()
    manager = LiveSessionManager(
        analysis_service=service,
        captures_dir=tmp_path,
    )

    attack_proc = FakeProcess(pid=9991)
    normal_proc = FakeProcess(pid=9992)
    sniffer_proc = object()

    manager._attack_proc = attack_proc
    manager._normal_proc = normal_proc
    manager._sniffer_proc = sniffer_proc

    session = {
        "id": "live_concurrent_stop_test",
        "interface": "vcan0",
        "state": "capturing",
        "capture_filename": "concurrent_test.csv",
        "incidents": [],
        "incident_records": {},
        "windows": [],
        "normal": {"pid": normal_proc.pid, "state": "RUNNING"},
        "attack": {"mode": 1, "pid": attack_proc.pid, "state": "RUNNING"},
        "open_incident_windows": [{
            "window_index": 1,
            "window_start_utc": "2026-11-09T10:00:01.000000000Z",
            "prediction": "ANOMALY",
            "anomaly_score": 0.9,
            "features": {},
            "response_evidence": {"can_id_counts": {"0x100": 100}, "unexpected_can_ids": []},
            "explanation": {"severity": "HIGH", "reasons": []},
        }],
        "open_incident_records": [{
            "timestamp_ns": 1_000_000_000,
            "can_id": "0x100",
            "interface": "vcan0",
            "frame_format": "standard",
            "payload": "01020304",
            "dlc": 4,
        }],
    }
    manager._active_session = session

    # Queue and trigger incident response via worker
    manager._close_live_incident(session)
    manager._incident_queue.join()

    # Attack process must be terminated
    assert manager._attack_proc is None
    assert session["attack"]["state"] == "STOPPED"

    # Normal process must still be running and untouched!
    assert manager._normal_proc is normal_proc
    assert session["normal"]["state"] == "RUNNING"
    assert normal_proc.signal_sent is None

    # Sniffer process must still be running and untouched!
    assert manager._sniffer_proc is sniffer_proc
    assert session["state"] == "capturing"


# ─── 6. Recovery verification with normal traffic continuing ─────────────────

def test_recovery_verification_with_normal_traffic_running(tmp_path, monkeypatch):
    manager = LiveSessionManager(
        analysis_service=FakeAnalysisService(),
        captures_dir=tmp_path,
    )
    live_module, model = _prepare_scoring(monkeypatch, [1, 1])

    normal_proc = FakeProcess(pid=8888)
    manager._normal_proc = normal_proc

    session = {
        "id": "live_recovery_with_normal",
        "windows": [],
        "open_incident_windows": [],
        "open_incident_records": [],
        "normal": {"pid": normal_proc.pid, "state": "RUNNING"},
        "recovery": {
            "state": "ATTACK_STOPPED_VERIFYING",
            "normal_windows": 0,
            "required_normal_windows": 2,
            "stopped_after_window_index": 0,
        },
    }

    # Record from legitimate normal traffic (0x100, 0x101, 0x102)
    normal_record = {
        "timestamp_ns": 1_000_000_000,
        "can_id": "0x100",
        "interface": "vcan0",
        "frame_format": "standard",
        "payload": "0A0B0C0D",
        "dlc": 4,
    }

    # First normal window
    manager._score_and_record_window(
        model, live_module.FEATURE_COLUMNS, [normal_record], 1, 0, session
    )
    assert session["recovery"]["state"] == "ATTACK_STOPPED_VERIFYING"
    assert session["recovery"]["normal_windows"] == 1
    assert manager._normal_proc is normal_proc  # Normal traffic still active

    # Second normal window
    manager._score_and_record_window(
        model, live_module.FEATURE_COLUMNS, [normal_record], 2, 0, session
    )
    assert session["recovery"]["state"] == "RECOVERED"
    assert session["recovery"]["normal_windows"] == 2
    assert manager._normal_proc is normal_proc  # Still active even after recovery verified!


# ─── 7. Duplicate start prevention ───────────────────────────────────────────

def test_duplicate_start_prevention(tmp_path, monkeypatch):
    manager = LiveSessionManager(
        analysis_service=FakeAnalysisService(),
        captures_dir=tmp_path,
        normal_path=tmp_path / "fake_normal",
        attack_path=tmp_path / "fake_attack",
    )
    for p in ("fake_normal", "fake_attack"):
        b = tmp_path / p
        b.write_text("#!/bin/sh\nexit 0\n")
        b.chmod(0o755)

    manager._active_session = {
        "id": "live_dup_test",
        "interface": "vcan0",
        "state": "capturing",
        "windows": [],
    }

    # Set running processes
    normal_proc = FakeProcess(pid=5001)
    attack_proc = FakeProcess(pid=5002)
    manager._normal_proc = normal_proc
    manager._attack_proc = attack_proc

    # Duplicate normal start must fail
    with pytest.raises(RuntimeError, match="A normal traffic generator is already running"):
        manager.start_normal("live_dup_test")

    # Duplicate attack start must fail
    with pytest.raises(RuntimeError, match="An attack simulator is already running"):
        manager.start_attack("live_dup_test", mode=1)


# ─── 8. Stopping normal traffic independently ────────────────────────────────

def test_stop_normal_independently(tmp_path):
    manager = LiveSessionManager(
        analysis_service=FakeAnalysisService(),
        captures_dir=tmp_path,
    )

    normal_proc = FakeProcess(pid=7001)
    attack_proc = FakeProcess(pid=7002)
    sniffer_proc = object()

    manager._normal_proc = normal_proc
    manager._attack_proc = attack_proc
    manager._sniffer_proc = sniffer_proc

    manager._active_session = {
        "id": "live_stop_indep_test",
        "interface": "vcan0",
        "state": "capturing",
        "windows": [],
        "normal": {"pid": normal_proc.pid, "state": "RUNNING"},
        "attack": {"pid": attack_proc.pid, "state": "RUNNING"},
    }

    result = manager.stop_normal("live_stop_indep_test")

    assert result["state"] == "STOPPED"
    assert manager._normal_proc is None
    # Attack process and sniffer process must remain completely unaffected
    assert manager._attack_proc is attack_proc
    assert manager._sniffer_proc is sniffer_proc


def test_stop_all_simulations_stops_both_preserves_sniffer(tmp_path):
    manager = LiveSessionManager(
        analysis_service=FakeAnalysisService(),
        captures_dir=tmp_path,
    )

    normal_proc = FakeProcess(pid=7001)
    attack_proc = FakeProcess(pid=7002)
    sniffer_proc = object()

    manager._normal_proc = normal_proc
    manager._attack_proc = attack_proc
    manager._sniffer_proc = sniffer_proc

    manager._active_session = {
        "id": "live_stop_all_test",
        "interface": "vcan0",
        "state": "capturing",
        "windows": [],
        "normal": {"pid": normal_proc.pid, "state": "RUNNING"},
        "attack": {"pid": attack_proc.pid, "state": "RUNNING"},
    }

    result = manager.stop_all_simulations("live_stop_all_test")

    assert result["normal"]["state"] == "STOPPED"
    assert result["attack"]["state"] == "STOPPED"
    assert manager._normal_proc is None
    assert manager._attack_proc is None
    # Sniffer must remain untouched
    assert manager._sniffer_proc is sniffer_proc
    assert manager._active_session["state"] == "capturing"
