from src.live_session_manager import LiveSessionManager


class FakeAnalysisService:
    def __init__(self):
        self.registered = {}

    def register_live_incident(
        self, analysis_id, incident, records, capture_name
    ):
        self.registered[analysis_id] = {
            "incident": incident,
            "records": records,
            "capture_name": capture_name,
        }


def test_live_incident_is_registered_and_processed_in_background(tmp_path):
    service = FakeAnalysisService()
    manager = LiveSessionManager(
        analysis_service=service,
        captures_dir=tmp_path,
    )

    callback_calls = []

    def fake_handler(analysis_id, incident_id):
        callback_calls.append((analysis_id, incident_id))
        return {"status": "MITIGATED"}

    manager.set_incident_handler(fake_handler)

    session = {
        "id": "live_test1234",
        "capture_filename": "test_capture.csv",
        "incidents": [],
        "incident_records": {},
        "open_incident_windows": [{
            "window_index": 1,
            "window_start_utc": "2026-11-08T10:00:01.000000000Z",
            "prediction": "ANOMALY",
            "anomaly_score": 0.9,
            "features": {},
            "response_evidence": {
                "can_id_counts": {"0x100": 120},
                "unexpected_can_ids": [],
                "dominant_can_id": "0x100",
                "dominant_can_id_share_pct": 100.0,
            },
            "explanation": {
                "severity": "HIGH",
                "reasons": [{
                    "code": "HIGH_TRAFFIC_VOLUME",
                    "message": "High traffic volume",
                    "evidence": {"total_frames": 120},
                }],
            },
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
    manager._close_live_incident(session)

    assert len(session["incidents"]) == 1
    assert session["incidents"][0]["response_state"] == "QUEUED"

    # Wait for the background worker to finish this job.
    manager._incident_queue.join()

    incident = session["incidents"][0]
    analysis_id = incident["analysis_id"]

    assert analysis_id in service.registered
    assert service.registered[analysis_id]["records"]
    assert callback_calls == [(analysis_id, incident["incident_id"])]
    assert incident["analysis_registered"] is True
    assert incident["response_state"] == "MITIGATED"


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


def _record():
    return {
        "timestamp_ns": 1_000_000_000,
        "can_id": "0x100",
        "interface": "vcan0",
        "frame_format": "standard",
        "payload": "01020304",
        "dlc": 4,
    }


def test_two_consecutive_anomalies_queue_one_incident(tmp_path, monkeypatch):
    manager = LiveSessionManager(
        analysis_service=FakeAnalysisService(),
        captures_dir=tmp_path,
    )
    live_module, model = _prepare_scoring(monkeypatch, [-1, -1])

    queued = []
    monkeypatch.setattr(
        manager,
        "_close_live_incident",
        lambda session: queued.append(len(session["open_incident_windows"])),
    )

    session = {
        "id": "live_detection_test",
        "windows": [],
        "open_incident_windows": [],
        "open_incident_records": [],
    }

    for index in range(2):
        manager._score_and_record_window(
            model=model,
            feature_columns=live_module.FEATURE_COLUMNS,
            records=[_record()],
            window_index=index,
            anchor_ns=0,
            session_dict=session,
        )

    assert len(session["windows"]) == 2
    assert session["attack_response_queued"] is True
    assert len(queued) == 1


def test_stop_attack_stops_only_owned_process(tmp_path):
    manager = LiveSessionManager(
        analysis_service=FakeAnalysisService(),
        captures_dir=tmp_path,
    )

    class FakeProcess:
        pid = 12345
        returncode = None

        def poll(self):
            return self.returncode

        def send_signal(self, sig):
            self.signal_sent = sig

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

    owned_process = FakeProcess()
    sniffer_process = object()

    manager._active_session = {
        "id": "live_owned_test",
        "interface": "vcan0",
        "state": "capturing",
        "windows": [],
        "attack": {"mode": 1, "pid": owned_process.pid, "state": "RUNNING"},
    }
    manager._attack_proc = owned_process
    manager._sniffer_proc = sniffer_process

    result = manager.stop_attack("live_owned_test")

    assert result["state"] == "STOPPED"
    assert manager._attack_proc is None
    assert manager._sniffer_proc is sniffer_process
    assert manager._active_session["recovery"]["state"] == (
        "ATTACK_STOPPED_VERIFYING"
    )


def test_recovery_requires_two_normal_windows_after_attack_stop(
    tmp_path, monkeypatch
):
    manager = LiveSessionManager(
        analysis_service=FakeAnalysisService(),
        captures_dir=tmp_path,
    )
    live_module, model = _prepare_scoring(monkeypatch, [1, 1])

    session = {
        "id": "live_recovery_test",
        "windows": [],
        "open_incident_windows": [],
        "open_incident_records": [],
        "recovery": {
            "state": "ATTACK_STOPPED_VERIFYING",
            "normal_windows": 0,
            "required_normal_windows": 2,
            "stopped_after_window_index": 0,
        },
    }

    manager._score_and_record_window(
        model, live_module.FEATURE_COLUMNS, [_record()], 1, 0, session
    )
    assert session["recovery"]["state"] == "ATTACK_STOPPED_VERIFYING"
    assert session["recovery"]["normal_windows"] == 1

    manager._score_and_record_window(
        model, live_module.FEATURE_COLUMNS, [_record()], 2, 0, session
    )
    assert session["recovery"]["state"] == "RECOVERED"
    assert session["recovery"]["normal_windows"] == 2
