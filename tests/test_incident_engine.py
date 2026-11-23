from incident_engine import correlate_incidents


def make_window(index, prediction):
    return {
        "window_index": index,
        "window_start_utc": f"2026-11-06T10:00:{index:02d}.000000000Z",
        "prediction": prediction,
        "anomaly_score": 0.8,
        "features": {
            "id_0x100_count": 5,
            "id_0x101_count": 0,
            "id_0x102_count": 0,
            "id_0x999_count": 0,
        },
        "explanation": {
            "severity": "MEDIUM",
            "reasons": [{
                "code": "TEST_ANOMALY",
                "message": "Test evidence",
                "evidence": {"total_frames": 120},
            }],
        },
    }


def test_consecutive_anomalies_form_one_incident():
    windows = [
        make_window(0, "NORMAL"),
        make_window(1, "ANOMALY"),
        make_window(2, "ANOMALY"),
        make_window(3, "NORMAL"),
    ]

    incidents = correlate_incidents(windows)

    assert len(incidents) == 1
    assert incidents[0]["window_count"] == 2
    assert incidents[0]["start_window"] == 1
    assert incidents[0]["end_window"] == 2


def test_normal_windows_separate_incidents():
    windows = [
        make_window(0, "ANOMALY"),
        make_window(1, "NORMAL"),
        make_window(2, "ANOMALY"),
    ]

    incidents = correlate_incidents(windows)

    assert len(incidents) == 2


def test_no_anomalies_produces_no_incidents():
    windows = [make_window(0, "NORMAL")]

    assert correlate_incidents(windows) == []


def test_three_consecutive_anomalies_are_high_severity():
    windows = [
        make_window(0, "ANOMALY"),
        make_window(1, "ANOMALY"),
        make_window(2, "ANOMALY"),
    ]

    incidents = correlate_incidents(windows)

    assert incidents[0]["severity"] == "HIGH"
    assert incidents[0]["window_count"] == 3


def test_incident_aggregates_can_id_counts():
    windows = [
        make_window(1, "ANOMALY"),
        make_window(2, "ANOMALY"),
    ]

    windows[0]["response_evidence"] = {
        "can_id_counts": {"0x100": 10, "0x555": 5},
        "unexpected_can_ids": ["0x555"],
    }
    windows[1]["response_evidence"] = {
        "can_id_counts": {"0x100": 10, "0x555": 15},
        "unexpected_can_ids": ["0x555"],
    }

    incident = correlate_incidents(windows)[0]
    evidence = incident["response_evidence"]

    assert evidence["can_id_counts"] == {
        "0x100": 20,
        "0x555": 20,
    }
    assert evidence["unexpected_can_ids"] == ["0x555"]


def test_incident_calculates_dominant_id_and_share():
    window = make_window(1, "ANOMALY")
    window["response_evidence"] = {
        "can_id_counts": {"0x100": 20, "0x555": 80},
        "unexpected_can_ids": ["0x555"],
    }

    evidence = correlate_incidents([window])[0]["response_evidence"]

    assert evidence["dominant_can_id"] == "0x555"
    assert evidence["dominant_can_id_share_pct"] == 80.0


def test_known_999_is_not_unexpected():
    window = make_window(1, "ANOMALY")
    window["response_evidence"] = {
        "can_id_counts": {"0x999": 100},
        "unexpected_can_ids": [],
    }

    evidence = correlate_incidents([window])[0]["response_evidence"]

    assert evidence["unexpected_can_ids"] == []
    assert evidence["dominant_can_id"] == "0x999"


def test_missing_response_evidence_is_safe():
    window = make_window(1, "ANOMALY")

    evidence = correlate_incidents([window])[0]["response_evidence"]

    assert evidence["can_id_counts"] == {}
    assert evidence["unexpected_can_ids"] == []
    assert evidence["dominant_can_id"] is None
    assert evidence["dominant_can_id_share_pct"] == 0.0


def test_missing_window_indices_separate_incidents():
    windows = [
        make_window(0, "ANOMALY"),
        make_window(156, "ANOMALY"),
        make_window(157, "NORMAL"),
        make_window(158, "NORMAL"),
        make_window(159, "ANOMALY"),
    ]

    incidents = correlate_incidents(windows)

    assert len(incidents) == 3

    assert incidents[0]["start_window"] == 0
    assert incidents[0]["end_window"] == 0

    assert incidents[1]["start_window"] == 156
    assert incidents[1]["end_window"] == 156

    assert incidents[2]["start_window"] == 159
    assert incidents[2]["end_window"] == 159
