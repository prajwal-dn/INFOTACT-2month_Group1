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
