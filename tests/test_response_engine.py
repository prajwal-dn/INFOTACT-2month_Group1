import pytest
from src.response_engine import ResponseEngine


@pytest.fixture
def engine():
    return ResponseEngine()


def make_incident(reason, can_ids=None, response_evidence=None):
    if response_evidence is None:
        if reason == "HIGH_TRAFFIC_VOLUME":
            response_evidence = {
                "can_id_counts": {"0x100": 120},
                "unexpected_can_ids": [],
            }
        else:
            response_evidence = {
                "can_id_counts": {},
                "unexpected_can_ids": [],
            }

    return {
        "incident_id": "INC-TEST-001",
        "status": "OPEN",
        "severity": "HIGH",
        "reasons": [{"code": reason}],
        "affected_can_ids": can_ids or [],
        "response_evidence": response_evidence,
    }
def attach_valid_replay(engine, incident_id="INC-TEST-001"):
    response = engine.get_response(incident_id)
    action = response["action"]
    target_ids = response["target_can_ids"]

    if action == "SIMULATED_ID_QUARANTINE":
        can_id = target_ids[0]
        before_count = 5
        after_count = 0
        removed_count = 5
    else:
        can_id = target_ids[0]
        before_count = 120
        after_count = 80
        removed_count = 40

    stats_before = {
        "total_frames": before_count,
        "frames_by_can_id": {can_id: before_count},
        "unique_can_ids": 1,
    }

    stats_after = {
        "total_frames": after_count,
        "frames_by_can_id": (
            {can_id: after_count} if after_count else {}
        ),
        "unique_can_ids": 1 if after_count else 0,
    }

    return engine.attach_replay_result(
        incident_id,
        {
            "mode": "OFFLINE_SIMULATION",
            "action": action,
            "before": stats_before,
            "after": stats_after,
            "removed_frames": removed_count,
            "removed_can_ids": {can_id: removed_count},
            "replay_records": [
                {
                    "timestamp_ns": i,
                    "can_id": can_id,
                    "interface": "vcan0",
                    "frame_format": "standard",
                    "payload": "AA",
                    "dlc": 1,
                }
                for i in range(after_count)
            ],
            "original_preserved": True,
        },
    )
def test_high_frequency_plan(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    plan = engine.plan(incident)

    assert plan["action"] == "SIMULATED_RATE_LIMIT"
    assert plan["status"] == "PLANNED"


def test_unknown_can_id_plan(engine):
    incident = make_incident(
        "UNEXPECTED_CAN_ID",
        ["0x555"],
        {
            "can_id_counts": {"0x555": 5},
            "unexpected_can_ids": ["0x555"],
        },
    )
    plan = engine.plan(incident)

    assert plan["action"] == "SIMULATED_ID_QUARANTINE"
    assert plan["target_can_ids"] == ["0x555"]

def test_normal_incident_requires_review(engine):
    incident = make_incident("SOME_UNKNOWN_REASON")
    plan = engine.plan(incident)

    assert plan["action"] == "MANUAL_REVIEW"


def test_empty_incident_rejected(engine):
    with pytest.raises((ValueError, TypeError)):
        engine.plan({})


def test_missing_incident_id_rejected(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    incident["incident_id"] = ""

    with pytest.raises(ValueError):
        engine.plan(incident)


def test_activation_is_idempotent(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")

    first = engine.activate(incident)
    second = engine.activate(incident)

    assert first["incident_id"] == second["incident_id"]
    assert first["status"] == second["status"]


def test_recovery_success(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)
    attach_valid_replay(engine)
    result = engine.verify_recovery(
        "INC-TEST-001",
        baseline_frame_rate=100,
        post_mitigation_frame_rate=80,
        remaining_unexpected_ids=0,
    )

    assert result["status"] == "MITIGATED"


def test_recovery_failure(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)
    attach_valid_replay(engine)
    result = engine.verify_recovery(
        "INC-TEST-001",
        baseline_frame_rate=100,
        post_mitigation_frame_rate=200,
        remaining_unexpected_ids=0,
    )

    assert result["status"] == "RECOVERY_FAILED"


def test_unknown_id_prevents_recovery(engine):
    incident = make_incident(
        "UNEXPECTED_CAN_ID",
        ["0x555"],
        {
            "can_id_counts": {"0x555": 5},
            "unexpected_can_ids": ["0x555"],
        },
    )
    engine.activate(incident)
    attach_valid_replay(engine)
    result = engine.verify_recovery(
        "INC-TEST-001",
        baseline_frame_rate=100,
        post_mitigation_frame_rate=50,
        remaining_unexpected_ids=1,
    )

    assert result["status"] == "RECOVERY_FAILED"

def test_zero_baseline_rejected(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)

    with pytest.raises(ValueError):
        engine.verify_recovery(
            "INC-TEST-001",
            baseline_frame_rate=0,
            post_mitigation_frame_rate=0,
            remaining_unexpected_ids=0,
        )


def test_negative_post_rate_rejected(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)

    with pytest.raises(ValueError):
        engine.verify_recovery(
            "INC-TEST-001",
            baseline_frame_rate=100,
            post_mitigation_frame_rate=-10,
            remaining_unexpected_ids=0,
        )


def test_negative_unknown_id_count_rejected(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)

    with pytest.raises(ValueError):
        engine.verify_recovery(
            "INC-TEST-001",
            baseline_frame_rate=100,
            post_mitigation_frame_rate=50,
            remaining_unexpected_ids=-1,
        )


def test_recovery_for_unknown_incident_rejected(engine):
    with pytest.raises((ValueError, KeyError)):
        engine.verify_recovery(
            "INC-NOT-FOUND",
            baseline_frame_rate=100,
            post_mitigation_frame_rate=50,
            remaining_unexpected_ids=0,
        )



def test_mitigated_incident_cannot_be_activated_again(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)
    attach_valid_replay(engine)
    engine.verify_recovery(
        "INC-TEST-001",
        baseline_frame_rate=100,
        post_mitigation_frame_rate=50,
        remaining_unexpected_ids=0,
    )

    result = engine.activate(incident)

    assert result["status"] == "MITIGATED"


def test_recovery_cannot_be_verified_twice_after_success(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)
    attach_valid_replay(engine)
    engine.verify_recovery(
        "INC-TEST-001",
        baseline_frame_rate=100,
        post_mitigation_frame_rate=50,
        remaining_unexpected_ids=0,
    )

    with pytest.raises((ValueError, RuntimeError)):
        engine.verify_recovery(
            "INC-TEST-001",
            baseline_frame_rate=100,
            post_mitigation_frame_rate=50,
            remaining_unexpected_ids=0,
        )


import math


def test_nan_measurement_rejected(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)

    with pytest.raises(ValueError):
        engine.verify_recovery(
            "INC-TEST-001", 100, math.nan, 0
        )


def test_infinity_measurement_rejected(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)

    with pytest.raises(ValueError):
        engine.verify_recovery(
            "INC-TEST-001", 100, math.inf, 0
        )


def test_known_999_id_does_not_trigger_quarantine(engine):
    incident = make_incident(
        "HIGH_TRAFFIC_VOLUME",
        ["0x999"],
        {
            "can_id_counts": {"0x999": 120},
            "unexpected_can_ids": [],
        },
    )

    plan = engine.plan(incident)

    assert plan["classification"] == "HIGH_FREQUENCY_FLOOD"
    assert plan["action"] == "SIMULATED_RATE_LIMIT"
    assert plan["target_can_ids"] == ["0x999"]


def test_malformed_reasons_rejected(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    incident["reasons"] = "invalid"

    with pytest.raises(ValueError):
        engine.plan(incident)


def test_malformed_can_ids_rejected(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    incident["affected_can_ids"] = "0x999"

    with pytest.raises(ValueError):
        engine.plan(incident)


def test_deep_copy_protection(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)

    response = engine.get_response("INC-TEST-001")
    response["status"] = "MITIGATED"

    stored = engine.get_response("INC-TEST-001")

    assert stored["status"] == "SIMULATED_ACTIVE"


def test_incident_id_whitespace_handled(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    incident["incident_id"] = " INC-TEST-001 "

    engine.activate(incident)

    response = engine.get_response("INC-TEST-001")

    assert response is not None
    assert response["incident_id"] == "INC-TEST-001"


def test_explicit_unexpected_id_triggers_quarantine(engine):
    incident = make_incident(
        "UNEXPECTED_CAN_ID",
        ["0x555"],
        {
            "can_id_counts": {"0x555": 5},
            "unexpected_can_ids": ["0x555"],
        },
    )

    plan = engine.plan(incident)

    assert plan["classification"] == "UNEXPECTED_CAN_ID"
    assert plan["action"] == "SIMULATED_ID_QUARANTINE"
    assert plan["target_can_ids"] == ["0x555"]

def test_attach_replay_result(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)

    result = attach_valid_replay(engine)

    assert "replay_result" in result

def test_replay_result_deep_copy_protection(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)

    result = attach_valid_replay(engine)
    result["replay_result"]["removed_frames"] = 999

    stored = engine.get_response("INC-TEST-001")
    assert stored["replay_result"]["removed_frames"] == 40

def test_duplicate_replay_result_does_not_overwrite(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)

    first = attach_valid_replay(engine)

    different_replay = dict(first["replay_result"])
    different_replay["removed_frames"] = 50

    result = engine.attach_replay_result(
        "INC-TEST-001",
        different_replay,
    )

    assert result["replay_result"]["removed_frames"] == 40

def test_recovery_requires_attached_replay_result(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)

    with pytest.raises(ValueError):
        engine.verify_recovery(
            "INC-TEST-001",
            baseline_frame_rate=100,
            post_mitigation_frame_rate=50,
            remaining_unexpected_ids=0,
        )


def test_invalid_replay_result_rejected(engine):
    incident = make_incident("HIGH_TRAFFIC_VOLUME")
    engine.activate(incident)

    with pytest.raises(ValueError):
        engine.attach_replay_result(
            "INC-TEST-001",
            {
                "mode": "OFFLINE_SIMULATION",
                "removed_frames": 20,
            },
        )
