import pytest
from src.replay_mitigator import ReplayMitigator


@pytest.fixture
def mitigator():
    return ReplayMitigator()


@pytest.fixture
def records():
    return [
        {
            "timestamp_ns": i * 10_000_000,
            "timestamp_utc": "2026-11-07T10:00:00.000000000Z",
            "interface": "vcan0",
            "can_id": "0x100" if i < 8 else "0x555",
            "frame_format": "standard",
            "flags": "",
            "dlc": 2,
            "payload": "AABB",
        }
        for i in range(10)
    ]


def test_quarantine_removes_only_target_id(mitigator, records):
    response = {"action": "SIMULATED_ID_QUARANTINE"}

    result = mitigator.apply(
        records,
        response,
        target_can_ids=["0x555"],
    )

    assert result["after"]["total_frames"] == 8
    assert result["removed_frames"] == 2
    assert all(r["can_id"] != "0x555" for r in result["replay_records"])


def test_rate_limit_reduces_target_frames(mitigator, records):
    response = {"action": "SIMULATED_RATE_LIMIT"}

    result = mitigator.apply(
        records,
        response,
        target_can_ids=["0x100"],
        max_frames_per_second=3,
    )

    assert result["after"]["total_frames"] == 5
    assert result["removed_frames"] == 5


def test_manual_review_preserves_all_frames(mitigator, records):
    response = {"action": "MANUAL_REVIEW"}

    result = mitigator.apply(records, response)

    assert result["after"]["total_frames"] == 10
    assert result["removed_frames"] == 0


def test_original_capture_is_preserved(mitigator, records):
    original = [dict(record) for record in records]

    mitigator.apply(
        records,
        {"action": "SIMULATED_ID_QUARANTINE"},
        target_can_ids=["0x555"],
    )

    assert records == original


def test_quarantine_requires_target_ids(mitigator, records):
    with pytest.raises(ValueError):
        mitigator.apply(
            records,
            {"action": "SIMULATED_ID_QUARANTINE"},
        )


def test_empty_capture_rejected(mitigator):
    with pytest.raises(ValueError):
        mitigator.apply([], {"action": "MANUAL_REVIEW"})


def test_invalid_interface_rejected(mitigator, records):
    records[0]["interface"] = "can0"

    with pytest.raises(ValueError):
        mitigator.apply(records, {"action": "MANUAL_REVIEW"})


def test_unsupported_action_rejected(mitigator, records):
    with pytest.raises(ValueError):
        mitigator.apply(records, {"action": "DELETE_EVERYTHING"})



def test_rate_limit_resets_at_second_boundary(mitigator):
    records = [
        {
            "timestamp_ns": timestamp,
            "timestamp_utc": "2026-11-07T10:00:00.000000000Z",
            "interface": "vcan0",
            "can_id": "0x100",
            "frame_format": "standard",
            "flags": "",
            "dlc": 1,
            "payload": "AA",
        }
        for timestamp in [
            100_000_000,
            200_000_000,
            300_000_000,
            1_100_000_000,
            1_200_000_000,
        ]
    ]

    result = mitigator.apply(
        records,
        {"action": "SIMULATED_RATE_LIMIT"},
        target_can_ids=["0x100"],
        max_frames_per_second=2,
    )

    assert result["after"]["total_frames"] == 4
    assert result["removed_frames"] == 1


def test_invalid_rate_limit_rejected(mitigator, records):
    with pytest.raises(ValueError):
        mitigator.apply(
            records,
            {"action": "SIMULATED_RATE_LIMIT"},
            target_can_ids=["0x100"],
            max_frames_per_second=0,
        )


def test_missing_can_id_rejected(mitigator, records):
    del records[0]["can_id"]

    with pytest.raises(ValueError):
        mitigator.apply(records, {"action": "MANUAL_REVIEW"})


def test_negative_timestamp_rejected(mitigator, records):
    records[0]["timestamp_ns"] = -1

    with pytest.raises(ValueError):
        mitigator.apply(records, {"action": "MANUAL_REVIEW"})


def test_invalid_record_type_rejected(mitigator):
    with pytest.raises(ValueError):
        mitigator.apply(
            [{"invalid": "record"}],
            {"action": "MANUAL_REVIEW"},
        )


def test_sliding_window_blocks_boundary_burst(mitigator):
    timestamps = [
        900_000_000,
        990_000_000,
        1_010_000_000,
        1_100_000_000,
        2_100_000_000,
    ]

    records = [
        {
            "timestamp_ns": ts,
            "timestamp_utc": "2026-11-07T10:00:00.000000000Z",
            "interface": "vcan0",
            "can_id": "0x100",
            "frame_format": "standard",
            "flags": "",
            "dlc": 1,
            "payload": "AA",
        }
        for ts in timestamps
    ]

    result = mitigator.apply(
        records,
        {"action": "SIMULATED_RATE_LIMIT"},
        target_can_ids=["0x100"],
        max_frames_per_second=2,
    )

    assert result["after"]["total_frames"] == 3
    assert result["removed_frames"] == 2


def test_unsorted_timestamps_are_handled(mitigator):
    timestamps = [
        300_000_000,
        100_000_000,
        200_000_000,
    ]

    records = [
        {
            "timestamp_ns": ts,
            "timestamp_utc": "2026-11-07T10:00:00.000000000Z",
            "interface": "vcan0",
            "can_id": "0x100",
            "frame_format": "standard",
            "flags": "",
            "dlc": 1,
            "payload": "AA",
        }
        for ts in timestamps
    ]

    original = [dict(record) for record in records]

    result = mitigator.apply(
        records,
        {"action": "SIMULATED_RATE_LIMIT"},
        target_can_ids=["0x100"],
        max_frames_per_second=2,
    )

    replay_times = [
        record["timestamp_ns"]
        for record in result["replay_records"]
    ]

    assert replay_times == sorted(replay_times)
    assert records == original
    assert result["after"]["total_frames"] == 2
    assert result["removed_frames"] == 1


@pytest.mark.parametrize("targets", [None, [], "", ["0x100", ""], [123]])
def test_rate_limit_rejects_missing_or_invalid_targets(
    mitigator, records, targets
):
    with pytest.raises(ValueError):
        mitigator.apply(
            records,
            {"action": "SIMULATED_RATE_LIMIT"},
            target_can_ids=targets,
        )


@pytest.mark.parametrize("targets", [None, [], "", ["0x555", ""], [123]])
def test_quarantine_rejects_missing_or_invalid_targets(
    mitigator, records, targets
):
    with pytest.raises(ValueError):
        mitigator.apply(
            records,
            {"action": "SIMULATED_ID_QUARANTINE"},
            target_can_ids=targets,
        )


def test_rate_limit_does_not_guess_target_ids(mitigator, records):
    original = [dict(record) for record in records]

    with pytest.raises(ValueError):
        mitigator.apply(
            records,
            {"action": "SIMULATED_RATE_LIMIT"},
            max_frames_per_second=3,
        )

    assert records == original
def test_rate_limit_applies_independently_per_can_id(mitigator):
    records = []

    for can_id in ["0x100", "0x555"]:
        for i in range(5):
            records.append({
                "timestamp_ns": i * 10_000_000,
                "interface": "vcan0",
                "can_id": can_id,
                "frame_format": "standard",
                "payload": "AA",
                "dlc": 1,
            })

    result = mitigator.apply(
        records,
        {"action": "SIMULATED_RATE_LIMIT"},
        target_can_ids=["0x100", "0x555"],
        max_frames_per_second=2,
    )

    assert result["after"]["frames_by_can_id"] == {
        "0x100": 2,
        "0x555": 2,
    }
    assert result["removed_frames"] == 6


def test_duplicate_timestamps_are_handled(mitigator):
    timestamps = [100_000_000, 100_000_000, 100_000_000]

    records = [
        {
            "timestamp_ns": ts,
            "interface": "vcan0",
            "can_id": "0x100",
            "frame_format": "standard",
            "payload": "AA",
            "dlc": 1,
        }
        for ts in timestamps
    ]

    result = mitigator.apply(
        records,
        {"action": "SIMULATED_RATE_LIMIT"},
        target_can_ids=["0x100"],
        max_frames_per_second=2,
    )

    assert result["after"]["total_frames"] == 2
    assert result["removed_frames"] == 1


def test_single_timestamp_capture_is_preserved(mitigator):
    records = [
        {
            "timestamp_ns": 100_000_000,
            "interface": "vcan0",
            "can_id": "0x100",
            "frame_format": "standard",
            "payload": "AA",
            "dlc": 1,
        }
    ]

    result = mitigator.apply(
        records,
        {"action": "MANUAL_REVIEW"},
    )

    assert result["after"]["total_frames"] == 1
    assert result["removed_frames"] == 0
    assert result["original_preserved"] is True
