from pathlib import Path

from src.api_analysis_service import ApiAnalysisService, parse_csv_records

ROOT = Path(__file__).resolve().parents[1]


def test_analysis_stores_original_capture_records(tmp_path):
    records = parse_csv_records(ROOT / "data/normal_baseline_60s.csv")
    service = ApiAnalysisService(reports_dir=tmp_path)

    result = service.score_records(
        records=records,
        capture_name="normal_baseline_60s.csv",
    )

    stored = service.get_capture_records(result["id"])

    assert stored == records
    assert stored is not records


def test_modifying_returned_records_does_not_change_stored_capture(tmp_path):
    records = parse_csv_records(ROOT / "data/normal_baseline_60s.csv")
    service = ApiAnalysisService(reports_dir=tmp_path)

    result = service.score_records(
        records=records,
        capture_name="normal_baseline_60s.csv",
    )

    returned_records = service.get_capture_records(result["id"])
    returned_records[0]["can_id"] = "0x555"

    stored_again = service.get_capture_records(result["id"])

    assert stored_again[0]["can_id"] == records[0]["can_id"]


def test_unknown_analysis_returns_no_capture_records(tmp_path):
    service = ApiAnalysisService(reports_dir=tmp_path)

    assert service.get_capture_records("unknown-analysis") is None


def test_single_incomplete_window_is_not_scored(tmp_path):
    records = parse_csv_records(ROOT / "data/normal_baseline_60s.csv")
    service = ApiAnalysisService(reports_dir=tmp_path)

    try:
        service.score_records(
            records=records[:2],
            capture_name="single_incomplete_window.csv",
        )
    except ValueError as exc:
        assert "Not enough complete windows" in str(exc)
    else:
        raise AssertionError("An incomplete single window must not be scored")


def test_exact_one_second_boundary_scores_first_window(tmp_path):
    records = parse_csv_records(ROOT / "data/normal_baseline_60s.csv")
    first = records[0].copy()
    second = records[0].copy()
    second["timestamp_ns"] = first["timestamp_ns"] + 1_000_000_000

    service = ApiAnalysisService(reports_dir=tmp_path)
    result = service.score_records(
        records=[first, second],
        capture_name="exact_boundary.csv",
    )

    assert result["windows_scored"] == 1
    assert result["windows"][0]["window_index"] == 0
    assert result["excluded_partial_window"] == 1


def test_multiple_windows_exclude_only_final_window(tmp_path):
    records = parse_csv_records(ROOT / "data/normal_baseline_60s.csv")
    first = records[0].copy()

    capture = []
    for index in range(3):
        record = first.copy()
        record["timestamp_ns"] = first["timestamp_ns"] + index * 1_000_000_000
        capture.append(record)

    service = ApiAnalysisService(reports_dir=tmp_path)
    result = service.score_records(
        records=capture,
        capture_name="three_windows.csv",
    )

    assert result["windows_scored"] == 2
    assert [w["window_index"] for w in result["windows"]] == [0, 1]
    assert result["excluded_partial_window"] == 2
