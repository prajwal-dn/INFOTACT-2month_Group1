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
