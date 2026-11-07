"""Correlate anomalous CAN windows into explainable incidents."""

from collections import Counter
from typing import Any, Dict, List


def correlate_incidents(windows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group consecutive anomalous windows into incidents."""
    incidents = []
    current = []

    def close_incident(group):
        if not group:
            return

        reasons = []
        can_ids = set()
        severities = []
        response_counts = Counter()
        unexpected_ids = set()

        for window in group:
            explanation = window.get("explanation") or {}

            for reason in explanation.get("reasons", []):
                reasons.append(reason)

            response_evidence = window.get("response_evidence") or {}

            if isinstance(response_evidence, dict):
                id_counts = response_evidence.get("can_id_counts", {})
                if isinstance(id_counts, dict):
                    for can_id, count in id_counts.items():
                        if (
                            isinstance(can_id, str)
                            and isinstance(count, int)
                            and not isinstance(count, bool)
                            and count >= 0
                        ):
                            response_counts[can_id] += count

                ids = response_evidence.get("unexpected_can_ids", [])
                if isinstance(ids, list):
                    unexpected_ids.update(
                        can_id for can_id in ids
                        if isinstance(can_id, str) and can_id.strip()
                    )

            features = window.get("features", {})
            for key in ("id_0x100_count", "id_0x101_count",
                        "id_0x102_count", "id_0x999_count"):
                if features.get(key, 0) > 0:
                    can_ids.add(key.replace("_count", "").replace("id_", ""))

            for can_id in explanation.get("affected_can_ids", []):
                can_ids.add(can_id)

            severities.append(explanation.get("severity", "REVIEW"))

        severity = (
            "HIGH" if "HIGH" in severities or len(group) >= 3
            else "MEDIUM" if "MEDIUM" in severities
            else "REVIEW"
        )

        first = group[0]
        last = group[-1]

        total_response_frames = sum(response_counts.values())
        dominant_id = (
            min(
                response_counts,
                key=lambda can_id: (-response_counts[can_id], can_id),
            )
            if response_counts else None
        )
        dominant_share = (
            round(response_counts[dominant_id] / total_response_frames * 100, 4)
            if dominant_id is not None and total_response_frames else 0.0
        )

        incidents.append({
            "incident_id": f"INC-{len(incidents) + 1:04d}",
            "response_evidence": {
                "can_id_counts": dict(sorted(response_counts.items())),
                "unexpected_can_ids": sorted(unexpected_ids),
                "dominant_can_id": dominant_id,
                "dominant_can_id_share_pct": dominant_share,
            },
            "severity": severity,
            "status": "OPEN",
            "start_window": first["window_index"],
            "end_window": last["window_index"],
            "window_count": len(group),
            "start_time_utc": first["window_start_utc"],
            "end_time_utc": last["window_start_utc"],
            "affected_can_ids": sorted(can_ids),
            "reasons": reasons,
            "windows": group,
            "summary": (
                f"{len(group)} consecutive anomalous windows correlated "
                f"from window {first['window_index']} to {last['window_index']}."
            ),
        })

    for window in windows:
        if window.get("prediction") == "ANOMALY":
            current.append(window)
        else:
            close_incident(current)
            current = []

    close_incident(current)
    return incidents
