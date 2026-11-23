"""Evidence-based explanations for CAN-Sentinel anomaly windows."""

from typing import Any, Dict, List


def explain_window(features: Dict[str, Any], prediction: str) -> Dict[str, Any]:
    """Explain an anomaly using observed CAN window features.

    These are heuristic explanations, not proof of an intrusion.
    """
    if prediction != "ANOMALY":
        return {
            "reasons": [],
            "severity": "INFO",
            "summary": "No anomaly detected by the Isolation Forest.",
        }

    reasons: List[Dict[str, Any]] = []

    other_count = int(features.get("other_id_count", 0))
    if other_count > 0:
        reasons.append({
            "code": "UNEXPECTED_CAN_ID",
            "message": "CAN traffic contains IDs outside the configured known-ID set.",
            "evidence": {"other_id_count": other_count},
        })

    frame_count = int(features.get("total_frames", 0))
    if frame_count > 100:
        reasons.append({
            "code": "HIGH_TRAFFIC_VOLUME",
            "message": "High frame volume observed in this 1-second window.",
            "evidence": {"total_frames": frame_count, "threshold": 100},
        })

    dominant_ratio = float(features.get("max_id_share_pct", 0))
    if dominant_ratio > 90:
        reasons.append({
            "code": "DOMINANT_CAN_ID",
            "message": "A single CAN ID dominates the window's traffic.",
            "evidence": {"max_id_share_pct": dominant_ratio, "threshold": 90},
        })

    extended_count = int(features.get("extended_frame_count", 0))
    if extended_count > 0:
        reasons.append({
            "code": "EXTENDED_FRAME_PRESENT",
            "message": "Extended CAN frames were observed in this window.",
            "evidence": {"extended_frame_count": extended_count},
        })

    if len(reasons) >= 3:
        severity = "HIGH"
    elif len(reasons) >= 1:
        severity = "MEDIUM"
    else:
        severity = "REVIEW"

    summary = (
        "; ".join(reason["message"] for reason in reasons)
        if reasons
        else "The Isolation Forest flagged this window, but the configured "
             "explanation rules did not identify a specific contributing pattern."
    )

    return {
        "reasons": reasons,
        "severity": severity,
        "summary": summary,
    }
