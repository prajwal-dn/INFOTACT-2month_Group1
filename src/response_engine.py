"""Sentinel X automated incident response engine.

This module plans and records simulated responses.
It never transmits CAN frames or modifies live interfaces.
"""

import math
from copy import deepcopy
from threading import RLock
from typing import Any, Dict, Optional

if __package__:
    from .frequency_analyzer import KNOWN_IDS
else:
    from frequency_analyzer import KNOWN_IDS


class ResponseEngine:
    """Thread-safe, idempotent incident response coordinator."""

    def __init__(self):
        self._lock = RLock()
        self._responses: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def classify(incident: Dict[str, Any]) -> str:
        """Classify incidents using exact, validated capture evidence."""

        if not isinstance(incident, dict):
            raise ValueError("Incident must be a dictionary.")

        reasons = incident.get("reasons", [])
        affected_ids = incident.get("affected_can_ids", [])
        evidence = incident.get("response_evidence", {})

        if not isinstance(reasons, list):
            raise ValueError("Incident reasons must be a list.")

        if not isinstance(affected_ids, list):
            raise ValueError("Affected CAN IDs must be a list.")

        for can_id in affected_ids:
            if not isinstance(can_id, str):
                raise ValueError("CAN IDs must be strings.")

        if not isinstance(evidence, dict):
            raise ValueError("Response evidence must be a dictionary.")

        counts = evidence.get("can_id_counts", {})
        unexpected_ids = evidence.get("unexpected_can_ids", [])

        if not isinstance(counts, dict):
            raise ValueError("CAN ID counts must be a dictionary.")

        for can_id, count in counts.items():
            if (
                not isinstance(can_id, str)
                or not can_id.strip()
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
            ):
                raise ValueError("Invalid CAN ID count evidence.")

        if not isinstance(unexpected_ids, list):
            raise ValueError("Unexpected CAN IDs must be a list.")

        for can_id in unexpected_ids:
            if (
                not isinstance(can_id, str)
                or not can_id.strip()
                or can_id not in counts
                or can_id in KNOWN_IDS
            ):
                raise ValueError("Invalid unexpected CAN ID evidence.")

        reason_codes = set()

        for reason in reasons:
            if not isinstance(reason, dict):
                raise ValueError("Each reason must be a dictionary.")

            code = reason.get("code")
            if code is not None:
                if not isinstance(code, str):
                    raise ValueError("Reason codes must be strings.")
                reason_codes.add(code.upper())

        high_frequency = "HIGH_TRAFFIC_VOLUME" in reason_codes
        unexpected_reason = "UNEXPECTED_CAN_ID" in reason_codes

        if high_frequency and unexpected_reason:
            return "MIXED_EVIDENCE"

        if high_frequency:
            total = sum(counts.values())
            if total <= 0:
                return "UNCLASSIFIED_ANOMALY"

            dominant_id = max(
                counts,
                key=lambda can_id: (counts[can_id], can_id),
                default=None,
            )

            if (
                dominant_id is not None
                and counts[dominant_id] / total > 0.90
            ):
                return "HIGH_FREQUENCY_FLOOD"

            return "UNCLASSIFIED_ANOMALY"

        if unexpected_reason and unexpected_ids:
            return "UNEXPECTED_CAN_ID"

        return "UNCLASSIFIED_ANOMALY"

    def plan(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Create a response plan with evidence-backed target IDs."""

        if not isinstance(incident, dict):
            raise ValueError("Incident must be a dictionary.")

        incident_id = incident.get("incident_id")

        if not isinstance(incident_id, str) or not incident_id.strip():
            raise ValueError("A valid incident_id is required.")

        incident_id = incident_id.strip()
        classification = self.classify(incident)
        evidence = incident.get("response_evidence", {})
        counts = evidence.get("can_id_counts", {})
        unexpected_ids = evidence.get("unexpected_can_ids", [])

        policies = {
            "HIGH_FREQUENCY_FLOOD": (
                "SIMULATED_RATE_LIMIT",
                "Rate-limit the dominant CAN ID in offline replay.",
            ),
            "UNEXPECTED_CAN_ID": (
                "SIMULATED_ID_QUARANTINE",
                "Exclude identified unexpected CAN IDs from offline replay.",
            ),
            "MIXED_EVIDENCE": (
                "MANUAL_REVIEW",
                "Conflicting attack evidence requires operator review.",
            ),
            "UNCLASSIFIED_ANOMALY": (
                "MANUAL_REVIEW",
                "Insufficient evidence for automatic simulated mitigation.",
            ),
        }

        action, description = policies[classification]

        target_ids = []

        if classification == "HIGH_FREQUENCY_FLOOD":
            target_ids = [
                max(counts, key=lambda can_id: (counts[can_id], can_id))
            ]
        elif classification == "UNEXPECTED_CAN_ID":
            target_ids = sorted(unexpected_ids)

        return {
            "incident_id": incident_id,
            "classification": classification,
            "action": action,
            "description": description,
            "target_can_ids": target_ids,
            "status": "PLANNED",
            "mode": "SIMULATION",
        }

    def activate(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Record a simulated response activation."""

        plan = self.plan(incident)
        incident_id = plan["incident_id"]

        with self._lock:
            existing = self._responses.get(incident_id)

            if existing is not None:
                return deepcopy(existing)

            if plan["action"] == "MANUAL_REVIEW":
                plan["status"] = "REVIEW_REQUIRED"
            else:
                plan["status"] = "SIMULATED_ACTIVE"

            self._responses[incident_id] = deepcopy(plan)
            return deepcopy(plan)

    def attach_replay_result(
        self,
        incident_id: str,
        replay_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Attach a validated offline replay result to an active response."""

        if not isinstance(incident_id, str) or not incident_id.strip():
            raise ValueError("A valid incident_id is required.")

        if not isinstance(replay_result, dict):
            raise ValueError("Replay result must be a dictionary.")

        required = {
            "mode",
            "action",
            "before",
            "after",
            "removed_frames",
            "removed_can_ids",
            "replay_records",
            "original_preserved",
        }

        if not required.issubset(replay_result):
            raise ValueError("Replay result is missing required fields.")

        if replay_result["mode"] != "OFFLINE_SIMULATION":
            raise ValueError("Only offline simulation results are accepted.")

        if replay_result["action"] not in {
            "SIMULATED_RATE_LIMIT",
            "SIMULATED_ID_QUARANTINE",
            "MANUAL_REVIEW",
        }:
            raise ValueError("Invalid replay action.")

        if not isinstance(replay_result["before"], dict):
            raise ValueError("Invalid before statistics.")

        if not isinstance(replay_result["after"], dict):
            raise ValueError("Invalid after statistics.")

        for stats in (replay_result["before"], replay_result["after"]):
            if not {
                "total_frames",
                "frames_by_can_id",
                "unique_can_ids",
            }.issubset(stats):
                raise ValueError("Incomplete replay statistics.")

            counts = stats["frames_by_can_id"]

            if (
                not isinstance(counts, dict)
                or any(
                    not isinstance(key, str)
                    or isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0
                    for key, value in counts.items()
                )
                or isinstance(stats["total_frames"], bool)
                or not isinstance(stats["total_frames"], int)
                or stats["total_frames"] < 0
                or stats["total_frames"] != sum(counts.values())
                or stats["unique_can_ids"] != len(counts)
            ):
                raise ValueError("Invalid replay statistics.")

        if (
            isinstance(replay_result["removed_frames"], bool)
            or not isinstance(replay_result["removed_frames"], int)
            or replay_result["removed_frames"] < 0
        ):
            raise ValueError("Invalid removed frame count.")

        if not isinstance(replay_result["removed_can_ids"], dict):
            raise ValueError("Invalid removed CAN ID statistics.")

        if (
            not isinstance(replay_result["replay_records"], list)
            or len(replay_result["replay_records"])
            != replay_result["after"]["total_frames"]
        ):
            raise ValueError("Invalid replay records.")

        if replay_result["original_preserved"] is not True:
            raise ValueError("Original capture was not preserved.")

        incident_id = incident_id.strip()

        with self._lock:
            response = self._responses.get(incident_id)

            if response is None:
                raise KeyError("Response not found.")

            if response["status"] != "SIMULATED_ACTIVE":
                raise ValueError("Response is not active.")

            if replay_result["action"] != response["action"]:
                raise ValueError("Replay action does not match response.")

            if "replay_result" in response:
                return deepcopy(response)

            response["replay_result"] = deepcopy(replay_result)
            return deepcopy(response)
    def verify_recovery(
        self,
        incident_id: str,
        baseline_frame_rate: float,
        post_mitigation_frame_rate: float,
        remaining_unexpected_ids: int = 0,
    ) -> Dict[str, Any]:
        """Verify recovery using offline replay measurements."""

        if not isinstance(incident_id, str) or not incident_id.strip():
            raise ValueError("A valid incident_id is required.")

        values = (
            baseline_frame_rate,
            post_mitigation_frame_rate,
            remaining_unexpected_ids,
        )

        for value in values:
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ValueError("Recovery measurements must be finite numbers.")

        if baseline_frame_rate <= 0 or post_mitigation_frame_rate < 0:
            raise ValueError("Invalid frame-rate measurements.")

        if (
            remaining_unexpected_ids < 0
            or not isinstance(remaining_unexpected_ids, int)
        ):
            raise ValueError(
                "Unexpected ID count must be a non-negative integer."
            )

        incident_id = incident_id.strip()

        with self._lock:
            response = self._responses.get(incident_id)

            if response is None:
                raise KeyError("Response not found.")

            if response["status"] != "SIMULATED_ACTIVE":
                raise ValueError(
                    "Response is not awaiting recovery verification."
                )
            if "replay_result" not in response:
                raise ValueError(
                    "Recovery cannot be verified without an offline replay result."
                )
            recovered = (
                post_mitigation_frame_rate < baseline_frame_rate
                and remaining_unexpected_ids == 0
            )

            response["status"] = (
                "MITIGATED" if recovered else "RECOVERY_FAILED"
            )

            response["recovery"] = {
                "verified": recovered,
                "baseline_frame_rate": baseline_frame_rate,
                "post_mitigation_frame_rate": post_mitigation_frame_rate,
                "remaining_unexpected_ids": remaining_unexpected_ids,
            }

            return deepcopy(response)

    def get_response(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Return an isolated copy of a response record."""

        if not isinstance(incident_id, str):
            return None

        with self._lock:
            response = self._responses.get(incident_id.strip())
            return deepcopy(response) if response else None
