"""Offline CAN replay mitigation.

Transforms copies of saved CAN records only.
Never transmits CAN frames or modifies live interfaces.
"""
from collections import Counter, defaultdict, deque
from copy import deepcopy
from typing import Any, Dict, List


class ReplayMitigator:
    """Apply simulated mitigation policies to offline CAN captures."""

    @staticmethod
    def _validate_records(records: List[Dict[str, Any]]) -> None:
        if not isinstance(records, list) or not records:
            raise ValueError("Records must be a non-empty list.")

        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Every CAN record must be a dictionary.")

            required = {
                "timestamp_ns",
                "can_id",
                "interface",
                "frame_format",
                "payload",
                "dlc",
            }

            if not required.issubset(record):
                raise ValueError("CAN record is missing required fields.")

            if record["interface"] != "vcan0":
                raise ValueError("Offline replay accepts vcan0 records only.")

            if not isinstance(record["can_id"], str):
                raise ValueError("CAN ID must be a string.")

            if (
                isinstance(record["timestamp_ns"], bool)
                or not isinstance(record["timestamp_ns"], int)
                or record["timestamp_ns"] < 0
            ):
                raise ValueError("Invalid timestamp.")

    @staticmethod
    def _statistics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
        counts = Counter(record["can_id"] for record in records)

        return {
            "total_frames": len(records),
            "frames_by_can_id": dict(counts),
            "unique_can_ids": len(counts),
        }

    def apply(
        self,
        records: List[Dict[str, Any]],
        response: Dict[str, Any],
        target_can_ids: List[str] = None,
        max_frames_per_second: int = 100,
    ) -> Dict[str, Any]:
        """Apply a simulated policy to a copy of saved capture records."""

        self._validate_records(records)

        if not isinstance(response, dict):
            raise ValueError("Response must be a dictionary.")

        action = response.get("action")

        if action not in {
            "SIMULATED_RATE_LIMIT",
            "SIMULATED_ID_QUARANTINE",
            "MANUAL_REVIEW",
        }:
            raise ValueError("Unsupported mitigation action.")

        if action in {"SIMULATED_RATE_LIMIT", "SIMULATED_ID_QUARANTINE"}:
            if (
                not isinstance(target_can_ids, list)
                or not target_can_ids
                or any(
                    not isinstance(can_id, str) or not can_id.strip()
                    for can_id in target_can_ids
                )
            ):
                raise ValueError(
                    "A non-empty list of explicit target CAN IDs is required."
                )

        if action == "SIMULATED_RATE_LIMIT":
            if (
                isinstance(max_frames_per_second, bool)
                or not isinstance(max_frames_per_second, int)
                or max_frames_per_second <= 0
            ):
                raise ValueError("Rate limit must be a positive integer.")

        original = deepcopy(records)
        replay = deepcopy(records)

        before = self._statistics(original)
        removed = []

        if action == "SIMULATED_RATE_LIMIT":
            targets = set(target_can_ids)

            kept = []
            timestamps_by_id = defaultdict(deque)

            # Process chronologically for correct sliding-window behavior.
            replay.sort(key=lambda record: record["timestamp_ns"])

            window_ns = 1_000_000_000

            for record in replay:
                can_id = record["can_id"]

                if can_id not in targets:
                    kept.append(record)
                    continue

                timestamp = record["timestamp_ns"]
                recent = timestamps_by_id[can_id]

                # Remove frames outside the preceding 1-second window.
                while recent and timestamp - recent[0] >= window_ns:
                    recent.popleft()

                if len(recent) < max_frames_per_second:
                    recent.append(timestamp)
                    kept.append(record)
                else:
                    removed.append(record)

            replay = kept

        elif action == "SIMULATED_ID_QUARANTINE":
            targets = set(target_can_ids)

            replay = []

            for record in original:
                if record["can_id"] in targets:
                    removed.append(record)
                else:
                    replay.append(record)

        # Manual review never changes replay traffic.
        after = self._statistics(replay)

        return {
            "mode": "OFFLINE_SIMULATION",
            "action": action,
            "before": before,
            "after": after,
            "removed_frames": len(removed),
            "removed_can_ids": dict(
                Counter(record["can_id"] for record in removed)
            ),
            "replay_records": replay,
            "original_preserved": records == original,
        }
