import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from socket_receiver import validate_event


VALID_EVENT = {
    "schema_version": 1,
    "event_type": "can_frame",
    "timestamp_utc": "2026-10-31T18:20:30.123456789Z",
    "interface": "vcan0",
    "can_id": "0x100",
    "frame_format": "standard",
    "flags": "none",
    "dlc": 2,
    "payload": "FFFF",
}


class SocketContractTests(unittest.TestCase):

    def test_valid_standard_frame(self):
        self.assertEqual(validate_event(copy.deepcopy(VALID_EVENT)),
                         VALID_EVENT)

    def test_valid_extended_frame(self):
        event = copy.deepcopy(VALID_EVENT)
        event["can_id"] = "0x999"
        event["frame_format"] = "extended"
        event["payload"] = "DEAD"
        self.assertEqual(validate_event(event), event)

    def assert_invalid(self, changes):
        event = copy.deepcopy(VALID_EVENT)
        event.update(changes)
        with self.assertRaises(ValueError):
            validate_event(event)

    def test_rejects_wrong_schema_version(self):
        self.assert_invalid({"schema_version": 2})

    def test_rejects_wrong_event_type(self):
        self.assert_invalid({"event_type": "other"})

    def test_rejects_non_vcan_interface(self):
        self.assert_invalid({"interface": "can0"})

    def test_rejects_invalid_timestamp(self):
        self.assert_invalid({"timestamp_utc": "not-a-timestamp"})

    def test_rejects_invalid_can_id(self):
        self.assert_invalid({"can_id": "100"})

    def test_rejects_standard_id_out_of_range(self):
        self.assert_invalid({"can_id": "0x800"})

    def test_rejects_invalid_frame_format(self):
        self.assert_invalid({"frame_format": "error"})

    def test_rejects_unsupported_flags(self):
        self.assert_invalid({"flags": "RTR"})

    def test_rejects_dlc_payload_mismatch(self):
        self.assert_invalid({"payload": "FF"})

    def test_rejects_lowercase_payload(self):
        self.assert_invalid({"payload": "dead"})

    def test_rejects_missing_or_extra_fields(self):
        event = copy.deepcopy(VALID_EVENT)
        del event["payload"]
        with self.assertRaises(ValueError):
            validate_event(event)

        event = copy.deepcopy(VALID_EVENT)
        event["unexpected"] = "value"
        with self.assertRaises(ValueError):
            validate_event(event)


if __name__ == "__main__":
    unittest.main(verbosity=2)
