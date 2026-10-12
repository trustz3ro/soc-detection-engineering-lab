import importlib.util
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

path = (
    Path(__file__).resolve().parents[1]
    / "scripts" / "correlate_windows_openssh.py"
)
spec = importlib.util.spec_from_file_location("correlation", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

NOW = datetime(2026, 10, 11, 23, 40, tzinfo=timezone.utc)


def event(user, source="192.0.2.10", age=0, agent_id="001"):
    return {
        "timestamp": (NOW - timedelta(seconds=age)).isoformat(),
        "rule": {"id": "100100"},
        "agent": {"id": agent_id, "name": "Ed_T14"},
        "data": {"win": {"eventdata": {
            "payload": f"Invalid user {user} from {source} port 50000"
        }}},
    }


class CorrelationTests(unittest.TestCase):
    def test_three_distinct_users_alert(self):
        events = [event("alpha", age=60), event("beta", age=30),
                  event("gamma")]
        results = module.correlate(events, NOW)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["unique_users"], 3)

    def test_repeated_username_no_alert(self):
        events = [event("alpha", age=i) for i in range(6)]
        self.assertEqual(module.correlate(events, NOW), [])

    def test_alternating_two_users_no_alert(self):
        events = [event(user, age=i) for i, user in enumerate(
            ["alpha", "beta", "alpha", "beta", "alpha", "beta"]
        )]
        self.assertEqual(module.correlate(events, NOW), [])

    def test_different_sources_no_alert(self):
        events = [event("alpha", "192.0.2.10"),
                  event("beta", "192.0.2.11"),
                  event("gamma", "192.0.2.12")]
        self.assertEqual(module.correlate(events, NOW), [])

    def test_outside_window_no_alert(self):
        events = [event("alpha", age=301), event("beta", age=150),
                  event("gamma")]
        self.assertEqual(module.correlate(events, NOW), [])

    def test_exact_window_boundary_included(self):
        events = [event("alpha", age=300), event("beta", age=150),
                  event("gamma")]
        self.assertEqual(len(module.correlate(events, NOW)), 1)

    def test_future_event_excluded(self):
        events = [event("alpha"), event("beta"),
                  event("gamma", age=-10)]
        self.assertEqual(module.correlate(events, NOW), [])

    def test_agents_not_combined(self):
        events = [event("alpha", agent_id="001"),
                  event("beta", agent_id="002"),
                  event("gamma", agent_id="003")]
        self.assertEqual(module.correlate(events, NOW), [])



    def test_wazuh_timestamp_format(self):
        events = [event("alpha"), event("beta"), event("gamma")]
        for item in events:
            item["timestamp"] = "2026-10-11T23:53:08.971+0000"
        now = datetime(2026, 10, 11, 23, 54, tzinfo=timezone.utc)
        self.assertEqual(len(module.correlate(events, now)), 1)


if __name__ == "__main__":
    unittest.main()
