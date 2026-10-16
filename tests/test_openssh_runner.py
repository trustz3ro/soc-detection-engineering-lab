import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location(
    "openssh_runner", SCRIPTS / "run_openssh_correlation.py"
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

NOW = datetime(2026, 10, 16, 0, 0, tzinfo=timezone.utc)


def event(user, when=NOW, source="192.0.2.10"):
    return {
        "timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.000%z"),
        "rule": {"id": "100100"},
        "agent": {"id": "001", "name": "Ed_T14"},
        "data": {"win": {"eventdata": {
            "payload": f"Invalid user {user} from {source} port 50000"
        }}},
    }


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.input = root / "alerts.json"
        self.state = root / "state.json"
        self.output = root / "correlation.json"

    def write_events(self, events):
        self.input.write_text(
            "".join(json.dumps(item) + "\n" for item in events)
        )

    def run_at(self, when):
        return runner.run(self.input, self.state, self.output, when)

    def output_events(self):
        if not self.output.exists():
            return []
        return [
            json.loads(line)
            for line in self.output.read_text().splitlines()
        ]

    def test_positive_and_duplicate_suppression(self):
        self.write_events([event("a"), event("b"), event("c")])
        self.assertEqual(len(self.run_at(NOW)), 1)
        self.assertEqual(self.run_at(NOW + timedelta(seconds=15)), [])
        self.assertEqual(len(self.output_events()), 1)

    def test_suppression_survives_reload(self):
        self.write_events([event("a"), event("b"), event("c")])
        self.run_at(NOW)
        saved = json.loads(self.state.read_text())
        self.assertEqual(len(saved["active_groups"]), 1)
        self.assertEqual(self.run_at(NOW + timedelta(seconds=30)), [])
        self.assertEqual(len(self.output_events()), 1)

    def test_cached_events_survive_rotation(self):
        self.write_events([event("a"), event("b")])
        self.assertEqual(self.run_at(NOW), [])
        self.input.rename(self.input.with_suffix(".rotated"))
        later = NOW + timedelta(seconds=15)
        self.write_events([event("c", later)])
        results = self.run_at(later)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["unique_users"], 3)

    def test_expired_cache_does_not_alert(self):
        self.write_events([event("a"), event("b")])
        self.run_at(NOW)
        later = NOW + timedelta(seconds=301)
        self.write_events([event("c", later)])
        self.assertEqual(self.run_at(later), [])
        saved = json.loads(self.state.read_text())
        self.assertEqual(len(saved["events"]), 1)

    def test_new_episode_can_alert(self):
        self.write_events([event("a"), event("b"), event("c")])
        self.run_at(NOW)
        self.write_events([])
        self.assertEqual(self.run_at(NOW + timedelta(seconds=301)), [])
        later = NOW + timedelta(seconds=320)
        self.write_events([
            event("d", later), event("e", later), event("f", later)
        ])
        self.assertEqual(len(self.run_at(later)), 1)
        self.assertEqual(len(self.output_events()), 2)

    def test_re_read_events_not_double_counted(self):
        self.write_events([event("a"), event("b")])
        self.run_at(NOW)
        later = NOW + timedelta(seconds=15)
        self.write_events([event("a"), event("b"), event("c", later)])
        results = self.run_at(later)
        self.assertEqual(results[0]["attempts"], 3)

    def test_malformed_json_line_skipped(self):
        self.write_events([event("a"), event("b"), event("c")])
        with self.input.open("a") as destination:
            destination.write("not-json\n")
        self.assertEqual(len(self.run_at(NOW)), 1)

    def test_corrupt_state_fails_without_writing_alert(self):
        self.write_events([event("a"), event("b"), event("c")])
        self.state.write_text("broken")
        with self.assertRaises(json.JSONDecodeError):
            self.run_at(NOW)
        self.assertEqual(self.output_events(), [])


if __name__ == "__main__":
    unittest.main()
