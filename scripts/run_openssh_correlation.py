#!/usr/bin/env python3
"""Run correlation with a persistent five-minute cache and episode suppression."""
import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from correlate_windows_openssh import correlate


def parse_time(value):
    value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2",
                   value.replace("Z", "+00:00"))
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError("Timezone required")
    return result


def event_key(event):
    return hashlib.sha256(
        json.dumps(event, sort_keys=True).encode()
    ).hexdigest()


def group_key(result):
    return json.dumps([
        result["target_agent_id"],
        result["target_agent_name"],
        result["source_ip"],
    ])


def run(input_path, state_path, output_path, now):
    input_path = Path(input_path)
    state_path = Path(state_path)
    output_path = Path(output_path)
    cutoff = now - timedelta(seconds=300)

    state = {"events": [], "active_groups": []}
    if state_path.exists():
        state = json.loads(state_path.read_text())

    events = {}

    def retain(event):
        if not isinstance(event, dict):
            return
        if str(event.get("rule", {}).get("id")) != "100100":
            return
        try:
            timestamp = parse_time(event["timestamp"])
        except (KeyError, ValueError, TypeError, AttributeError):
            return
        if cutoff <= timestamp <= now:
            events[event_key(event)] = event

    for event in state["events"]:
        retain(event)

    # Read the current file each run. Cache retains previously observed events
    # if Wazuh rotates the input between runs.
    with input_path.open(encoding="utf-8") as source:
        for line in source:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            retain(event)

    results = correlate(events.values(), now)
    previous = set(state["active_groups"])
    active = {group_key(result) for result in results}
    emitted = [
        result for result in results if group_key(result) not in previous
    ]

    state_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if emitted:
        with output_path.open("a", encoding="utf-8") as destination:
            for result in emitted:
                destination.write(json.dumps(result) + "\n")
            destination.flush()
            os.fsync(destination.fileno())

    new_state = {
        "events": list(events.values()),
        "active_groups": sorted(active),
        "last_run": now.isoformat(),
    }
    temporary = state_path.with_name(state_path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as destination:
        json.dump(new_state, destination)
        destination.flush()
        os.fsync(destination.fileno())
    temporary.replace(state_path)
    return emitted


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    emitted = run(args.input, args.state, args.output,
                  datetime.now(timezone.utc))
    print(f"Emitted {len(emitted)} correlation alert(s).")


if __name__ == "__main__":
    main()
