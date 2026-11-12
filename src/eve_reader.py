import json
from collections import deque
from pathlib import Path

def load_events(eve_file: Path, max_events: int = 5000):
    """Return (recent_events, status) from a Suricata EVE JSON file."""
    eve_file = Path(eve_file)
    if not eve_file.is_file():
        return [], "missing"
    events = deque(maxlen=max_events)
    try:
        with eve_file.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    item = json.loads(line.strip())
                except (json.JSONDecodeError, TypeError):
                    continue
                if isinstance(item, dict):
                    events.append(item)
    except OSError:
        return [], "unreadable"
    return (list(events), "ok") if events else ([], "empty")
