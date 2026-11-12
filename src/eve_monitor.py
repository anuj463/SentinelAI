import json
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVE_FILE = Path(os.getenv("CYBERSENTINEL_EVE_FILE", str(ROOT / "logs" / "eve.json")))

def display_event(event):
    kind = event.get("event_type", "unknown")
    timestamp = event.get("timestamp", "-")
    src, dst = event.get("src_ip", "-"), event.get("dest_ip", "-")
    if kind == "alert":
        alert = event.get("alert") or {}
        print(f"[ALERT] {timestamp} | {alert.get('signature', 'Unknown')} | SID={alert.get('signature_id', '-')} | {src} -> {dst}")
    elif kind == "dns":
        dns = event.get("dns") or {}
        names = [q.get("rrname", "?") for q in dns.get("queries", []) if isinstance(q, dict)]
        print(f"[DNS] {timestamp} | {src} -> {dst} | {', '.join(names) or '-'}")
    elif kind in {"tls", "quic", "flow"}:
        print(f"[{kind.upper()}] {timestamp} | {src} -> {dst}")

def follow_file(path):
    print(f"Watching {path}. Press Ctrl+C to stop.")
    while not path.exists():
        print("Waiting for EVE log...")
        time.sleep(2)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(0, os.SEEK_END)
        while True:
            line = handle.readline()
            if not line:
                time.sleep(0.25)
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                display_event(event)

if __name__ == "__main__":
    try:
        follow_file(EVE_FILE)
    except KeyboardInterrupt:
        print("\nEvent monitor stopped.")
