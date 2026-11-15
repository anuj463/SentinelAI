
import os
import json
import time
from pathlib import Path
from supabase import create_client

# Suricata EVE JSON location
EVE_FILE = Path(
    os.path.expandvars(
        r"%USERPROFILE%\Downloads\CyberSentinelAI\logs\eve.json"
    )
)

# Supabase credentials from environment variables
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY")

if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
    raise RuntimeError("Supabase environment variables are missing.")

supabase = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)

def convert_event(event):
    alert = event.get("alert") or {}
    flow = event.get("flow") or {}

    return {
        "timestamp": event.get("timestamp"),
        "event_type": event.get("event_type"),
        "src_ip": event.get("src_ip") or flow.get("src_ip"),
        "dest_ip": event.get("dest_ip") or flow.get("dest_ip"),
        "src_port": event.get("src_port") or flow.get("src_port"),
        "dest_port": event.get("dest_port") or flow.get("dest_port"),
        "protocol": event.get("proto"),
        "signature_id": alert.get("signature_id"),
        "signature": alert.get("signature"),
        "severity": alert.get("severity"),
        "alert_action": alert.get("action"),
        "raw_event": event,
        "event_data": event
    }

def forward_events():
    print("CyberSentinel AI - Supabase Forwarder Started")

    while not EVE_FILE.exists():
        print("Waiting for Suricata eve.json...")
        time.sleep(2)

    with EVE_FILE.open("r", encoding="utf-8") as file:
        # Process only newly generated events
        file.seek(0, os.SEEK_END)

        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            try:
                event = json.loads(line)

                record = convert_event(event)

                response = (
                    supabase.table("suricata_events")
                    .insert(record)
                    .execute()
                )

                print(
                    "Uploaded:",
                    event.get("event_type"),
                    event.get("src_ip"),
                    "->",
                    event.get("dest_ip")
                )

            except json.JSONDecodeError:
                continue

            except Exception as error:
                print("Upload error:", error)
                time.sleep(2)

if __name__ == "__main__":
    forward_events()
