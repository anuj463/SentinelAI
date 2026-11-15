
import json
import time
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent

EVE_FILE = PROJECT_DIR / "logs" / "eve.json"

POLL_INTERVAL = 0.5

SUPPORTED_EVENTS = {
    "alert",
    "dns",
    "tls",
    "http",
    "flow",
    "quic",
    "stats"
}


def process_event(event):
    """Process a newly detected Suricata event."""

    event_type = event.get("event_type", "unknown")

    if event_type not in SUPPORTED_EVENTS:
        return

    timestamp = event.get("timestamp", "Unknown time")

    print("\n" + "=" * 60)
    print(f"NEW EVENT: {event_type.upper()}")
    print(f"Timestamp: {timestamp}")

    if event_type == "alert":
        alert = event.get("alert", {})

        print("Signature:", alert.get("signature"))
        print("Severity:", alert.get("severity"))
        print("Source:", event.get("src_ip"))
        print("Destination:", event.get("dest_ip"))

    elif event_type == "dns":
        dns = event.get("dns", {})
        print("DNS Query:", dns.get("rrname"))
        print("Source:", event.get("src_ip"))

    elif event_type == "tls":
        tls = event.get("tls", {})
        print("TLS SNI:", tls.get("sni"))

    elif event_type == "flow":
        print("Source:", event.get("src_ip"))
        print("Destination:", event.get("dest_ip"))

    else:
        print("Source:", event.get("src_ip"))
        print("Destination:", event.get("dest_ip"))

    print("=" * 60)


def monitor_eve():

    print("CyberSentinel AI - Live EVE Monitor")
    print("Monitoring:", EVE_FILE)

    while not EVE_FILE.exists():
        print("Waiting for EVE JSON file...")
        time.sleep(2)

    with EVE_FILE.open(
        "r",
        encoding="utf-8",
        errors="replace"
    ) as file:

        # Start from the end of the existing log.
        file.seek(0, 2)

        current_inode = EVE_FILE.stat().st_ino

        while True:

            line = file.readline()

            if line:
                try:
                    event = json.loads(line)
                    process_event(event)

                except json.JSONDecodeError:
                    # Ignore incomplete or malformed lines.
                    pass

                continue

            # Detect file replacement / rotation.
            try:
                new_stat = EVE_FILE.stat()

                if (
                    new_stat.st_ino != current_inode
                    or new_stat.st_size < file.tell()
                ):
                    file.close()

                    file = EVE_FILE.open(
                        "r",
                        encoding="utf-8",
                        errors="replace"
                    )

                    current_inode = new_stat.st_ino

                    print("EVE file changed. Monitoring new file.")

            except FileNotFoundError:
                pass

            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":

    try:
        monitor_eve()

    except KeyboardInterrupt:
        print("\nLive monitoring stopped.")
