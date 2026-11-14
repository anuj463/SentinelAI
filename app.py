import streamlit as st
import pandas as pd
import json
import os
from pathlib import Path
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
 


# ==================================================
# 1. PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="CyberSentinel AI",
    page_icon="🛡️",
    layout="wide"
)
# Automatic dashboard refresh every 3 seconds
refresh_count = st_autorefresh(
    interval=3000,
    limit=None,
    key="cybersentinel_refresh"
)
st.title("🛡️ CyberSentinel AI")
st.caption(
    f"Last refreshed: {datetime.now().strftime('%H:%M:%S')} "
    f"| Refresh count: {refresh_count}"
)


# ==================================================
# 2. CONFIGURATION
# ==================================================

PROJECT_DIR = Path(__file__).resolve().parent

DEFAULT_EVE_FILE = PROJECT_DIR / "logs" / "eve.json"

EVE_FILE = os.getenv(
    "CYBERSENTINEL_EVE_FILE",
    str(DEFAULT_EVE_FILE)
)


# ==================================================
# 3. READ EVE JSON FILE
# ==================================================

def read_eve_logs(file_path, max_lines=5000):

    events = []

    path = Path(file_path)

    if not path.exists():
        return events, False

    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            lines = file.readlines()[-max_lines:]

            for line in lines:

                try:
                    event = json.loads(line)

                    if isinstance(event, dict):
                        events.append(event)

                except json.JSONDecodeError:
                    continue

    except OSError:
        return events, False

    return events, True


# ==================================================
# 4. SIDEBAR
# ==================================================

st.sidebar.title("🛡️ Monitoring")

st.sidebar.subheader("Event Source")

eve_path = st.sidebar.text_input(
    "EVE JSON file path",
    value=str(EVE_FILE)
)

st.sidebar.caption("Automatic refresh: 3 seconds")

st.sidebar.info(
    "Suricata captures and inspects network packets. "
    "This dashboard visualizes EVE JSON events. "
    "It does not block network traffic."
)

st.sidebar.markdown("---")

st.sidebar.caption("CyberSentinel AI | CNS Lab Project")


# ==================================================
# 5. LOAD EVENTS
# ==================================================

st.title("🛡️ CyberSentinel AI")

st.caption(
    "Suricata-based Network Intrusion Detection and Monitoring"
)

events, file_exists = read_eve_logs(eve_path)

if not file_exists:
    st.error(
        "EVE JSON file not found. Check the file path "
        "or start Suricata with EVE logging enabled."
    )
    st.stop()

if not events:
    st.warning("Waiting for Suricata network events...")
    st.stop()

df = pd.DataFrame(events)

if "event_type" not in df.columns:
    df["event_type"] = "unknown"

df["event_type"] = df["event_type"].fillna("unknown")


# ==================================================
# 6. SEPARATE EVENT TYPES
# ==================================================

alerts = df[df["event_type"] == "alert"].copy()

dns_events = df[df["event_type"] == "dns"]

tls_events = df[df["event_type"] == "tls"]

flow_events = df[df["event_type"] == "flow"]

quic_events = df[df["event_type"] == "quic"]


# ==================================================
# 7. NETWORK OVERVIEW
# ==================================================

st.header("Network Overview")

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Events Loaded", len(df))
col2.metric("Security Alerts", len(alerts))
col3.metric("DNS Events", len(dns_events))
col4.metric("TLS Events", len(tls_events))
col5.metric("Network Flows", len(flow_events))


# ==================================================
# 8. EVENT DISTRIBUTION
# ==================================================

st.markdown("---")

left_col, right_col = st.columns(2)

with left_col:

    st.subheader("Event Distribution")

    event_counts = df["event_type"].value_counts()

    st.bar_chart(event_counts)


# ==================================================
# 9. ALERT SEVERITY GRAPH
# ==================================================

with right_col:

    st.subheader("Alert Severity")

    severity_counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 0
    }

    for event in alerts.to_dict("records"):

        alert_data = event.get("alert", {})

        if not isinstance(alert_data, dict):
            alert_data = {}

        severity = str(
            alert_data.get("severity", "Unknown")
        ).strip()

        if severity == "1":
            severity_counts["High"] += 1

        elif severity == "2":
            severity_counts["Medium"] += 1

        elif severity == "3":
            severity_counts["Low"] += 1

        else:
            severity_counts["Unknown"] += 1

    severity_df = pd.DataFrame(
        {
            "Number of Alerts": list(severity_counts.values())
        },
        index=list(severity_counts.keys())
    )

    st.bar_chart(severity_df)

    st.caption(
        "Severity 1 = High | Severity 2 = Medium | "
        "Severity 3 = Low"
    )

    if len(alerts) == 0:
        st.info(
            "No Suricata alerts detected yet. "
            "The graph will update when alerts are generated."
        )


# ==================================================
# 10. SECURITY ALERTS TABLE
# ==================================================

st.markdown("---")

st.header("🚨 Security Alerts")

if not alerts.empty:

    alert_records = []

    for event in alerts.to_dict("records"):

        alert_data = event.get("alert", {})

        if not isinstance(alert_data, dict):
            alert_data = {}

        severity = str(
            alert_data.get("severity", "Unknown")
        )

        severity_label = {
            "1": "High",
            "2": "Medium",
            "3": "Low"
        }.get(severity, "Unknown")

        alert_records.append({

            "Timestamp": event.get("timestamp", "N/A"),

            "Signature": alert_data.get(
                "signature", "Unknown"
            ),

            "Severity": severity_label,

            "Source IP": event.get("src_ip", "N/A"),

            "Destination IP": event.get("dest_ip", "N/A"),

            "Protocol": event.get("proto", "N/A"),

            "Action": alert_data.get("action", "N/A"),

            "SID": alert_data.get("signature_id", "N/A")

        })

    alert_df = pd.DataFrame(alert_records)

    st.dataframe(
        alert_df,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No security alerts in the loaded events.")


# ==================================================
# 11. DNS EVENTS
# ==================================================

st.markdown("---")

st.header("🌐 DNS Events")

if not dns_events.empty:

    dns_records = []

    for event in dns_events.to_dict("records"):

        dns_data = event.get("dns", {})

        if not isinstance(dns_data, dict):
            dns_data = {}

        dns_records.append({

            "Timestamp": event.get("timestamp", "N/A"),

            "Source IP": event.get("src_ip", "N/A"),

            "Destination IP": event.get("dest_ip", "N/A"),

            "DNS Query": dns_data.get("rrname", "N/A"),

            "DNS Type": dns_data.get("rrtype", "N/A"),

            "Protocol": event.get("proto", "N/A")

        })

    st.dataframe(
        pd.DataFrame(dns_records).tail(100),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No DNS events available.")


# ==================================================
# 12. TLS EVENTS
# ==================================================

st.markdown("---")

st.header("🔐 TLS Events")

if not tls_events.empty:

    tls_records = []

    for event in tls_events.to_dict("records"):

        tls_data = event.get("tls", {})

        if not isinstance(tls_data, dict):
            tls_data = {}

        tls_records.append({

            "Timestamp": event.get("timestamp", "N/A"),

            "Source IP": event.get("src_ip", "N/A"),

            "Destination IP": event.get("dest_ip", "N/A"),

            "SNI": tls_data.get("sni", "N/A"),

            "TLS Version": tls_data.get("version", "N/A")

        })

    st.dataframe(
        pd.DataFrame(tls_records).tail(100),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No TLS events available.")


# ==================================================
# 13. NETWORK FLOWS
# ==================================================

st.markdown("---")

st.header("📡 Network Flows")

if not flow_events.empty:

    flow_records = []

    for event in flow_events.to_dict("records"):

        flow_data = event.get("flow", {})

        if not isinstance(flow_data, dict):
            flow_data = {}

        flow_records.append({

            "Timestamp": event.get("timestamp", "N/A"),

            "Source IP": event.get("src_ip", "N/A"),

            "Source Port": event.get("src_port", "N/A"),

            "Destination IP": event.get("dest_ip", "N/A"),

            "Destination Port": event.get("dest_port", "N/A"),

            "Protocol": event.get("proto", "N/A"),

            "Packets": flow_data.get("pkts_toserver", "N/A"),

            "Bytes": flow_data.get("bytes_toserver", "N/A")

        })

    st.dataframe(
        pd.DataFrame(flow_records).tail(100),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No network flow events available.")


# ==================================================
# 14. QUIC EVENTS
# ==================================================

st.markdown("---")

st.header("⚡ QUIC Events")

if not quic_events.empty:

    quic_columns = [
        column for column in [
            "timestamp",
            "src_ip",
            "dest_ip",
            "proto"
        ]
        if column in quic_events.columns
    ]

    st.dataframe(
        quic_events[quic_columns].tail(100),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No QUIC events available.")


# ==================================================
# 15. FOOTER
# ==================================================

st.markdown("---")

st.caption(
    "CyberSentinel AI | Powered by Suricata IDS, "
    "Emerging Threats Rules, Python and Streamlit"
)
