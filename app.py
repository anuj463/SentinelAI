
import json
import os
from pathlib import Path
from datetime import datetime
from collections import Counter, deque

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh


# ============================================================
# 1. PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberSentinel AI",
    page_icon="🛡️",
    layout="wide"
)

# Refresh the dashboard every 3 seconds.
refresh_count = st_autorefresh(
    interval=3000,
    limit=None,
    key="cybersentinel_refresh"
)

PROJECT_DIR = Path(__file__).resolve().parent

DEFAULT_EVE_FILE = (
    Path.home()
    / "Downloads"
    / "CyberSentinelAI"
    / "logs"
    / "eve.json"
)

# ============================================================
# 2. DATA SOURCE
# ============================================================

st.sidebar.title("🛡️ Monitoring")

st.sidebar.subheader("Event Source")

use_supabase = (
    "SUPABASE_URL" in st.secrets
    and "SUPABASE_SECRET_KEY" in st.secrets
)

events = []
source_description = ""

if use_supabase:

    st.sidebar.success("Cloud database: Supabase")

    try:
        from supabase import create_client

        @st.cache_resource
        def get_supabase_client():
            return create_client(
                st.secrets["SUPABASE_URL"],
                st.secrets["SUPABASE_SECRET_KEY"]
            )

        client = get_supabase_client()

        response = (
            client.table("suricata_events")
            .select("id,event_data")
            .order("id", desc=True)
            .limit(5000)
            .execute()
        )

        rows = response.data or []

        events = [
            row["event_data"]
            for row in reversed(rows)
            if isinstance(row.get("event_data"), dict)
        ]

        source_description = "Supabase cloud database"

    except Exception as error:
        st.error(f"Supabase connection failed: {error}")
        st.stop()

else:

    eve_path = st.sidebar.text_input(
        "EVE JSON file path",
        value=os.getenv(
            "CYBERSENTINEL_EVE_FILE",
            str(DEFAULT_EVE_FILE)
        )
    )

    st.sidebar.caption("Automatic refresh: 3 seconds")

    eve_file = Path(eve_path)

    if eve_file.exists():

        try:
            # Read the latest events on every Streamlit rerun.
            # No caching is used here.
            with eve_file.open(
                "r",
                encoding="utf-8",
                errors="replace"
            ) as file:

                latest_lines = deque(file, maxlen=10000)

            for line in latest_lines:
                try:
                    event = json.loads(line)

                    if isinstance(event, dict):
                        events.append(event)

                except json.JSONDecodeError:
                    continue

            source_description = str(eve_file)

        except OSError as error:
            st.error(f"Unable to read EVE JSON: {error}")
            st.stop()

    else:
        st.error(f"EVE JSON file not found: {eve_file}")
        st.info(
            "Start Suricata with EVE JSON logging enabled "
            "or enter the correct EVE JSON path."
        )
        st.stop()


st.sidebar.caption(f"Event source: {source_description}")

st.sidebar.info(
    "Suricata captures and inspects network packets. "
    "This dashboard visualizes EVE JSON events; "
    "it does not block network traffic."
)

st.sidebar.caption(
    f"Last refreshed: {datetime.now().strftime('%H:%M:%S')}"
)

st.sidebar.caption(f"Refresh count: {refresh_count}")

# ============================================================
# 3. MAIN TITLE
# ============================================================

st.title("🛡️ CyberSentinel AI")

st.caption(
    "Suricata-based Network Intrusion Detection and Monitoring"
)

st.caption(
    f"Dashboard refreshed at "
    f"{datetime.now().strftime('%H:%M:%S')}"
)

if not events:
    st.warning(
        "No events are available yet. "
        "Start Suricata and generate network traffic."
    )
    st.stop()

# ============================================================
# 4. DATAFRAME CREATION
# ============================================================

df = pd.DataFrame(events)

if "event_type" not in df.columns:
    df["event_type"] = "unknown"

df["event_type"] = (
    df["event_type"]
    .fillna("unknown")
    .astype(str)
    .str.lower()
)

# ============================================================
# 5. EXTRACT SECURITY ALERTS
# ============================================================

alert_records = []

for event in events:

    if str(event.get("event_type", "")).lower() != "alert":
        continue

    alert_data = event.get("alert", {})

    if not isinstance(alert_data, dict):
        alert_data = {}

    severity = alert_data.get("severity")

    try:
        severity = int(severity)
    except (ValueError, TypeError):
        severity = 0

    if severity == 1:
        severity_label = "High"

    elif severity == 2:
        severity_label = "Medium"

    elif severity == 3:
        severity_label = "Low"

    else:
        severity_label = "Unknown"

    alert_records.append({
        "Timestamp": event.get("timestamp", "Unknown"),
        "Signature": alert_data.get(
            "signature", "Unknown signature"
        ),
        "Severity": severity_label,
        "Severity Number": severity,
        "Source IP": event.get("src_ip", "Unknown"),
        "Destination IP": event.get("dest_ip", "Unknown"),
        "Protocol": event.get("proto", "Unknown"),
        "Action": alert_data.get("action", "Unknown"),
        "Signature ID": alert_data.get("signature_id", "Unknown")
    })

alerts_df = pd.DataFrame(alert_records)

# ============================================================
# 6. NETWORK OVERVIEW
# ============================================================

st.header("Network Overview")

total_events = len(events)

total_alerts = len(alert_records)

dns_count = int(
    (df["event_type"] == "dns").sum()
)

tls_count = int(
    (df["event_type"] == "tls").sum()
)

flow_count = int(
    (df["event_type"] == "flow").sum()
)

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Events Loaded", total_events)
col2.metric("Security Alerts", total_alerts)
col3.metric("DNS Events", dns_count)
col4.metric("TLS Events", tls_count)
col5.metric("Network Flows", flow_count)

st.divider()

# ============================================================
# 7. EVENT DISTRIBUTION
# ============================================================

st.subheader("Event Distribution")

event_counts = (
    df["event_type"]
    .value_counts()
    .sort_values(ascending=False)
)

left_col, right_col = st.columns(2)

with left_col:

    st.subheader("Event Types")

    if not event_counts.empty:
        st.bar_chart(event_counts)
    else:
        st.info("No event data available.")

# ============================================================
# 8. ALERT SEVERITY GRAPH
# ============================================================

with right_col:

    st.subheader("Alert Severity")

    if not alerts_df.empty:

        severity_order = [
            "High",
            "Medium",
            "Low",
            "Unknown"
        ]

        severity_counts = (
            alerts_df["Severity"]
            .value_counts()
            .reindex(severity_order, fill_value=0)
        )

        # Remove categories with zero alerts.
        severity_counts = severity_counts[
            severity_counts > 0
        ]

        st.bar_chart(
            severity_counts,
            y_label="Number of security alerts",
            x_label="Severity level"
        )

        st.caption(
            "Severity 1 = High | "
            "Severity 2 = Medium | "
            "Severity 3 = Low"
        )

    else:

        st.info(
            "No Suricata alerts detected yet. "
            "The graph will update when alerts are generated."
        )

st.divider()

# ============================================================
# 9. SECURITY ALERTS TABLE
# ============================================================

st.header("Security Alerts")

if not alerts_df.empty:

    st.metric("Total Detected Alerts", len(alerts_df))

    st.dataframe(
        alerts_df.sort_values(
            by="Timestamp",
            ascending=False
        ),
        use_container_width=True,
        hide_index=True
    )

else:

    st.success(
        "No security alerts detected in the loaded events."
    )

st.divider()

# ============================================================
# 10. DNS EVENTS
# ============================================================

st.header("DNS Monitoring")

dns_events = [
    event for event in events
    if event.get("event_type") == "dns"
]

if dns_events:

    dns_records = []

    for event in dns_events:

        dns_data = event.get("dns", {})

        if not isinstance(dns_data, dict):
            dns_data = {}

        dns_records.append({
            "Timestamp": event.get("timestamp"),
            "Source IP": event.get("src_ip"),
            "Destination IP": event.get("dest_ip"),
            "DNS Query": dns_data.get("rrname"),
            "Record Type": dns_data.get("rrtype")
        })

    st.dataframe(
        pd.DataFrame(dns_records).tail(100),
        use_container_width=True,
        hide_index=True
    )

else:
    st.info("No DNS events available.")

st.divider()

# ============================================================
# 11. TLS EVENTS
# ============================================================

st.header("TLS Monitoring")

tls_events = [
    event for event in events
    if event.get("event_type") == "tls"
]

if tls_events:

    tls_records = []

    for event in tls_events:

        tls_data = event.get("tls", {})

        if not isinstance(tls_data, dict):
            tls_data = {}

        tls_records.append({
            "Timestamp": event.get("timestamp"),
            "Source IP": event.get("src_ip"),
            "Destination IP": event.get("dest_ip"),
            "Server Name": tls_data.get("sni"),
            "TLS Version": tls_data.get("version")
        })

    st.dataframe(
        pd.DataFrame(tls_records).tail(100),
        use_container_width=True,
        hide_index=True
    )

else:
    st.info("No TLS events available.")

st.divider()

# ============================================================
# 12. NETWORK FLOW EVENTS
# ============================================================

st.header("Network Flow Monitoring")

flow_events = [
    event for event in events
    if event.get("event_type") == "flow"
]

if flow_events:

    flow_records = []

    for event in flow_events:

        flow_data = event.get("flow", {})

        if not isinstance(flow_data, dict):
            flow_data = {}

        flow_records.append({
            "Timestamp": event.get("timestamp"),
            "Source IP": event.get("src_ip"),
            "Source Port": event.get("src_port"),
            "Destination IP": event.get("dest_ip"),
            "Destination Port": event.get("dest_port"),
            "Protocol": event.get("proto"),
            "Flow State": flow_data.get("state")
        })

    st.dataframe(
        pd.DataFrame(flow_records).tail(100),
        use_container_width=True,
        hide_index=True
    )

else:
    st.info("No network flow events available.")

# ============================================================
# 13. FOOTER
# ============================================================

st.divider()

st.caption(
    "CyberSentinel AI | Powered by Suricata IDS, "
    "Emerging Threats Rules, Python and Streamlit"
)

st.caption(
    "Automatic refresh interval: 3 seconds"
)
