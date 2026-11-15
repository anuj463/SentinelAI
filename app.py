

import os
import json
from pathlib import Path
from datetime import datetime
from collections import deque

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

# Refresh dashboard every 3 seconds
refresh_count = st_autorefresh(
    interval=3000,
    limit=None,
    key="cybersentinel_refresh"
)

PROJECT_DIR = Path(__file__).resolve().parent

DEFAULT_EVE_FILE = PROJECT_DIR / "logs" / "eve.json"

# ============================================================
# 2. SUPABASE CONFIGURATION
# ============================================================

def get_supabase_credentials():
    """Read credentials safely. Missing secrets are allowed."""

    try:
        url = st.secrets.get("SUPABASE_URL", "")
        key = st.secrets.get("SUPABASE_SECRET_KEY", "")

        if url and key:
            return url, key

    except Exception:
        pass

    return None, None


SUPABASE_URL, SUPABASE_KEY = get_supabase_credentials()

USE_SUPABASE = bool(SUPABASE_URL and SUPABASE_KEY)


@st.cache_resource
def get_supabase_client(url, key):
    from supabase import create_client
    return create_client(url, key)


# ============================================================
# 3. LOCAL EVE JSON READER
# ============================================================

def read_local_events(file_path, max_events=10000):
    """Read the latest EVE JSON events without caching."""

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

            latest_lines = deque(file, maxlen=max_events)

        for line in latest_lines:
            try:
                event = json.loads(line)

                if isinstance(event, dict):
                    events.append(event)

            except json.JSONDecodeError:
                continue

        return events, True

    except OSError as error:
        st.error(f"Unable to read EVE JSON: {error}")
        return [], False


# ============================================================
# 4. SUPABASE EVENT READER
# ============================================================

def read_cloud_events():

    client = get_supabase_client(
        SUPABASE_URL,
        SUPABASE_KEY
    )

    response = (
        client.table("suricata_events")
        .select("id,event_data")
        .order("id", desc=True)
        .limit(5000)
        .execute()
    )

    rows = response.data or []

    events = []

    for row in reversed(rows):
        event = row.get("event_data")

        if isinstance(event, dict):
            events.append(event)

    return events


# ============================================================
# 5. SIDEBAR AND DATA SOURCE
# ============================================================

st.sidebar.title("🛡️ Monitoring")
st.sidebar.subheader("Event Source")

events = []
source_description = ""

if USE_SUPABASE:

    st.sidebar.success("Connected data source: Supabase")

    try:
        events = read_cloud_events()
        source_description = "Supabase Cloud Database"

    except Exception as error:
        st.error(f"Supabase connection failed: {error}")
        st.stop()

else:

    default_path = os.getenv(
        "CYBERSENTINEL_EVE_FILE",
        str(DEFAULT_EVE_FILE)
    )

    eve_path = st.sidebar.text_input(
        "EVE JSON file path",
        value=default_path
    )

    st.sidebar.caption("Automatic refresh: 3 seconds")

    events, file_exists = read_local_events(eve_path)

    if not file_exists:
        st.error(f"EVE JSON file not found: {eve_path}")
        st.info(
            "Start Suricata with EVE JSON logging enabled "
            "or enter the correct file path."
        )
        st.stop()

    source_description = str(eve_path)

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
# 6. MAIN TITLE
# ============================================================

st.title("🛡️ CyberSentinel AI")

st.caption(
    "Suricata-based Network Intrusion Detection and Monitoring"
)

st.caption(
    f"Last dashboard update: "
    f"{datetime.now().strftime('%H:%M:%S')}"
)

if not events:

    st.warning(
        "No events available. Start Suricata and "
        "generate network traffic."
    )

    st.stop()


# ============================================================
# 7. DATAFRAME CREATION
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
# 8. SECURITY ALERT EXTRACTION
# ============================================================

alert_records = []

for event in events:

    if str(event.get("event_type", "")).lower() != "alert":
        continue

    alert_data = event.get("alert", {})

    if not isinstance(alert_data, dict):
        alert_data = {}

    try:
        severity = int(alert_data.get("severity", 0))
    except (ValueError, TypeError):
        severity = 0

    severity_labels = {
        1: "High",
        2: "Medium",
        3: "Low"
    }

    severity_label = severity_labels.get(
        severity,
        "Unknown"
    )

    alert_records.append({
        "Timestamp": event.get("timestamp", "Unknown"),
        "Signature": alert_data.get(
            "signature",
            "Unknown signature"
        ),
        "Severity": severity_label,
        "Severity Number": severity,
        "Source IP": event.get("src_ip", "Unknown"),
        "Destination IP": event.get("dest_ip", "Unknown"),
        "Protocol": event.get("proto", "Unknown"),
        "Action": alert_data.get("action", "Unknown"),
        "Signature ID": alert_data.get(
            "signature_id",
            "Unknown"
        )
    })

alerts_df = pd.DataFrame(alert_records)


# ============================================================
# 9. NETWORK OVERVIEW
# ============================================================

st.header("Network Overview")

total_events = len(events)
total_alerts = len(alert_records)

dns_count = int((df["event_type"] == "dns").sum())
tls_count = int((df["event_type"] == "tls").sum())
flow_count = int((df["event_type"] == "flow").sum())

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Events Loaded", total_events)
col2.metric("Security Alerts", total_alerts)
col3.metric("DNS Events", dns_count)
col4.metric("TLS Events", tls_count)
col5.metric("Network Flows", flow_count)

st.divider()


# ============================================================
# 10. EVENT DISTRIBUTION
# ============================================================

st.header("Event Analytics")

left_col, right_col = st.columns(2)

with left_col:

    st.subheader("Event Distribution")

    event_counts = (
        df["event_type"]
        .value_counts()
        .sort_values(ascending=False)
    )

    if not event_counts.empty:
        st.bar_chart(event_counts)
    else:
        st.info("No event data available.")


# ============================================================
# 11. ALERT SEVERITY GRAPH
# ============================================================

with right_col:

    st.subheader("Alert Severity")

    severity_order = [
        "High",
        "Medium",
        "Low",
        "Unknown"
    ]

    if not alerts_df.empty:

        severity_counts = (
            alerts_df["Severity"]
            .value_counts()
            .reindex(severity_order, fill_value=0)
        )

    else:

        severity_counts = pd.Series(
            [0, 0, 0, 0],
            index=severity_order,
            dtype=int
        )

    severity_chart = severity_counts.rename_axis(
        "Severity"
    ).reset_index(name="Alert Count")

    st.bar_chart(
        severity_chart.set_index("Severity")
    )

    st.caption(
        "Severity 1 = High | "
        "Severity 2 = Medium | "
        "Severity 3 = Low"
    )

    if alerts_df.empty:
        st.info(
            "No Suricata alerts detected in the loaded events."
        )

st.divider()


# ============================================================
# 12. SECURITY ALERT TABLE
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

    st.success("No security alerts detected yet.")


# ============================================================
# 13. DNS MONITORING
# ============================================================

st.divider()
st.header("DNS Monitoring")

dns_records = []

for event in events:

    if event.get("event_type") != "dns":
        continue

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

if dns_records:

    st.dataframe(
        pd.DataFrame(dns_records).tail(100),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No DNS events available.")


# ============================================================
# 14. TLS MONITORING
# ============================================================

st.divider()
st.header("TLS Monitoring")

tls_records = []

for event in events:

    if event.get("event_type") != "tls":
        continue

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

if tls_records:

    st.dataframe(
        pd.DataFrame(tls_records).tail(100),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No TLS events available.")


# ============================================================
# 15. NETWORK FLOW MONITORING
# ============================================================

st.divider()
st.header("Network Flow Monitoring")

flow_records = []

for event in events:

    if event.get("event_type") != "flow":
        continue

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

if flow_records:

    st.dataframe(
        pd.DataFrame(flow_records).tail(100),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No network flow events available.")


# ============================================================
# 16. FOOTER
# ============================================================

st.divider()

st.caption(
    "CyberSentinel AI | Powered by Suricata IDS, "
    "Emerging Threats Rules, Python and Streamlit"
)

st.caption("Automatic refresh interval: 3 seconds")
