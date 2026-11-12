# CyberSentinel AI

A Suricata-based network monitoring and intrusion-detection dashboard built with Python, Pandas, and Streamlit.

## Features
- Reads Suricata EVE JSON events.
- Displays event counts and event distribution.
- Displays signature alerts, severity, and alert metadata.
- Displays DNS queries and recent flow/TLS/QUIC events.
- Refreshes the dashboard every three seconds.
- Includes a harmless custom DNS laboratory rule (SID 1000001).

## Architecture
Network interface -> Suricata IDS -> EVE JSON -> Python/Streamlit dashboard.

Suricata inspects traffic. The dashboard visualizes events written by Suricata. The dashboard does not capture packets or block traffic.

## Windows / VS Code setup
```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```
Open http://localhost:8501.

## EVE JSON path
By default, the app reads `logs/eve.json` in this project. To use another location:
```powershell
$env:CYBERSENTINEL_EVE_FILE = "C:\path\to\eve.json"
python -m streamlit run app.py
```

## Event monitor
```powershell
python .\src\eve_monitor.py
```
It follows newly appended events. Press Ctrl+C to stop.

## Custom laboratory rule
`active-rules/local.rules` contains SID 1000001 and alerts on DNS queries containing `cybersentinel-lab.test`. This is a harmless lab signature, not an ET Open rule and not evidence that the domain is malicious. The alert action is allowed (alert-only), not a block.

Add `local.rules` to the `rule-files:` list in your Suricata YAML configuration, ensure `default-rule-path` points to the folder containing it, validate the configuration, and restart Suricata. Suricata and its YAML configuration are installed/configured separately from this repository.

## GitHub and Streamlit Community Cloud
Do not commit real EVE logs, secrets, or local Suricata configuration. A hosted dashboard cannot directly read EVE JSON on your laptop. Secure authenticated event forwarding is required for remote live events.

## Limitations
This is a signature-based IDS dashboard, not a trained machine-learning model. It visualizes alerts and does not block network traffic.
