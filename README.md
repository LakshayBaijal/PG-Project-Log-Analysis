# Cisco Wireless SNMP Trap Log Analyzer

**PG Project - CSIS, IIIT Hyderabad**

This project is an end-to-end log analysis suite specifically designed to parse, analyze, and visualize Cisco wireless SNMP trap logs. It extracts actionable inferences that network administrators and security teams need, presenting facts about network usage, roaming, authentication failures, and potential security threats (e.g., rogue APs, deauth storms) without requiring extensive manual analysis.

---
# Demo Video
Uploading Screen Recording 2026-05-13 150017.mp4…
---

## Project Overview

Wireless networks generate massive amounts of SNMP trap logs concerning client connections, authentications, handoffs, and disruptions. The `Wireless Analyzer` interprets these cryptic OIDs mapped via Cisco MIBs into clear semantic fields (e.g., `client_mac`, `ap_name`, `reason_code`) and performs aggregate temporal and client-specific analysis.

The system features both:
- **A CLI Analysis tool** generating extensive JSON reports from raw SNMP logs.
- **A Web Interface (FastAPI + HTML/JS/CSS)** allowing users to upload `.log` files and visually inspect the analytical insights.

---
## Project Report

For a complete academic context, the breakdown of our methodology, deep dives into OID hierarchies, and the real-world evaluation of this system over actual campus logs, please read parsing details covered in:
**`Report/PG_Project_Report.pdf`**
## Repository Structure

---
```text
📦 PG Project
 ┣ 📂 datasets/                  # Raw SNMP trap datasets (e.g., loghub)
 ┣ 📂 librenms-mibs-cisco/       # Extracted Cisco MIBs used for OID reference
 ┣ 📂 Report/                    # Contains PG_Project_Report.pdf detailing methodologies, experiments, and findings
 ┣ 📂 snmp_log_analysis/         # Core application directory
 ┃  ┣ 📂 frontend/               # Web application UI (index.html, app.js, style.css)
 ┃  ┣ 📜 main.py                 # FastAPI application server backend
 ┃  ┣ 📜 wireless_analyzer.py    # The core analysis engine script parsing OIDs
 ┃  ┣ 📜 name_to_oid.json        # Compiled OID mappings
 ┃  ┗ 📜 commands.txt            # Commands for running the application
 ┣ 📂 snmptrap_dataset/          # Additional sample log files for testing and evaluation
 ┣ 📜 split_log.py               # Utility to split large log files into parts (e.g. 30MB chunks)
 ┗ 📜 README.md                  # This file
```

---

## Features & Inferences

The analysis engine automatically extracts the following patterns:

* **Per-AP Metrics:**
  * Unique client MACs attached per AP.
  * Total connection sessions, auth failures, deauths, and disassociations.
  * Identification of busiest hours of the day.
  * Repeat vs. single-visit clients.
* **Per-Client Profiling:**
  * First-seen / last-seen timestamps.
  * **Roam Paths:** Tracking exact AP-to-AP transition sequences.
  * **Authentication:** Tracking auth failure counts and reasons.
  * **Session Analysis:** Identifying short (<30s) or very-short (<5s) sessions.
  * Gap analysis, calculating time between disconnects and reconnects.
* **Temporal Patterns:**
  * Event heatmaps (per hour, per weekday).
  * Burst window detection (e.g., highly dense 5-minute event intervals).
* **Security & Instability Events:**
  * **Deauth / Disassoc Storms:** Finding heavy disconnect windows.
  * **Rogue Devices:** Tracking `rogue_ap_detected` and `rogue_client_detected` alerts.
  * Identifying off-hours events outside specified business availability boundaries.

---

## Getting Started

### Prerequisites
* Python 3.8+
* `pip` dependencies: FastAPI, Uvicorn, python-multipart (Install via `requirements.txt` if present)

# Cisco Wireless SNMP Trap Log Analyzer

**PG Project — CSIS, IIIT Hyderabad**

An end-to-end analysis suite for Cisco wireless SNMP trap logs. The project parses raw SNMP trap text, maps OIDs to semantic fields using Cisco/AireSpace MIB knowledge, and produces human-friendly reports that highlight client behavior, AP health, roaming, authentication failures, and potential security incidents.

---

## Project Essentials

- Core analyzer: `snmp_log_analysis/wireless_analyzer.py` — reads log text, decodes OIDs, and builds analytical structures (per-AP, per-client, temporal windows).
- Backend + UI: `snmp_log_analysis/main.py` + `snmp_log_analysis/frontend/` — a FastAPI server powering a minimal web UI for uploading logs and viewing results.
- Utility: `split_log.py` — chunk very large log files to avoid memory exhaustion.
- MIB/OID data: `snmp_log_analysis/oid_trie.json`, `oid_flat.json`, `name_to_oid.json` and `trap_db.json`.
- Full academic write-up: `Report/PG_Project_Report.pdf`.

---

## How to Run

1. Install requirements (example):

```powershell
cd "snmp_log_analysis"
pip install -r requirements.txt

# or minimal
pip install fastapi uvicorn python-multipart
```

2. Start the web UI / API:

```powershell
cd "snmp_log_analysis"
python -m uvicorn main:app --host 127.0.0.1 --port 8000

# then open http://127.0.0.1:8000
```

3. Run CLI analysis on a log file:

```powershell
cd "snmp_log_analysis"
python wireless_analyzer.py --log "snmptrap-20260511.log" --out report.json
```

4. If a log file is very large, split it first:

```powershell
python split_log.py
```

---

## API Endpoints (FastAPI)

- `POST /api/analyze` — multipart form upload with `file` (log file), optional `start_datetime` and `end_datetime` (ISO format). Returns full JSON report.
- `GET /api/sample` — returns analysis of sample bundled log file. Accepts `start_datetime` and `end_datetime` as query params.

Example (curl):

```bash
curl -F "file=@snmptrap-sample.log" http://127.0.0.1:8000/api/analyze
```

---

## Results — What the Reports Contain (and How to Read Them)

The analyzer produces a JSON report (example file: `snmp_log_analysis/report.json`). Reports are structured with these top-level sections:

- `overview`: high-level aggregated metrics (total traps, unique clients/APs/SSIDs, auth failures, deauth windows, off-hours events, business hours config).
- `ap_summary`: per-AP metrics (unique client count, one-time vs repeat visitors, total sessions, auth failures, deauths/disassocs, peak hour, link flaps).
- `clients`: per-client profiles including first/last seen, APs visited (roam path), sessions list (start/end/duration), auth failure counts, and session duration statistics.
- `auth_failure_analysis`: failure counts aggregated by client and AP.
- `temporal`: optional—histograms per-hour / per-weekday and detected burst windows.
- `deauth_windows` / `roam_transitions` / `rogue_events`: event lists for security-focused inspection.

### Example — Overview Snippet

From a full campus run (`report.json`):

```json
"overview": {
  "total_trap_blocks": 67504,
  "unique_client_macs": 1220,
  "unique_aps": 232,
  "unique_ssids": 12,
  "completed_sessions_paired": 1074,
  "total_auth_failures": 7643,
  "clients_with_auth_failures": 889,
  "clients_failed_never_succeeded": 18,
  "total_roam_transitions": 627,
  "off_hours_events": 31014,
  "deauth_windows_detected": 2413,
  "business_hours": "08:00 – 20:00"
}
```

Interpretation: large `off_hours_events` may indicate background scanning or misbehaving clients; `clients_failed_never_succeeded` helps shortlist devices that repeatedly fail authentication and may require support.

### Example — Per-AP Row (tabular report)

One AP entry looks like this in the human-friendly text output and as JSON objects in `ap_summary`:

```text
AP: Vindhya_External_Canteen — unique_clients: 372, one_time_visitors: 1, repeat_visitors: 371, total_sessions: 0, auth_failures: 1014, total_events: 2256, peak_hour: 20
```

Interpretation: this AP shows unusually high auth failures (1014). Investigate its authentication backend, configuration, and surrounding radio environment.

### Example — Client Entry (JSON)

Client objects contain a `sessions` array with start/end timestamps and a `deauth_disassoc_reasons` map. Short sessions are marked in `sessions_under_30s` and `sessions_under_5s` counters.

```json
{
  "mac": "12:7E:CC:DB:9E:5C",
  "first_seen": "2026-03-20T16:14:49",
  "last_seen":  "2026-03-20T16:14:49",
  "auth_failures": 1,
  "never_succeeded_auth": true,
  "sessions": [ { "start": "2026-03-20T16:14:49", "end": "2026-03-20T16:14:49", "duration_sec": 0, "reason": "Auth Failure" } ]
}
```

Actionable insight: clients with `never_succeeded_auth: true` represent devices repeatedly failing authentication and are good candidates for on-ground troubleshooting.

---

## How to Use the Report for Triage (Quick Checklist)

- Sort `ap_summary` by `auth_failures` to find APs with large numbers of failed authentication attempts.
- Sort `ap_summary` by `deauths` or `disassocs` to spot instability or storms.
- Inspect `clients` with high `sessions_under_30s` or `sessions_under_5s` — short-duration sessions often indicate roaming, poor signal, or posture checks.
- Look at `deauth_windows_detected` and their timestamps to correlate with known incidents or scheduled changes.
- Use `roam_transitions` to find frequent AP-to-AP hops that may indicate poor coverage overlap or misconfiguration.

---

## Frontend / UI Notes

- The UI in `snmp_log_analysis/frontend` is intentionally minimal. It posts logs to `/api/analyze` and displays JSON output. Use the backend API for automation or integrate into dashboards.
- The `GET /api/sample` endpoint returns an analysis of the included sample log — useful for smoke tests.

---

## Performance & Practical Tips

- For very large logs (multi-GB), pre-split the logs using `split_log.py` and analyze parts sequentially.
- The analyzer is single-process and memory use depends on the number of tracked clients/APs; process large traces on a machine with sufficient RAM or aggregate results incrementally.
- Tuning: increase session pairing timeouts or adjust business hours in `wireless_analyzer.py` arguments when analyzing datasets from different time zones or schedules.

## Known Limitations

- The tool relies on MIB-to-OID mappings in `oid_trie.json`/`oid_flat.json`. Unknown/custom OIDs will appear as raw OIDs in outputs and require adding to the mapping for semantic fields.
- Timestamps are parsed heuristically from trap text; malformed timestamps may be skipped.

---

## Contributing

- Add OIDs to `snmp_log_analysis/name_to_oid.json` and `oid_flat.json` if your site uses vendor-specific traps not already mapped.
- Improve visualization in `frontend/` to add charts and timelines.

---

## License & Contact

This repository includes academic work for a PG project. Contact the author / project owner (maintainer listed in the `Report/PG_Project_Report.pdf`) for reuse, attribution, or collaboration.

---
