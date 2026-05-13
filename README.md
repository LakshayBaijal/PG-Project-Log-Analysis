# Cisco Wireless SNMP Trap Log Analyzer

**PG Project - CSIS, IIIT Hyderabad**

This project is an end-to-end log analysis suite specifically designed to parse, analyze, and visualize Cisco wireless SNMP trap logs. It extracts actionable inferences that network administrators and security teams need, presenting facts about network usage, roaming, authentication failures, and potential security threats (e.g., rogue APs, deauth storms) without requiring extensive manual analysis.

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

```bash
cd snmp_log_analysis
pip install fastapi uvicorn python-multipart
```

### Running the Web Application
To spin up the web interface and API backend locally:

```bash
cd snmp_log_analysis
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```
Open your browser and navigate to: [http://127.0.0.1:8000](http://127.0.0.1:8000)

### Running Analysis via Command Line
To run the analysis directly on a log file and generate a JSON report:

```bash
cd snmp_log_analysis
python wireless_analyzer.py --log "snmptrap-sample.log" --out report.json
```
*(You can also optionally supply arguments like `--hours-start 8 --hours-end 20` to highlight events that occur out of expected business hours.)*

### Managing Large Log Files
Standard logging solutions generate extremely large text files. Use the included Python splitter utility to chunk logs before analysis to preserve memory:

```bash
python split_log.py
```
*(Update `log_file_path` inside `split_log.py` or customize the `chunk_size_mb` value to fit your needs.)*

---

