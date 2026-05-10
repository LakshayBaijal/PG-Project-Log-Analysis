"""
wireless_analyzer.py
====================
Analyzes Cisco wireless SNMP trap logs and extracts every inference
a security team would want. No severity labels — just facts and counts.

Inferences produced
-------------------
  Per-AP
    - Unique client MACs
    - Total sessions, auth failures, deauths, disassocs
    - Clients seen only once vs repeat visitors
    - Busiest hour of the day

  Per-client
    - First seen / last seen timestamps
    - All APs visited (roam path)
    - All SSIDs connected to
    - Session count, total connected time, avg / min / max session duration
    - Auth failure count
    - Deauth reasons breakdown
    - Short session count (<30 s) and very-short (<5 s)
    - Sessions outside business hours
    - Gap analysis: time between last disconnect and next connect

  Temporal patterns
    - Events per hour (all 24 h)
    - Events per weekday
    - Burst windows: any 5-minute window with unusually high event density

  Deauth / disassoc storms
    - AP + time window + count, every instance, no thresholds hidden

  Roaming
    - Per-client roam count and exact AP transition sequence
    - Most common AP-to-AP transitions

  Auth failures
    - Per-client and per-AP failure counts
    - Clients with failures but never a successful association

  Rogue events
    - Raw list with all available fields

  SSID analysis
    - Clients per SSID
    - SSIDs seen only in one AP vs spread across many APs

  Off-hours events
    - Every event outside configured business hours

Usage
-----
    python wireless_analyzer.py --log snmptrap-20250522.log
    python wireless_analyzer.py --log snmptrap-20250522.log \
        --out report.json --hours-start 8 --hours-end 20
"""

import re
import json
import argparse
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import redirect_stdout
import sys
import io
import os

# Ensure stdout/stderr use UTF-8 on Windows to avoid UnicodeEncodeError
# when printing box-drawing or other Unicode characters to the console.
# This attempts the modern reconfigure API first, then falls back to
# wrapping streams with TextIOWrapper. If both fail we silently continue
# so the rest of the script can still run (writes to --out will work).
try:
    # set PYTHONIOENCODING for child processes and libraries that read it
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    else:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    # best-effort only; avoid failing early due to encoding issues
    pass

# Install a safe-print shim to gracefully handle consoles that cannot
# encode box-drawing characters. The shim first attempts to write
# UTF-8 bytes to the underlying buffer; if that fails it falls back
# to replacing box-drawing characters with ASCII equivalents.
try:
    import builtins
    _orig_print = builtins.print

    def _safe_print(*args, **kwargs):
        sep = kwargs.get('sep', ' ')
        end = kwargs.get('end', '\n')
        file = kwargs.get('file', sys.stdout)
        try:
            text = sep.join(str(a) for a in args) + end
            try:
                file.buffer.write(text.encode('utf-8', errors='replace'))
            except Exception:
                # fallback: replace box characters and use original print
                text2 = text.replace('─', '-').replace('═', '=').replace('≥', '>=')
                _orig_print(text2, **{k: v for k, v in kwargs.items() if k != 'file'})
        except Exception:
            _orig_print(*args, **kwargs)

    builtins.print = _safe_print
except Exception:
    # if anything goes wrong installing the shim, continue with default print
    pass

from collections import Counter
trap_oid_counter = Counter()
# inside ingest(), after extract_trap_oid():

# after the loop, print:
# for oid, count in trap_oid_counter.most_common(20):
#     print(oid, count)
# ---------------------------------------------------------------------------
# OID → semantic field  (Cisco LWAPP / Airespace / common WLC MIBs)
# Add your site-specific OIDs here without touching anything else.
# ---------------------------------------------------------------------------

OID_FIELD_MAP = {
    ".1.3.6.1.4.1.9.9.599.1.1.1.1.2":  "client_mac",
    ".1.3.6.1.4.1.9.9.514.1.2.1.1.1":  "client_mac",
    ".1.3.6.1.4.1.14179.2.1.4.1.1":    "client_mac",
    ".1.3.6.1.4.1.9.9.599.1.1.1.1.3":  "client_ip",
    ".1.3.6.1.4.1.9.9.599.1.1.1.1.7":  "ap_name",
    ".1.3.6.1.4.1.9.9.599.1.1.1.1.5":  "ap_mac",
    ".1.3.6.1.4.1.9.9.599.1.1.1.1.6":  "ssid",
    ".1.3.6.1.4.1.9.9.599.1.1.1.1.8":  "slot_id",
    ".1.3.6.1.4.1.9.9.599.1.1.1.1.9":  "reason_code",
    ".1.3.6.1.4.1.9.9.599.1.1.1.1.4":  "username",
    ".1.3.6.1.4.1.9.9.599.1.2.1.1.3":  "auth_fail_reason",
    ".1.3.6.1.4.1.9.9.599.1.2.1.1.2":  "auth_fail_count",
    ".1.3.6.1.4.1.9.9.599.1.1.1.1.10": "rssi",
    ".1.3.6.1.4.1.9.9.599.1.1.1.1.11": "snr",
    ".1.3.6.1.2.1.1.3.0":              "sysuptime",
}

TRAP_EVENT_MAP = {
    ".1.3.6.1.4.1.9.9.599.0.1":  "assoc",
    ".1.3.6.1.4.1.9.9.599.0.2":  "reassoc",
    ".1.3.6.1.4.1.9.9.599.0.3":  "disassoc",
    ".1.3.6.1.4.1.9.9.599.0.4":  "deauth",
    ".1.3.6.1.4.1.9.9.599.0.8":  "auth_fail",
    ".1.3.6.1.4.1.9.9.599.0.9":  "auth_success",
    ".1.3.6.1.4.1.9.9.599.0.10": "roam",
    ".1.3.6.1.4.1.9.9.599.0.20": "roam_complete",
    ".1.3.6.1.4.1.9.9.599.0.30": "rogue_ap_detected",
    ".1.3.6.1.4.1.9.9.599.0.31": "rogue_client_detected",
    ".1.3.6.1.6.3.1.1.5.3":      "link_down",
    ".1.3.6.1.6.3.1.1.5.4":      "link_up",
    # AireSpace MIB mappings for Deauth/Disassoc/Assoc
    ".1.3.6.1.4.1.14179.2.6.3.41":"disassoc",
    ".1.3.6.1.4.1.14179.2.6.3.53":"deauth",
    ".1.3.6.1.4.1.14179.2.6.3.2": "assoc",
}

# 802.11 reason codes — raw facts only
REASON_CODES = {
    "1":  "Unspecified",
    "2":  "Auth no longer valid",
    "3":  "Deauth: station leaving IBSS or ESS",
    "4":  "Disassoc: inactivity / idle timeout",
    "5":  "Disassoc: AP cannot handle all associations",
    "6":  "Class 2 frame from unauthenticated station",
    "7":  "Class 3 frame from unassociated station",
    "8":  "Disassoc: station leaving BSS",
    "9":  "Station requesting (re)assoc is not authenticated",
    "17": "802.1X authentication failed",
    "23": "802.1X authentication timeout",
    "36": "Declined cipher suite",
}

# -----------------------------
# LOAD OID DATABASE
# -----------------------------
import json

with open("oid_trie.json") as f:
    trie = json.load(f)

with open("oid_flat.json") as f:
    flat_db = json.load(f)

with open("name_to_oid.json") as f:
    reverse_db = json.load(f)

with open("trap_db.json") as f:
    trap_db = json.load(f)

def lookup_oid(trie, oid):
    parts = oid.strip(".").split(".")
    node = trie
    last_found = None

    for part in parts:
        if part in node:
            node = node[part]
            if "_value" in node:
                last_found = node["_value"]
        else:
            break

    return last_found

# ---------------------------------------------------------------------------
# PARSING HELPERS
# ---------------------------------------------------------------------------

TS_PATTERNS = [
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
    r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})",
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
]


def parse_timestamp(block):
    year = datetime.now().year
    for pat in TS_PATTERNS:
        m = re.search(pat, block)
        if not m:
            continue
        raw = m.group(1)
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(raw, fmt).replace(tzinfo=None)
            except ValueError:
                pass
        try:
            return datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
        except ValueError:
            pass
    return None


def normalize_oid(oid):
    oid = oid.strip()
    if oid.startswith("iso."):
        oid = "." + oid.replace("iso.", "1.", 1)
    if not oid.startswith("."):
        oid = "." + oid
    # print(oid)
    return oid


def parse_varbind_value(raw):
    raw = raw.strip()

    for p in ("STRING:", "INTEGER:", "IpAddress:", "OID:", "Hex-STRING:",
              "Counter32:", "Counter64:", "Gauge32:", "Timeticks:"):
        if raw.startswith(p):
            raw = raw[len(p):].strip()
            break

    # Hex MAC → normalize
    if re.fullmatch(r'([0-9A-Fa-f]{2}\s){5}[0-9A-Fa-f]{2}', raw):
        raw = ":".join(raw.strip().split()).upper()

    return raw.strip('"')


import re

MAC_REGEX = re.compile(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', re.I)
IP_REGEX  = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def infer_field(name, value):
    if not name:
        return None

    n = name.lower()
    v = value.strip() if isinstance(value, str) else ""

    # -------------------------
    # STRONG: value-based detection
    # -------------------------
    if MAC_REGEX.match(v):
        if "ap" in n:
            return "ap_mac"
        return "client_mac"

    if IP_REGEX.match(v):
        return "client_ip"

    # -------------------------
    # NAME-based detection
    # -------------------------
    if "ssid" in n:
        return "ssid"

    if "user" in n or "login" in n:
        return "username"

    if "apname" in n or ("ap" in n and "name" in n):
        return "ap_name"

    if "bssid" in n:
        return "ap_mac"

    if "mac" in n:
        if "ap" in n:
            return "ap_mac"
        return "client_mac"

    if "ip" in n:
        return "client_ip"

    if "reason" in n:
        return "reason_code"

    if "rssi" in n:
        return "rssi"

    if "snr" in n:
        return "snr"

    if "auth" in n and "fail" in n:
        return "auth_fail_reason"

    return None

def extract_trap_oid(block):
    m = re.search(
        r'(?:iso|1)\.3\.6\.1\.6\.3\.1\.1\.4\.1\.0.*?value=OID:\s*([^\s\n]+)',
        block
    )
    return normalize_oid(m.group(1)) if m else None


def extract_source_ip(block):
    m = re.search(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', block)
    if m:
        return m.group(1)
    m = re.search(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})', block)
    return m.group(1) if m else None

def extract_mac_from_oid(oid):
    # Only aggressively extract if it follows a typical client-based table index
    # like .27. (or .1. but that overlaps with .1.1.1.0). Let's be safe.
    m = re.search(r'\.(?:27|1)\.((?:\d{1,3}\.){5}\d{1,3})$', oid)
    if m:
        try:
            mac = ':'.join(f"{int(p):02X}" for p in m.group(1).split('.'))
            if mac not in ("01:02:01:01:01:00", "01:03:02:01:03:00", "01:03:01:01:01:00", "01:03:01:01:08:00"):
                return mac
        except ValueError:
            return None
    return None

EXTRACT_VARBINDS_ALLOWED_FIELDS = {
    "client_mac",
    "client_ip",
    "ap_name",
    "ap_mac",
    "ssid",
    "username",
    "reason_code",
}

def extract_varbinds(block, trie, strict=True):
    fields = {}

    for line in block.splitlines():
        m = re.match(r'\s*([^\s]+)\s+type=\d+\s+value=(.+)', line)
        if not m:
            continue

        oid = normalize_oid(m.group(1))
        raw_val = m.group(2)
        value = parse_varbind_value(raw_val)

        # -------------------------
        # 1. DB lookup
        # -------------------------
        result = lookup_oid(trie, oid)
        name = result.get("name", "") if result else ""

        # -------------------------
        # 2. Infer field
        # -------------------------
        field = infer_field(name, value)

        # -------------------------
        # 3. Fallback to old map
        # -------------------------
        if not field:
            field = OID_FIELD_MAP.get(oid)

        # -------------------------
        # 4. Store
        # -------------------------
        if field:
            if field not in fields or len(str(value)) > len(str(fields[field])):
                fields[field] = value

        # -------------------------
        # 5. Opportunistic MAC extraction
        # -------------------------
        mac_suffix = extract_mac_from_oid(oid)
        if mac_suffix and not fields.get("client_mac"):
            fields["client_mac"] = mac_suffix

    if strict:
        return {k: v for k, v in fields.items() if k in EXTRACT_VARBINDS_ALLOWED_FIELDS}

    return fields


def split_traps(log_text):
    blocks = re.split(
        r'\n(?=\d{4}-\d{2}-\d{2}T|\w{3}\s+\d{1,2}\s+\d{2}:\d{2})',
        log_text
    )
    return [b.strip() for b in blocks if b.strip()]


def valid_mac(mac):
    return bool(re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac.upper().strip()))

def decode_hex_ssid(ssid):
    ssid = ssid.strip()
    if re.fullmatch(r'([0-9A-Fa-f]{2}\s)+[0-9A-Fa-f]{2}', ssid) or re.fullmatch(r'([0-9A-Fa-f]{2})+', ssid):
        try:
            return bytes.fromhex(ssid.replace(' ', '')).decode('utf-8', errors='replace')
        except Exception:
            pass
    return ssid


# ---------------------------------------------------------------------------
# ANALYSIS ENGINE
# ---------------------------------------------------------------------------

class WirelessAnalyzer:

    def __init__(self, business_start=8, business_end=20, start_dt=None, end_dt=None):
        self.business_start = business_start
        self.business_end   = business_end
        self.start_dt       = start_dt
        self.end_dt         = end_dt
        self.events         = []

        # AP-level
        self.ap_clients     = defaultdict(set)
        self.ap_events      = defaultdict(list)
        self.ap_sessions    = defaultdict(int)
        self.ap_auth_fails  = defaultdict(int)
        self.ap_deauths     = defaultdict(int)
        self.ap_disassocs   = defaultdict(int)
        self.ap_link_events = defaultdict(list)

        # Client-level
        self.client_events     = defaultdict(list)
        self.client_sessions   = defaultdict(list)
        self.client_first_seen = {}
        self.client_last_seen  = {}
        self.client_auth_fails = defaultdict(int)
        self.client_auth_ok    = defaultdict(int)
        self.client_roams      = defaultdict(list)
        self.client_aps        = defaultdict(list)   # ordered by first visit
        self.client_ssids      = defaultdict(set)
        self.client_ips        = defaultdict(set)
        self.client_usernames  = defaultdict(set)
        self.client_reasons    = defaultdict(list)

        # SSID-level
        self.ssid_clients   = defaultdict(set)
        self.ssid_aps       = defaultdict(set)
        self.ssid_sessions  = defaultdict(int)
        self.ssid_auth_fails= defaultdict(int)

        # Temporal
        self.events_by_hour    = defaultdict(int)
        self.events_by_weekday = defaultdict(int)
        self.off_hours_events  = []
        self.five_min_buckets  = defaultdict(int)

        # Special
        self.rogue_events   = []
        self.deauth_windows = []
        self._pending_assoc = {}   # mac → event (for session pairing)
        self._recent_auth_fail = {}  # (mac, ap) → ts (for deduping immediate deauth-after-authfail)
        self._recent_deauth = {}     # (mac, ap) → ts (for deduping immediate authfail-after-deauth)

    def _update_seen(self, mac, ts):
        if not mac or not ts:
            return
        if mac not in self.client_first_seen or ts < self.client_first_seen[mac]:
            self.client_first_seen[mac] = ts
        if mac not in self.client_last_seen or ts > self.client_last_seen[mac]:
            self.client_last_seen[mac] = ts

    def _bucket5(self, ts):
        if not ts:
            return None
        floored = ts.replace(minute=(ts.minute // 5) * 5, second=0, microsecond=0)
        return floored.strftime("%Y-%m-%d %H:%M")

    def ingest(self, log_text):
        blocks = split_traps(log_text)
        print(f"  Found {len(blocks)} trap blocks.")

        deauth_times_by_ap = defaultdict(list)

        for block in blocks:
            ts         = parse_timestamp(block)
            if ts:
                if self.start_dt and ts < self.start_dt:
                    continue
                if self.end_dt and ts > self.end_dt:
                    continue
            elif self.start_dt or self.end_dt:
                continue

            trap_oid   = extract_trap_oid(block)
            trap_oid_counter[trap_oid] += 1
            src_ip     = extract_source_ip(block)
            fields = extract_varbinds(block, trie, strict=False)

            # event_type = TRAP_EVENT_MAP.get(trap_oid, "unknown") if trap_oid else "unknown"
            if trap_oid in TRAP_EVENT_MAP:
                event_type = TRAP_EVENT_MAP[trap_oid]
            elif trap_oid in trap_db:
                event_type = trap_db[trap_oid]["name"]
            else:
                event_type = "unknown"
            mac        = fields.get("client_mac", "").upper().strip()
            mac        = mac if valid_mac(mac) else ""
            ap         = fields.get("ap_name") or fields.get("ap_mac") or src_ip or "unknown_ap"
            ssid       = decode_hex_ssid(fields.get("ssid", ""))
            username   = fields.get("username", "")
            client_ip  = fields.get("client_ip", "")
            raw_reason = fields.get("reason_code", "")
            if event_type == "auth_fail" and not raw_reason:
                raw_reason = fields.get("auth_fail_reason", "")
            reason     = REASON_CODES.get(raw_reason, raw_reason)
            
            if not reason:
                reason = "Unknown"

            event = {
                "ts": ts, "event_type": event_type, "trap_oid": trap_oid,
                "mac": mac, "ap": ap, "ssid": ssid, "src_ip": src_ip,
                "username": username, "client_ip": client_ip,
                "rssi": fields.get("rssi", ""), "snr": fields.get("snr", ""),
                "reason": reason, "raw_fields": fields,
            }
            self.events.append(event)

            # Temporal
            if ts:
                self.events_by_hour[ts.hour] += 1
                self.events_by_weekday[ts.weekday()] += 1
                b = self._bucket5(ts)
                if b:
                    self.five_min_buckets[b] += 1
                if not (self.business_start <= ts.hour < self.business_end):
                    self.off_hours_events.append(event)

            # AP
            self.ap_events[ap].append(event)
            if mac:
                self.ap_clients[ap].add(mac)

            # Client
            if mac:
                self._update_seen(mac, ts)
                self.client_events[mac].append(event)
                if ap not in self.client_aps[mac]:
                    self.client_aps[mac].append(ap)
                if ssid:
                    self.client_ssids[mac].add(ssid)
                    self.ssid_clients[ssid].add(mac)
                    self.ssid_aps[ssid].add(ap)
                if client_ip:
                    self.client_ips[mac].add(client_ip)
                if username:
                    self.client_usernames[mac].add(username)
            if ssid:
                self.ssid_aps[ssid].add(ap)

            # Dispatch
            if event_type in ("assoc", "reassoc", "auth_success"):
                self.ap_sessions[ap] += 1
                if ssid:
                    self.ssid_sessions[ssid] += 1
                if mac:
                    if event_type == "auth_success":
                        self.client_auth_ok[mac] += 1
                    prev = self._pending_assoc.get(mac)
                    if prev and prev["ap"] != ap:
                        self.client_roams[mac].append({
                            "from_ap": prev["ap"], "to_ap": ap, "ts": ts,
                        })
                    self._pending_assoc[mac] = {
                        "start_event": event,
                        "ts": ts,
                        "username": username,
                        "client_ip": client_ip,
                        "mac": mac,
                        "ap": ap,
                        "ssid": ssid,
                    }
            elif event_type in ("disassoc", "deauth"):
                correlated_deauth = False
                if event_type == "deauth" and mac and ts:
                    self._recent_deauth[(mac, ap)] = ts
                    recent = self._recent_auth_fail.get((mac, ap))
                    if recent and 0 <= (ts - recent).total_seconds() <= 2:
                        correlated_deauth = True

                if event_type == "deauth":
                    if not correlated_deauth:
                        self.ap_deauths[ap] += 1
                else:
                    self.ap_disassocs[ap] += 1
                if ts:
                    deauth_times_by_ap[ap].append(ts)
                if mac:
                    if not correlated_deauth:
                        self.client_reasons[mac].append(reason)
                    if mac in self._pending_assoc:
                        start_ev = self._pending_assoc.pop(mac)
                        duration = None
                        if ts and start_ev["ts"]:
                            duration = (ts - start_ev["ts"]).total_seconds()
                        self.client_sessions[mac].append({
                            "start": start_ev["ts"], "end": ts,
                            "ap": start_ev["ap"], "ssid": start_ev["ssid"],
                            "duration_sec": duration, "reason": reason,
                            "off_hours": not (
                                self.business_start
                                <= (start_ev["ts"].hour if start_ev["ts"] else 0)
                                < self.business_end
                            ),
                        })
                    else:
                        # Orphan end event (disconnect without a seen start in log)
                        if not correlated_deauth:
                            self.ap_sessions[ap] += 1
                            if ssid:
                                self.ssid_sessions[ssid] += 1
                            # Treat it as a 0-second session so it shows up in client stats
                            self.client_sessions[mac].append({
                                "start": ts, "end": ts,
                                "ap": ap, "ssid": ssid,
                                "duration_sec": 0, "reason": reason,
                                "off_hours": not (self.business_start <= (ts.hour if ts else 0) < self.business_end),
                            })

            elif event_type == "auth_fail":
                correlated = False
                recent_deauth = self._recent_deauth.get((mac, ap))
                if recent_deauth and ts and 0 <= (ts - recent_deauth).total_seconds() <= 2:
                    correlated = True

                # Count authentication failures as session attempts.
                if not correlated:
                    self.ap_sessions[ap] += 1
                    if ssid:
                        self.ssid_sessions[ssid] += 1
                    if mac:
                        self.client_sessions[mac].append({
                            "start": ts, "end": ts,
                            "ap": ap, "ssid": ssid,
                            "duration_sec": 0, "reason": "Auth Failure",
                            "off_hours": not (self.business_start <= (ts.hour if ts else 0) < self.business_end),
                        })

                self.ap_auth_fails[ap] += 1
                if mac:
                    self.client_auth_fails[mac] += 1
                    if ts:
                        self._recent_auth_fail[(mac, ap)] = ts
                if ssid:
                    self.ssid_auth_fails[ssid] += 1
                else:
                    self.ssid_auth_fails["Unknown"] += 1

                # If we already processed a deauth for this event, undo the deauth counts
                if correlated:
                    if self.ap_deauths[ap] > 0: self.ap_deauths[ap] -= 1
                    if mac and self.client_reasons[mac]: self.client_reasons[mac].pop()
                    # Also undo the orphan session created by that deauth
                    if mac and self.client_sessions[mac] and self.client_sessions[mac][-1]["duration_sec"] == 0:
                        self.client_sessions[mac].pop()
                    if self.ap_sessions[ap] > 0: self.ap_sessions[ap] -= 1
                    if ssid and self.ssid_sessions[ssid] > 0: self.ssid_sessions[ssid] -= 1

            elif event_type in ("roam", "roam_complete"):
                if mac:
                    self.client_roams[mac].append({
                        "from_ap": "unknown", "to_ap": ap, "ts": ts,
                    })

            elif "rogue" in event_type:
                self.rogue_events.append(event)

            elif event_type in (
                "link_up",
                "link_down",
                # Cisco WLC: AP radio/interface up/down notifications
                "ciscoLwappApIfUpNotify",
                "ciscoLwappApIfDownNotify",
                # Cisco IfExtensionMIB (common on IOS)
                "cieLinkUp",
                "cieLinkDown",
                "cieDelayedLinkUpDownNotif",
            ):
                self.ap_link_events[ap].append({"ts": ts, "event": event_type})

        # Compute disjoint deauth burst windows (every window with ≥3 events in 60 s)
        for ap, times in deauth_times_by_ap.items():
            times.sort()
            i = 0
            while i < len(times):
                t = times[i]
                window = [x for x in times[i:] if (x - t).total_seconds() <= 60]
                if len(window) >= 3:
                    self.deauth_windows.append({
                        "ap": ap,
                        "window_start": t,
                        "window_end": window[-1],
                        "count": len(window),
                        "duration_sec": (window[-1] - t).total_seconds(),
                    })
                    # Skip to the end of this window to avoid overlapping counts
                    i += len(window)
                else:
                    i += 1

        print(f"  Parsed {len(self.events)} events.")
    
        for oid, count in trap_oid_counter.most_common(20):
            print(oid, count)

# ---------------------------------------------------------------------------
# REPORT BUILDER
# ---------------------------------------------------------------------------

def hms(s):
    if s is None:
        return "N/A"
    s = int(s)
    h, r = divmod(s, 3600)
    m, sc = divmod(r, 60)
    return f"{h}h {m}m {sc}s" if h else (f"{m}m {sc}s" if m else f"{sc}s")


def ts_str(t):
    return t.isoformat() if t else None


def gap_analysis(sessions):
    sorted_s = sorted(
        [s for s in sessions if s["start"] and s["end"]],
        key=lambda x: x["start"]
    )
    gaps = []
    for i in range(1, len(sorted_s)):
        gap = (sorted_s[i]["start"] - sorted_s[i-1]["end"]).total_seconds()
        gaps.append(gap)
    return gaps


def build_report(az):
    report = {}

    # ── 1. Overview ────────────────────────────────────────────────────────
    all_macs = set(az.client_first_seen)
    fails_no_success = {m for m in az.client_auth_fails
                        if az.client_auth_ok.get(m, 0) == 0}
    report["overview"] = {
        "total_trap_blocks":              len(az.events),
        "unique_client_macs":             len(all_macs),
        "unique_aps":                     len(az.ap_clients),
        "unique_ssids":                   len(az.ssid_clients),
        "completed_sessions_paired":      sum(len(v) for v in az.client_sessions.values()),
        "total_auth_failures":            sum(az.client_auth_fails.values()),
        "clients_with_auth_failures":     len(az.client_auth_fails),
        "clients_failed_never_succeeded": len(fails_no_success),
        "total_roam_transitions":         sum(len(v) for v in az.client_roams.values()),
        "rogue_events":                   len(az.rogue_events),
        "off_hours_events":               len(az.off_hours_events),
        "deauth_windows_detected":        len(az.deauth_windows),
        "business_hours":                 f"{az.business_start:02d}:00 – {az.business_end:02d}:00",
    }

    # ── 2. AP summary ─────────────────────────────────────────────────────
    ap_rows = []
    for ap in az.ap_clients:
        evs   = az.ap_events[ap]
        hours = defaultdict(int)
        for e in evs:
            if e["ts"]:
                hours[e["ts"].hour] += 1
        peak_hour = max(hours, key=hours.get) if hours else None
        one_time  = sum(
            1 for m in az.ap_clients[ap]
            if sum(1 for e in az.client_events[m] if e["ap"] == ap) == 1
        )
        ap_rows.append({
            "ap":               ap,
            "unique_clients":   len(az.ap_clients[ap]),
            "one_time_visitors":one_time,
            "repeat_visitors":  len(az.ap_clients[ap]) - one_time,
            "total_sessions":   az.ap_sessions[ap],
            "auth_failures":    az.ap_auth_fails[ap],
            "deauths":          az.ap_deauths[ap],
            "disassocs":        az.ap_disassocs[ap],
            "total_events":     len(evs),
            "peak_hour":        peak_hour,
            "link_flaps":       len(az.ap_link_events[ap]),
        })
    report["ap_summary"] = sorted(ap_rows, key=lambda x: x["unique_clients"], reverse=True)

    # ── 3. Client analysis ────────────────────────────────────────────────
    client_rows = []
    for mac in all_macs:
        sessions  = az.client_sessions[mac]
        durations = [s["duration_sec"] for s in sessions if s["duration_sec"] is not None]
        gaps      = gap_analysis(sessions)
        off_sess  = [s for s in sessions if s.get("off_hours")]
        reasons   = az.client_reasons[mac]
        reason_breakdown = defaultdict(int)
        for r in reasons:
            reason_breakdown[r] += 1

        client_rows.append({
            "mac":                      mac,
            "usernames_seen":           sorted(az.client_usernames[mac]),
            "ips_seen":                 sorted(az.client_ips[mac]),
            "first_seen":               ts_str(az.client_first_seen.get(mac)),
            "last_seen":                ts_str(az.client_last_seen.get(mac)),
            "total_event_count":        len(az.client_events[mac]),
            "aps_visited":              az.client_aps[mac],
            "ssids_used":               sorted(az.client_ssids[mac]),
            "roam_count":               len(az.client_roams[mac]),
            "roam_path":                [
                {"from_ap": r["from_ap"], "to_ap": r["to_ap"], "ts": ts_str(r["ts"])}
                for r in az.client_roams[mac]
            ],
            "auth_failures":            az.client_auth_fails[mac],
            "auth_successes":           az.client_auth_ok[mac],
            "never_succeeded_auth":     az.client_auth_ok[mac] == 0 and az.client_auth_fails[mac] > 0,
            "completed_sessions":       len(sessions),
            "unclosed_session":         mac in az._pending_assoc,
            "total_connected_sec":      sum(durations) if durations else None,
            "total_connected_human":    hms(sum(durations)) if durations else None,
            "avg_session_sec":          (sum(durations)/len(durations)) if durations else None,
            "avg_session_human":        hms(sum(durations)/len(durations)) if durations else None,
            "min_session_sec":          min(durations) if durations else None,
            "max_session_sec":          max(durations) if durations else None,
            "sessions_under_30s":       sum(1 for d in durations if d < 30),
            "sessions_under_5s":        sum(1 for d in durations if d < 5),
            "off_hours_sessions":       len(off_sess),
            "avg_gap_between_sessions_sec": (sum(gaps)/len(gaps)) if gaps else None,
            "min_gap_sec":              min(gaps) if gaps else None,
            "max_gap_sec":              max(gaps) if gaps else None,
            "deauth_disassoc_reasons":  dict(reason_breakdown),
            "sessions": [
                {
                    "start":          ts_str(s["start"]),
                    "end":            ts_str(s["end"]),
                    "duration_sec":   s["duration_sec"],
                    "duration_human": hms(s["duration_sec"]),
                    "ap":             s["ap"],
                    "ssid":           s["ssid"],
                    "reason":         s["reason"],
                    "off_hours":      s["off_hours"],
                }
                for s in sorted(sessions, key=lambda x: x["start"] or datetime.min)
            ],
        })

    report["clients"] = sorted(
        client_rows, key=lambda x: x["completed_sessions"], reverse=True
    )

    # ── 4. Auth failure analysis ───────────────────────────────────────────
    report["auth_failure_analysis"] = {
        "per_client": sorted(
            [{"mac": m, "failures": c, "successes": az.client_auth_ok.get(m, 0)}
             for m, c in az.client_auth_fails.items()],
            key=lambda x: x["failures"], reverse=True
        ),
        "per_ap": sorted(
            [{"ap": ap, "failures": c} for ap, c in az.ap_auth_fails.items()],
            key=lambda x: x["failures"], reverse=True
        ),
        "per_ssid": sorted(
            [{"ssid": s, "failures": c} for s, c in az.ssid_auth_fails.items()],
            key=lambda x: x["failures"], reverse=True
        ),
        "clients_that_failed_and_never_succeeded": sorted(
            [{"mac": m, "failures": az.client_auth_fails[m]} for m in fails_no_success],
            key=lambda x: x["failures"], reverse=True
        ),
    }

    # ── 5. Deauth / disassoc windows ──────────────────────────────────────
    report["deauth_windows"] = sorted(
        [
            {
                "ap":           w["ap"],
                "window_start": ts_str(w["window_start"]),
                "window_end":   ts_str(w["window_end"]),
                "count_in_60s": w["count"],
                "duration_sec": w["duration_sec"],
            }
            for w in az.deauth_windows
        ],
        key=lambda x: x["count_in_60s"], reverse=True
    )

    # ── 6. Roaming analysis ───────────────────────────────────────────────
    transitions = defaultdict(int)
    for mac, roams in az.client_roams.items():
        for r in roams:
            if r["from_ap"] != "unknown":
                transitions[(r["from_ap"], r["to_ap"])] += 1

    report["roaming_analysis"] = {
        "total_roam_transitions": sum(len(v) for v in az.client_roams.values()),
        "clients_that_roamed":    len([m for m in az.client_roams if az.client_roams[m]]),
        "top_roamers": sorted(
            [{"mac": m, "roam_count": len(r), "aps_visited": az.client_aps[m]}
             for m, r in az.client_roams.items() if r],
            key=lambda x: x["roam_count"], reverse=True
        )[:20],
        "most_common_ap_transitions": sorted(
            [{"from_ap": k[0], "to_ap": k[1], "count": v}
             for k, v in transitions.items()],
            key=lambda x: x["count"], reverse=True
        )[:20],
    }

    # ── 7. SSID analysis ──────────────────────────────────────────────────
    report["ssid_analysis"] = sorted(
        [
            {
                "ssid":             ssid,
                "unique_clients":   len(clients),
                "aps_broadcasting": len(az.ssid_aps[ssid]),
                "total_sessions":   az.ssid_sessions[ssid],
                "auth_failures":    az.ssid_auth_fails[ssid],
                "single_ap_only":   len(az.ssid_aps[ssid]) == 1,
            }
            for ssid, clients in az.ssid_clients.items()
        ],
        key=lambda x: x["unique_clients"], reverse=True
    )

    # ── 8. Temporal analysis ──────────────────────────────────────────────
    DAYS = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
    report["temporal_analysis"] = {
        "events_by_hour":    {str(h): az.events_by_hour[h] for h in range(24)},
        "events_by_weekday": {DAYS[d]: az.events_by_weekday[d] for d in range(7)},
        "top_5min_burst_windows": sorted(
            [{"window": w, "event_count": c} for w, c in az.five_min_buckets.items()],
            key=lambda x: x["event_count"], reverse=True
        )[:20],
    }

    # ── 9. Off-hours activity ─────────────────────────────────────────────
    off_macs = defaultdict(list)
    for ev in az.off_hours_events:
        if ev["mac"]:
            off_macs[ev["mac"]].append(ev)

    report["off_hours_activity"] = {
        "total_off_hours_events": len(az.off_hours_events),
        "unique_devices":         len(off_macs),
        "per_device": sorted(
            [
                {
                    "mac":         mac,
                    "event_count": len(evs),
                    "event_types": {
                        et: sum(1 for e in evs if e["event_type"] == et)
                        for et in set(e["event_type"] for e in evs)
                    },
                    "hours_active": sorted({e["ts"].hour for e in evs if e["ts"]}),
                    "aps":          sorted({e["ap"] for e in evs}),
                }
                for mac, evs in off_macs.items()
            ],
            key=lambda x: x["event_count"], reverse=True
        ),
        "raw_events": [
            {
                "ts": ts_str(e["ts"]), "event_type": e["event_type"],
                "mac": e["mac"], "ap": e["ap"], "ssid": e["ssid"],
            }
            for e in az.off_hours_events
        ],
    }

    # ── 10. Rogue events ──────────────────────────────────────────────────
    report["rogue_events"] = [
        {
            "ts": ts_str(e["ts"]), "event_type": e["event_type"],
            "mac": e["mac"], "ap": e["ap"], "ssid": e["ssid"],
            "raw_fields": e["raw_fields"],
        }
        for e in az.rogue_events
    ]

    # ── 11. AP link flaps ─────────────────────────────────────────────────
    report["ap_link_flaps"] = [
        {
            "ap":     ap,
            "count":  len(evs),
            "events": [{"ts": ts_str(e["ts"]), "event": e["event"]} for e in evs],
        }
        for ap, evs in az.ap_link_events.items()
        if evs
    ]

    # ── 12. Multi-SSID clients ────────────────────────────────────────────
    report["multi_ssid_clients"] = sorted(
        [
            {"mac": mac, "ssid_count": len(ssids), "ssids": sorted(ssids)}
            for mac, ssids in az.client_ssids.items()
            if len(ssids) > 1
        ],
        key=lambda x: x["ssid_count"], reverse=True
    )

    # ── 13. Unclosed sessions ─────────────────────────────────────────────
    report["unclosed_sessions"] = [
        {
            "mac":             mac,
            "last_assoc_ap":   ev["ap"],
            "last_assoc_ts":   ts_str(ev["ts"]),
            "last_assoc_ssid": ev["ssid"],
        }
        for mac, ev in az._pending_assoc.items()
    ]

    return report


# ---------------------------------------------------------------------------
# HUMAN-READABLE TEXT REPORT
# ---------------------------------------------------------------------------

def print_report(report, az):
    ov = report["overview"]

    def section(title):
        s = f"\n{'─'*72}\n  {title}\n{'─'*72}"
        try:
            sys.stdout.buffer.write(s.encode('utf-8', errors='replace'))
        except Exception:
            print(s.replace('─', '-'))

    try:
        sys.stdout.buffer.write(("\n" + "═"*72 + "\n").encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(("  WIRELESS SNMP TRAP ANALYSIS\n").encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(("═"*72 + "\n").encode("utf-8", errors="replace"))
    except Exception:
        # fallback to ASCII-only rendering when buffer isn't available
        print("\n" + "="*72)
        print("  WIRELESS SNMP TRAP ANALYSIS")
        print("="*72)
        content = (f"""
    Trap blocks parsed             : {ov['total_trap_blocks']}
    Unique client MACs             : {ov['unique_client_macs']}
    Unique access points           : {ov['unique_aps']}
    Unique SSIDs                   : {ov['unique_ssids']}
    Completed (paired) sessions    : {ov['completed_sessions_paired']}
    Total auth failures            : {ov['total_auth_failures']}
    Clients with auth failures     : {ov['clients_with_auth_failures']}
    Clients failed, never authed   : {ov['clients_failed_never_succeeded']}
    Roam transitions               : {ov['total_roam_transitions']}
    Rogue events                   : {ov['rogue_events']}
    Off-hours events               : {ov['off_hours_events']}
    Deauth burst windows (≥3/60s)  : {ov['deauth_windows_detected']}
    Business hours configured      : {ov['business_hours']}""")
        try:
                sys.stdout.buffer.write(content.encode("utf-8", errors="replace"))
        except Exception:
                # fallback to normal print if buffer not available
                print(content)

    section("ACCESS POINTS")
    print(f"  {'AP':<30} {'Clients':>7} {'1-time':>6} {'Repeat':>6} "
          f"{'Sessions':>9} {'Deauths':>8} {'Disassocs':>9} {'AuthFail':>9} {'PeakHr':>7}")
    print(f"  {'─'*30} {'─'*7} {'─'*6} {'─'*6} {'─'*9} {'─'*8} {'─'*9} {'─'*9} {'─'*7}")
    for ap in report["ap_summary"]:
        ph = f"{ap['peak_hour']:02d}:xx" if ap['peak_hour'] is not None else "  N/A"
        print(f"  {ap['ap']:<30} {ap['unique_clients']:>7} {ap['one_time_visitors']:>6} "
              f"{ap['repeat_visitors']:>6} {ap['total_sessions']:>9} {ap['deauths']:>8} "
              f"{ap['disassocs']:>9} {ap['auth_failures']:>9} {ph:>7}")

    section("SSID BREAKDOWN")
    print(f"  {'SSID':<35} {'Clients':>7} {'APs':>4} {'Sessions':>9} "
          f"{'AuthFail':>9} {'Single-AP':>10}")
    print(f"  {'─'*35} {'─'*7} {'─'*4} {'─'*9} {'─'*9} {'─'*10}")
    for s in report["ssid_analysis"]:
        print(f"  {s['ssid']:<35} {s['unique_clients']:>7} {s['aps_broadcasting']:>4} "
              f"{s['total_sessions']:>9} {s['auth_failures']:>9} "
              f"{str(s['single_ap_only']):>10}")

    section("CLIENT SESSIONS (top 20 by session count)")
    print(f"  {'MAC':<20} {'Sess':>5} {'TotTime':>10} {'Avg':>9} {'Min':>7} "
          f"{'Max':>7} {'<30s':>5} {'<5s':>4} {'Roams':>6} {'AuthF':>6} {'OffHr':>6}")
    print(f"  {'─'*20} {'─'*5} {'─'*10} {'─'*9} {'─'*7} {'─'*7} "
          f"{'─'*5} {'─'*4} {'─'*6} {'─'*6} {'─'*6}")
    for c in report["clients"][:20]:
        print(f"  {c['mac']:<20} {c['completed_sessions']:>5} "
              f"{(c['total_connected_human'] or 'N/A'):>10} "
              f"{(c['avg_session_human'] or 'N/A'):>9} "
              f"{hms(c['min_session_sec']):>7} "
              f"{hms(c['max_session_sec']):>7} "
              f"{c['sessions_under_30s']:>5} "
              f"{c['sessions_under_5s']:>4} "
              f"{c['roam_count']:>6} "
              f"{c['auth_failures']:>6} "
              f"{c['off_hours_sessions']:>6}")

    section("AUTH FAILURE ANALYSIS")
    print("  By client (top 15):")
    for row in report["auth_failure_analysis"]["per_client"][:15]:
        never = "  [never succeeded]" if row["successes"] == 0 else ""
        print(f"    {row['mac']:<20}  {row['failures']:>4} failures  "
              f"{row['successes']:>4} successes{never}")
    print("\n  By AP (top 10):")
    for row in report["auth_failure_analysis"]["per_ap"][:10]:
        print(f"    {row['ap']:<30}  {row['failures']:>4} failures")
    print("\n  By SSID:")
    for row in report["auth_failure_analysis"]["per_ssid"]:
        print(f"    {row['ssid']:<35}  {row['failures']:>4} failures")

    section("DEAUTH / DISASSOC BURST WINDOWS (every window with ≥3 events in 60 s)")
    if report["deauth_windows"]:
        print(f"  {'AP':<30} {'Window start':<24} {'Count':>6} {'Duration':>10}")
        print(f"  {'─'*30} {'─'*24} {'─'*6} {'─'*10}")
        for w in report["deauth_windows"][:30]:
            print(f"  {w['ap']:<30} {str(w['window_start']):<24} "
                  f"{w['count_in_60s']:>6} {hms(w['duration_sec']):>10}")
    else:
        print("  None detected.")

    section("ROAMING")
    rm = report["roaming_analysis"]
    print(f"  Total transitions   : {rm['total_roam_transitions']}")
    print(f"  Clients that roamed : {rm['clients_that_roamed']}")
    print("\n  Top roamers:")
    for r in rm["top_roamers"][:10]:
        print(f"    {r['mac']:<20}  {r['roam_count']:>3} roams  APs: {r['aps_visited']}")
    print("\n  Most common AP-to-AP transitions:")
    for t in rm["most_common_ap_transitions"][:10]:
        print(f"    {t['from_ap']}  →  {t['to_ap']}  ({t['count']}×)")

    section("TEMPORAL PATTERN — events per hour")
    hours = report["temporal_analysis"]["events_by_hour"]
    max_count = max(hours.values()) if hours else 1
    for h in range(24):
        cnt = hours.get(str(h), 0)
        bar = "█" * int(40 * cnt / max_count) if max_count else ""
        tag = "  [off-hours]" if not (az.business_start <= h < az.business_end) else ""
        print(f"  {h:02d}:xx  {cnt:>5}  {bar}{tag}")

    section("TEMPORAL PATTERN — events by weekday")
    for day, cnt in report["temporal_analysis"]["events_by_weekday"].items():
        print(f"  {day:<10}  {cnt:>6}")

    section("TOP 5-MINUTE BURST WINDOWS")
    for bw in report["temporal_analysis"]["top_5min_burst_windows"][:10]:
        print(f"  {bw['window']}   {bw['event_count']:>5} events")

    section("OFF-HOURS ACTIVITY")
    oh = report["off_hours_activity"]
    print(f"  Total events   : {oh['total_off_hours_events']}")
    print(f"  Unique devices : {oh['unique_devices']}")
    print("\n  Per-device:")
    for d in oh["per_device"][:20]:
        print(f"    {d['mac']:<20}  {d['event_count']:>4} events  "
              f"hours: {d['hours_active']}  APs: {d['aps']}")

    section("CLIENTS ON MULTIPLE SSIDs")
    if report["multi_ssid_clients"]:
        for c in report["multi_ssid_clients"][:20]:
            print(f"  {c['mac']:<20}  {c['ssid_count']} SSIDs: {c['ssids']}")
    else:
        print("  None.")

    section("UNCLOSED SESSIONS (assoc seen, no disconnect in log)")
    if report["unclosed_sessions"]:
        for u in report["unclosed_sessions"][:20]:
            print(f"  {u['mac']:<20}  assoc @ {u['last_assoc_ts']}  "
                  f"AP: {u['last_assoc_ap']}  SSID: {u['last_assoc_ssid']}")
    else:
        print("  None.")

    section("ROGUE EVENTS")
    if report["rogue_events"]:
        for e in report["rogue_events"]:
            print(f"  {e['ts']}  {e['event_type']:<25}  MAC: {e['mac']}  AP: {e['ap']}")
    else:
        print("  None in this log.")

    section("AP LINK FLAPS")
    if report["ap_link_flaps"]:
        for f in report["ap_link_flaps"]:
            print(f"  {f['ap']:<30}  {f['count']} flap events")
    else:
        print("  None detected.")

    try:
        sys.stdout.buffer.write(("\n" + "═"*72 + "\n").encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(("  End of report.\n").encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(("═"*72 + "\n\n").encode("utf-8", errors="replace"))
    except Exception:
        print("\n" + "="*72)
        print("  End of report.")
        print("="*72 + "\n")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def serialize(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Not serializable: {type(obj)}")


# def main():
#     parser = argparse.ArgumentParser(description="Wireless SNMP trap analyzer")
#     parser.add_argument("--log",         required=True)
#     parser.add_argument("--out",         default="wireless_report.json")
#     parser.add_argument("--hours-start", type=int, default=8)
#     parser.add_argument("--hours-end",   type=int, default=20)
#     args = parser.parse_args()

#     print(f"\nLoading {args.log!r} ...")
#     log_text = Path(args.log).read_text(errors="ignore")

#     az = WirelessAnalyzer(args.hours_start, args.hours_end)
#     print("Analyzing ...")
#     az.ingest(log_text)

#     report = build_report(az)
#     print_report(report, az)

#     with open(args.out, "w") as f:
#         json.dump(report, f, indent=2, default=serialize)
#     print(f"JSON report → {args.out!r}")





def main():
    parser = argparse.ArgumentParser(description="Wireless SNMP trap analyzer")
    parser.add_argument("--log", required=True)
    parser.add_argument("--out", default="wireless_report.json")
    parser.add_argument("--txt-report", default="wireless_report.txt")
    parser.add_argument("--hours-start", type=int, default=8)
    parser.add_argument("--hours-end", type=int, default=20)
    args = parser.parse_args()

    log_text = Path(args.log).read_text(errors="ignore")

    az = WirelessAnalyzer(args.hours_start, args.hours_end)

    # Capture ALL console output into text report
    with open(args.txt_report, "w") as txt_out:
        with redirect_stdout(txt_out):

            print(f"\nLoading {args.log!r} ...")
            print("Analyzing ...")

            az.ingest(log_text)

            report = build_report(az)

            print_report(report, az)

            print("\nTop Trap OIDs:")
            for oid, count in trap_oid_counter.most_common(20):
                print(f"{oid} -> {count}")

            print("\nEnd of analysis.")

    # Save JSON separately
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2, default=serialize)

    print(f"Text report saved to: {args.txt_report}")
    print(f"JSON report saved to: {args.out}")


if __name__ == "__main__":
    main()
