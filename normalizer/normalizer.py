"""
AHRAS v4 — Log Normalizer
Converts logs from any source (Windows, Linux, Apache, Syslog, etc.)
into a single unified schema so every downstream module sees the same fields.

Unified Schema (all fields optional unless marked *required*):
─────────────────────────────────────────────────────────────
  timestamp*      ISO-8601 string          "2024-01-15T10:23:00Z"
  event_type*     string                   "failed_login" | "process_created" | ...
  src_ip          string                   source IP address
  dst_ip          string                   destination IP address
  src_port        int
  dst_port        int
  username        string
  hostname        string
  process_name    string
  command_line    string
  file_path       string
  url             string
  http_method     string
  http_status     int
  bytes_sent      int
  severity        string                   INFO | LOW | MEDIUM | HIGH | CRITICAL
  mitre_technique string                   T1078, T1110, ...
  tags            list[str]
  raw             string                   original log line
  source          string                   collector that produced it
  _normalizer_version  string

Event type mapping:
  Windows EventIDs  → event_type strings
  Linux auth lines  → event_type strings
  HTTP access       → event_type strings
"""

import re
import time
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

logger = logging.getLogger("ahras.normalizer")

NORMALIZER_VERSION = "1.0"

# ── MITRE technique hints per event type ─────────────────────────────────────
_MITRE_HINTS: Dict[str, str] = {
    "failed_login":            "T1110",   # Brute Force
    "ssh_failed_login":        "T1110",
    "successful_login":        "T1078",   # Valid Accounts
    "ssh_successful_login":    "T1078",
    "process_created":         "T1059",   # Command & Scripting Interpreter
    "sudo_command":            "T1548",   # Abuse Elevation Control
    "user_created":            "T1136",   # Create Account
    "user_deleted":            "T1531",   # Account Access Removal
    "service_installed":       "T1543",   # Create/Modify System Process
    "scheduled_task_created":  "T1053",   # Scheduled Task/Job
    "sql_injection_attempt":   "T1190",   # Exploit Public-Facing Application
    "path_traversal_attempt":  "T1083",   # File & Directory Discovery
    "remote_command_execution":"T1059",
    "scanner_known_path":      "T1595",   # Active Scanning
    "large_data_transfer":     "T1041",   # Exfiltration Over C2 Channel
    "privilege_assigned":      "T1134",   # Access Token Manipulation
}

# ── Severity ladder ───────────────────────────────────────────────────────────
_SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

def _max_severity(a: str, b: str) -> str:
    ia = _SEV_ORDER.index(a) if a in _SEV_ORDER else 0
    ib = _SEV_ORDER.index(b) if b in _SEV_ORDER else 0
    return _SEV_ORDER[max(ia, ib)]


# ── Timestamp normalisation ───────────────────────────────────────────────────
_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",   # Apache CLF
    "%b %d %H:%M:%S",         # syslog (no year)
    "%b  %d %H:%M:%S",        # syslog with single-digit day
]

def _normalise_ts(raw: Any) -> str:
    """Convert various timestamp formats to ISO-8601 UTC string."""
    if not raw:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(float(raw)/1000 if float(raw) > 1e10 else float(raw),
                                          tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass
    s = str(raw).strip()
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return s  # return as-is if nothing matched


# ── Field aliases per source ──────────────────────────────────────────────────
# Maps source-specific key → unified key
_WINDOWS_ALIASES = {
    "EventID":           "windows_event_id",
    "event_id":          "windows_event_id",
    "TargetUserName":    "username",
    "SubjectUserName":   "subject_user",
    "IpAddress":         "src_ip",
    "WorkstationName":   "hostname",
    "ProcessName":       "process_name",
    "CommandLine":       "command_line",
    "LogonType":         "logon_type",
    "Status":            "status_code",
    "ServiceName":       "service_name",
    "TaskName":          "task_name",
    "NewProcessName":    "process_name",
    "ObjectName":        "file_path",
}

_LINUX_ALIASES = {
    "process":      "process_name",
    "message":      "_raw_message",
    "unit":         "service_name",
    "addr":         "src_ip",
}

_HTTP_ALIASES = {
    "method":       "http_method",
    "path":         "url",
    "status_code":  "http_status",
    "status":       "http_status",
    "ua":           "user_agent",
}

_WINDOWS_EID_TO_EVENT_TYPE = {
    4624: "successful_login",
    4625: "failed_login",
    4627: "group_membership_change",
    4634: "logoff",
    4648: "explicit_credential_login",
    4672: "privilege_assigned",
    4688: "process_created",
    4689: "process_exited",
    4698: "scheduled_task_created",
    4720: "user_created",
    4726: "user_deleted",
    4740: "account_locked",
    4756: "group_member_added",
    4771: "kerberos_preauth_failed",
    4776: "ntlm_auth_attempt",
    5140: "network_share_accessed",
    7045: "service_installed",
}


class LogNormalizer:
    """
    Converts any raw log dict into the AHRAS unified schema.
    Works with Windows, Linux, Apache, and generic JSON logs.
    """

    def __init__(self):
        self._stats = {"total": 0, "windows": 0, "linux": 0, "http": 0, "generic": 0}
        logger.info("LogNormalizer ready")

    def normalise(self, raw: Dict) -> Dict:
        """
        Main entry point. Auto-detects source and returns unified event dict.
        """
        source = str(raw.get("source", "")).lower()

        if "windows" in source or "event_id" in raw or "windows_event_id" in raw:
            normalised = self._normalise_windows(raw)
        elif "linux" in source or "journald" in source or "audit" in source:
            normalised = self._normalise_linux(raw)
        elif "apache" in source or "nginx" in source or "http_access" in str(raw.get("event_type", "")):
            normalised = self._normalise_http(raw)
        else:
            normalised = self._normalise_generic(raw)

        # Common post-processing
        normalised["timestamp"]           = _normalise_ts(normalised.get("timestamp"))
        normalised["_normalizer_version"] = NORMALIZER_VERSION
        normalised.setdefault("severity", "INFO")
        normalised.setdefault("tags", [])
        normalised.setdefault("source", raw.get("source", "unknown"))
        normalised.setdefault("raw", raw.get("raw", ""))

        # Auto-assign MITRE hint if not already set
        if not normalised.get("mitre_technique"):
            et = normalised.get("event_type", "")
            hint = _MITRE_HINTS.get(et, "")
            # Also check individual threats list (HTTP)
            for threat in normalised.get("tags", []):
                hint = hint or _MITRE_HINTS.get(threat, "")
            if hint:
                normalised["mitre_technique"] = hint

        self._stats["total"] += 1
        return normalised

    def normalise_batch(self, records: List[Dict]) -> List[Dict]:
        return [self.normalise(r) for r in records]

    def stats(self) -> Dict:
        return dict(self._stats)

    # ── Source-specific normalisers ───────────────────────────────────────

    def _normalise_windows(self, raw: Dict) -> Dict:
        self._stats["windows"] += 1
        out: Dict = {}

        # Apply field aliases
        for k, v in raw.items():
            mapped = _WINDOWS_ALIASES.get(k, k)
            out[mapped] = v

        # Derive event_type from EventID
        eid = raw.get("event_id") or raw.get("EventID") or raw.get("windows_event_id")
        if eid:
            try:
                eid_int = int(eid)
                out["windows_event_id"] = eid_int
                out["event_type"] = _WINDOWS_EID_TO_EVENT_TYPE.get(eid_int, f"windows_event_{eid_int}")
            except (ValueError, TypeError):
                out.setdefault("event_type", "windows_event_unknown")
        else:
            out.setdefault("event_type", raw.get("event_type", "windows_generic"))

        # Severity mapping
        sev_map = {
            "failed_login": "MEDIUM", "account_locked": "HIGH",
            "privilege_assigned": "HIGH", "service_installed": "HIGH",
            "user_created": "HIGH", "user_deleted": "HIGH",
            "scheduled_task_created": "MEDIUM", "process_created": "LOW",
            "successful_login": "INFO",
        }
        out["severity"] = sev_map.get(out.get("event_type", ""), raw.get("severity", "INFO"))
        out["os"] = "windows"
        return out

    def _normalise_linux(self, raw: Dict) -> Dict:
        self._stats["linux"] += 1
        out: Dict = {}

        for k, v in raw.items():
            mapped = _LINUX_ALIASES.get(k, k)
            out[mapped] = v

        # Absorb _raw_message into description
        rm = out.pop("_raw_message", None)
        if rm:
            out.setdefault("description", rm)

        out.setdefault("event_type", raw.get("event_type", "linux_generic"))
        out["os"] = "linux"
        return out

    def _normalise_http(self, raw: Dict) -> Dict:
        self._stats["http"] += 1
        out: Dict = {}

        for k, v in raw.items():
            mapped = _HTTP_ALIASES.get(k, k)
            out[mapped] = v

        # Move HTTP threats into tags
        threats = raw.get("threats", [])
        existing_tags = out.get("tags", [])
        out["tags"] = list(set(existing_tags + threats))

        # Derive event_type from threat or HTTP status
        if threats:
            out["event_type"] = threats[0]
        else:
            status = raw.get("status_code", raw.get("status", 0))
            try:
                sc = int(status)
                if sc >= 500:
                    out["event_type"] = "http_server_error"
                elif sc >= 400:
                    out["event_type"] = "http_client_error"
                else:
                    out["event_type"] = "http_access"
            except (ValueError, TypeError):
                out["event_type"] = "http_access"

        out["protocol"] = "HTTP"
        return out

    def _normalise_generic(self, raw: Dict) -> Dict:
        self._stats["generic"] += 1
        out = dict(raw)
        out.setdefault("event_type", "generic_log")
        return out

    # ── Convenience: normalise from collector output ──────────────────────

    @staticmethod
    def describe_schema() -> Dict:
        """Return the unified schema definition for documentation/API use."""
        return {
            "required": ["timestamp", "event_type"],
            "fields": {
                "timestamp":          "ISO-8601 UTC string",
                "event_type":         "Normalised event classification",
                "src_ip":             "Source IP address",
                "dst_ip":             "Destination IP address",
                "src_port":           "Source port (int)",
                "dst_port":           "Destination port (int)",
                "username":           "Authenticated or target user",
                "hostname":           "Source hostname",
                "process_name":       "Process name or path",
                "command_line":       "Full command line",
                "file_path":          "File or object path",
                "url":                "HTTP request path or full URL",
                "http_method":        "GET | POST | PUT | ...",
                "http_status":        "HTTP response code (int)",
                "bytes_sent":         "Response size in bytes (int)",
                "severity":           "INFO | LOW | MEDIUM | HIGH | CRITICAL",
                "mitre_technique":    "MITRE ATT&CK technique ID",
                "tags":               "List of additional labels",
                "raw":                "Original log line",
                "source":             "Collector that produced this event",
                "_normalizer_version":"Normalizer version string",
                "os":                 "windows | linux | (unset for HTTP)",
            },
        }
