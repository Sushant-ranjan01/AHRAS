"""
AHRAS v4 — Windows Log Collector
Reads from the Windows Event Log (via the `winevt` or `win32evtlog` API on Windows)
and falls back to parsing exported EVTX text files on non-Windows environments.

Collects:
  - Security events (4624/4625 logins, 4688 process creation, 4672 privilege use)
  - System events (service installs, crashes)
  - Application events

Usage:
    collector = WindowsLogCollector()
    for event in collector.collect(channel="Security", max_events=200):
        print(event)
"""

import os
import re
import time
import json
import platform
import logging
from datetime import datetime
from typing import Iterator, Dict, Optional, List

logger = logging.getLogger("ahras.collectors.windows")

# Map EventID → human label
_EVENT_LABELS = {
    4624: "Successful Login",
    4625: "Failed Login",
    4627: "Group Membership",
    4634: "Logoff",
    4647: "User Initiated Logoff",
    4648: "Explicit Credential Login",
    4656: "Object Access Request",
    4663: "Object Access Attempt",
    4672: "Special Privilege Assigned",
    4688: "Process Created",
    4689: "Process Exited",
    4698: "Scheduled Task Created",
    4702: "Scheduled Task Modified",
    4720: "User Account Created",
    4726: "User Account Deleted",
    4740: "User Account Locked",
    4756: "Member Added to Group",
    4768: "Kerberos TGT Request",
    4769: "Kerberos Service Ticket",
    4771: "Kerberos Pre-Auth Failed",
    4776: "NTLM Auth Attempt",
    5140: "Network Share Access",
    7045: "Service Installed",
}

# Normalised field names
_FIELD_MAP = {
    "TargetUserName":     "username",
    "SubjectUserName":    "subject_user",
    "IpAddress":          "src_ip",
    "WorkstationName":    "workstation",
    "ProcessName":        "process_name",
    "CommandLine":        "command_line",
    "LogonType":          "logon_type",
    "Status":             "status_code",
    "SubStatus":          "sub_status",
    "ServiceName":        "service_name",
    "TaskName":           "task_name",
    "NewProcessName":     "new_process",
    "ObjectName":         "object_name",
    "ShareName":          "share_name",
}


def _ts_now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_evtx_line(line: str) -> Optional[Dict]:
    """Parse a line from a text-exported EVTX file. Best-effort."""
    try:
        m = re.search(r"EventID[:\s]+(\d+)", line)
        if not m:
            return None
        eid = int(m.group(1))
        event: Dict = {
            "event_id":    eid,
            "event_label": _EVENT_LABELS.get(eid, f"Event {eid}"),
            "timestamp":   _ts_now(),
            "channel":     "Security",
            "source":      "windows_collector",
            "raw":         line.strip(),
        }
        for xml_key, norm_key in _FIELD_MAP.items():
            fm = re.search(rf"{xml_key}[:\s>]+([^\s<\n]+)", line)
            if fm:
                event[norm_key] = fm.group(1).strip("-").strip()
        return event
    except Exception:
        return None


class WindowsLogCollector:
    """
    Collects Windows security events.
    On Windows: uses win32evtlog / winevt.
    On Linux/macOS: reads exported EVTX text log files placed in `log_dir`.
    """

    CHANNELS = ["Security", "System", "Application", "Microsoft-Windows-Sysmon/Operational"]

    def __init__(self, log_dir: str = "logs/windows"):
        self._log_dir = log_dir
        self._is_windows = platform.system() == "Windows"
        os.makedirs(log_dir, exist_ok=True)
        logger.info(f"WindowsLogCollector init | windows={self._is_windows} | log_dir={log_dir}")

    def collect(self, channel: str = "Security", max_events: int = 500) -> Iterator[Dict]:
        """Yield normalised event dicts from the specified channel."""
        if self._is_windows:
            yield from self._collect_live(channel, max_events)
        else:
            yield from self._collect_from_files(channel, max_events)

    def collect_failed_logins(self, max_events: int = 200) -> List[Dict]:
        return [e for e in self.collect("Security", max_events) if e.get("event_id") == 4625]

    def collect_process_creations(self, max_events: int = 200) -> List[Dict]:
        return [e for e in self.collect("Security", max_events) if e.get("event_id") == 4688]

    def collect_privilege_use(self, max_events: int = 200) -> List[Dict]:
        return [e for e in self.collect("Security", max_events) if e.get("event_id") == 4672]

    def collect_service_installs(self, max_events: int = 200) -> List[Dict]:
        return [e for e in self.collect("System", max_events) if e.get("event_id") == 7045]

    # ── Live collection (Windows only) ──────────────────────────────────────

    def _collect_live(self, channel: str, max_events: int) -> Iterator[Dict]:
        try:
            import win32evtlog  # type: ignore
            import win32evtlogutil  # type: ignore
            import pywintypes  # type: ignore

            hand = win32evtlog.OpenEventLog(None, channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            count = 0
            while count < max_events:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                for ev in events:
                    if count >= max_events:
                        break
                    eid = ev.EventID & 0xFFFF
                    record: Dict = {
                        "event_id":      eid,
                        "event_label":   _EVENT_LABELS.get(eid, f"Event {eid}"),
                        "timestamp":     ev.TimeGenerated.Format(),
                        "channel":       channel,
                        "source":        str(ev.SourceName),
                        "computer":      str(ev.ComputerName),
                        "strings":       list(ev.StringInserts or []),
                        "source":        "windows_collector",
                    }
                    yield record
                    count += 1
            win32evtlog.CloseEventLog(hand)
        except ImportError:
            logger.warning("win32evtlog not available — switch to file-based collection")
            yield from self._collect_from_files(channel, max_events)
        except Exception as e:
            logger.error(f"Live collection error: {e}")

    # ── File-based collection (cross-platform) ───────────────────────────────

    def _collect_from_files(self, channel: str, max_events: int) -> Iterator[Dict]:
        safe_channel = channel.replace("/", "_").replace("\\", "_")
        patterns = [
            os.path.join(self._log_dir, f"{safe_channel}.log"),
            os.path.join(self._log_dir, f"{safe_channel}.txt"),
            os.path.join(self._log_dir, "*.log"),
        ]
        found_any = False
        for pattern in patterns:
            import glob
            for path in glob.glob(pattern):
                found_any = True
                yield from self._read_log_file(path, max_events)
                return

        if not found_any:
            logger.info(f"No log files found in {self._log_dir} for channel '{channel}'. "
                        f"Place exported .log or .txt files there for parsing.")

    def _read_log_file(self, path: str, max_events: int) -> Iterator[Dict]:
        count = 0
        try:
            with open(path, "r", errors="replace") as f:
                for line in f:
                    if count >= max_events:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    # Try JSON first
                    try:
                        record = json.loads(line)
                        record.setdefault("source", "windows_collector")
                        record.setdefault("timestamp", _ts_now())
                        yield record
                        count += 1
                        continue
                    except json.JSONDecodeError:
                        pass
                    # Fall back to regex parsing
                    parsed = _parse_evtx_line(line)
                    if parsed:
                        yield parsed
                        count += 1
        except Exception as e:
            logger.error(f"Failed reading {path}: {e}")
