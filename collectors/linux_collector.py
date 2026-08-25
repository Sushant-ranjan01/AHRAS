"""
AHRAS v4 — Linux Log Collector
Reads from standard Linux log files:
  - /var/log/auth.log        (SSH, sudo, PAM authentication)
  - /var/log/syslog          (kernel, daemons)
  - /var/log/messages        (RHEL/CentOS equivalent of syslog)
  - /var/log/kern.log        (kernel messages)
  - /var/log/secure          (RHEL/CentOS auth)
  - Systemd journal (via journalctl subprocess)

Usage:
    collector = LinuxLogCollector()
    for event in collector.collect_auth(max_lines=500):
        print(event)
"""

import os
import re
import json
import time
import subprocess
import logging
from datetime import datetime
from typing import Iterator, Dict, Optional, List

logger = logging.getLogger("ahras.collectors.linux")

# Common Linux log file paths
AUTH_LOGS    = ["/var/log/auth.log", "/var/log/secure"]
SYSLOG_PATHS = ["/var/log/syslog", "/var/log/messages"]
KERN_PATHS   = ["/var/log/kern.log"]
AUDIT_PATHS  = ["/var/log/audit/audit.log"]

# Regex patterns for auth.log
_PAT_SSH_FAIL    = re.compile(r"Failed (\w+) for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)")
_PAT_SSH_OK      = re.compile(r"Accepted (\w+) for (\S+) from ([\d.]+) port (\d+)")
_PAT_SUDO        = re.compile(r"sudo:\s+(\S+)\s+: TTY=(\S+).*COMMAND=(.+)")
_PAT_USERADD     = re.compile(r"useradd.*name=(\S+)")
_PAT_USERDEL     = re.compile(r"userdel.*name=(\S+)")
_PAT_SU          = re.compile(r"su[:\s]+\(to (\S+)\) (\S+)")
_PAT_SYSLOG_HDR  = re.compile(
    r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)"
)


def _ts_now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_syslog_line(line: str) -> Optional[Dict]:
    """Parse a standard syslog-format line into a normalised event dict."""
    m = _PAT_SYSLOG_HDR.match(line)
    if not m:
        return None
    ts_raw, host, process, pid, message = m.groups()
    event: Dict = {
        "timestamp":    ts_raw,
        "hostname":     host,
        "process":      process,
        "pid":          int(pid) if pid else None,
        "message":      message.strip(),
        "raw":          line.strip(),
        "source":       "linux_collector",
        "event_type":   "generic",
    }
    _enrich_auth(event, message)
    return event


def _enrich_auth(event: Dict, message: str):
    """Detect specific auth events and add structured fields."""
    m = _PAT_SSH_FAIL.search(message)
    if m:
        event.update({
            "event_type": "ssh_failed_login",
            "auth_method": m.group(1),
            "username": m.group(2),
            "src_ip": m.group(3),
            "src_port": int(m.group(4)),
            "severity": "MEDIUM",
        })
        return

    m = _PAT_SSH_OK.search(message)
    if m:
        event.update({
            "event_type": "ssh_successful_login",
            "auth_method": m.group(1),
            "username": m.group(2),
            "src_ip": m.group(3),
            "src_port": int(m.group(4)),
            "severity": "INFO",
        })
        return

    m = _PAT_SUDO.search(message)
    if m:
        event.update({
            "event_type": "sudo_command",
            "username": m.group(1),
            "tty": m.group(2),
            "command": m.group(3).strip(),
            "severity": "LOW",
        })
        return

    m = _PAT_USERADD.search(message)
    if m:
        event.update({
            "event_type": "user_created",
            "username": m.group(1),
            "severity": "HIGH",
        })
        return

    m = _PAT_USERDEL.search(message)
    if m:
        event.update({
            "event_type": "user_deleted",
            "username": m.group(1),
            "severity": "HIGH",
        })
        return

    m = _PAT_SU.search(message)
    if m:
        event.update({
            "event_type": "su_attempt",
            "target_user": m.group(1),
            "from_user": m.group(2),
            "severity": "MEDIUM",
        })


class LinuxLogCollector:
    """
    Reads Linux system logs from disk (or journalctl) and yields
    normalised event dicts suitable for the AHRAS normalizer.
    """

    def __init__(self, log_dir: str = None):
        """
        log_dir: override base directory for log files
                 (useful for testing — point to a folder with sample logs)
        """
        self._log_dir = log_dir
        logger.info(f"LinuxLogCollector init | log_dir={log_dir or 'system defaults'}")

    def _resolve_path(self, candidates: List[str]) -> Optional[str]:
        """Return the first readable file from a list of candidate paths."""
        for p in candidates:
            if self._log_dir:
                override = os.path.join(self._log_dir, os.path.basename(p))
                if os.path.isfile(override) and os.access(override, os.R_OK):
                    return override
            if os.path.isfile(p) and os.access(p, os.R_OK):
                return p
        return None

    # ── Public collection methods ─────────────────────────────────────────

    def collect_auth(self, max_lines: int = 1000) -> Iterator[Dict]:
        """Yield authentication events from auth.log / secure."""
        path = self._resolve_path(AUTH_LOGS)
        if path:
            yield from self._tail_file(path, max_lines)
        else:
            logger.info("No auth log found — trying journalctl")
            yield from self._journalctl(unit="ssh", max_lines=max_lines)

    def collect_syslog(self, max_lines: int = 1000) -> Iterator[Dict]:
        """Yield general syslog events."""
        path = self._resolve_path(SYSLOG_PATHS)
        if path:
            yield from self._tail_file(path, max_lines)
        else:
            logger.info("No syslog found — trying journalctl")
            yield from self._journalctl(max_lines=max_lines)

    def collect_kernel(self, max_lines: int = 500) -> Iterator[Dict]:
        """Yield kernel events."""
        path = self._resolve_path(KERN_PATHS)
        if path:
            yield from self._tail_file(path, max_lines)

    def collect_audit(self, max_lines: int = 500) -> Iterator[Dict]:
        """Yield auditd events."""
        path = self._resolve_path(AUDIT_PATHS)
        if path:
            yield from self._read_audit_log(path, max_lines)
        else:
            logger.info("auditd log not found or not readable")

    def collect_failed_logins(self, max_lines: int = 1000) -> List[Dict]:
        return [e for e in self.collect_auth(max_lines) if e.get("event_type") == "ssh_failed_login"]

    def collect_successful_logins(self, max_lines: int = 1000) -> List[Dict]:
        return [e for e in self.collect_auth(max_lines) if e.get("event_type") == "ssh_successful_login"]

    def collect_sudo_events(self, max_lines: int = 1000) -> List[Dict]:
        return [e for e in self.collect_auth(max_lines) if e.get("event_type") == "sudo_command"]

    # ── Internal readers ──────────────────────────────────────────────────

    def _tail_file(self, path: str, max_lines: int) -> Iterator[Dict]:
        """Read the last max_lines lines from a log file and parse them."""
        logger.info(f"Reading {path} (last {max_lines} lines)")
        try:
            result = subprocess.run(
                ["tail", "-n", str(max_lines), path],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.splitlines()
        except (FileNotFoundError, subprocess.SubprocessError):
            try:
                with open(path, "r", errors="replace") as f:
                    lines = f.readlines()[-max_lines:]
            except Exception as e:
                logger.error(f"Cannot read {path}: {e}")
                return

        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Try JSON (pre-structured logs)
            try:
                rec = json.loads(line)
                rec.setdefault("source", "linux_collector")
                rec.setdefault("timestamp", _ts_now())
                yield rec
                continue
            except json.JSONDecodeError:
                pass
            parsed = _parse_syslog_line(line)
            if parsed:
                yield parsed

    def _journalctl(self, unit: str = None, max_lines: int = 500) -> Iterator[Dict]:
        """Collect events from systemd journal."""
        cmd = ["journalctl", "-n", str(max_lines), "--no-pager", "-o", "json"]
        if unit:
            cmd += ["-u", unit]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    event = {
                        "timestamp":  raw.get("__REALTIME_TIMESTAMP", _ts_now()),
                        "hostname":   raw.get("_HOSTNAME", ""),
                        "process":    raw.get("_COMM", ""),
                        "pid":        raw.get("_PID"),
                        "message":    raw.get("MESSAGE", ""),
                        "unit":       raw.get("_SYSTEMD_UNIT", ""),
                        "source":     "linux_collector",
                        "event_type": "journald",
                    }
                    _enrich_auth(event, event["message"])
                    yield event
                except json.JSONDecodeError:
                    pass
        except FileNotFoundError:
            logger.warning("journalctl not available")
        except Exception as e:
            logger.error(f"journalctl error: {e}")

    def _read_audit_log(self, path: str, max_lines: int) -> Iterator[Dict]:
        """Parse auditd log format."""
        try:
            with open(path, "r", errors="replace") as f:
                lines = f.readlines()[-max_lines:]
        except Exception as e:
            logger.error(f"Cannot read audit log {path}: {e}")
            return

        for line in lines:
            line = line.strip()
            if not line:
                continue
            event: Dict = {"raw": line, "source": "linux_collector", "event_type": "audit"}
            # Extract key=value pairs
            for kv in re.finditer(r'(\w+)=("([^"]+)"|(\S+))', line):
                k = kv.group(1)
                v = kv.group(3) or kv.group(4)
                event[k.lower()] = v

            # Map common audit fields
            if "type" in event:
                event["event_type"] = f"audit_{event['type'].lower()}"
            if "addr" in event:
                event["src_ip"] = event["addr"]
            event.setdefault("timestamp", _ts_now())
            yield event
