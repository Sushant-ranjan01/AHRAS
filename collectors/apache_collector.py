"""
AHRAS v4 — Apache / Nginx Log Collector
Reads Combined Log Format (CLF) and JSON access/error logs from:
  - Apache httpd  (/var/log/apache2/, /var/log/httpd/)
  - Nginx         (/var/log/nginx/)
  - Custom path supplied at init time

Detects suspicious patterns:
  - Scanner / directory brute-force (40x floods)
  - SQL injection signatures in URL
  - Path traversal attempts (../  etc.)
  - Common exploit paths (wp-login, phpmyadmin, .env, etc.)
  - Abnormally large response sizes (data exfil hint)
"""

import os
import re
import json
import glob
import time
import logging
from datetime import datetime
from typing import Iterator, Dict, Optional, List

logger = logging.getLogger("ahras.collectors.apache")

# Default candidate paths
APACHE_ACCESS = [
    "/var/log/apache2/access.log",
    "/var/log/httpd/access_log",
    "/var/log/apache2/access.log.1",
]
APACHE_ERROR = [
    "/var/log/apache2/error.log",
    "/var/log/httpd/error_log",
]
NGINX_ACCESS = [
    "/var/log/nginx/access.log",
    "/var/log/nginx/access.log.1",
]
NGINX_ERROR = [
    "/var/log/nginx/error.log",
]

# Combined Log Format regex
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref" "Mozilla..."
_CLF_RE = re.compile(
    r'(?P<ip>[\d.:a-fA-F]+)\s+'       # client IP
    r'\S+\s+\S+\s+'                    # ident, auth
    r'\[(?P<time>[^\]]+)\]\s+'         # [time]
    r'"(?P<method>\S+)?\s*'            # method
    r'(?P<path>\S+)?\s*'               # path
    r'(?:HTTP/[\d.]+)?"\s+'            # protocol
    r'(?P<status>\d{3})\s+'            # status
    r'(?P<bytes>\d+|-)'                # bytes
    r'(?:\s+"(?P<referer>[^"]*)")?' 
    r'(?:\s+"(?P<ua>[^"]*)")?'
)

# Suspicious URL patterns
_SQLI_RE   = re.compile(r"(union\s+select|or\s+1=1|drop\s+table|xp_cmdshell|exec\s*\()", re.I)
_TRAV_RE   = re.compile(r"\.\./|\.\.\\|%2e%2e%2f|%252e", re.I)
_SHELL_RE  = re.compile(r"(cmd\.exe|/bin/sh|/bin/bash|wget\s|curl\s)", re.I)
_SCAN_PATHS = re.compile(
    r"(wp-login|wp-admin|phpmyadmin|\.env|\.git/|admin/config|"
    r"\.htaccess|autodiscover\.xml|xmlrpc\.php|eval-stdin|"
    r"shell\.php|c99\.php|r57\.php)", re.I
)


def _ts_now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _classify_threat(path: str, status: int, bytes_sent: int) -> Dict:
    threats = []
    severity = "INFO"

    if _SQLI_RE.search(path):
        threats.append("sql_injection_attempt")
        severity = "HIGH"
    if _TRAV_RE.search(path):
        threats.append("path_traversal_attempt")
        severity = "HIGH"
    if _SHELL_RE.search(path):
        threats.append("remote_command_execution")
        severity = "CRITICAL"
    if _SCAN_PATHS.search(path):
        threats.append("scanner_known_path")
        severity = "MEDIUM"
    if status == 200 and bytes_sent > 5_000_000:
        threats.append("large_data_transfer")
        severity = "MEDIUM"
    if status in (401, 403):
        threats.append("access_denied")

    return {"threats": threats, "severity": severity if threats else "INFO"}


def _parse_clf_line(line: str) -> Optional[Dict]:
    m = _CLF_RE.match(line.strip())
    if not m:
        return None
    path    = m.group("path") or "/"
    status  = int(m.group("status") or 0)
    raw_bytes = m.group("bytes") or "-"
    byte_count = int(raw_bytes) if raw_bytes != "-" else 0

    threat_info = _classify_threat(path, status, byte_count)

    return {
        "src_ip":      m.group("ip"),
        "timestamp":   m.group("time"),
        "method":      m.group("method") or "UNKNOWN",
        "path":        path,
        "status_code": status,
        "bytes_sent":  byte_count,
        "referer":     m.group("referer") or "",
        "user_agent":  m.group("ua") or "",
        "event_type":  "http_access",
        "source":      "apache_collector",
        **threat_info,
        "raw":         line.strip(),
    }


class ApacheLogCollector:
    """
    Collects and parses Apache/Nginx access and error logs.
    Works with Combined Log Format and JSON log format.
    """

    def __init__(self, log_dir: str = None, server: str = "apache"):
        """
        log_dir : override directory (point to sample logs for testing)
        server  : "apache" | "nginx"
        """
        self._log_dir = log_dir
        self._server  = server.lower()
        logger.info(f"ApacheLogCollector init | server={self._server} | log_dir={log_dir or 'system'}")

    def _resolve(self, candidates: List[str]) -> Optional[str]:
        for p in candidates:
            if self._log_dir:
                alt = os.path.join(self._log_dir, os.path.basename(p))
                if os.path.isfile(alt):
                    return alt
            if os.path.isfile(p) and os.access(p, os.R_OK):
                return p
        return None

    # ── Public API ────────────────────────────────────────────────────────

    def collect_access(self, max_lines: int = 2000) -> Iterator[Dict]:
        """Yield normalised HTTP access log events."""
        candidates = NGINX_ACCESS if self._server == "nginx" else APACHE_ACCESS
        if self._log_dir:
            for f in glob.glob(os.path.join(self._log_dir, "*.log")):
                yield from self._read_file(f, max_lines)
            return
        path = self._resolve(candidates)
        if path:
            yield from self._read_file(path, max_lines)
        else:
            logger.info(f"No {self._server} access log found")

    def collect_error(self, max_lines: int = 500) -> Iterator[Dict]:
        """Yield error log events."""
        candidates = NGINX_ERROR if self._server == "nginx" else APACHE_ERROR
        path = self._resolve(candidates)
        if path:
            yield from self._read_error_file(path, max_lines)
        else:
            logger.info(f"No {self._server} error log found")

    def collect_threats(self, max_lines: int = 2000) -> List[Dict]:
        """Return only events that have detected threats."""
        return [e for e in self.collect_access(max_lines) if e.get("threats")]

    def collect_scanners(self, max_lines: int = 2000) -> List[Dict]:
        """Return IPs with 3+ 404 responses (directory scanner heuristic)."""
        from collections import defaultdict
        ip_404: Dict[str, int] = defaultdict(int)
        events = list(self.collect_access(max_lines))
        for e in events:
            if e.get("status_code") == 404:
                ip_404[e.get("src_ip", "")] += 1
        scanner_ips = {ip for ip, cnt in ip_404.items() if cnt >= 3}
        return [e for e in events if e.get("src_ip") in scanner_ips]

    def get_top_ips(self, max_lines: int = 2000, top_n: int = 20) -> List[Dict]:
        from collections import Counter
        ips = [e.get("src_ip", "") for e in self.collect_access(max_lines)]
        return [{"ip": ip, "requests": cnt} for ip, cnt in Counter(ips).most_common(top_n)]

    # ── File readers ──────────────────────────────────────────────────────

    def _read_file(self, path: str, max_lines: int) -> Iterator[Dict]:
        logger.info(f"Reading {path}")
        try:
            with open(path, "r", errors="replace") as f:
                lines = f.readlines()
            for line in lines[-max_lines:]:
                line = line.strip()
                if not line:
                    continue
                # JSON log format?
                try:
                    rec = json.loads(line)
                    rec.setdefault("source", "apache_collector")
                    rec.setdefault("event_type", "http_access")
                    rec.setdefault("timestamp", _ts_now())
                    threat_info = _classify_threat(
                        rec.get("path", rec.get("request", "")),
                        int(rec.get("status", rec.get("status_code", 0))),
                        int(rec.get("bytes", rec.get("bytes_sent", 0))),
                    )
                    rec.update(threat_info)
                    yield rec
                    continue
                except json.JSONDecodeError:
                    pass
                parsed = _parse_clf_line(line)
                if parsed:
                    yield parsed
        except Exception as e:
            logger.error(f"Failed reading {path}: {e}")

    def _read_error_file(self, path: str, max_lines: int) -> Iterator[Dict]:
        try:
            with open(path, "r", errors="replace") as f:
                lines = f.readlines()
            for line in lines[-max_lines:]:
                line = line.strip()
                if not line:
                    continue
                yield {
                    "raw":        line,
                    "event_type": "http_error",
                    "source":     "apache_collector",
                    "timestamp":  _ts_now(),
                    "severity":   "MEDIUM" if "[error]" in line.lower() else "LOW",
                }
        except Exception as e:
            logger.error(f"Failed reading error log {path}: {e}")
