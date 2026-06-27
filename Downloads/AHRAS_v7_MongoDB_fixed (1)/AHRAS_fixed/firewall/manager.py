"""
AHRAS — Adaptive Firewall Manager
Wraps OS-level firewall with runtime ON/OFF toggles for every feature.

Features (all independently togglable):
  - ip_blocking       : block/unblock individual IPs
  - port_blocking     : block/unblock specific ports
  - auto_block        : automatically block IPs above risk threshold
  - rate_limiting     : detect and flag high-rate sources
  - protocol_filter   : block specific protocols
  - whitelist         : guaranteed-pass IP list (overrides all blocks)

Master switch: firewall_enabled — if False, NO rules are applied.
"""

import os
import time
import platform
import subprocess
import threading
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Set, List, Optional, Deque

from config import config

logger = logging.getLogger("ahras.firewall")
OS = platform.system()


@dataclass
class FirewallRule:
    rule_id: str
    rule_type: str          # "ip_block" | "port_block" | "protocol_block"
    target: str             # IP, port number, or protocol name
    direction: str = "in"   # "in" | "out" | "both"
    protocol: str = "any"
    created_at: float = field(default_factory=time.time)
    created_by: str = "system"
    reason: str = ""
    active: bool = True

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_type": self.rule_type,
            "target": self.target,
            "direction": self.direction,
            "protocol": self.protocol,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.created_at)),
            "created_by": self.created_by,
            "reason": self.reason,
            "active": self.active,
        }


@dataclass
class FirewallToggles:
    """Independent on/off toggles for each firewall feature."""
    firewall_enabled: bool = False      # MASTER SWITCH
    ip_blocking: bool = False
    port_blocking: bool = False
    auto_block: bool = False
    rate_limiting: bool = True
    protocol_filter: bool = False
    whitelist_enforcement: bool = True
    dry_run: bool = True                # True = log only, False = apply real rules

    def to_dict(self) -> dict:
        return {
            "firewall_enabled": self.firewall_enabled,
            "ip_blocking": self.ip_blocking,
            "port_blocking": self.port_blocking,
            "auto_block": self.auto_block,
            "rate_limiting": self.rate_limiting,
            "protocol_filter": self.protocol_filter,
            "whitelist_enforcement": self.whitelist_enforcement,
            "dry_run": self.dry_run,
        }


class FirewallManager:
    """
    Central firewall controller.
    All operations check feature toggles before acting.
    Provides full audit trail of all rule changes.
    """

    AUTO_BLOCK_RISK = config.AUTO_BLOCK_RISK_THRESHOLD

    def __init__(self):
        self.toggles = FirewallToggles(
            firewall_enabled=config.FIREWALL_ENABLED,
            ip_blocking=config.AUTO_BLOCK_ENABLED,
            auto_block=config.AUTO_BLOCK_ENABLED,
            port_blocking=config.PORT_CONTROL_ENABLED,
        )

        self._rules: Dict[str, FirewallRule] = {}
        self._blocked_ips: Set[str] = set()
        self._blocked_ports: Dict[int, str] = {}    # port → protocol
        self._whitelist: Set[str] = set(config.TRUST_IP_WHITELIST)
        self._audit_log: List[dict] = []
        self._rate_buckets: Dict[str, Deque[float]] = defaultdict(deque)
        self._rule_counter = 0
        self._lock = threading.Lock()

        logger.info(f"FirewallManager initialised | master={self.toggles.firewall_enabled} | dry_run={self.toggles.dry_run}")

    # ── Toggle Management ─────────────────────────────────────────────────────

    def set_toggle(self, feature: str, enabled: bool, changed_by: str = "system") -> bool:
        """Enable or disable a specific firewall feature."""
        if not hasattr(self.toggles, feature):
            return False
        old = getattr(self.toggles, feature)
        setattr(self.toggles, feature, enabled)
        self._audit(f"TOGGLE_CHANGE", f"{feature}: {old} → {enabled}", changed_by)
        logger.info(f"Firewall toggle '{feature}' set to {enabled} by {changed_by}")
        return True

    # ── IP Blocking ───────────────────────────────────────────────────────────

    def block_ip(self, ip: str, reason: str = "", operator: str = "system") -> dict:
        """Block an IP address."""
        if not self.toggles.firewall_enabled or not self.toggles.ip_blocking:
            return {"success": False, "reason": "IP blocking is disabled"}
        if ip in self._whitelist and self.toggles.whitelist_enforcement:
            return {"success": False, "reason": f"{ip} is whitelisted — cannot block"}
        with self._lock:
            if ip in self._blocked_ips:
                return {"success": False, "reason": "IP already blocked"}
            self._blocked_ips.add(ip)
            rule = self._create_rule("ip_block", ip, reason=reason, created_by=operator)
        self._apply_ip_block(ip)
        self._audit("IP_BLOCKED", f"{ip} — {reason}", operator)
        logger.warning(f"[FIREWALL] Blocked IP: {ip} by {operator} | reason: {reason}")
        return {"success": True, "rule_id": rule.rule_id, "ip": ip}

    def unblock_ip(self, ip: str, operator: str = "system") -> dict:
        """Unblock a previously blocked IP."""
        with self._lock:
            if ip not in self._blocked_ips:
                return {"success": False, "reason": "IP not blocked"}
            self._blocked_ips.discard(ip)
            # Deactivate rule
            for r in self._rules.values():
                if r.rule_type == "ip_block" and r.target == ip:
                    r.active = False
        self._remove_ip_block(ip)
        self._audit("IP_UNBLOCKED", ip, operator)
        logger.info(f"[FIREWALL] Unblocked IP: {ip} by {operator}")
        return {"success": True, "ip": ip}

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked_ips

    def is_whitelisted(self, ip: str) -> bool:
        with self._lock:
            return ip in self._whitelist

    def add_to_whitelist(self, ip: str, operator: str = "system"):
        with self._lock:
            self._whitelist.add(ip)
        self._audit("WHITELIST_ADD", ip, operator)

    def remove_from_whitelist(self, ip: str, operator: str = "system"):
        with self._lock:
            self._whitelist.discard(ip)
        self._audit("WHITELIST_REMOVE", ip, operator)

    # ── Port Blocking ─────────────────────────────────────────────────────────

    def block_port(self, port: int, protocol: str = "tcp",
                   reason: str = "", operator: str = "system") -> dict:
        if not self.toggles.firewall_enabled or not self.toggles.port_blocking:
            return {"success": False, "reason": "Port blocking is disabled"}
        with self._lock:
            if port in self._blocked_ports:
                return {"success": False, "reason": "Port already blocked"}
            self._blocked_ports[port] = protocol
            rule = self._create_rule("port_block", str(port), protocol=protocol,
                                     reason=reason, created_by=operator)
        self._apply_port_block(port, protocol)
        self._audit("PORT_BLOCKED", f"{port}/{protocol} — {reason}", operator)
        return {"success": True, "rule_id": rule.rule_id, "port": port}

    def unblock_port(self, port: int, operator: str = "system") -> dict:
        with self._lock:
            if port not in self._blocked_ports:
                return {"success": False, "reason": "Port not blocked"}
            protocol = self._blocked_ports.pop(port)
        self._remove_port_block(port, protocol)
        self._audit("PORT_UNBLOCKED", f"{port}/{protocol}", operator)
        return {"success": True, "port": port}

    # ── Auto-block ────────────────────────────────────────────────────────────

    def evaluate_auto_block(self, ip: str, risk_score: float,
                            reason: str = "") -> Optional[dict]:
        """Called by risk engine — auto-blocks if threshold exceeded."""
        if not self.toggles.auto_block:
            return None
        if risk_score >= self.AUTO_BLOCK_RISK:
            return self.block_ip(ip, reason=f"Auto-block: risk={risk_score:.2f}", operator="auto")
        return None

    # ── Rate Limiting ─────────────────────────────────────────────────────────

    def check_rate_limit(self, ip: str, window: float = 10.0,
                         max_events: int = 50) -> bool:
        """Returns True if IP exceeds rate limit."""
        if not self.toggles.rate_limiting:
            return False
        now = time.time()
        with self._lock:
            dq = self._rate_buckets[ip]
            dq.append(now)
            cutoff = now - window
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq) > max_events

    # ── State queries ──────────────────────────────────────────────────────────

    def blocked_ips_list(self) -> List[dict]:
        with self._lock:
            return [
                {"ip": ip, "whitelisted": False}
                for ip in sorted(self._blocked_ips)
            ]

    def blocked_ports_list(self) -> List[dict]:
        with self._lock:
            return [{"port": p, "protocol": proto}
                    for p, proto in sorted(self._blocked_ports.items())]

    def whitelist_list(self) -> List[str]:
        with self._lock:
            return sorted(self._whitelist)

    def all_rules(self) -> List[dict]:
        with self._lock:
            return [r.to_dict() for r in sorted(self._rules.values(),
                    key=lambda x: x.created_at, reverse=True)]

    def audit_log(self, limit: int = 100) -> List[dict]:
        with self._lock:
            return self._audit_log[:limit]

    def status(self) -> dict:
        with self._lock:
            return {
                "toggles": self.toggles.to_dict(),
                "blocked_ip_count": len(self._blocked_ips),
                "blocked_port_count": len(self._blocked_ports),
                "whitelist_count": len(self._whitelist),
                "total_rules": len(self._rules),
            }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _create_rule(self, rule_type: str, target: str, **kwargs) -> FirewallRule:
        self._rule_counter += 1
        rule = FirewallRule(
            rule_id=f"FW-{self._rule_counter:05d}",
            rule_type=rule_type,
            target=target,
            **kwargs,
        )
        self._rules[rule.rule_id] = rule
        return rule

    def _audit(self, action: str, detail: str, operator: str):
        with self._lock:
            self._audit_log.insert(0, {
                "action": action,
                "detail": detail,
                "operator": operator,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
            if len(self._audit_log) > 500:
                self._audit_log.pop()

    def _apply_ip_block(self, ip: str):
        if self.toggles.dry_run:
            logger.info(f"[DRY-RUN] Would block IP: {ip}")
            return
        try:
            if OS == "Linux":
                subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            elif OS == "Windows":
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=AHRAS_BLOCK_{ip.replace('.','_')}",
                    "dir=in", "action=block", f"remoteip={ip}"
                ], check=True)
        except Exception as e:
            logger.error(f"Firewall apply error: {e}")

    def _remove_ip_block(self, ip: str):
        if self.toggles.dry_run:
            logger.info(f"[DRY-RUN] Would unblock IP: {ip}")
            return
        try:
            if OS == "Linux":
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            elif OS == "Windows":
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name=AHRAS_BLOCK_{ip.replace('.','_')}"
                ], check=True)
        except Exception as e:
            logger.error(f"Firewall remove error: {e}")

    def _apply_port_block(self, port: int, protocol: str):
        if self.toggles.dry_run:
            logger.info(f"[DRY-RUN] Would block port {port}/{protocol}")
            return
        try:
            if OS == "Linux":
                subprocess.run([
                    "iptables", "-I", "INPUT", "-p", protocol,
                    "--dport", str(port), "-j", "DROP"
                ], check=True)
        except Exception as e:
            logger.error(f"Port block error: {e}")

    def _remove_port_block(self, port: int, protocol: str):
        if self.toggles.dry_run:
            return
        try:
            if OS == "Linux":
                subprocess.run([
                    "iptables", "-D", "INPUT", "-p", protocol,
                    "--dport", str(port), "-j", "DROP"
                ], check=True)
        except Exception as e:
            logger.error(f"Port unblock error: {e}")
