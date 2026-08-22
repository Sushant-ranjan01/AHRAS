"""
AHRAS v6 — Role-Based Access Control (RBAC)
============================================
Five enterprise roles, each with a precise permission set.

Role Hierarchy (highest to lowest privilege):
  ADMIN              → everything
  SOC_ANALYST        → alerts, events, cases, IOC, threat intel
  THREAT_HUNTER      → threat hunting, IOC search, MITRE, TI
  INCIDENT_RESPONDER → SOAR, forensics, cases, assets
  MANAGER            → dashboard, reports, read-only stats

Every FastAPI route uses a require_permission(perm) dependency.
"""

from enum import Enum
from typing import Set, Dict


# ── Permission constants ─────────────────────────────────────────────────────
class Perm(str, Enum):
    # System
    SYSTEM_ADMIN         = "system:admin"           # manage users, settings
    SYSTEM_LOGS          = "system:logs"            # server logs, maintenance

    # Events & Alerts
    EVENTS_READ          = "events:read"
    EVENTS_EXPORT        = "events:export"
    ALERTS_READ          = "alerts:read"
    ALERTS_ACKNOWLEDGE   = "alerts:acknowledge"
    ALERTS_DELETE        = "alerts:delete"

    # Cases
    CASES_READ           = "cases:read"
    CASES_CREATE         = "cases:create"
    CASES_UPDATE         = "cases:update"
    CASES_DELETE         = "cases:delete"           # admin only

    # Forensics
    FORENSICS_READ       = "forensics:read"
    FORENSICS_WRITE      = "forensics:write"
    FORENSICS_DELETE     = "forensics:delete"       # admin only

    # Threat Hunting
    HUNT_READ            = "hunt:read"
    HUNT_EXECUTE         = "hunt:execute"

    # IOC
    IOC_READ             = "ioc:read"
    IOC_WRITE            = "ioc:write"
    IOC_DELETE           = "ioc:delete"             # admin only

    # Threat Intel
    TI_READ              = "ti:read"
    TI_ENRICH            = "ti:enrich"              # trigger live API calls

    # MITRE
    MITRE_READ           = "mitre:read"

    # Risk
    RISK_READ            = "risk:read"
    RISK_EXPLAIN         = "risk:explain"
    RISK_HISTORY         = "risk:history"

    # SOAR
    SOAR_READ            = "soar:read"
    SOAR_EXECUTE         = "soar:execute"           # trigger playbooks
    SOAR_CONFIG          = "soar:config"            # admin only

    # Firewall
    FIREWALL_READ        = "firewall:read"
    FIREWALL_TOGGLE      = "firewall:toggle"        # admin only
    FIREWALL_BLOCK       = "firewall:block"         # admin only

    # Assets
    ASSETS_READ          = "assets:read"
    ASSETS_WRITE         = "assets:write"

    # UBA
    UBA_READ             = "uba:read"
    UBA_CONFIG           = "uba:config"             # admin only

    # Honeypot
    HONEYPOT_READ        = "honeypot:read"
    HONEYPOT_CONFIG      = "honeypot:config"        # admin only

    # Reports
    REPORTS_READ         = "reports:read"
    REPORTS_GENERATE     = "reports:generate"

    # Dashboard
    DASHBOARD_READ       = "dashboard:read"

    # Historical Risk
    HISTORY_READ         = "history:read"
    HISTORY_WRITE        = "history:write"

    # Normalizer / Collectors
    NORMALIZER_USE       = "normalizer:use"
    COLLECTORS_RUN       = "collectors:run"


# ── Role definitions ──────────────────────────────────────────────────────────
class Role(str, Enum):
    ADMIN              = "admin"
    SOC_ANALYST        = "soc_analyst"
    THREAT_HUNTER      = "threat_hunter"
    INCIDENT_RESPONDER = "incident_responder"
    MANAGER            = "manager"
    # Legacy roles kept for backward compatibility
    MASTER             = "master"    # maps to ADMIN
    ANALYST            = "analyst"   # maps to SOC_ANALYST


# ── Permission sets per role ─────────────────────────────────────────────────
_ALL_PERMS: Set[Perm] = set(Perm)

ROLE_PERMISSIONS: Dict[Role, Set[Perm]] = {

    Role.ADMIN: _ALL_PERMS,  # admin gets everything

    Role.SOC_ANALYST: {
        Perm.DASHBOARD_READ,
        Perm.EVENTS_READ,
        Perm.EVENTS_EXPORT,
        Perm.ALERTS_READ,
        Perm.ALERTS_ACKNOWLEDGE,
        Perm.CASES_READ,
        Perm.CASES_CREATE,
        Perm.CASES_UPDATE,
        Perm.IOC_READ,
        Perm.IOC_WRITE,
        Perm.TI_READ,
        Perm.TI_ENRICH,
        Perm.MITRE_READ,
        Perm.RISK_READ,
        Perm.ASSETS_READ,
        Perm.UBA_READ,
        Perm.REPORTS_READ,
        Perm.REPORTS_GENERATE,
        Perm.HISTORY_READ,
        Perm.NORMALIZER_USE,
        Perm.HUNT_READ,
    },

    Role.THREAT_HUNTER: {
        Perm.DASHBOARD_READ,
        Perm.EVENTS_READ,
        Perm.HUNT_READ,
        Perm.HUNT_EXECUTE,
        Perm.IOC_READ,
        Perm.IOC_WRITE,
        Perm.TI_READ,
        Perm.TI_ENRICH,
        Perm.MITRE_READ,
        Perm.RISK_READ,
        Perm.RISK_EXPLAIN,
        Perm.RISK_HISTORY,
        Perm.ALERTS_READ,
        Perm.CASES_READ,
        Perm.HISTORY_READ,
        Perm.NORMALIZER_USE,
        Perm.ASSETS_READ,
    },

    Role.INCIDENT_RESPONDER: {
        Perm.DASHBOARD_READ,
        Perm.EVENTS_READ,
        Perm.ALERTS_READ,
        Perm.ALERTS_ACKNOWLEDGE,
        Perm.CASES_READ,
        Perm.CASES_CREATE,
        Perm.CASES_UPDATE,
        Perm.FORENSICS_READ,
        Perm.FORENSICS_WRITE,
        Perm.SOAR_READ,
        Perm.SOAR_EXECUTE,
        Perm.IOC_READ,
        Perm.IOC_WRITE,
        Perm.TI_READ,
        Perm.MITRE_READ,
        Perm.RISK_READ,
        Perm.RISK_EXPLAIN,
        Perm.ASSETS_READ,
        Perm.ASSETS_WRITE,
        Perm.REPORTS_READ,
        Perm.REPORTS_GENERATE,
        Perm.HISTORY_READ,
        Perm.HUNT_READ,
        Perm.NORMALIZER_USE,
    },

    Role.MANAGER: {
        Perm.DASHBOARD_READ,
        Perm.EVENTS_READ,
        Perm.ALERTS_READ,
        Perm.CASES_READ,
        Perm.REPORTS_READ,
        Perm.REPORTS_GENERATE,
        Perm.RISK_READ,
        Perm.RISK_HISTORY,
        Perm.HISTORY_READ,
        Perm.ASSETS_READ,
        Perm.UBA_READ,
        Perm.MITRE_READ,
        Perm.TI_READ,
    },

    # Legacy role mappings
    Role.MASTER:  _ALL_PERMS,           # master = admin (backward compat)
    Role.ANALYST: {                     # analyst = soc_analyst subset
        Perm.DASHBOARD_READ, Perm.EVENTS_READ, Perm.ALERTS_READ,
        Perm.ALERTS_ACKNOWLEDGE, Perm.CASES_READ, Perm.CASES_CREATE,
        Perm.IOC_READ, Perm.TI_READ, Perm.MITRE_READ, Perm.RISK_READ,
        Perm.REPORTS_READ, Perm.HUNT_READ, Perm.HISTORY_READ,
        Perm.FORENSICS_READ, Perm.ASSETS_READ,
    },
}


def get_permissions(role: str) -> Set[Perm]:
    """Return the set of Perm values for a given role string."""
    try:
        r = Role(role.lower())
        return ROLE_PERMISSIONS.get(r, set())
    except ValueError:
        return set()


def has_permission(role: str, perm: Perm) -> bool:
    """Check if a role has a specific permission."""
    return perm in get_permissions(role)


def role_summary() -> dict:
    """Return a human-readable summary of all roles and their permission counts."""
    return {
        r.value: {
            "permission_count": len(perms),
            "permissions": sorted(p.value for p in perms),
        }
        for r, perms in ROLE_PERMISSIONS.items()
    }
