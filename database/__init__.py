"""
AHRAS Database Layer — Public API
===================================
Import everything you need from here:

    from database import db_connect, db_health, is_connected
    from database import (
        EventRepository, AlertRepository, CaseRepository,
        IOCRepository, ForensicsRepository, ThreatIntelCacheRepository,
        HistoricalRiskRepository, UserRepository,
        SOARLogRepository, HoneypotRepository, NormalizerLogRepository,
    )
"""

from .connection import connect as db_connect, disconnect as db_disconnect
from .connection import get_db, get_collection, is_connected, is_fallback, health as db_health
from .repositories import (
    EventRepository,
    AlertRepository,
    CaseRepository,
    IOCRepository,
    ForensicsRepository,
    ThreatIntelCacheRepository,
    HistoricalRiskRepository,
    UserRepository,
    SOARLogRepository,
    HoneypotRepository,
    NormalizerLogRepository,
)

__all__ = [
    "db_connect", "db_disconnect", "get_db", "get_collection",
    "is_connected", "is_fallback", "db_health",
    "EventRepository", "AlertRepository", "CaseRepository",
    "IOCRepository", "ForensicsRepository", "ThreatIntelCacheRepository",
    "HistoricalRiskRepository", "UserRepository",
    "SOARLogRepository", "HoneypotRepository", "NormalizerLogRepository",
]
