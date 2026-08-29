"""
AHRAS v4 — STIX/TAXII Threat Feed Ingestor
(Phase 2 — Structural Addition, feeds ioc_management/manager.py)
═══════════════════════════════════════════════════════════════════════════
Problem: threat_intel/intel.py does live per-indicator lookups (AbuseIPDB,
VirusTotal, OTX) — great for "is this one IP bad?", but there's no bulk
ingestion of the standardized threat-intel feeds most orgs and ISACs
actually share (STIX 2.x bundles served over a TAXII 2.x API), so IOCs
have to be added one at a time.

Solution: a small TAXII 2.1 client (plain `requests`, no heavyweight STIX
library required) that pulls STIX `indicator` objects from a configured
collection, parses the common `pattern` syntax for IPv4/IPv6/domain/URL/
file-hash indicators, and bulk-loads them into ioc_management.IOCManager.

Honest scope note: this implements the TAXII 2.1 "get objects" endpoint
and a pragmatic subset of the STIX pattern grammar (equality comparisons
on ipv4-addr/domain-name/url/file:hashes — covers the vast majority of
real-world STIX indicator objects). It does not implement the full STIX
pattern grammar (no boolean logic across observable types, no cyber
observable relationships). Point AHRAS_STIX_TAXII_URL/COLLECTION_ID at
any TAXII 2.1 server (MITRE's own OpenTAXII test server, a commercial
feed, or an internal MISP-TAXII bridge) to use it for real.
"""
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

logger = logging.getLogger("ahras.threat_intel.stix")

TAXII_URL = os.environ.get("AHRAS_STIX_TAXII_URL", "")             # e.g. https://cti-taxii.mitre.org/taxii/
TAXII_COLLECTION_ID = os.environ.get("AHRAS_STIX_COLLECTION_ID", "")
TAXII_USERNAME = os.environ.get("AHRAS_STIX_TAXII_USER", "")
TAXII_PASSWORD = os.environ.get("AHRAS_STIX_TAXII_PASS", "")
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"

# Pragmatic STIX pattern parser: matches the common
# [ipv4-addr:value = 'x.x.x.x'] / [domain-name:value = '...'] /
# [url:value = '...'] shapes (type:value = 'val'), and separately the
# hash shape [file:hashes.'SHA-256' = 'val'] which has no colon before '='.
_SIMPLE_PATTERN_RE = re.compile(
    r"\[(?P<obj>ipv4-addr|ipv6-addr|domain-name|url)\s*:\s*value\s*=\s*'(?P<val>[^']+)'\]"
)
_HASH_PATTERN_RE = re.compile(
    r"\[file:hashes\.'[^']+'\s*=\s*'(?P<val>[^']+)'\]"
)

_OBJ_TO_IOC_TYPE = {
    "ipv4-addr": "ip", "ipv6-addr": "ip",
    "domain-name": "domain", "url": "url",
}


@dataclass
class IngestedIndicator:
    indicator: str
    ioc_type: str
    description: str
    stix_id: str
    source_label: str = "stix_taxii"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"indicator": self.indicator, "ioc_type": self.ioc_type,
                "description": self.description, "stix_id": self.stix_id,
                "source_label": self.source_label,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))}


def _parse_stix_pattern(pattern: str) -> Optional[tuple]:
    """Returns (ioc_type, value) or None if the pattern isn't in our supported subset."""
    pattern = pattern or ""
    hm = _HASH_PATTERN_RE.search(pattern)
    if hm:
        return "hash", hm.group("val")
    m = _SIMPLE_PATTERN_RE.search(pattern)
    if not m:
        return None
    ioc_type = _OBJ_TO_IOC_TYPE.get(m.group("obj"))
    return (ioc_type, m.group("val")) if ioc_type else None


class STIXTAXIIIngestor:
    def __init__(self, taxii_url: str = TAXII_URL, collection_id: str = TAXII_COLLECTION_ID,
                 ioc_mgr=None):
        self.taxii_url = taxii_url.rstrip("/") if taxii_url else ""
        self.collection_id = collection_id
        self.ioc_mgr = ioc_mgr
        self._last_sync: Optional[float] = None
        self._last_count = 0

    def is_configured(self) -> bool:
        return bool(self.taxii_url and self.collection_id and REQUESTS_OK)

    def sync(self, api_root: str = "api1", limit: int = 500) -> List[IngestedIndicator]:
        """
        Pulls up to `limit` STIX objects from the configured TAXII 2.1
        collection, extracts indicator objects, converts to IOCs, and
        (if an ioc_mgr was injected) adds them. Returns what was ingested.
        """
        if not self.is_configured():
            logger.info("STIX/TAXII not configured (set AHRAS_STIX_TAXII_URL + "
                        "AHRAS_STIX_COLLECTION_ID) — skipping sync")
            return []

        url = f"{self.taxii_url}/{api_root}/collections/{self.collection_id}/objects/"
        headers = {"Accept": TAXII_MEDIA_TYPE}
        auth = (TAXII_USERNAME, TAXII_PASSWORD) if TAXII_USERNAME else None

        try:
            resp = requests.get(url, headers=headers, auth=auth,
                                 params={"limit": limit}, timeout=15)
            resp.raise_for_status()
            bundle = resp.json()
        except Exception as exc:
            logger.error("STIX/TAXII sync failed: %s", exc)
            return []

        objects = bundle.get("objects", bundle.get("indicators", []))
        ingested: List[IngestedIndicator] = []

        for obj in objects:
            if obj.get("type") != "indicator":
                continue
            parsed = _parse_stix_pattern(obj.get("pattern", ""))
            if not parsed:
                continue
            ioc_type, value = parsed
            item = IngestedIndicator(
                indicator=value, ioc_type=ioc_type,
                description=obj.get("name") or obj.get("description", "STIX indicator"),
                stix_id=obj.get("id", ""),
            )
            ingested.append(item)

            if self.ioc_mgr is not None:
                try:
                    self.ioc_mgr.add_ioc(
                        indicator=value, ioc_type=ioc_type, threat_level="medium",
                        description=item.description, tags=obj.get("labels", []) or ["stix_taxii"],
                        source="stix_taxii", added_by="stix_ingestor",
                    )
                except Exception as exc:
                    logger.debug("IOC add skipped for %s: %s", value, exc)

        self._last_sync = time.time()
        self._last_count = len(ingested)
        logger.info("STIX/TAXII sync complete: %d indicators ingested", len(ingested))
        return ingested

    def status(self) -> dict:
        return {
            "configured": self.is_configured(),
            "taxii_url": self.taxii_url or None,
            "collection_id": self.collection_id or None,
            "last_sync": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self._last_sync)) if self._last_sync else None,
            "last_ingested_count": self._last_count,
        }


stix_ingestor = STIXTAXIIIngestor()
