"""AHRAS — Enrichment Service"""
import socket, threading, logging, json, urllib.request
from typing import Dict, Optional
logger=logging.getLogger("ahras.enrichment")
_PRIV=("10.","192.168.","172.16.","172.17.","172.18.","172.19.","172.20.",
       "172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.",
       "172.28.","172.29.","172.30.","172.31.","127.","169.254.","::1","fe80:")

# Small fast-path table for extremely common infra IPs — avoids a network
# round-trip for the IPs you'll see constantly (Google DNS, Cloudflare, etc).
# Anything NOT in this table now falls through to a real GeoIP API lookup
# below instead of just returning "Unknown" — previously that table was the
# ONLY source of country/org data, which is why almost every real-world IP
# showed "Unknown": it simply wasn't one of these 12 entries.
_KNOWN={
    "8.8.8.8":("United States","Google LLC"),
    "8.8.4.4":("United States","Google LLC"),
    "1.1.1.1":("United States","Cloudflare"),
    "1.0.0.1":("United States","Cloudflare"),
}

class EnrichmentService:
    def __init__(self):
        self._cache:Dict[str,dict]={}; self._l=threading.Lock()

    def enrich(self,ip:str)->dict:
        with self._l:
            if ip in self._cache: return self._cache[ip]
        r=self._lookup(ip)
        with self._l: self._cache[ip]=r
        return r

    def _lookup(self,ip):
        if any(ip.startswith(p) for p in _PRIV):
            h=self._rdns(ip)
            return {"country":"Private Network","organization":h or "Local","dns_name":h or ip,"is_private":True}
        if ip in _KNOWN:
            c,o=_KNOWN[ip]
            return {"country":c,"organization":o,"dns_name":self._rdns(ip) or ip,"is_private":False}
        geo = self._geoip(ip)
        h = self._rdns(ip)
        if geo:
            # Prefer a real ISP/org name from GeoIP; fall back to the
            # reverse-DNS hostname if GeoIP didn't return one.
            org = geo.get("organization") or h or "Unknown"
            return {"country":geo.get("country","Unknown"),"organization":org,"dns_name":h or ip,"is_private":False}
        # GeoIP API unreachable/failed (offline, rate-limited, blocked
        # network egress, etc). Fall back to whatever rDNS gave us instead
        # of just saying "Unknown" across the board.
        return {"country":"Unknown","organization":h or "Unknown","dns_name":h or ip,"is_private":False}

    @staticmethod
    def _rdns(ip)->Optional[str]:
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(0.75)   # don't let a slow/absent DNS server stall the analysis worker
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
        finally:
            socket.setdefaulttimeout(old_timeout)

    @staticmethod
    def _geoip(ip)->Optional[dict]:
        """Free, keyless GeoIP lookup (ipwho.is). Cached per-IP by enrich(),
        so this only costs a real network round-trip once per unique
        public IP ever seen, not once per packet/flow. Fails closed (returns
        None) if there's no internet access, the API is down/rate-limited,
        or the response is malformed — callers handle that gracefully."""
        try:
            req = urllib.request.Request(
                f"https://ipwho.is/{ip}",
                headers={"User-Agent": "AHRAS-enrichment/1.0"},
            )
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if not data.get("success", True):
                return None
            org = data.get("connection", {}).get("isp") or data.get("connection", {}).get("org")
            return {"country": data.get("country") or "Unknown", "organization": org}
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
            return None
