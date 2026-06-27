"""AHRAS — Enrichment Service"""
import socket, threading, logging
from typing import Dict, Optional
logger=logging.getLogger("ahras.enrichment")
_PRIV=("10.","192.168.","172.16.","172.17.","172.18.","172.19.","172.20.",
       "172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.",
       "172.28.","172.29.","172.30.","172.31.","127.","169.254.","::1","fe80:")
_KNOWN={
    "13.107.137.11":("United States","Microsoft Corp"),
    "52.114.128.10":("United States","Microsoft Azure"),
    "8.8.8.8":("United States","Google LLC"),
    "8.8.4.4":("United States","Google LLC"),
    "1.1.1.1":("United States","Cloudflare"),
    "104.21.4.50":("United States","Cloudflare"),
    "172.217.3.110":("United States","Google LLC"),
    "185.199.108.153":("United States","GitHub"),
    "185.220.101.45":("Germany","Tor Exit Node"),
    "45.33.32.156":("United States","Linode"),
    "198.20.69.74":("United States","DigitalOcean"),
    "23.45.67.89":("United States","Akamai"),
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
        return {"country":"Unknown","organization":"Unknown","dns_name":self._rdns(ip) or ip,"is_private":False}
    @staticmethod
    def _rdns(ip)->Optional[str]:
        try: return socket.gethostbyaddr(ip)[0]
        except: return None
