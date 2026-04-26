import socket
from functools import lru_cache

TRUSTED_KEYWORDS = [
    "google", "github", "cloudflare",
    "microsoft", "amazon", "akamai"
]

@lru_cache(maxsize=1000)
def resolve_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0].lower()
    except:
        return "unknown"


def calculate_trust_score(ip):
    domain = resolve_domain(ip)

    score = 0

    for keyword in TRUSTED_KEYWORDS:
        if keyword in domain:
            score += 0.4

    return min(score, 1), domain