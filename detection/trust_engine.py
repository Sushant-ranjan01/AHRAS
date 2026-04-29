import socket


def calculate_trust_score(ip):
    """
    Returns:
        (trust_score, domain)
    """

    # 🔥 basic validation
    if not isinstance(ip, str) or not ip:
        return 0.1, "unknown"

    try:
        hostname = socket.gethostbyaddr(ip)[0]
        hostname_lower = hostname.lower()

        trusted_domains = [
            "google",
            "amazonaws",
            "cloudflare",
            "microsoft",
            "facebook",
            "akamai",
            "fastly"
        ]

        for domain in trusted_domains:
            if domain in hostname_lower:
                return 0.8, domain

        return 0.4, hostname

    except socket.herror:
        # No reverse DNS
        return 0.1, "unknown"

    except Exception:
        # Any unexpected failure
        return 0.1, "unknown"