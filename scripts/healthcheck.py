import sys, urllib.request
url = "http://127.0.0.1:8000/health"
try:
    with urllib.request.urlopen(url, timeout=5) as r:
        data = r.read().decode()
        print(data)
        sys.exit(0 if r.status == 200 else 1)
except Exception as exc:
    print(f"healthcheck failed: {exc}")
    sys.exit(1)
