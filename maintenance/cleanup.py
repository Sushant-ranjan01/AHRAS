"""AHRAS v4.0 — maintenance/cleanup.py
Smart cleanup with retention policies:
  - Logs older than 30 days
  - Duplicate alerts
  - Expired IOC entries
  - Closed cases older than 60 days
Run: python maintenance/cleanup.py
"""
import os, time, json, glob
from pathlib import Path
from datetime import datetime

BASE   = Path(__file__).parent.parent
LOG_RETENTION_DAYS  = 30
CASE_RETENTION_DAYS = 60
NOW = time.time()

def _age_days(ts): return (NOW - ts) / 86400

def cleanup_logs():
    log_dir = BASE / "logs"
    if not log_dir.exists(): print("  ⏭  Logs: not found"); return
    removed = 0
    for f in log_dir.rglob("*.txt"):
        age = _age_days(f.stat().st_mtime)
        if age > LOG_RETENTION_DAYS:
            f.unlink(); removed += 1
    for f in log_dir.rglob("*.log"):
        age = _age_days(f.stat().st_mtime)
        if age > LOG_RETENTION_DAYS:
            f.unlink(); removed += 1
    print(f"  ✅ Logs: {removed} files older than {LOG_RETENTION_DAYS}d removed")

def cleanup_reports():
    rep_dir = BASE / "reports"
    if not rep_dir.exists(): print("  ⏭  Reports: not found"); return
    removed = 0
    for f in rep_dir.rglob("*.html"):
        if _age_days(f.stat().st_mtime) > LOG_RETENTION_DAYS:
            f.unlink(); removed += 1
    print(f"  ✅ Reports: {removed} old reports removed")

def cleanup_ti_cache():
    cache = BASE / "threat_intel" / "cache"
    if not cache.exists(): print("  ⏭  TI Cache: not found"); return
    removed = 0
    for f in cache.rglob("*.json"):
        try:
            data = json.loads(f.read_text())
            ts = data.get("cached_at", 0)
            if _age_days(ts) > 1:   # TI cache TTL: 1 day
                f.unlink(); removed += 1
        except Exception:
            f.unlink(); removed += 1
    print(f"  ✅ TI Cache: {removed} expired entries removed")

def cleanup_db_data():
    """Clean in-memory exported data file."""
    db_file = BASE / "ahras_data.json"
    if not db_file.exists(): print("  ⏭  DB: not found"); return
    try:
        data = json.loads(db_file.read_text())
        orig_events = len(data.get("events", []))
        # Keep only last 30 days of events
        if "events" in data:
            data["events"] = [
                e for e in data["events"]
                if _age_days(e.get("timestamp", 0)) <= LOG_RETENTION_DAYS
            ]
        # Remove duplicate alerts (same src_ip + attack_type within 1 min)
        if "alerts" in data:
            seen = set(); deduped = []
            for a in data["alerts"]:
                key = f"{a.get('src_ip')}-{a.get('attack_type')}-{int(a.get('timestamp',0)//60)}"
                if key not in seen:
                    seen.add(key); deduped.append(a)
            dup_removed = len(data["alerts"]) - len(deduped)
            data["alerts"] = deduped
        else:
            dup_removed = 0
        # Remove closed cases older than 60 days
        case_removed = 0
        if "cases" in data:
            filtered = []
            for c in data["cases"]:
                if c.get("status") in ("CLOSED","FALSE_POSITIVE"):
                    closed_at = c.get("closed_at_ts", 0)
                    if closed_at and _age_days(closed_at) > CASE_RETENTION_DAYS:
                        case_removed += 1; continue
                filtered.append(c)
            data["cases"] = filtered
        new_events = len(data.get("events", []))
        db_file.write_text(json.dumps(data, indent=2))
        print(f"  ✅ Events: {orig_events-new_events} old events purged")
        print(f"  ✅ Alerts: {dup_removed} duplicates removed")
        print(f"  ✅ Cases: {case_removed} old closed cases removed")
    except Exception as e:
        print(f"  ❌ DB cleanup failed: {e}")

def main():
    print("\n🧹 AHRAS — Smart Cleanup")
    print(f"  Policy: logs>{LOG_RETENTION_DAYS}d, cases>{CASE_RETENTION_DAYS}d")
    print("=" * 50)
    cleanup_logs()
    cleanup_reports()
    cleanup_ti_cache()
    cleanup_db_data()
    print(f"\n✅ Cleanup complete at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

if __name__ == "__main__":
    main()
