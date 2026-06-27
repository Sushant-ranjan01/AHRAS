"""AHRAS v4.0 — maintenance/delete.py
Deletes: reports, logs, temp datasets, cached TI, expired alerts.
Run: python maintenance/delete.py
"""
import os, shutil, glob, json, time
from pathlib import Path

BASE = Path(__file__).parent.parent

TARGETS = {
    "Reports":          BASE / "reports",
    "Logs":             BASE / "logs",
    "Temp datasets":    BASE / "ml_engine" / "datasets" / "temp",
    "TI Cache":         BASE / "threat_intel" / "cache",
    "In-memory DB":     BASE / "data",
}

def delete_all():
    print("\n🗑  AHRAS — Full Data Delete")
    print("=" * 50)
    total = 0
    for label, path in TARGETS.items():
        if path.exists():
            try:
                count = sum(1 for _ in path.rglob("*") if _.is_file())
                shutil.rmtree(path, ignore_errors=True)
                path.mkdir(parents=True, exist_ok=True)
                print(f"  ✅ {label}: {count} files deleted ({path})")
                total += count
            except Exception as e:
                print(f"  ❌ {label}: {e}")
        else:
            print(f"  ⏭  {label}: not found (skipped)")

    # Also clear the in-memory DB file if it exists
    db_file = BASE / "ahras_data.json"
    if db_file.exists():
        db_file.write_text("{}")
        print(f"  ✅ In-memory DB reset: {db_file}")
        total += 1

    print(f"\n✅ Done — {total} files deleted.\n")

if __name__ == "__main__":
    confirm = input("⚠️  This will delete ALL logs, reports, and cached data. Type YES to continue: ")
    if confirm.strip().upper() == "YES":
        delete_all()
    else:
        print("Cancelled.")
