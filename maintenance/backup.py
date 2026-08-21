"""AHRAS v4.0 — maintenance/backup.py
Creates timestamped zip backup of all AHRAS data.
Run: python maintenance/backup.py
"""
import os, zipfile, time
from pathlib import Path
from datetime import datetime

BASE    = Path(__file__).parent.parent
BACKUP_DIR = BASE / "backups"

INCLUDE = [
    "logs", "reports", "data", "models",
    "ahras_data.json", ".env",
    "ioc_management", "case_management",
    "ml_engine/models",
]

def backup():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = BACKUP_DIR / f"ahras_backup_{ts}.zip"
    print(f"\n💾 AHRAS — Backup → {out}")
    print("=" * 50)
    count = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for target in INCLUDE:
            p = BASE / target
            if p.is_file():
                zf.write(p, target); count += 1
                print(f"  ✅ {target}")
            elif p.is_dir():
                for f in p.rglob("*"):
                    if f.is_file():
                        zf.write(f, str(f.relative_to(BASE))); count += 1
                print(f"  ✅ {target}/ ({sum(1 for _ in p.rglob('*') if _.is_file())} files)")
            else:
                print(f"  ⏭  {target} (not found)")
    size_kb = out.stat().st_size // 1024
    print(f"\n✅ Backup complete: {count} files, {size_kb} KB → {out}\n")
    return str(out)

if __name__ == "__main__":
    backup()
