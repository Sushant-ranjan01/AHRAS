"""AHRAS v4.0 — maintenance/restore.py
Restores from a backup zip.
Run: python maintenance/restore.py backups/ahras_backup_YYYYMMDD_HHMMSS.zip
"""
import sys, zipfile, shutil
from pathlib import Path

BASE = Path(__file__).parent.parent

def restore(backup_path: str):
    bp = Path(backup_path)
    if not bp.exists():
        print(f"❌ Backup not found: {backup_path}"); return False
    print(f"\n🔄 AHRAS — Restore from {bp.name}")
    print("=" * 50)
    with zipfile.ZipFile(bp, "r") as zf:
        names = zf.namelist()
        print(f"  📦 {len(names)} files in backup")
        zf.extractall(BASE)
    print(f"\n✅ Restore complete — {len(names)} files restored to {BASE}\n")
    return True

def list_backups():
    bd = BASE / "backups"
    if not bd.exists(): print("No backups found."); return
    backups = sorted(bd.glob("ahras_backup_*.zip"), reverse=True)
    if not backups: print("No backups found."); return
    print("\n📦 Available backups:")
    for i, b in enumerate(backups):
        size = b.stat().st_size // 1024
        print(f"  [{i+1}] {b.name}  ({size} KB)")
    print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        list_backups()
        path = input("Enter backup filename (or full path): ").strip()
        if not path: print("Cancelled."); sys.exit(0)
        if not Path(path).is_absolute():
            path = str(BASE / "backups" / path)
    else:
        path = sys.argv[1]
    confirm = input(f"⚠️  Restore from {path}? This overwrites current data. Type YES: ")
    if confirm.strip().upper() == "YES":
        restore(path)
    else:
        print("Cancelled.")
