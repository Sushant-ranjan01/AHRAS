"""MongoDB backup helper; requires mongodump in PATH."""
import os, subprocess, sys, datetime
from config import config
out = os.path.abspath(os.getenv("BACKUP_DIR", "backups"))
os.makedirs(out, exist_ok=True)
target = os.path.join(out, datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"))
cmd = ["mongodump", f"--uri={config.MONGO_URI}", f"--db={config.MONGO_DB}", f"--out={target}"]
raise SystemExit(subprocess.call(cmd))
