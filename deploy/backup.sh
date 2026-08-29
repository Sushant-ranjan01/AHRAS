#!/bin/sh
set -eu
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="/backups/${STAMP}"
mkdir -p "$TARGET"

mongodump \
  --host mongo:27017 \
  --username "$MONGO_ROOT_USERNAME" \
  --password "$MONGO_ROOT_PASSWORD" \
  --authenticationDatabase admin \
  --db "$MONGO_DB" \
  --out "$TARGET"

echo "Backup created: $TARGET"
# Keep the newest 14 backup directories.
ls -1dt /backups/* 2>/dev/null | tail -n +15 | xargs -r rm -rf
