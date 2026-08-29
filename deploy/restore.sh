#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 /backups/YYYYMMDDTHHMMSSZ" >&2
  exit 2
fi
BACKUP="$1"
if [ ! -d "$BACKUP/$MONGO_DB" ]; then
  echo "Backup database directory not found: $BACKUP/$MONGO_DB" >&2
  exit 1
fi

mongorestore \
  --host mongo:27017 \
  --username "$MONGO_ROOT_USERNAME" \
  --password "$MONGO_ROOT_PASSWORD" \
  --authenticationDatabase admin \
  --db "$MONGO_DB" \
  --drop "$BACKUP/$MONGO_DB"
