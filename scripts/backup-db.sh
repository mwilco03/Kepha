#!/bin/sh
# scripts/backup-db.sh — SQLite database backup with retention.
# Safe for WAL-mode databases (uses .backup command).
#
# Usage: scripts/backup-db.sh [db_path] [backup_dir] [retention_days]
#
# Intended to run daily via cron or OpenRC cron:
#   echo "0 2 * * * /usr/local/bin/backup-db.sh" | crontab -

set -eu

DB_PATH="${1:-/var/lib/gatekeeper/gatekeeper.db}"
BACKUP_DIR="${2:-/var/lib/gatekeeper/backups}"
RETENTION_DAYS="${3:-7}"

if [ ! -f "$DB_PATH" ]; then
    echo "Database not found: $DB_PATH" >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"

BACKUP_FILE="${BACKUP_DIR}/gatekeeper-$(date +%Y%m%d-%H%M%S).db"

# sqlite3 .backup is the only safe way to copy a WAL-mode database.
sqlite3 "$DB_PATH" ".backup '$BACKUP_FILE'"

if [ -f "$BACKUP_FILE" ]; then
    echo "Backup created: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
else
    echo "Backup failed" >&2
    exit 1
fi

# Prune old backups.
find "$BACKUP_DIR" -name "gatekeeper-*.db" -mtime +"$RETENTION_DAYS" -delete
REMAINING=$(find "$BACKUP_DIR" -name "gatekeeper-*.db" | wc -l)
echo "Retention: keeping $REMAINING backup(s) within ${RETENTION_DAYS} days"
