#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p backups

docker compose -f docker-compose.prod.yml exec -T db pg_dump -U oauth oauth | gzip > "backups/oauth-$(date +%F).sql.gz"
find backups -name 'oauth-*.sql.gz' -mtime +14 -delete
