#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
: "${IMAGE:?IMAGE is required}"

compose=(docker compose -f docker-compose.prod.yml)
api_container() { "${compose[@]}" ps -q api; }

# Keeps IMAGE in .env so plain "docker compose ps/logs/exec" work on the server.
remember_image() {
  touch .env
  if grep -q '^IMAGE=' .env; then
    sed -i.bak "s|^IMAGE=.*|IMAGE=$1|" .env && rm -f .env.bak
  else
    printf 'IMAGE=%s\n' "$1" >> .env
  fi
}

previous=""
if [ -n "$(api_container)" ]; then
  previous="$(docker inspect -f '{{.Config.Image}}' "$(api_container)")"
fi

export IMAGE
"${compose[@]}" pull api
"${compose[@]}" up -d --remove-orphans

for _ in $(seq 1 30); do
  status="$(docker inspect -f '{{.State.Health.Status}}' "$(api_container)" 2>/dev/null || echo starting)"
  if [ "$status" = "healthy" ]; then
    remember_image "$IMAGE"
    echo "deployed $IMAGE"
    exit 0
  fi
  sleep 3
done

echo "$IMAGE did not become healthy" >&2
"${compose[@]}" logs --tail 50 api >&2 || true

if [ -n "$previous" ] && [ "$previous" != "$IMAGE" ]; then
  echo "rolling back to $previous" >&2
  IMAGE="$previous" "${compose[@]}" up -d api
  remember_image "$previous"
fi
exit 1
