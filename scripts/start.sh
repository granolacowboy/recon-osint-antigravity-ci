#!/usr/bin/env sh
set -eu

detach=false
case "${1:-}" in
  "") ;;
  --detach) detach=true ;;
  *)
    printf '%s\n' "usage: $0 [--detach]" >&2
    exit 2
    ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
env_path="$repo_root/.env"
template_path="$repo_root/.env.example"

random_secret() {
  od -An -N48 -tx1 /dev/urandom | tr -d ' \n'
}

if [ ! -f "$env_path" ]; then
  umask 077
  redis_password=$(random_secret)
  neo4j_password=$(random_secret)
  sed \
    -e "s/REPLACE_WITH_RANDOM_REDIS_PASSWORD/$redis_password/g" \
    -e "s/REPLACE_WITH_RANDOM_NEO4J_PASSWORD/$neo4j_password/g" \
    "$template_path" > "$env_path"
  printf '%s\n' "Created .env with random local datastore credentials."
fi

if grep -q 'REPLACE_WITH_RANDOM_' "$env_path"; then
  printf '%s\n' ".env still contains credential placeholders; replace them before startup." >&2
  exit 1
fi

cd "$repo_root"
docker compose run --rm --build --no-deps configcheck
if [ "$detach" = true ]; then
  exec docker compose up --build --detach --wait
fi
exec docker compose up --build
