#!/usr/bin/env sh
set -eu

detach=false
no_build=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --detach) detach=true ;;
    --no-build) no_build=true ;;
    *)
      printf '%s\n' "usage: $0 [--detach] [--no-build]" >&2
      exit 2
      ;;
  esac
  shift
done

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
if [ "$no_build" = true ]; then
  set -- \
    compose up \
    --no-build \
    --pull never \
    --no-deps \
    --abort-on-container-exit \
    --exit-code-from configcheck \
    configcheck
else
  set -- compose run --rm --build --no-deps configcheck
fi
docker "$@"

set -- compose up
if [ "$no_build" = true ]; then
  set -- "$@" --no-build --pull never
else
  set -- "$@" --build
fi
if [ "$detach" = true ]; then
  set -- "$@" --detach --wait
fi
exec docker "$@"
