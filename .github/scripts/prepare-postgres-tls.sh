#!/usr/bin/env bash
# Upgrade only the disposable GitHub job's Postgres service. No production use.
set -euo pipefail
umask 077

task_container="${1:?expected job.services.postgres.id}"
[[ "$task_container" =~ ^[a-f0-9]{12,64}$ ]] || { echo 'Invalid service container ID' >&2; exit 1; }
: "${RUNNER_TEMP:?GitHub runner temporary directory is required}"
: "${GITHUB_ENV:?GitHub environment file is required}"
task_tls_root="$(mktemp -d "$RUNNER_TEMP/rauth-postgres-tls.XXXXXX")"
task_service_root=/tmp/rauth-ci-postgres-tls

# A disposable, narrowly trusted certificate; never install it in OS trust.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$task_tls_root/server.key" -out "$task_tls_root/server.crt" \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1' \
  -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1

docker exec --user root "$task_container" mkdir -p "$task_service_root"
docker cp "$task_tls_root/server.key" "$task_container:$task_service_root/server.key"
docker cp "$task_tls_root/server.crt" "$task_container:$task_service_root/server.crt"
docker exec --user root "$task_container" chown -R postgres:postgres "$task_service_root"
docker exec --user root "$task_container" chmod 700 "$task_service_root"
docker exec --user root "$task_container" chmod 600 "$task_service_root/server.key"

task_psql=(docker exec --user postgres "$task_container" psql -X -U postgres -d postgres -v ON_ERROR_STOP=1)
"${task_psql[@]}" -c "ALTER SYSTEM SET ssl_cert_file = '$task_service_root/server.crt'"
"${task_psql[@]}" -c "ALTER SYSTEM SET ssl_key_file = '$task_service_root/server.key'"
"${task_psql[@]}" -c 'ALTER SYSTEM SET ssl = on'
"${task_psql[@]}" -c 'SELECT pg_reload_conf()'
for task_attempt in {1..20}; do
  if [[ "$("${task_psql[@]}" -Atc 'SHOW ssl')" == on ]]; then break; fi
  sleep 0.25
done
[[ "$("${task_psql[@]}" -Atc 'SHOW ssl')" == on ]] || { echo 'Test PostgreSQL TLS did not activate' >&2; exit 1; }
# Exercise actual CA+hostname verification before publishing the runner URL.
docker exec --user postgres --env PGPASSWORD=test --env PGSSLMODE=verify-full \
  --env "PGSSLROOTCERT=$task_service_root/server.crt" "$task_container" \
  psql -X -h localhost -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -Atc 'SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()' | { read -r task_ssl; [[ "$task_ssl" == t ]]; }
printf 'RAUTH_TEST_DATABASE_URL=postgres://postgres:test@localhost:5432/postgres?sslmode=verify-full&sslrootcert=%s/server.crt\n' "$task_tls_root" >> "$GITHUB_ENV"
