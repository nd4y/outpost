#!/bin/sh
set -eu
: "${BACKUP_PATH:?export BACKUP_PATH}"
: "${NB_MANAGEMENT_URL:?export NB_MANAGEMENT_URL}"
: "${NB_HOSTNAME:?export NB_HOSTNAME}"
: "${OUTPOST_RSYNC_PASSWORD:?export OUTPOST_RSYNC_PASSWORD}"
if [ ! -d "$BACKUP_PATH" ]; then
  echo "Create a dedicated backup directory and grant UID/GID 65532 write access first." >&2
  exit 1
fi
docker network inspect outpost >/dev/null 2>&1 || docker network create outpost >/dev/null
exec docker run -d --name outpost --hostname "$NB_HOSTNAME" \
  --restart unless-stopped --network outpost \
  --user 65532:65532 --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 128 --memory "${OUTPOST_MEMORY_LIMIT:-1g}" --memory-swap "${OUTPOST_MEMORY_LIMIT:-1g}" --cpu-shares 256 \
  --stop-timeout 45 --log-opt max-size=5m --log-opt max-file=2 \
  --mount "type=bind,src=$BACKUP_PATH,dst=/data" \
  --mount type=volume,src=outpost-hardened-state,dst=/state \
  --tmpfs /run/outpost:rw,noexec,nosuid,nodev,size=4m,uid=65532,gid=65532,mode=0700 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700 \
  -e NB_MANAGEMENT_URL -e NB_HOSTNAME -e NB_SETUP_KEY \
  -e OUTPOST_METRICS_URL -e OUTPOST_LOGS_URL -e OUTPOST_TELEMETRY_TRANSPORT \
  -e OUTPOST_TELEMETRY_BUFFER -e OUTPOST_TELEMETRY_INTERVAL -e OUTPOST_TELEMETRY_TOKEN \
  -e OUTPOST_RSYNC_PASSWORD -e OUTPOST_RSYNC_USER=backup \
  "${OUTPOST_IMAGE:-ghcr.io/nd4y/outpost:edge}"
