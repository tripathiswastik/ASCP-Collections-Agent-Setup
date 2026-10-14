#!/usr/bin/env bash
# ==============================================================================
# Wait for a Docker container to report healthy status.
# Usage: ./scripts/wait_for_container.sh [container_name] [max_attempts]
# ==============================================================================
set -euo pipefail

CONTAINER_NAME="${1:-ascp-diagnostic-agent}"
MAX_ATTEMPTS="${2:-30}"
DELAY_SECONDS="${3:-2}"

echo "[*] Waiting for container '${CONTAINER_NAME}' to report healthy status (max ${MAX_ATTEMPTS} attempts)..."

i=0
STATUS='"unknown"'
while [ "$i" -lt "$MAX_ATTEMPTS" ]; do
  STATUS=$(docker inspect --format='{{json .State.Health.Status}}' "${CONTAINER_NAME}" 2>/dev/null || echo '"unknown"')
  echo "Attempt $((i + 1))/${MAX_ATTEMPTS}: ${CONTAINER_NAME} health = ${STATUS}"

  if [ "${STATUS}" = '"healthy"' ]; then
    echo "[+] Container '${CONTAINER_NAME}' is healthy!"
    exit 0
  fi

  i=$((i + 1))
  sleep "${DELAY_SECONDS}"
done

echo "[-] ERROR: Container '${CONTAINER_NAME}' did not become healthy within ${MAX_ATTEMPTS} attempts (last status: ${STATUS})" >&2
echo "[*] Container logs:" >&2
docker logs --tail 50 "${CONTAINER_NAME}" >&2 || true
exit 1
