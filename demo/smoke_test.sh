#!/usr/bin/env sh
# Runs the Hunt-005 demo in Docker and fails (non-zero) if any scenario
# did not behave as expected. Suitable for CI.
set -eu
cd "$(dirname "$0")"
docker compose up --build --abort-on-container-exit --exit-code-from hunt-005-demo
status=$?
docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
exit $status
