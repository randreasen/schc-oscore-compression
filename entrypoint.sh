#! /bin/bash
set -e

DEFAULT_DIR="/app"

if [[ -n "$DOCKER_APP_WORK_DIR" ]] && [[ "$DOCKER_APP_WORK_DIR" != "$DEFAULT_DIR" ]]; then
    echo "Got non-default dir: $DOCKER_APP_WORK_DIR"
    cd "$DOCKER_APP_WORK_DIR"
    export PYTHONPATH="$(pwd)"
fi

exec "$@"
