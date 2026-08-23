#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 1 ] && [ "$1" = daemon ]; then
    exec /usr/bin/python3 \
        /source-install-lifecycle/test/fake-facelock-daemon.py
fi

echo "source-install daemon stub only supports daemon mode" >&2
exit 64
