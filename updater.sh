#!/bin/sh
# Update this NoFlagVPN checkout.  The work is done by updater.py, so that the
# shell, batch and direct invocations all behave the same; this script only
# finds an interpreter and hands over.
#
#   ./updater.sh              update to the tip of this branch
#   ./updater.sh --check      report whether an update exists (exit 10 if yes)
#   ./updater.sh --force      update even with local changes (they are stashed)
#
# NoFlagVPN needs Python 3.10+ to run, so a Python interpreter is guaranteed to
# exist wherever this is useful.

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ -n "${NFVPN_PYTHON:-}" ]; then
    python=$NFVPN_PYTHON
elif command -v python3 >/dev/null 2>&1; then
    python=python3
elif command -v python >/dev/null 2>&1; then
    python=python
else
    echo "updater: no python3 on PATH; install Python 3.10+ or update with git pull" >&2
    exit 1
fi

# Prefer the checkout's own virtualenv when one exists: it is where nfvpn and
# its optional dependencies were installed, so the pip step lands in the right
# place.
if [ -x "$here/.venv/bin/python" ]; then
    python="$here/.venv/bin/python"
fi

exec "$python" "$here/updater.py" "$@"
