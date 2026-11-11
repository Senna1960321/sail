#!/bin/sh
# Check tree, range BASE HEAD, index, or message FILE. See docs/contributing.md.
set -eu
exec python3 "$(dirname "$0")/sensitive-check.py" "$@"
