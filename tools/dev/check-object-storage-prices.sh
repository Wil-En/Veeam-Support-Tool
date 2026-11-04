#!/bin/bash
# Refresh the object storage prices before a Linux build. The Windows builds do
# the same in tools/Build-Debug.ps1 and Build-Release.ps1. Never fails the build: a source that
# does not answer, or a host without Python 3, is a WARNING and the last known values stay in use.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="$here/tools/update_object_storage_prices.py"
python=""
if command -v python3 >/dev/null 2>&1; then
  python="python3"
elif [ -x /usr/libexec/platform-python ]; then
  python="/usr/libexec/platform-python"   # AlmaLinux 8 ships only the platform Python
fi
if [ -z "$python" ]; then
  echo "WARNING: object storage prices: no Python 3 on this build host; the last known values stay in use."
elif ! "$python" "$script"; then
  echo "WARNING: object storage prices: the price check did not finish; the last known values stay in use."
fi
exit 0
