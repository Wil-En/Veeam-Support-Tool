#!/usr/bin/env bash
# If a user explicitly invokes this Bash script with `sh`, recover cleanly instead
# of letting dash report opaque "Bad substitution" / "[[ not found" errors.
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi
set -euo pipefail

install=0
headless=0
for arg in "$@"; do
  case "$arg" in
    --install) install=1 ;;
    --headless) headless=1 ;;
    -h|--help)
      echo "usage: $0 [--install] [--headless]"
      echo "Developer build prerequisites only. Finished SAT runtime packages do not require these packages on the engineer workstation. Without --install, prints the detected package-manager command only."
      exit 0 ;;
    *) echo "usage: $0 [--install] [--headless]" >&2; exit 64 ;;
  esac
done

if [[ ! -r /etc/os-release ]]; then
  echo "Cannot identify this Linux distribution (/etc/os-release missing)." >&2
  exit 69
fi
# shellcheck disable=SC1091
# Qt is included by default because it is what the Linux frontend is being built on.
# --no-qt skips it for a CLI-only or headless build host.
qt=1
for arg in "$@"; do [[ "$arg" == "--no-qt" ]] && qt=0; done

source /etc/os-release
family="${ID,,} ${ID_LIKE:-}"

cmd=()
if [[ "$family" == *debian* || "$family" == *ubuntu* ]]; then
  packages=(build-essential cmake ninja-build pkg-config python3 libsqlite3-dev libarchive-dev libssl-dev libssh2-1-dev unixodbc-dev patchelf)
  (( headless )) || packages+=(libx11-dev)
  # The Qt frontend is the current Linux edition (docs/DESIGN_LINUX_GUI.md). Qt is a BUILD-host
  # dependency only: released packages carry their own Qt under ./lib, so a customer machine
  # never needs it installed.
  (( headless )) || (( qt )) && packages+=(qt6-base-dev libgl1-mesa-dev)
  cmd=(sudo apt-get install -y "${packages[@]}")
elif [[ "$family" == *rhel* || "$family" == *fedora* || "$family" == *rocky* || "$family" == *almalinux* || "$family" == *ol* || "$family" == *amzn* ]]; then
  packages=(gcc-c++ cmake ninja-build pkgconf-pkg-config python3 sqlite-devel libarchive-devel openssl-devel libssh2-devel unixODBC-devel patchelf)
  (( headless )) || packages+=(libX11-devel)
  (( headless )) || (( qt )) && packages+=(qt6-qtbase-devel mesa-libGL-devel)
  if command -v dnf >/dev/null 2>&1; then cmd=(sudo dnf install -y "${packages[@]}"); else cmd=(sudo yum install -y "${packages[@]}"); fi
elif [[ "$family" == *suse* || "$family" == *sles* || "$family" == *opensuse* ]]; then
  packages=(gcc-c++ cmake ninja pkg-config python3 sqlite3-devel libarchive-devel libopenssl-devel libssh2-devel unixODBC-devel patchelf)
  (( headless )) || packages+=(libX11-devel)
  (( headless )) || (( qt )) && packages+=(qt6-base-devel Mesa-libGL-devel)
  cmd=(sudo zypper --non-interactive install "${packages[@]}")
else
  echo "Distribution family not mapped automatically: ID=${ID:-unknown} ID_LIKE=${ID_LIKE:-unknown}" >&2
  echo "Developer build requirements: C++20 compiler, CMake >= 3.25, Ninja, Python 3, SQLite3, OpenSSL, libarchive, libssh2 and ODBC development headers, patchelf, and X11 development headers for GUI. These are not end-user runtime prerequisites." >&2
  exit 69
fi

printf 'Detected: %s %s\n' "${NAME:-$ID}" "${VERSION_ID:-}"
printf 'Command:'
printf ' %q' "${cmd[@]}"
printf '\n'

if (( install )); then
  if command -v apt-get >/dev/null 2>&1; then sudo apt-get update; fi
  "${cmd[@]}"
fi
