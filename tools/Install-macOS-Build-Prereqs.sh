#!/usr/bin/env bash
# Installs or reports the native macOS SAT build prerequisites.
if [ -z "${BASH_VERSION:-}" ]; then
  exec /usr/bin/env bash "$0" "$@"
fi
set -euo pipefail

install=0
for arg in "$@"; do
  case "$arg" in
    --install) install=1 ;;
    -h|--help)
      echo "usage: $0 [--install]"
      echo "Without --install, report the required commands/formulae."
      exit 0 ;;
    *) echo "usage: $0 [--install]" >&2; exit 64 ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This prerequisite helper must run on macOS." >&2
  exit 69
fi

cat <<'MSG'
Support Assist Tool native macOS DEVELOPER build prerequisites:
  - Apple Command Line Tools / Apple Clang
  - CMake
  - Ninja
  - Python 3 (packaging/security SBOM gate)
  - libarchive
  - SQLite
  - OpenSSL 3
  - libssh2 (SSH/SFTP Explorer and Remote Console)
  - unixODBC (native SQL Tools ODBC path)

The native AppKit GUI is built with Apple frameworks supplied by macOS/Xcode.
These packages are for compiling SAT; the packaged .app embeds SAT-owned third-party runtime dylibs so engineers do not need Homebrew merely to launch SAT.
MSG

if (( ! install )); then
  echo
  echo "Re-run with --install to use Homebrew for the non-Apple dependencies."
  exit 0
fi

if ! xcode-select -p >/dev/null 2>&1; then
  echo "Apple Command Line Tools are not installed. Starting Apple's installer..." >&2
  xcode-select --install || true
  echo "Complete the Apple Command Line Tools installation, then re-run this command." >&2
  exit 69
fi

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is not available. Install the dependencies with your approved package-management method, then run tools/Build-macOS.sh." >&2
  exit 69
fi

brew install cmake ninja python libarchive sqlite openssl@3 libssh2 unixodbc

echo "macOS build prerequisites installed/reconciled."
echo "Next: ./tools/Build-macOS.sh --clean --test"
