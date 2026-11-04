#!/usr/bin/env bash
# If a user explicitly invokes this Bash script with `sh`, recover cleanly instead
# of letting dash report opaque "Bad substitution" / "[[ not found" errors.
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if ! command -v cmake >/dev/null 2>&1; then
  echo "CMake is not installed. Run: ./tools/Install-Linux-Build-Prereqs.sh --install" >&2
  exit 69
fi

clean=0
test_build=0
headless=0
package_build=0
allow_new_glibc=0
allow_insecure_dependencies=0
for arg in "$@"; do
  case "$arg" in
    --clean) clean=1 ;;
    --test) test_build=1 ;;
    --headless) headless=1 ;;
    --package) package_build=1 ;;
    --allow-new-glibc) allow_new_glibc=1 ;;
    --allow-insecure-dependencies) allow_insecure_dependencies=1 ;;
    -h|--help)
      echo "usage: $0 [--clean] [--test] [--headless] [--package] [--allow-new-glibc] [--allow-insecure-dependencies]"
      echo "  default: build native Linux X11 GUI + CLI Release"
      echo "  --test: Debug build + CTest + safe functional/tool validation, then Release"
      echo "  --package: create self-contained runtime package after Release"
      echo "  --allow-new-glibc: permit developer package on a host newer than glibc 2.28"
      echo "  --allow-insecure-dependencies: developer-only package when dependency security floor is not met"
      exit 0 ;;
    *) echo "usage: $0 [--clean] [--test] [--headless] [--package] [--allow-new-glibc] [--allow-insecure-dependencies]" >&2; exit 64 ;;
  esac
done

if (( headless )); then
  debug_preset="linux-headless-debug"
  release_preset="linux-headless-release"
else
  debug_preset="linux-native-debug"
  release_preset="linux-native-release"
fi

jobs=2
if command -v nproc >/dev/null 2>&1; then jobs="$(nproc)"; fi
if [[ "$jobs" -gt 8 ]]; then jobs=8; fi

if (( clean )); then
  rm -rf "out/build/$debug_preset" "out/build/$release_preset"
fi

if (( test_build )); then
  cmake --preset "$debug_preset"
  cmake --build --preset "$debug_preset" --parallel "$jobs"
  ctest --preset "$debug_preset" --output-on-failure
  "$root/tools/Test-Linux-Functional.sh" \
    "$root/out/build/$debug_preset/SupportAssistTool" \
    "$root/out/linux-functional-test-report.txt"
fi

cmake --preset "$release_preset"
cmake --build --preset "$release_preset" --parallel "$jobs"

binary="$root/out/build/$release_preset/SupportAssistTool"
"$binary" version
"$binary" capabilities --json
printf 'Linux build: %s\n' "$binary"
if (( ! headless )); then
  printf 'Launch the GUI from a graphical session with: %s\n' "$binary"
fi

if (( package_build )); then
  if (( headless )); then
    echo "Self-contained GUI packaging is currently defined for the native Linux GUI build, not --headless." >&2
    exit 64
  fi
  package_args=()
  (( allow_new_glibc )) && package_args+=(--allow-new-glibc)
  (( allow_insecure_dependencies )) && package_args+=(--allow-insecure-dependencies)
  "$root/tools/Package-Linux.sh" --binary "$binary" "${package_args[@]}"
fi
