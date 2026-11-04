#!/usr/bin/env bash
# SAT macOS build wrapper requires Bash. If an operator launches it with `sh`,
# re-enter Bash before any bash-only syntax is evaluated.
if [ -z "${BASH_VERSION:-}" ]; then
  exec /usr/bin/env bash "$0" "$@"
fi
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Build-macOS.sh must run on macOS. Visual Studio may orchestrate it over SSH, but Apple Clang/Cocoa linking must execute on a Mac." >&2
  exit 69
fi

clean=0
test_build=0
headless=0
package_build=0
allow_insecure_dependencies=0
sign_identity="-"
while (($#)); do
  case "$1" in
    --clean) clean=1; shift ;;
    --test) test_build=1; shift ;;
    --headless) headless=1; shift ;;
    --package) package_build=1; shift ;;
    --allow-insecure-dependencies) allow_insecure_dependencies=1; shift ;;
    --sign-identity)
      [[ $# -ge 2 ]] || { echo "--sign-identity requires a value" >&2; exit 64; }
      sign_identity="$2"; shift 2 ;;
    -h|--help)
      echo "usage: $0 [--clean] [--test] [--headless] [--package] [--sign-identity ID] [--allow-insecure-dependencies]"
      echo "  default: build native Cocoa GUI + CLI Release"
      echo "  --package: embed non-system runtime dylibs into the .app and create a ZIP"
      echo "  --allow-insecure-dependencies: developer-only package when dependency security floor is not met"
      exit 0 ;;
    *) echo "usage: $0 [--clean] [--test] [--headless] [--package] [--sign-identity ID] [--allow-insecure-dependencies]" >&2; exit 64 ;;
  esac
done

if (( headless )); then
  debug_preset="macos-headless-debug"
  release_preset="macos-headless-release"
else
  debug_preset="macos-native-debug"
  release_preset="macos-native-release"
fi

extra_cmake=()
if command -v brew >/dev/null 2>&1; then
  prefixes=()
  for formula in libarchive sqlite openssl@3 libssh2 unixodbc; do
    if prefix="$(brew --prefix "$formula" 2>/dev/null)"; then prefixes+=("$prefix"); fi
  done
  if (( ${#prefixes[@]} > 0 )); then
    prefix_path="$(IFS=';'; echo "${prefixes[*]}")"
    extra_cmake+=("-DCMAKE_PREFIX_PATH=$prefix_path")
  fi
fi

if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake is required. Run: ./tools/Install-macOS-Build-Prereqs.sh --install" >&2
  exit 69
fi

jobs="$(sysctl -n hw.logicalcpu 2>/dev/null || echo 4)"
if [[ "$jobs" -gt 8 ]]; then jobs=8; fi

if (( clean )); then
  rm -rf "out/build/$debug_preset" "out/build/$release_preset"
fi

if (( test_build )); then
  cmake --preset "$debug_preset" "${extra_cmake[@]}"
  cmake --build --preset "$debug_preset" --parallel "$jobs"
  ctest --preset "$debug_preset" --output-on-failure
fi

cmake --preset "$release_preset" "${extra_cmake[@]}"
cmake --build --preset "$release_preset" --parallel "$jobs"

binary="$root/out/build/$release_preset/SupportAssistTool"
if (( ! headless )); then
  bundle_binary="$root/out/build/$release_preset/SupportAssistTool.app/Contents/MacOS/SupportAssistTool"
  if [[ -x "$bundle_binary" ]]; then binary="$bundle_binary"; fi
fi
"$binary" version
"$binary" capabilities --json
printf 'macOS build: %s\n' "$binary"
if (( ! headless )); then
  printf 'Launch GUI: open "%s"\n' "$root/out/build/$release_preset/SupportAssistTool.app"
fi

if (( package_build )); then
  if (( headless )); then
    echo "Self-contained .app packaging is not defined for --headless." >&2
    exit 64
  fi
  package_args=(--app "$root/out/build/$release_preset/SupportAssistTool.app" --sign-identity "$sign_identity")
  (( allow_insecure_dependencies )) && package_args+=(--allow-insecure-dependencies)
  "$root/tools/Package-macOS.sh" "${package_args[@]}"
fi
