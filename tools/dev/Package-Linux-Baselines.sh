#!/bin/bash
# Build and package a Linux deliverable on its documented compatibility baseline.
#
# Run inside the WSL instance that matches the profile, as root, from the source tree:
#   AlmaLinux 9 (glibc 2.34)   bash tools/dev/Package-Linux-Baselines.sh --gui
#   AlmaLinux 8 (glibc 2.28)   bash tools/dev/Package-Linux-Baselines.sh --cli
#
# The two baselines are different KINDS of number and are not interchangeable. The CLI baseline is
# a product decision about which customer machines SAT must run on. The GUI baseline is imposed by
# Qt 6: no RHEL 8 repository packages it, so 2.34 is the lowest base that can build a Qt 6
# application without building Qt from source. Neither may be produced on the Ubuntu dev box - a
# binary runs on its build glibc and NEWER, never older, so that package would only work on
# distributions newer than the machine that built it.
#
# A script rather than an inline `wsl.exe -- bash -c`: the Windows shell expands $PATH first and
# injects directories like "C:\Program Files (x86)", whose parentheses are a bash syntax error.
set -uo pipefail

# Derived, never written literally. The version belongs to project-metadata.json, and a path
# spelled out here would go stale on the next fork - which is what the source-consistency
# pre-flight checks for.
if [ -f "$PWD/CMakeLists.txt" ]; then
  ROOT="$PWD"
else
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fi
cd "$ROOT" || exit 1

MODE=gui
SELFCHECK=OFF
while [ $# -gt 0 ]; do
  case "$1" in
    --gui) MODE=gui; shift ;;
    --cli) MODE=cli; shift ;;
    # A test package with the Qt self-check compiled in, for running the harness on a lab machine.
    # It goes to its own build, staging and output folders and is never delivered.
    --selfcheck) SELFCHECK=ON; shift ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done
if [ "$SELFCHECK" = ON ] && [ "$MODE" != gui ]; then
  echo "--selfcheck needs --gui" >&2; exit 64
fi
FLAVOUR="$MODE"
[ "$SELFCHECK" = ON ] && FLAVOUR="$MODE-selfcheck"

PREFIX=/root/sat-thirdparty
BUILD="$ROOT/out/build/alma-$FLAVOUR"
JOBS="$(nproc 2>/dev/null || echo 4)"

export PATH="/usr/local/bin:$PATH"

# The distribution GCC on AlmaLinux 9 is 11.5, whose libstdc++ has no std::chrono::clock_cast -
# SAT uses it to turn a POSIX file timestamp into a system_clock time point. gcc-toolset-14 is
# installed for exactly this; enter it here rather than relying on the caller's shell.
for toolset in /opt/rh/gcc-toolset-14 /opt/rh/gcc-toolset-13; do
  if [ -f "$toolset/enable" ]; then
    # shellcheck disable=SC1090
    . "$toolset/enable"
    break
  fi
done

echo "== $MODE package on $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}"), glibc $(ldd --version | head -1 | awk '{print $NF}')"

if [ "$MODE" = gui ]; then
  GUI_ARGS="-DSUPPORT_ASSIST_BUILD_GUI=ON -DSUPPORT_ASSIST_LINUX_QT=ON"
else
  # --as-needed: a library the CLI imports nothing from (libssh2; SSH is the GUI's Remote page)
  # is not a dependency, so the package does not carry it.
  GUI_ARGS="-DSUPPORT_ASSIST_BUILD_GUI=OFF -DCMAKE_EXE_LINKER_FLAGS=-Wl,--as-needed"
fi

# A packaging run configures clean. CMake caches CMAKE_CXX_COMPILER on first configure, so a build
# directory created before the toolset was enabled keeps using the system GCC no matter what is on
# PATH - which is how "clock_cast is not a member of std::chrono" survived enabling gcc-toolset-14.
rm -rf "$BUILD"

echo "   compiler: $(g++ --version | head -1)"

# Object storage prices, refreshed before every build; never fails the build.
bash tools/dev/check-object-storage-prices.sh

# shellcheck disable=SC2086
cmake -S . -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$PREFIX" \
  $GUI_ARGS \
  -DSUPPORT_ASSIST_PORTABLE_RUNTIME=ON \
  -DSUPPORT_ASSIST_ENABLE_LIBARCHIVE=ON \
  -DSUPPORT_ASSIST_BUILD_TESTS=OFF \
  -DSUPPORT_ASSIST_UI_SELFCHECK="$SELFCHECK" \
  -DSUPPORT_ASSIST_OBJECT_STORAGE_CHECK=OFF \
  -DSUPPORT_ASSIST_STRICT_WARNINGS=ON > "/tmp/sat-cfg-$FLAVOUR.log" 2>&1
if [ $? -ne 0 ]; then
  echo "CONFIGURE FAILED"; tail -20 "/tmp/sat-cfg-$FLAVOUR.log"; exit 1
fi
# A package never carries the Object Storage Check (test builds only).
if ! grep -q '^SUPPORT_ASSIST_OBJECT_STORAGE_CHECK:BOOL=OFF$' "$BUILD/CMakeCache.txt"; then
  echo "REFUSED: the Object Storage Check is switched on in $BUILD"; exit 1
fi

errs=$(cmake --build "$BUILD" -j"$JOBS" 2>&1 | grep -E "error:" | head -5)
if [ -n "$errs" ]; then
  echo "BUILD ERRORS:"; echo "$errs"; exit 1
fi
echo "   build ok: $("$BUILD/SupportAssistTool" version 2>&1 | head -1)"

# Package into the WSL filesystem, not /mnt/e. DrvFs reports every file as mode 0777, so the
# packaging hardening check that refuses to ship a world-writable runtime library fires on every
# bundled .so - a property of the mount, not of the package. Staging natively keeps that check
# meaningful; the finished tarball is copied back afterwards.
STAGE="/root/sat-packages-$FLAVOUR"
rm -rf "$STAGE"
mkdir -p "$STAGE"

bash tools/Package-Linux.sh --binary "$BUILD/SupportAssistTool" \
     --output "$STAGE" --profile "$MODE"
status=$?
if [ $status -ne 0 ]; then
  echo "PACKAGING FAILED ($status)"
  exit $status
fi

mkdir -p "$ROOT/out/packages-$FLAVOUR"
cp -f "$STAGE"/*.tar.gz "$ROOT/out/packages-$FLAVOUR/" 2>/dev/null
cp -f "$STAGE"/*/SupportAssistTool "$ROOT/out/packages-$FLAVOUR/" 2>/dev/null
echo "   delivered:"
ls -la "$ROOT/out/packages-$FLAVOUR/" | sed "s/^/     /"
