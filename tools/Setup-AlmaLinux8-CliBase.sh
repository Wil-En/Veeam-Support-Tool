#!/bin/bash
# Prepare an AlmaLinux 8 machine as the SAT Linux CLI build base.
#
# Why AlmaLinux 8
# ---------------
# glibc 2.28. A CLI built here reaches RHEL/Alma/Rocky 8+, Debian 10+ and Ubuntu 20.04+ - the
# customer servers SAT is carried onto. The GUI cannot use this base because no RHEL 8 repository
# packages Qt 6, which is exactly why the GUI and CLI are packaged separately: the CLI has no Qt
# dependency, so it can go lower.
#
# Two things about RHEL 8 that this script exists to handle:
#
#   * The default compiler is GCC 8.5, which CANNOT compile C++20. Red Hat ships newer compilers
#     as "toolsets" that install alongside rather than replacing the system one, so the build must
#     be run inside `scl enable gcc-toolset-13 bash`.
#   * The packaged CMake is older than the 3.25 SAT requires, so a newer one comes from pip.
#
# Run as root inside the AlmaLinux 8 WSL instance:
#   wsl -d AlmaLinux-8 -u root -- bash tools/Setup-AlmaLinux8-CliBase.sh
set -uo pipefail

say()  { printf '\n== %s ==\n' "$1"; }
warn() { printf 'WARNING: %s\n' "$1" >&2; }
fail() { printf 'FAILED: %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" = "0" ] || fail "run this as root (wsl -d AlmaLinux-8 -u root)"

say "system"
cat /etc/redhat-release
ldd --version | head -1

say "EPEL"
dnf -y install epel-release > /tmp/sat-epel.log 2>&1 \
  || { tail -20 /tmp/sat-epel.log; fail "epel-release install"; }
echo "  installed"

# One package at a time, so a single missing name reports itself instead of losing the transaction.
install_each() {
  local missing=()
  for pkg in "$@"; do
    rpm -q "$pkg" > /dev/null 2>&1 && continue
    dnf -y install "$pkg" >> /tmp/sat-install.log 2>&1 || missing+=("$pkg")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    printf '  could not install: %s\n' "${missing[*]}"
    return 1
  fi
  return 0
}

say "base packages"
: > /tmp/sat-install.log
install_each make git patch perl-core python3 python3-pip \
             zlib-devel bzip2-devel xz-devel libzstd-devel libxml2-devel openssl-devel \
             binutils tar gzip curl file findutils which \
  || warn "some base packages are missing (see above)"
echo "  done"

# The C++20 compiler. gcc-toolset-13 installs to /opt/rh and does not disturb the system GCC.
say "gcc-toolset (C++20 compiler)"
toolset=""
for candidate in gcc-toolset-14 gcc-toolset-13 gcc-toolset-12; do
  if dnf -y install "$candidate" >> /tmp/sat-install.log 2>&1; then
    toolset="$candidate"
    break
  fi
done
[ -n "$toolset" ] || fail "no gcc-toolset available; SAT needs a C++20 compiler and RHEL 8's GCC 8.5 is not one"
echo "  installed $toolset"
echo "$toolset" > /root/.sat-toolset

say "cmake and ninja"
# RHEL 8's cmake is older than SAT's 3.25 requirement, and ninja is not packaged at all.
pip3 install --quiet --upgrade cmake ninja >> /tmp/sat-install.log 2>&1 \
  || warn "pip install of cmake/ninja failed (see /tmp/sat-install.log)"
hash -r
printf '  cmake : %s\n' "$(cmake --version 2>/dev/null | head -1 || echo absent)"
printf '  ninja : %s\n' "$(ninja --version 2>/dev/null || echo absent)"

say "C++20 check inside the toolset"
cat > /tmp/cxx20test.cpp <<'CPP'
#include <version>
#include <string>
#include <vector>
#include <algorithm>
#include <ranges>
#include <optional>
int main() {
  std::vector<int> v{3, 1, 2};
  std::ranges::sort(v);
  std::optional<std::string> s{"ok"};
  return (v.front() == 1 && s && *s == "ok") ? 0 : 1;
}
CPP
if scl enable "$toolset" -- bash -c 'g++ --version | head -1; g++ -std=c++20 -o /tmp/cxx20test /tmp/cxx20test.cpp' \
   > /tmp/sat-cxx.log 2>&1 && /tmp/cxx20test; then
  echo "  C++20 with ranges: OK"
  sed -n '1p' /tmp/sat-cxx.log | sed 's/^/  compiler: /'
else
  warn "C++20 test failed even inside $toolset"
  tail -12 /tmp/sat-cxx.log
fi

say "glibc floor this base produces"
printf '  glibc : %s  -> CLI reaches RHEL 8+, Debian 10+, Ubuntu 20.04+\n' \
  "$(ldd --version | head -1 | grep -oE '[0-9]+\.[0-9]+$')"

say "ready"
echo "Everything must run inside the toolset shell. From the source tree:"
echo "  scl enable $toolset -- bash tools/Build-ThirdParty-Linux.sh --prefix /root/sat-thirdparty"
echo "  scl enable $toolset -- bash tools/dev/Build-On-Alma.sh --cli --build-dir /root/alma8-cli"
