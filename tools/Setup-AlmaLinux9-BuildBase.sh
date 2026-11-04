#!/bin/bash
# Prepare an AlmaLinux 9 machine as the SAT Linux GUI build base.
#
# Why AlmaLinux 9
# ---------------
# A Linux binary runs on its build machine's glibc and anything NEWER, never older. Building on a
# current Ubuntu produces a package needing glibc 2.38+, which excludes every enterprise release a
# customer actually runs. AlmaLinux 9 is a RHEL 9 rebuild with glibc 2.34, so a GUI built here
# reaches RHEL/Alma/Rocky 9, Ubuntu 22.04 LTS, Debian 12 and SLES 15 SP4 - the versions in the
# field - while still running on everything newer.
#
# It is not the lowest possible floor. RHEL 8 (glibc 2.28) reaches further back, but no RHEL 8
# repository packages Qt 6, so that base costs a full Qt build from source. The CLI package covers
# those older machines instead, which is the whole reason the two are packaged separately.
#
# Run as root inside the AlmaLinux 9 WSL instance:
#   wsl -d AlmaLinux-9 -u root -- bash tools/Setup-AlmaLinux9-BuildBase.sh
set -uo pipefail

say()  { printf '\n== %s ==\n' "$1"; }
warn() { printf 'WARNING: %s\n' "$1" >&2; }
fail() { printf 'FAILED: %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" = "0" ] || fail "run this as root (wsl -d AlmaLinux-9 -u root)"

say "system"
cat /etc/redhat-release
ldd --version | head -1

# EPEL FIRST. ninja-build, patchelf and Qt 6 are not in the AlmaLinux base repositories, and dnf
# fails an entire transaction when a single package is missing rather than installing the rest -
# which is exactly how the first attempt at this lost the whole toolchain over ninja.
say "EPEL (ninja, patchelf and Qt 6 live here, not in base)"
dnf -y install epel-release > /tmp/sat-epel.log 2>&1 \
  || { tail -20 /tmp/sat-epel.log; fail "epel-release install"; }
echo "  installed"

# Install one package at a time and report what is missing, rather than losing everything to a
# single bad name. Slower, but it says which package is the problem instead of hiding it.
install_each() {
  local missing=()
  for pkg in "$@"; do
    if rpm -q "$pkg" > /dev/null 2>&1; then
      continue
    fi
    if ! dnf -y install "$pkg" >> /tmp/sat-install.log 2>&1; then
      missing+=("$pkg")
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    printf '  could not install: %s\n' "${missing[*]}"
    return 1
  fi
  return 0
}

say "base toolchain"
: > /tmp/sat-install.log
# perl-core is needed to configure OpenSSL from source; the rest is the ordinary build set.
install_each gcc gcc-c++ make cmake git patch perl-core python3 python3-pip \
             zlib-devel bzip2-devel xz-devel libzstd-devel libxml2-devel openssl-devel \
             binutils tar gzip || warn "some base packages are missing (see above)"
echo "  done"

say "ninja"
if ! install_each ninja-build; then
  warn "ninja-build unavailable; falling back to pip"
  pip3 install --quiet ninja >> /tmp/sat-install.log 2>&1 || warn "pip ninja failed too"
fi
# RHEL-family packages the binary as 'ninja-build'; CMake looks for 'ninja'.
if ! command -v ninja > /dev/null 2>&1 && command -v ninja-build > /dev/null 2>&1; then
  ln -sf "$(command -v ninja-build)" /usr/local/bin/ninja
  echo "  linked ninja-build -> ninja"
fi
echo "  ninja: $(ninja --version 2>/dev/null || echo ABSENT)"

say "Qt 6 and patchelf"
install_each qt6-qtbase-devel qt6-qtsvg-devel qt6-qttools-devel patchelf \
  || warn "some Qt 6 packages are missing - the GUI will not configure without qt6-qtbase-devel"
echo "  done"

say "versions"
printf '  gcc     : %s\n' "$(gcc --version 2>/dev/null | head -1 || echo absent)"
printf '  cmake   : %s\n' "$(cmake --version 2>/dev/null | head -1 || echo absent)"
printf '  ninja   : %s\n' "$(ninja --version 2>/dev/null || echo absent)"
printf '  qt6base : %s\n' "$(rpm -q qt6-qtbase 2>/dev/null || echo absent)"
printf '  patchelf: %s\n' "$(patchelf --version 2>/dev/null || echo absent)"
printf '  glibc   : %s\n' "$(ldd --version | head -1 | grep -oE '[0-9]+\.[0-9]+$')"

# SAT requires CMake 3.25 or newer. RHEL 9 has shipped 3.20 and 3.26 depending on the minor
# release, so check rather than assume, and fall back to a pip build which is self-contained and
# does not disturb the distribution package.
say "CMake version check (SAT requires >= 3.25)"
have="$(cmake --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
if [ -z "$have" ]; then
  warn "cmake is not installed"
else
  major="${have%%.*}"; rest="${have#*.}"; minor="${rest%%.*}"
  if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 25 ]; }; then
    echo "  cmake $have is sufficient"
  else
    echo "  cmake $have is too old; installing a newer one via pip"
    pip3 install --quiet --upgrade cmake >> /tmp/sat-install.log 2>&1 \
      || fail "cmake upgrade failed (see /tmp/sat-install.log)"
    hash -r
    echo "  now: $(cmake --version | head -1)"
  fi
fi

# A C++20-capable compiler. MEASURED, not assumed: AlmaLinux 9's stock GCC 11.5 fails to build SAT
# with "'clock_cast' is not a member of 'std::chrono'" - libstdc++ 11 has only partial C++20
# <chrono>. SAT uses clock_cast in src/core/filesystem/filesystem_scanner_posix.cpp to convert a
# file timestamp for change detection, and the usual portable workaround
# (timestamp - file_clock::now() + system_clock::now()) is NOT safe there: the skew between the two
# now() calls would make an unchanged file look modified between two baseline runs.
#
# Red Hat ships newer compilers as "toolsets" that install alongside the system one. Qt's own
# supported-platform table expects exactly this on RHEL, so it is the normal arrangement rather
# than a workaround.
say "gcc-toolset (C++20 compiler)"
toolset=""
for candidate in gcc-toolset-14 gcc-toolset-13; do
  if dnf -y install "$candidate" >> /tmp/sat-install.log 2>&1; then toolset="$candidate"; break; fi
done
if [ -n "$toolset" ]; then
  echo "  installed $toolset"
  echo "$toolset" > /root/.sat-toolset
else
  warn "no gcc-toolset available; the stock GCC 11.5 cannot build SAT"
fi

say "C++20 check"
cat > /tmp/cxx20test.cpp <<'CPP'
#include <version>
#include <string>
#include <vector>
#include <algorithm>
#include <ranges>
#include <optional>
#include <chrono>
#include <filesystem>
int main() {
  std::vector<int> v{3, 1, 2};
  std::ranges::sort(v);
  std::optional<std::string> s{"ok"};
  // The feature that actually fails on stock GCC 11.5.
  const auto ft = std::filesystem::file_time_type::clock::now();
  const auto st = std::chrono::clock_cast<std::chrono::system_clock>(ft);
  (void)st;
  return (v.front() == 1 && s && *s == "ok") ? 0 : 1;
}
CPP
# Test what SAT actually needs - clock_cast - not just that some C++20 compiles.
cat >> /tmp/cxx20test.cpp <<'CPP2'
CPP2
if [ -n "$toolset" ]; then
  if scl enable "$toolset" -- bash -c 'g++ -std=c++20 -o /tmp/cxx20test /tmp/cxx20test.cpp'        > /tmp/sat-cxx.log 2>&1 && /tmp/cxx20test; then
    echo "  C++20 inside $toolset: OK"
    scl enable "$toolset" -- g++ --version | head -1 | sed 's/^/  compiler: /'
  else
    warn "C++20 test failed even inside $toolset"
    tail -12 /tmp/sat-cxx.log
  fi
else
  warn "no toolset installed; stock GCC will fail on clock_cast"
fi

say "ready"
echo "Build INSIDE the toolset shell - the stock GCC cannot compile SAT:"
echo "  scl enable \$(cat /root/.sat-toolset) -- bash tools/dev/Build-On-Alma.sh --gui"
echo
echo "Next, from the source tree:"
echo "  bash tools/Build-ThirdParty-Linux.sh --prefix \$HOME/sat-thirdparty"
echo "  cmake -S . -B out/build/alma9-qt -G Ninja -DCMAKE_BUILD_TYPE=Release \\"
echo "        -DCMAKE_PREFIX_PATH=\$HOME/sat-thirdparty -DSUPPORT_ASSIST_BUILD_GUI=ON \\"
echo "        -DSUPPORT_ASSIST_LINUX_QT=ON -DSUPPORT_ASSIST_PORTABLE_RUNTIME=ON"
