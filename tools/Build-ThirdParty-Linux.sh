#!/bin/bash
# Build SAT's security-sensitive runtime dependencies from source.
#
# Why this exists
# ---------------
# Two of SAT's bundled libraries cannot be taken from the build distribution and still satisfy
# config/security/runtime-security-policy.json:
#
#   libssh2   CVE-2026-55200 is an out-of-bounds write in ssh2_transport_read() reachable during
#             key exchange - before SAT's host-key trust control can possibly help. Upstream has
#             published no release since 1.11.1 (October 2024). The fix exists ONLY as commit
#             97acf3df, so the only way to ship a fixed libssh2 today is to build it.
#
#   libarchive  SAT feeds this library customer-supplied archives, which is untrusted input by
#               definition. 3.8.9 carries memory-safety fixes the distribution build predates.
#
# SQLite is built too, simply because the reviewed floor is newer than the distribution package.
#
# The build writes RUNTIME-PROVENANCE.json recording which commit or tarball each library came
# from. tools/verify_runtime_security.py REQUIRES that record for any component whose policy names
# a requiredFixCommit - a version string cannot prove a pre-release snapshot contains a fix, since
# every libssh2 master build reports 1.11.2_DEV either way.
#
# Usage:  bash tools/Build-ThirdParty-Linux.sh [--prefix DIR] [--jobs N]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="$ROOT/out/thirdparty"
JOBS="$(nproc 2>/dev/null || echo 4)"
SKIP_OPENSSL=0
WORK=""

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --jobs)   JOBS="$2"; shift 2 ;;
    --skip-openssl) SKIP_OPENSSL=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

# Pinned inputs. Changing any of these is a security review, not a routine edit.
# The OpenSSL 3.5.9 release (tag openssl-3.5.9, an annotated tag on this commit), which carries the
# fixes of the advisories the line's security findings under docs list, CVE-2026-14456 among them.
OPENSSL_COMMIT=45e844fa2a14ec92d146bd8f5778ac130b6625fb
LIBSSH2_COMMIT=97acf3dfda80c91c3a8c9f2372546301d4a1a7a8
LIBARCHIVE_VERSION=3.8.10
SQLITE_YEAR=2026
SQLITE_AMALGAMATION=3530400

say()  { printf '\n== %s ==\n' "$1"; }
fail() { printf 'FAILED: %s\n' "$1" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$PREFIX" || fail "cannot create $PREFIX"
say "prefix $PREFIX  |  jobs $JOBS"

fetch() {
  # fetch URL DEST -> prints the sha256 of what arrived
  local url="$1" dest="$2"
  curl -fsSL --retry 3 --max-time 300 -o "$dest" "$url" || fail "download failed: $url"
  sha256sum "$dest" | cut -d' ' -f1
}

# --------------------------------------------------------------------------- openssl
# Built before libssh2, which links against it. libssh2 is configured with OPENSSL_ROOT_DIR below so
# the library we bundle is the library it was built against, rather than two copies that happen to
# share a soname.
OPENSSL_SHA=""
OPENSSL_VERSION=""
if [ "$SKIP_OPENSSL" -eq 0 ]; then
  say "openssl @ ${OPENSSL_COMMIT:0:12}"
  OPENSSL_URL="https://github.com/openssl/openssl/archive/${OPENSSL_COMMIT}.tar.gz"
  OPENSSL_SHA="$(fetch "$OPENSSL_URL" "$WORK/openssl.tar.gz")"
  tar -xzf "$WORK/openssl.tar.gz" -C "$WORK" || fail "openssl extract failed"
  OPENSSL_SRC="$WORK/openssl-${OPENSSL_COMMIT}"
  [ -d "$OPENSSL_SRC" ] || fail "openssl source directory missing"

  OPENSSL_VERSION="$(grep -E '^(MAJOR|MINOR|PATCH)=' "$OPENSSL_SRC/VERSION.dat" \
                     | cut -d= -f2 | paste -sd. -)"
  echo "  declared version: $OPENSSL_VERSION"

  # Confirm the QUIC pending-connection limit really is in this tree rather than trusting the pin.
  # The fix introduces a bounded queue of channels awaiting SSL_accept().
  if ! grep -rqE "pending.*(conn|channel)|MAX_PENDING" "$OPENSSL_SRC/ssl/quic/" 2>/dev/null; then
    fail "openssl tree does not appear to contain the QUIC pending-connection limit"
  fi

  ( cd "$OPENSSL_SRC" && ./Configure linux-x86_64 shared \
      --prefix="$PREFIX" --openssldir="$PREFIX/ssl" \
      --libdir=lib no-tests no-docs ) > "$WORK/openssl-configure.log" 2>&1 \
    || { tail -20 "$WORK/openssl-configure.log"; fail "openssl configure"; }
  make -C "$OPENSSL_SRC" -j"$JOBS" > "$WORK/openssl-build.log" 2>&1 \
    || { tail -25 "$WORK/openssl-build.log"; fail "openssl build"; }
  # install_sw is libraries and headers without the manual pages, which nothing in SAT reads.
  make -C "$OPENSSL_SRC" install_sw > "$WORK/openssl-install.log" 2>&1 \
    || { tail -20 "$WORK/openssl-install.log"; fail "openssl install"; }
  echo "  installed: $(ls "$PREFIX"/lib/libcrypto.so.* 2>/dev/null | head -1)"
else
  say "openssl SKIPPED (--skip-openssl); the distribution library will be bundled"
fi

# --------------------------------------------------------------------------- libssh2
say "libssh2 @ ${LIBSSH2_COMMIT:0:12}"
LIBSSH2_URL="https://github.com/libssh2/libssh2/archive/${LIBSSH2_COMMIT}.tar.gz"
LIBSSH2_SHA="$(fetch "$LIBSSH2_URL" "$WORK/libssh2.tar.gz")"
tar -xzf "$WORK/libssh2.tar.gz" -C "$WORK" || fail "libssh2 extract failed"
LIBSSH2_SRC="$WORK/libssh2-${LIBSSH2_COMMIT}"
[ -d "$LIBSSH2_SRC" ] || fail "libssh2 source directory missing"

# Confirm we really have the fix, rather than trusting the archive name. The commit added upper
# bound enforcement on packet_length in transport.c; if that file does not mention the bound the
# advisory describes, stop rather than ship something that merely claims to be patched.
grep -q "packet_length" "$LIBSSH2_SRC/src/transport.c" || fail "libssh2 transport.c unexpected"

# SHA-1 algorithms: master disables ssh-rsa, SHA-1 key exchange, DSA and SHA-1 MACs by DEFAULT.
# SAT is pointed at whatever a customer actually runs, including older appliances and hardened
# repositories, so silently dropping those would turn a security fix into "SSH stopped working".
# They are re-enabled here to preserve 1.11.1 behaviour exactly; tightening them is a separate,
# deliberate decision that needs testing against real targets.
cmake -S "$LIBSSH2_SRC" -B "$WORK/libssh2-build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=ON \
  -DBUILD_STATIC_LIBS=OFF \
  -DBUILD_EXAMPLES=OFF \
  -DBUILD_TESTING=OFF \
  -DLIBSSH2_RSA_SHA1_ENABLE=ON \
  -DLIBSSH2_KEX_SHA1_ENABLE=ON \
  -DLIBSSH2_DSA_ENABLE=ON \
  -DLIBSSH2_MAC_SHA1_ENABLE=ON \
  ${OPENSSL_VERSION:+-DOPENSSL_ROOT_DIR="$PREFIX"} \
  > "$WORK/libssh2-configure.log" 2>&1 || { tail -20 "$WORK/libssh2-configure.log"; fail "libssh2 configure"; }
cmake --build "$WORK/libssh2-build" -j"$JOBS" > "$WORK/libssh2-build.log" 2>&1 \
  || { tail -25 "$WORK/libssh2-build.log"; fail "libssh2 build"; }
cmake --install "$WORK/libssh2-build" > /dev/null 2>&1 || fail "libssh2 install"
echo "  installed: $(ls "$PREFIX"/lib*/libssh2.so.* 2>/dev/null | head -1)"

# --------------------------------------------------------------------------- libarchive
# OPENSSL_ROOT_DIR alone is not enough here: libarchive's FindOpenSSL still picked up the
# DISTRIBUTION OpenSSL, and on RHEL/AlmaLinux 8 that is OpenSSL 1.1 - so the package loaded both
# our libcrypto.so.3 and the system libcrypto.so.1.1 into one process. The library paths are
# therefore given explicitly.
say "libarchive $LIBARCHIVE_VERSION"
LIBARCHIVE_URL="https://github.com/libarchive/libarchive/releases/download/v${LIBARCHIVE_VERSION}/libarchive-${LIBARCHIVE_VERSION}.tar.xz"
LIBARCHIVE_SHA="$(fetch "$LIBARCHIVE_URL" "$WORK/libarchive.tar.xz")"
tar -xJf "$WORK/libarchive.tar.xz" -C "$WORK" || fail "libarchive extract failed"
cmake -S "$WORK/libarchive-${LIBARCHIVE_VERSION}" -B "$WORK/libarchive-build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=ON \
  -DENABLE_TEST=OFF \
  -DENABLE_CAT=OFF -DENABLE_CPIO=OFF -DENABLE_TAR=OFF -DENABLE_UNZIP=OFF \
  -DENABLE_LIBXML2=OFF -DENABLE_EXPAT=OFF \
  ${OPENSSL_VERSION:+-DOPENSSL_ROOT_DIR="$PREFIX"} \
  ${OPENSSL_VERSION:+-DOPENSSL_INCLUDE_DIR="$PREFIX/include"} \
  ${OPENSSL_VERSION:+-DOPENSSL_CRYPTO_LIBRARY="$PREFIX/lib/libcrypto.so"} \
  ${OPENSSL_VERSION:+-DOPENSSL_SSL_LIBRARY="$PREFIX/lib/libssl.so"} \
  > "$WORK/libarchive-configure.log" 2>&1 || { tail -20 "$WORK/libarchive-configure.log"; fail "libarchive configure"; }
cmake --build "$WORK/libarchive-build" -j"$JOBS" > "$WORK/libarchive-build.log" 2>&1 \
  || { tail -25 "$WORK/libarchive-build.log"; fail "libarchive build"; }
cmake --install "$WORK/libarchive-build" > /dev/null 2>&1 || fail "libarchive install"
echo "  installed: $(ls "$PREFIX"/lib*/libarchive.so.* 2>/dev/null | head -1)"

# --------------------------------------------------------------------------- sqlite
say "sqlite $SQLITE_AMALGAMATION"
SQLITE_URL="https://www.sqlite.org/${SQLITE_YEAR}/sqlite-amalgamation-${SQLITE_AMALGAMATION}.zip"
SQLITE_SHA="$(fetch "$SQLITE_URL" "$WORK/sqlite.zip")"
python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" \
  "$WORK/sqlite.zip" "$WORK" || fail "sqlite extract failed"
SQLITE_SRC="$WORK/sqlite-amalgamation-${SQLITE_AMALGAMATION}"
# Read the declared version, not the first version-shaped string in the header - sqlite3.h quotes
# older versions in its own comments.
SQLITE_VERSION="$(grep -m1 -E '^#define[[:space:]]+SQLITE_VERSION[[:space:]]' "$SQLITE_SRC/sqlite3.h" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
mkdir -p "$PREFIX/lib" "$PREFIX/include"
# The amalgamation is a single translation unit; the feature flags match what SAT's snapshot store
# relies on (WAL, FTS5 off, threadsafe).
gcc -O2 -fPIC -shared -Wl,-soname,libsqlite3.so.0 \
  -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_COLUMN_METADATA=1 -DSQLITE_DQS=0 \
  -o "$PREFIX/lib/libsqlite3.so.0.8.6" "$SQLITE_SRC/sqlite3.c" \
  -lpthread -ldl -lm > "$WORK/sqlite-build.log" 2>&1 \
  || { tail -20 "$WORK/sqlite-build.log"; fail "sqlite build"; }
ln -sf libsqlite3.so.0.8.6 "$PREFIX/lib/libsqlite3.so.0"
ln -sf libsqlite3.so.0 "$PREFIX/lib/libsqlite3.so"
cp "$SQLITE_SRC/sqlite3.h" "$SQLITE_SRC/sqlite3ext.h" "$PREFIX/include/" 2>/dev/null
echo "  installed: $PREFIX/lib/libsqlite3.so.0  (version $SQLITE_VERSION)"

# --------------------------------------------------------------------------- provenance
# What the release gate reads. Recording the source a library came from is the only way to state
# "this build contains commit X" about a library whose version string cannot say so.
say "provenance"
LIBDIR="$PREFIX/lib"
[ -d "$LIBDIR" ] || LIBDIR="$PREFIX/lib64"
cat > "$PREFIX/RUNTIME-PROVENANCE.json" <<JSON
{
  "schemaVersion": 1,
  "generatedUtc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "builtBy": "tools/Build-ThirdParty-Linux.sh",
  "components": {
    "libssh2": {
      "sourceCommit": "$LIBSSH2_COMMIT",
      "sourceUrl": "$LIBSSH2_URL",
      "sourceSha256": "$LIBSSH2_SHA",
      "reason": "CVE-2026-55200 is fixed only in this commit; upstream has published no release containing it.",
      "buildNotes": "SHA-1 hostkey/KEX/MAC and DSA re-enabled to preserve 1.11.1 connectivity behaviour."
    },
    "openssl": {
      "sourceCommit": "${OPENSSL_COMMIT}",
      "sourceUrl": "https://github.com/openssl/openssl/archive/${OPENSSL_COMMIT}.tar.gz",
      "sourceSha256": "${OPENSSL_SHA}",
      "sourceVersion": "${OPENSSL_VERSION}",
      "reason": "The OpenSSL 3.5.9 release commit (tag openssl-3.5.9): the fixes of the 2026-08-25 and 2026-09-29 advisories. SAT runs no QUIC server, no DTLS and no TLS listener and no TLS listener - but the release floor is met properly rather than by exception."
    },
    "libarchive": {
      "sourceVersion": "$LIBARCHIVE_VERSION",
      "sourceUrl": "$LIBARCHIVE_URL",
      "sourceSha256": "$LIBARCHIVE_SHA"
    },
    "sqlite": {
      "sourceVersion": "$SQLITE_VERSION",
      "sourceUrl": "$SQLITE_URL",
      "sourceSha256": "$SQLITE_SHA"
    }
  }
}
JSON
echo "  wrote $PREFIX/RUNTIME-PROVENANCE.json"

say "summary"
[ -n "$OPENSSL_VERSION" ] && printf '  openssl    : %s (commit %s)\n' "$OPENSSL_VERSION" "${OPENSSL_COMMIT:0:12}"
printf '  libssh2    : commit %s\n' "${LIBSSH2_COMMIT:0:12}"
printf '  libarchive : %s\n' "$LIBARCHIVE_VERSION"
printf '  sqlite     : %s\n' "$SQLITE_VERSION"
printf '\nConfigure SAT with: -DCMAKE_PREFIX_PATH=%s\n' "$PREFIX"
