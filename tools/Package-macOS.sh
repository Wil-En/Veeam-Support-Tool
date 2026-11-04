#!/usr/bin/env bash
# Package the native SAT .app with application-owned Homebrew dylibs embedded in
# Contents/Frameworks. Apple system frameworks and /usr/lib runtime stay OS-owned.
if [ -z "${BASH_VERSION:-}" ]; then exec /usr/bin/env bash "$0" "$@"; fi
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="$root/out/build/macos-native-release/SupportAssistTool.app"
output="$root/out/packages"
sign_identity="-"
allow_insecure_dependencies=0

while (($#)); do
  case "$1" in
    --app) app="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --sign-identity) sign_identity="$2"; shift 2 ;;
    --allow-insecure-dependencies) allow_insecure_dependencies=1; shift ;;
    -h|--help)
      cat <<'EOF'
usage: tools/Package-macOS.sh [--app PATH] [--output DIR] [--sign-identity ID] [--allow-insecure-dependencies]

Stages SupportAssistTool.app, copies non-system dylibs into Contents/Frameworks,
rewrites install names to @rpath, optionally includes unixODBC for SQL Tools,
then signs the staged bundle. Default signing is ad-hoc (-) for lab/dev testing.
Use a Developer ID Application identity for distributable signed builds.
--allow-insecure-dependencies is restricted to isolated developer testing and
marks the resulting bundle as security-unapproved.
EOF
      exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 64 ;;
  esac
done

[[ "$(uname -s)" == Darwin ]] || { echo "Package-macOS.sh must run on macOS." >&2; exit 69; }
for tool in otool install_name_tool codesign ditto shasum python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Required macOS packaging tool missing: $tool" >&2; exit 69; }
done
[[ -d "$app" ]] || { echo "Release app not found: $app" >&2; exit 66; }

version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$root/project-metadata.json" | head -1)"
revision="$(sed -n 's/.*"buildRevision"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$root/project-metadata.json" | head -1)"
arch="$(uname -m)"
mkdir -p "$output"
package_suffix=""
if [[ "$allow_insecure_dependencies" -eq 1 ]]; then package_suffix="-Developer-SECURITY-UNAPPROVED"; fi
stage="$output/Support-Assist-Tool-${revision}-macOS-${arch}${package_suffix}.app"
zip="$output/Support-Assist-Tool-${revision}-macOS-${arch}${package_suffix}.zip"
rm -rf "$stage" "$zip"
ditto "$app" "$stage"
frameworks="$stage/Contents/Frameworks"
resources="$stage/Contents/Resources"
mkdir -p "$frameworks" "$resources/docs"
ditto "$root/docs" "$resources/docs"
cp "$root/README.md" "$root/CHANGELOG.md" "$root/LICENSE" "$root/THIRD_PARTY_NOTICES.md" "$root/BUILD-REVISION.txt" "$resources/"
: > "$resources/portable.flag"

binary="$stage/Contents/MacOS/SupportAssistTool"
[[ -x "$binary" ]] || { echo "Bundle executable not found: $binary" >&2; exit 66; }

is_system_dylib() {
  [[ "$1" == /System/Library/* || "$1" == /usr/lib/* ]]
}

declare -A copied=()
queue=()
queue_dep() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  is_system_dylib "$path" && return 0
  [[ -n "${copied[$path]:-}" ]] && return 0
  copied[$path]=queued
  queue+=("$path")
}

scan_object() {
  local object="$1"
  while IFS= read -r dep; do
    [[ -z "$dep" ]] && continue
    case "$dep" in
      @rpath/*|@loader_path/*|@executable_path/*) continue ;;
    esac
    is_system_dylib "$dep" && continue
    [[ -f "$dep" ]] && queue_dep "$dep"
  done < <(otool -L "$object" | tail -n +2 | awk '{print $1}')
}

scan_object "$binary"

# ODBC is runtime-optional, but include unixODBC in the app when the build host
# provides it so SQL Tools does not require Homebrew on the engineer workstation.
if command -v brew >/dev/null 2>&1; then
  if prefix="$(brew --prefix unixodbc 2>/dev/null)"; then
    for candidate in "$prefix/lib/libodbc.2.dylib" "$prefix/lib/libodbc.dylib"; do
      [[ -f "$candidate" ]] && { queue_dep "$candidate"; break; }
    done
  fi
fi

index=0
while (( index < ${#queue[@]} )); do
  source_path="${queue[$index]}"; ((index+=1))
  base="$(basename "$source_path")"
  dest="$frameworks/$base"
  if [[ ! -f "$dest" ]]; then
    ditto "$source_path" "$dest"
    chmod 0755 "$dest" || true
    copied[$source_path]="$dest"
    scan_object "$dest"
  fi
done

rewrite_object() {
  local object="$1"
  while IFS= read -r dep; do
    [[ -z "$dep" ]] && continue
    is_system_dylib "$dep" && continue
    case "$dep" in
      @rpath/*|@loader_path/*|@executable_path/*) continue ;;
    esac
    if [[ -f "$dep" ]]; then
      local base="$(basename "$dep")"
      [[ -f "$frameworks/$base" ]] && install_name_tool -change "$dep" "@rpath/$base" "$object"
    fi
  done < <(otool -L "$object" | tail -n +2 | awk '{print $1}')
}

# Ensure the executable has the application-local Frameworks search path.
if ! otool -l "$binary" | grep -A2 LC_RPATH | grep -q '@executable_path/../Frameworks'; then
  install_name_tool -add_rpath '@executable_path/../Frameworks' "$binary"
fi
rewrite_object "$binary"
for dylib in "$frameworks"/*.dylib; do
  [[ -f "$dylib" ]] || continue
  install_name_tool -id "@rpath/$(basename "$dylib")" "$dylib" || true
  rewrite_object "$dylib"
done

# No non-system absolute dylib path may remain.
for object in "$binary" "$frameworks"/*.dylib; do
  [[ -f "$object" ]] || continue
  while IFS= read -r dep; do
    [[ -z "$dep" ]] && continue
    if [[ "$dep" == /* ]] && ! is_system_dylib "$dep"; then
      echo "Non-system dependency escaped application bundle: $object -> $dep" >&2
      exit 65
    fi
  done < <(otool -L "$object" | tail -n +2 | awk '{print $1}')
done

cat > "$resources/README-RUNTIME.md" <<EOF
# Support Assist Tool ${version} — macOS runtime package

Build revision: \`${revision}\`  
Architecture: \`${arch}\`

The application bundle carries SAT-owned third-party runtime dylibs in \`Contents/Frameworks\`. The engineer workstation does not need Homebrew to launch SAT. Apple system frameworks remain supplied by macOS.

SQL/ODBC is optional. SAT dynamically loads an ODBC driver manager when SQL Tools is used. A vendor SQL Server ODBC driver remains a separate optional integration and is not required for SAT startup or non-SQL features.
EOF

security_args=(--stage "$stage" --platform macos --output "$resources/RUNTIME-SBOM.json")
if [[ "$allow_insecure_dependencies" -eq 1 ]]; then security_args+=(--developer); fi
python3 "$root/tools/verify_runtime_security.py" "${security_args[@]}"
if [[ "$allow_insecure_dependencies" -eq 1 ]]; then
  cat > "$resources/SECURITY-NOT-APPROVED.txt" <<'SECURITY_EOF'
This bundle was created with --allow-insecure-dependencies for isolated developer testing.
It did not pass the SAT official runtime dependency security gate and must not be distributed
as an engineer/customer release artifact. Review RUNTIME-SBOM.json for blocking findings.
SECURITY_EOF
fi
find "$stage" -type f -print0 | sort -z | xargs -0 shasum -a 256 > "$resources/SHA256SUMS.txt"

codesign --force --deep --options runtime --sign "$sign_identity" "$stage"
codesign --verify --deep --strict "$stage"
ditto -c -k --sequesterRsrc --keepParent "$stage" "$zip"
printf 'Created self-contained macOS package: %s\n' "$zip"
