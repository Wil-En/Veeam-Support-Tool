#!/usr/bin/env bash
# Create a self-contained SAT Linux runtime directory/tarball from the Release build.
# The package intentionally does NOT bundle glibc/the ELF loader. Build official
# releases on the documented compatibility baseline; application-owned third-party
# libraries are copied into ./lib and resolved through $ORIGIN/lib.
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$root/out/build/linux-native-release/SupportAssistTool"
output="$root/out/packages"
allow_new_glibc=0
allow_insecure_dependencies=0
profile=""

# Compatibility baselines, per package profile. See the note above --profile in the usage text.
#
# These are not the same kind of number. The CLI baseline is a product decision about which
# customer machines SAT must run on. The GUI baseline is a constraint imposed by Qt 6: no RHEL 8
# repository packages it, so 2.34 (RHEL/AlmaLinux 9) is the lowest base that can build a Qt 6
# application without building Qt itself from source.
cli_glibc_baseline="2.28"
gui_glibc_baseline="2.34"

while (($#)); do
  case "$1" in
    --binary) binary="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --allow-new-glibc) allow_new_glibc=1; shift ;;
    --profile) profile="$2"; shift 2 ;;
    --allow-insecure-dependencies) allow_insecure_dependencies=1; shift ;;
    -h|--help)
      cat <<'EOF'
usage: tools/Package-Linux.sh [--binary PATH] [--output DIR] [--allow-new-glibc] [--allow-insecure-dependencies]

Creates a no-root SAT Linux runtime package. The release executable must have
$ORIGIN/lib in RUNPATH/RPATH. SAT-owned third-party shared libraries are copied
beside the application; glibc and the ELF loader remain supplied by the OS.

Official broad-compatibility packages should be produced on the documented
baseline (glibc <= 2.28). --allow-new-glibc permits a developer/test package on
a newer build host but does not make that binary portable to older distributions.

--allow-insecure-dependencies is for isolated developer testing only. Official
packages fail closed when the bundled dependency security policy is stale or
when a detected security-sensitive library is below the reviewed release floor.
EOF
      exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 64 ;;
  esac
done

for tool in ldd readelf sha256sum tar python3 stat; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Required packaging tool missing: $tool" >&2; exit 69; }
done
[[ -x "$binary" ]] || { echo "Release binary not found/executable: $binary" >&2; exit 66; }

version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$root/project-metadata.json" | head -1)"
revision="$(sed -n 's/.*"buildRevision"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$root/project-metadata.json" | head -1)"
[[ -n "$version" && -n "$revision" ]] || { echo "Could not read project metadata" >&2; exit 65; }

arch="$(uname -m)"
case "$arch" in
  x86_64) package_arch=x64 ;;
  aarch64|arm64) package_arch=arm64 ;;
  *) package_arch="$arch" ;;
esac

# The executable can only run on a system with an equal/newer glibc than the one
# it was linked against. Do not accidentally publish a broad Linux package from
# a bleeding-edge workstation.
# Which package is this? A binary that links Qt is the GUI, by definition. Detecting it rather
# than trusting a flag means the baseline applied always matches the artifact being produced.
if [[ -z "$profile" ]]; then
  if ldd "$binary" 2>/dev/null | grep -q "libQt[56]Core"; then profile="gui"; else profile="cli"; fi
fi
case "$profile" in
  gui) glibc_baseline="$gui_glibc_baseline" ;;
  cli) glibc_baseline="$cli_glibc_baseline" ;;
  *) echo "Unknown --profile '$profile' (expected gui or cli)." >&2; exit 64 ;;
esac
echo "Package profile: $profile (glibc baseline <= $glibc_baseline)"

glibc_version="$(ldd --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+' | tail -1 || true)"
if [[ -n "$glibc_version" && "$allow_new_glibc" -eq 0 ]]; then
  if ! awk -v v="$glibc_version" -v b="$glibc_baseline" \
       'BEGIN { split(v,a,"."); split(b,c,"."); exit !((a[1] < c[1]) || (a[1] == c[1] && a[2] <= c[2])) }'; then
    echo "Refusing official $profile package: build host glibc is $glibc_version; the $profile baseline requires <= $glibc_baseline." >&2
    if [[ "$profile" == "gui" ]]; then
      echo "Build the GUI on AlmaLinux/Rocky/RHEL 9 (glibc 2.34). See tools/Setup-AlmaLinux9-BuildBase.sh." >&2
      echo "That reaches RHEL 9+, Ubuntu 22.04 LTS+, Debian 12+ and SLES 15 SP4+. Older machines are covered by the CLI package." >&2
    else
      echo "Build the CLI on a RHEL 8 / AlmaLinux 8-era base (glibc 2.28) so it reaches the servers the GUI cannot." >&2
    fi
    echo "Pass --allow-new-glibc for a developer-only test package." >&2
    exit 78
  fi
fi

if ! readelf -d "$binary" | grep -Eq '\$ORIGIN/lib'; then
  echo "Release binary is missing required \$ORIGIN/lib RUNPATH/RPATH. Configure with SUPPORT_ASSIST_PORTABLE_RUNTIME=ON." >&2
  exit 65
fi
if readelf -d "$binary" | grep -E 'NEEDED.*libodbc' >/dev/null; then
  echo "ODBC must remain runtime-optional; executable still has a hard libodbc dependency." >&2
  exit 65
fi

mkdir -p "$output"
package_suffix=""
# The CLI artifact is named apart from the GUI one so the two can sit in the same output directory
# without one silently replacing the other.
if [[ "$profile" == "cli" ]]; then package_suffix="-cli"; fi
if [[ "$allow_new_glibc" -eq 1 ]]; then package_suffix="${package_suffix}-Developer"; fi
if [[ "$allow_insecure_dependencies" -eq 1 ]]; then package_suffix="${package_suffix}-SECURITY-UNAPPROVED"; fi
# The package is named for the RELEASE identity: the full version, version.buildNumber, which is
# what Help / About shows. Never the build revision - "dev.2" in a filename reads to a support
# engineer as a developer-only build that should not be taken to a lab or a customer.
#
# The build number is in the name because a version is rebuilt after it has shipped, and a later
# build of a released version must not be a file of the same name. The guide inside keeps the
# plain version: that is the name the application looks it up by.
#
# The revision is not lost: README-RUNTIME.md inside the package records it, and the binary reports
# it from `version` and in Help / About.
build_number="$(sed -n 's/.*"buildNumber"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$root/project-metadata.json" | head -1)"
package_version="$version"
if [[ -n "$build_number" ]]; then package_version="${version}.${build_number}"; fi
stage="$output/Support-Assist-Tool-${package_version}-linux-${package_arch}${package_suffix}"
archive="$output/Support-Assist-Tool-${package_version}-linux-${package_arch}${package_suffix}.tar.gz"
rm -rf "$stage" "$archive"
mkdir -p "$stage/lib"
chmod 0755 "$stage" "$stage/lib"
cp "$binary" "$stage/SupportAssistTool"
# A Release binary carrying full debug symbols is ~7.8 MB of a customer-facing package that nothing
# on the customer machine can use, and it hands out more about the build than a support tool needs
# to. Stripping is a footprint AND a disclosure decision.
if command -v strip >/dev/null 2>&1; then
  strip --strip-unneeded "$stage/SupportAssistTool" 2>/dev/null || true
fi
chmod 0755 "$stage/SupportAssistTool"
# Runtime package only. An engineer carries this onto a customer or lab machine, runs it, and
# deletes the directory; repository documentation is not part of that job and previously made up
# the bulk of the archive (the whole docs/ tree, an 84 KB CHANGELOG.md and a 21 KB developer
# README.md). Nothing reads any of it at runtime.
#
# No loose licence documents in the payload. The attribution for every bundled .so now lives in
# the User Guide as an Open-Source Components section, so the notice still travels with the
# distribution, in the document an engineer would actually open.

# The user guide travels with the package.
#
# The exclusion above is right about REPOSITORY documentation - the developer guide, the build-fix
# reports, the reference corpus - none of which the person running SAT needs. The user guide is a
# different thing: it is the one document written for them, and leaving it out meant an engineer
# unpacked SAT on a customer machine with no instructions and no network to fetch any.
#
# The guides are self-contained - figures, stylesheet and script embedded - so one opened from a
# USB stick renders exactly as it does in the repository. The GUI package also carries the CLI
# guide, because the same executable is also the command line.
guide_dir="$root/docs/user-guide"
# The GUI resolves the guide by one exact path, built in user_guide_path(): the executable
# directory, then documents/, then Support-Assist-Tool-Linux-User-Guide-<version>.html. This staged
# it as Documentation/ under the unversioned repository file name, so Help > User Guide could not
# find a guide the package contained. Stage the name the application asks for.
mkdir -p "$stage/documents"
# One guide, matching the package. Two would add roughly 5 MB to a runtime package an engineer
# carries onto a customer machine, and the point of these packages is a minimal footprint.
if [[ "$profile" == "cli" ]]; then
  guide="Support-Assist-Tool-CLI-User-Guide.html"
  shipped_guide="Support-Assist-Tool-CLI-User-Guide-$version.html"
else
  guide="Support-Assist-Tool-Linux-User-Guide.html"
  shipped_guide="Support-Assist-Tool-Linux-User-Guide-$version.html"
fi
if [[ ! -f "$guide_dir/$guide" ]]; then
  echo "Required user guide not found: $guide_dir/$guide" >&2
  echo "Run tools/Generate-Project-Docs.py before packaging - a package that ships without its guide is not a deliverable." >&2
  exit 66
fi
cp "$guide_dir/$guide" "$stage/documents/$shipped_guide"
# portable.flag is not created. It was an empty file, and no line under src/ reads it - SAT does
# not behave differently for its presence or absence.

cat > "$stage/Run-SupportAssistTool.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Do not inherit loader injection variables into the convenience launcher. The
# user can always execute a binary under a custom environment deliberately, but
# the SAT launcher itself never extends an untrusted LD_LIBRARY_PATH/LD_PRELOAD.
unset LD_PRELOAD LD_AUDIT
export LD_LIBRARY_PATH="$here/lib"
exec "$here/SupportAssistTool" "$@"
EOF
chmod 0755 "$stage/Run-SupportAssistTool.sh"

cat > "$stage/lib/Verify-Runtime.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# This script lives in lib/; the package root is its parent.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
unset LD_PRELOAD LD_AUDIT
export LD_LIBRARY_PATH="$here/lib"
missing="$(ldd "$here/SupportAssistTool" | grep 'not found' || true)"
if [[ -n "$missing" ]]; then
  echo "$missing" >&2
  exit 1
fi
"$here/SupportAssistTool" version
"$here/SupportAssistTool" capabilities --json >/dev/null

# When the Qt frontend is present, prove the package is self-contained.
#
# The failure this catches is a package that works perfectly on the machine it was built on and
# fails on every customer machine, because Qt silently resolved its libraries or its platform
# plugin from the host. Both checks below fail loudly instead.
if ldd "$here/SupportAssistTool" 2>/dev/null | grep -q 'libQt[56]Core'; then
  host_qt="$(ldd "$here/SupportAssistTool" 2>/dev/null | awk '/libQt[56][A-Za-z]*\.so.*=> \//{print $3}' | grep -v "^$here/lib/" || true)"
  if [[ -n "$host_qt" ]]; then
    echo "Qt resolved from OUTSIDE the package; this build is not self-contained:" >&2
    echo "$host_qt" >&2
    exit 1
  fi
  if [[ ! -f "$here/qt.conf" ]]; then
    echo "qt.conf is missing; Qt would search the build host plugin path." >&2
    exit 1
  fi
  if ! ls "$here"/plugins/platforms/*.so >/dev/null 2>&1; then
    echo "No Qt platform plugin is bundled; the GUI cannot start on a machine without Qt." >&2
    exit 1
  fi
  # The check above only proved the BINARY is self-contained. Qt dlopen()s the platform plugin, and
  # that plugin resolves its own dependencies independently - so verify each plugin points back
  # into ./lib rather than at whatever Qt the host happens to have.
  plugin_faults=0
  while IFS= read -r plugin; do
    if ! readelf -d "$plugin" 2>/dev/null | grep -qE 'RUNPATH|RPATH'; then
      echo "Plugin has no RUNPATH and would bind to host Qt: $plugin" >&2
      plugin_faults=$((plugin_faults + 1))
      continue
    fi
    lib_real="$(readlink -f "$here/lib")"
    stray=""
    while IFS= read -r resolved; do
      [[ -n "$resolved" ]] || continue
      case "$(readlink -f "$resolved")" in
        "$lib_real"/*) ;;
        *) stray="$stray$resolved"$'\n' ;;
      esac
    done < <(env -u LD_LIBRARY_PATH ldd "$plugin" 2>/dev/null | awk '/libQt[56][A-Za-z]*\.so.*=> \//{print $3}')
    if [[ -n "$stray" ]]; then
      echo "Plugin resolves Qt from OUTSIDE the package: $plugin" >&2
      echo "$stray" >&2
      plugin_faults=$((plugin_faults + 1))
    fi
  done < <(find "$here/plugins" -name '*.so' 2>/dev/null)
  if (( plugin_faults > 0 )); then
    echo "$plugin_faults bundled plugin(s) are not self-contained." >&2
    exit 1
  fi
  printf 'Qt frontend verified self-contained.\n'
fi

printf 'SAT Linux runtime verification passed.\n'
EOF
chmod 0755 "$stage/lib/Verify-Runtime.sh"

if [[ "$profile" == "gui" ]]; then
  host_note="Linux itself still supplies glibc, the ELF loader, the kernel and the display. The GUI needs an X11 or Wayland session."
else
  host_note="Linux itself still supplies glibc, the ELF loader and the kernel."
fi
cat > "$stage/README-RUNTIME.md" <<EOF
# Support Assist Tool ${version}: Linux runtime package

Full version: \`${package_version}\`
Build revision: \`${revision}\`  
Architecture: \`${arch}\`  
Build-host glibc: \`${glibc_version:-unknown}\`

## Run

No package-manager installation or root access is required for the SAT-owned runtime libraries in this directory:

\`\`\`bash
./SupportAssistTool
\`\`\`

or use the diagnostic launcher:

\`\`\`bash
./Run-SupportAssistTool.sh
\`\`\`

The package carries application-owned third-party shared libraries in \`./lib\`. ${host_note}

SQL/ODBC is optional. SAT loads the ODBC driver manager only when SQL Tools is used. The package may include unixODBC itself when available on the build host, but a vendor SQL Server ODBC driver is a separate optional integration and is not required to launch SAT or use non-SQL features.

Run \`./lib/Verify-Runtime.sh\` to inspect the packaged loader closure.
EOF

# Core system runtime: never copy these from the build host. Everything else
# reached by the binary or bundled optional ODBC manager is SAT-local.
is_os_runtime() {
  case "$1" in
    linux-vdso.so.*|ld-linux*.so.*|ld-musl-*.so.*|libc.so.*|libm.so.*|libpthread.so.*|libdl.so.*|librt.so.*) return 0 ;;
    *) return 1 ;;
  esac
}

declare -A queued=()
queue=()
queue_dep() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  local real base
  real="$(readlink -f "$path")"
  base="$(basename "$path")"
  is_os_runtime "$base" && return 0
  [[ -n "${queued[$real]:-}" ]] && return 0
  queued[$real]=1
  queue+=("$real|$base")
}

scan_ldd() {
  local object="$1"
  # Data-only libraries have nothing to walk, and ldd on one can hang: it executes the object under
  # the loader. Skip them by their own report rather than by name, so this holds for any such file.
  if timeout 20 ldd "$object" 2>/dev/null | grep -q 'statically linked'; then
    return 0
  fi
  while IFS= read -r line; do
    local path=""
    if [[ "$line" == *"=> /"* ]]; then
      path="$(awk '{for(i=1;i<=NF;i++) if($i=="=>"){print $(i+1); exit}}' <<<"$line")"
    elif [[ "$line" =~ ^[[:space:]]*(/[^[:space:]]+) ]]; then
      path="${BASH_REMATCH[1]}"
    fi
    [[ -n "$path" && -f "$path" ]] && queue_dep "$path"
  done < <(timeout 20 ldd "$object" 2>/dev/null || true)
}

runtime_manifest="$stage/lib/RUNTIME-LIBRARIES.txt"
scan_ldd "$binary"

# unixODBC is not a hard dependency anymore. Bundle the driver manager when it
# exists on the build host so SQL Tools can work without installing libodbc.
odbc_path=""
if command -v ldconfig >/dev/null 2>&1; then
  odbc_path="$(ldconfig -p 2>/dev/null | awk '/libodbc\.so\.2 .*=>/{print $NF; exit}')"
fi
if [[ -z "$odbc_path" ]]; then
  for candidate in /usr/lib*/libodbc.so.2 /usr/lib/*/libodbc.so.2 /lib/*/libodbc.so.2; do
    [[ -f "$candidate" ]] && { odbc_path="$candidate"; break; }
  done
fi
[[ -n "$odbc_path" ]] && queue_dep "$odbc_path"

# --- Qt platform plugins -------------------------------------------------------------------------
#
# Qt's own shared libraries arrive through the ldd closure above because the binary links them.
# Its PLUGINS do not: Qt dlopen()s the platform plugin at startup, so nothing in the ELF headers
# mentions it and a package that ships only the libraries starts with
#
#   "This application failed to start because no Qt platform plugin could be initialized"
#
# on a machine with no Qt installed - which is every customer machine. The plugin directory and a
# qt.conf pointing at it are therefore part of the package, not an optimisation.
qt_core="$(awk -F'\t' '$1 ~ /^libQt[56]Core\.so/ {print $2; exit}' "$runtime_manifest" 2>/dev/null || true)"
if [[ -z "$qt_core" ]]; then
  qt_core="$(LD_LIBRARY_PATH="$stage/lib" ldd "$binary" 2>/dev/null | awk '/libQt[56]Core\.so.*=> \//{print $3; exit}' || true)"
fi

if [[ -n "$qt_core" ]]; then
  echo "Qt frontend detected ($qt_core); bundling platform plugins."
  qt_lib_dir="$(dirname "$qt_core")"
  qt_plugin_root=""
  for candidate in \
      "$qt_lib_dir/qt6/plugins" "$qt_lib_dir/qt5/plugins" "$qt_lib_dir/qt/plugins" \
      "$qt_lib_dir/../lib/qt6/plugins" "$qt_lib_dir/../lib/qt5/plugins" \
      "$qt_lib_dir/../plugins" "/usr/lib64/qt6/plugins" "/usr/lib64/qt5/plugins"; do
    if [[ -d "$candidate/platforms" ]]; then qt_plugin_root="$candidate"; break; fi
  done
  if [[ -z "$qt_plugin_root" ]] && command -v qmake >/dev/null 2>&1; then
    qt_plugin_root="$(qmake -query QT_INSTALL_PLUGINS 2>/dev/null || true)"
  fi
  if [[ -z "$qt_plugin_root" || ! -d "$qt_plugin_root/platforms" ]]; then
    echo "Qt platform plugin directory was not found. The package would not start on a machine without Qt installed." >&2
    exit 65
  fi

  # Only the plugin families SAT actually needs. Copying every plugin Qt ships would add tens of
  # megabytes of database drivers and image formats this product never loads.
  mkdir -p "$stage/plugins/platforms"
  copied_plugins=0
  # libqwayland.so is NOT optional. Every current Debian and Ubuntu desktop - and WSLg - runs a
  # Wayland session, so Qt asks for the "wayland" platform plugin first. A package without it starts
  # with "Could not find the Qt platform plugin \"wayland\"" and paints an empty window. xcb remains
  # bundled for X11 sessions and as the XWayland fallback.
  # SAT draws QtWidgets in software and uses no OpenGL, so the EGL platform (libqwayland-egl) is
  # left out: Qt's wayland platform draws through shared memory. The minimal platform is for tests;
  # offscreen stays for a headless run.
  for plugin in "$qt_plugin_root"/platforms/libqwayland.so \
                "$qt_plugin_root"/platforms/libqwayland-generic.so \
                "$qt_plugin_root"/platforms/libqxcb.so \
                "$qt_plugin_root"/platforms/libqoffscreen.so; do
    if [[ -f "$plugin" ]]; then
      cp -L "$plugin" "$stage/plugins/platforms/"
      chmod 0644 "$stage/plugins/platforms/$(basename "$plugin")"
      queue_dep "$plugin"
      copied_plugins=$((copied_plugins + 1))
    fi
  done
  # Distributions do not agree on the plugin's file name. Debian and Ubuntu ship
  # libqwayland.so; EPEL's Qt 6 for RHEL/AlmaLinux ships libqwayland-generic.so and
  # libqwayland-egl.so and no plain libqwayland.so at all. Checking only the Debian name reported
  # "wayland plugin was not found" on a package that had in fact just bundled two of them.
  staged_wayland=""
  for candidate in "$stage/plugins/platforms/libqwayland.so"                    "$stage/plugins/platforms/libqwayland-generic.so"                    "$stage/plugins/platforms/libqwayland-egl.so"; do
    if [[ -f "$candidate" ]]; then staged_wayland="$candidate"; break; fi
  done
  if [[ -z "$staged_wayland" ]]; then
    echo "Qt wayland platform plugin was not found. Debian and Ubuntu desktops run Wayland "\
         "sessions, so the package would start to an empty window there." >&2
    echo "Install the Qt Wayland platform plugin on the BUILD host (it is bundled into the "\
         "package, never required on the target machine)." >&2
    exit 65
  fi
  if [[ "$copied_plugins" -eq 0 ]]; then
    echo "No Qt platform plugin could be staged; refusing to produce a package that cannot start." >&2
    exit 65
  fi
  # Each platform plugin needs its own helper plugins on Qt 6. The wayland ones are what draw the
  # window decorations and connect the client to the compositor's shell; without them the plugin
  # loads and then fails to produce a usable window. Left out: the xcb GL integrations and the
  # wayland graphics-integration client plugins (EGL, and server buffers for Qt compositors), as SAT
  # uses no OpenGL; and the shells other than xdg-shell (fullscreen, ivi, qt-shell, wl-shell),
  # which desktop compositors do not use.
  for extra in platforminputcontexts wayland-decoration-client wayland-shell-integration; do
    if [[ -d "$qt_plugin_root/$extra" ]]; then
      mkdir -p "$stage/plugins/$extra"
      for object in "$qt_plugin_root/$extra"/*.so; do
        [[ -f "$object" ]] || continue
        if [[ "$extra" == wayland-shell-integration && "$(basename "$object")" != libxdg-shell.so ]]; then
          continue
        fi
        cp -L "$object" "$stage/plugins/$extra/"
        chmod 0644 "$stage/plugins/$extra/$(basename "$object")"
        queue_dep "$object"
      done
    fi
  done

  # Qt dlopen()s these plugins, and DT_RUNPATH does NOT propagate to a dlopen'd object's own
  # dependencies. Without a RUNPATH of their own the plugins resolve libQt6Gui/libQt6XcbQpa from
  # the HOST: fine on a machine with the same Qt, and on a machine with no Qt it is
  #   "This application failed to start because no Qt platform plugin could be initialized"
  # while the main binary sat there resolving its own Qt from ./lib perfectly happily. Worse, on a
  # host with a DIFFERENT Qt 6 it loads two Qt versions into one process instead of failing.
  #
  # The launcher script papers over this by exporting LD_LIBRARY_PATH, so the defect is invisible
  # until someone runs ./SupportAssistTool directly - which is the first thing an engineer does.
  if ! command -v patchelf >/dev/null 2>&1; then
    echo "patchelf is required to make the bundled Qt plugins self-contained." >&2
    echo "Install it on the BUILD host: ./tools/Install-Linux-Build-Prereqs.sh --install" >&2
    echo "(patchelf is a build-host tool; it is never required on a customer machine.)" >&2
    exit 65
  fi
  while IFS= read -r staged_plugin; do
    patchelf --set-rpath '$ORIGIN/../../lib' "$staged_plugin" 2>/dev/null || {
      echo "Could not set RUNPATH on $staged_plugin; refusing to ship a plugin that would bind to host Qt." >&2
      exit 65
    }
  done < <(find "$stage/plugins" -name '*.so')

  # Without this, Qt uses the plugin path compiled into libQtCore at BUILD time - a path that
  # exists on the build host and not on the customer machine.
  cat > "$stage/qt.conf" <<'QTCONF'
[Paths]
Prefix = .
Plugins = plugins
Libraries = lib
QTCONF
  chmod 0644 "$stage/qt.conf"
fi

index=0
: > "$runtime_manifest"
while (( index < ${#queue[@]} )); do
  entry="${queue[$index]}"; ((index+=1))
  source_path="${entry%%|*}"
  soname="${entry#*|}"
  dest="$stage/lib/$soname"
  if [[ ! -f "$dest" ]]; then
    cp -L "$source_path" "$dest"
    chmod 0644 "$dest"
    # The libraries built from source keep their symbol tables; --strip-unneeded removes them and
    # keeps every dynamic symbol and the version strings the release security gate reads.
    if command -v strip >/dev/null 2>&1; then strip --strip-unneeded "$dest" 2>/dev/null || true; fi
    printf '%s\t%s\t%s\n' "$soname" "$source_path" "$(sha256sum "$dest" | awk '{print $1}')" >> "$runtime_manifest"
    scan_ldd "$dest"
  fi
done

# Bundle Qt's own Wayland client library.
#
# The wayland platform plugin links libQt6WaylandClient, which lives with the rest of Qt and is NOT
# present on a machine that has no Qt installed. Without it the plugin cannot load, Qt falls back,
# and the window comes up blank - which is exactly what shipped. libwayland-client/cursor come from
# the desktop itself, like libX11 and libGL, and are deliberately not bundled: every Debian and
# Ubuntu desktop has them, and bundling core system libraries causes worse breakage than it avoids
# (the same reason linuxdeployqt excludes them).
if [[ -n "${staged_wayland:-}" ]]; then
  qt_lib_dir_for_wayland="$(dirname "$qt_core")"
  for qt_wayland_lib in "$qt_lib_dir_for_wayland"/libQt6WaylandClient.so.6; do
    if [[ -f "$qt_wayland_lib" ]]; then
      wayland_base="$(basename "$qt_wayland_lib")"
      if [[ ! -f "$stage/lib/$wayland_base" ]]; then
        cp -L "$qt_wayland_lib" "$stage/lib/$wayland_base"
        chmod 0644 "$stage/lib/$wayland_base"
        printf '%s\t%s\t%s\n' "$wayland_base" "$qt_wayland_lib" \
          "$(sha256sum "$stage/lib/$wayland_base" | awk '{print $1}')" >> "$runtime_manifest"
      fi
    fi
  done
fi

# Fail closed: a package whose wayland plugin still needs Qt from the host is not self-contained,
# and would open an empty window on any Wayland desktop without Qt installed.
if [[ -n "${staged_wayland:-}" ]]; then
  wayland_closure="$(LD_LIBRARY_PATH="$stage/lib" ldd "$staged_wayland" 2>/dev/null || true)"
  if grep -q 'libQt6.*=> /usr' <<<"$wayland_closure"; then
    echo "The bundled wayland plugin resolves Qt from the build host:" >&2
    grep 'libQt6.*=> /usr' <<<"$wayland_closure" >&2
    echo "SAT must not require Qt to be installed on the target machine." >&2
    exit 65
  fi
fi

# Every bundled plugin must find its QT libraries in ./lib. Core system libraries (X11, wayland
# client, GL, systemd) intentionally come from the desktop, which by definition has them.
# Every bundled library resolves its own dependencies from the bundle.
#
# The binary's RUNPATH covers what the BINARY needs. It does not cover what those libraries need in
# turn: a distro-built libQt6Gui has no RUNPATH, so its own dependency on libQt6DBus resolved from
# /usr/lib while an identical copy sat unused in ./lib. The launcher's LD_LIBRARY_PATH masked it.
# Fail closed when patchelf is absent and there is anything to patch.
#
# This used to skip silently, which produced a package that LOOKED fine: the bundled libraries were
# all present, the runtime check passed because it sets LD_LIBRARY_PATH, and the tarball was
# published. On any machine that did not happen to have the same system libraries it died with
# "libxml2.so.2: cannot open shared object file", because bundled libarchive had no RUNPATH telling
# it to look beside itself. A package that only runs on its own build host is worse than no package.
if ! command -v patchelf >/dev/null 2>&1 && \
   [[ -n "$(find "$stage/lib" -maxdepth 1 -name '*.so*' -type f -print -quit 2>/dev/null)" ]]; then
  echo "patchelf is not installed, and bundled libraries need a RUNPATH to find each other." >&2
  echo "Without it the package resolves libraries from the BUILD HOST and will not run elsewhere." >&2
  echo "Install it on the build host: dnf -y install patchelf  (or apt install patchelf)" >&2
  echo "(patchelf is a build-host tool; it is never required on a customer machine.)" >&2
  exit 65
fi

if command -v patchelf >/dev/null 2>&1; then
  # Only libraries that actually depend on another BUNDLED library need a RUNPATH. Rewriting every
  # object costs real size: patchelf expands the dynamic section and may add a segment, and doing
  # it to all 101 added roughly 4 MB, most of it on libraries with nothing in the bundle to find.
  runpath_set=0
  runpath_skipped=0
  while IFS= read -r staged_lib; do
    [[ -f "$staged_lib" ]] || continue
    needs_bundle=0
    while IFS= read -r needed; do
      if [[ -e "$stage/lib/$needed" ]]; then needs_bundle=1; break; fi
    done < <(patchelf --print-needed "$staged_lib" 2>/dev/null)
    if (( needs_bundle == 0 )); then
      runpath_skipped=$((runpath_skipped + 1))
      continue
    fi
    if patchelf --set-rpath '$ORIGIN' "$staged_lib" 2>/dev/null; then
      runpath_set=$((runpath_set + 1))
    fi
  done < <(find "$stage/lib" -maxdepth 1 -name '*.so*' -type f)
  printf 'Set $ORIGIN RUNPATH on %d bundled library(ies); %d needed none.\n' \
    "$runpath_set" "$runpath_skipped"
fi

# queue_dep() stages every object it walks, including the plugins themselves, so each plugin ends
# up both under plugins/ where Qt looks for it and under lib/ where nothing does. The copies in
# lib/ are dead weight and are misleading besides - a plugin is not a shared library the loader
# should ever find on its search path.
removed_duplicates=0
while IFS= read -r staged_plugin; do
  duplicate="$stage/lib/$(basename "$staged_plugin")"
  if [[ -f "$duplicate" ]]; then
    rm -f "$duplicate"
    removed_duplicates=$((removed_duplicates + 1))
  fi
done < <(find "$stage/plugins" -name '*.so' 2>/dev/null)
if (( removed_duplicates > 0 )); then
  printf 'Removed %d duplicate plugin copy(ies) from lib/.\n' "$removed_duplicates"
fi

for plugin_object in "$stage"/plugins/*/*.so; do
  [[ -f "$plugin_object" ]] || continue
  plugin_closure="$(LD_LIBRARY_PATH="$stage/lib" ldd "$plugin_object" 2>/dev/null || true)"
  if grep -q 'libQt6.*=> /usr' <<<"$plugin_closure"; then
    echo "Plugin $plugin_object resolves Qt from the build host instead of ./lib:" >&2
    grep 'libQt6.*=> /usr' <<<"$plugin_closure" >&2
    exit 65
  fi
done

# Validate that every non-glibc dependency resolves from the staged lib folder.
closure="$(LD_LIBRARY_PATH="$stage/lib" ldd "$stage/SupportAssistTool")"
if grep 'not found' <<<"$closure"; then
  echo "Packaged runtime has unresolved dependencies." >&2
  exit 65
fi
while IFS= read -r line; do
  base="$(awk '{print $1}' <<<"$line")"
  path=""
  if [[ "$line" == *"=> /"* ]]; then
    path="$(awk '{for(i=1;i<=NF;i++) if($i=="=>"){print $(i+1); exit}}' <<<"$line")"
  elif [[ "$line" =~ ^[[:space:]]*(/[^[:space:]]+) ]]; then
    path="${BASH_REMATCH[1]}"; base="$(basename "$path")"
  fi
  [[ -z "$path" ]] && continue
  if ! is_os_runtime "$base" && [[ "$path" != "$stage/lib/"* ]]; then
    echo "Runtime closure escaped SAT package: $base -> $path" >&2
    exit 65
  fi
done <<<"$closure"

# --- source-build provenance ---------------------------------------------------------------------
#
# Libraries built from source carry a RUNTIME-PROVENANCE.json in their install prefix naming the
# commit or tarball each came from. The release gate requires it for any component whose policy
# names a requiredFixCommit, because a version string cannot prove a pre-release build contains a
# fix - every libssh2 master snapshot reports the same version whether or not it does.
#
# The prefix is discovered from the libraries actually bundled, so this can only ever describe the
# build that was really used.
provenance_source=""
while IFS=$'\t' read -r _name source_path _rest; do
  [[ -z "${source_path:-}" || ! -f "$source_path" ]] && continue
  lib_dir="$(dirname "$source_path")"
  for candidate in "$lib_dir/RUNTIME-PROVENANCE.json" "$lib_dir/../RUNTIME-PROVENANCE.json"; do
    if [[ -f "$candidate" ]]; then provenance_source="$candidate"; break 2; fi
  done
done < "$runtime_manifest"

if [[ -n "$provenance_source" ]]; then
  # Into the stage first. The release gate below reads provenance from the staged tree, so moving
  # this out before it runs makes a correctly remediated build fail as though it had no provenance
  # at all. It is relocated beside the archive once the gate has passed.
  cp "$provenance_source" "$stage/lib/RUNTIME-PROVENANCE.json"
  chmod 0644 "$stage/lib/RUNTIME-PROVENANCE.json"
  echo "Source-build provenance: $provenance_source"
fi

# Pick a Python new enough to run the verifier.
#
# RHEL/AlmaLinux 8 ships python3.6 as "python3", which predates `from __future__ import annotations`
# (3.7) and fails with a SyntaxError before the verifier does any work. Newer interpreters are
# available there as python3.9/3.11/3.12, so choose one rather than assuming python3 is current.
sat_python=""
for candidate in python3.12 python3.11 python3.9 python3; do
  if command -v "$candidate" > /dev/null 2>&1; then
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 7) else 1)' 2>/dev/null; then
      sat_python="$candidate"
      break
    fi
  fi
done
if [[ -z "$sat_python" ]]; then
  echo "No Python 3.7 or newer found; the runtime security verifier cannot run." >&2
  echo "On RHEL/AlmaLinux 8: dnf -y install python39" >&2
  exit 65
fi

# Written BESIDE the archive. The gate still runs over the staged closure - that provenance is
# what proves the CVE-2026-55200 fix commit is in this build - but the JSON is for whoever audits
# the release, not for the engineer carrying SAT onto a customer server.
sbom_output="$stage/lib/RUNTIME-SBOM.json"
security_args=(--stage "$stage" --platform linux --output "$sbom_output")
if [[ "$allow_insecure_dependencies" -eq 1 ]]; then security_args+=(--developer); fi
"$sat_python" "$root/tools/verify_runtime_security.py" "${security_args[@]}"
if [[ "$allow_insecure_dependencies" -eq 1 ]]; then
  cat > "$stage/lib/SECURITY-NOT-APPROVED.txt" <<'SECURITY_EOF'
This package was created with --allow-insecure-dependencies for isolated developer testing.
It did not pass the SAT official runtime dependency security gate and must not be distributed
as an engineer/customer release artifact. Review the RUNTIME-SBOM.json beside the archive for the
blocking findings.
SECURITY_EOF
fi

"$stage/lib/Verify-Runtime.sh"

# The gate has read what it needs; the audit artifacts now move out of the payload and sit beside
# the archive, where whoever audits the release can find them and the engineer carrying SAT onto a
# customer machine does not carry them along.
for audit_artifact in RUNTIME-PROVENANCE.json RUNTIME-SBOM.json; do
  if [[ -f "$stage/lib/$audit_artifact" ]]; then
    mv "$stage/lib/$audit_artifact" "$output/$(basename "$stage")-$audit_artifact"
  fi
done

tar -C "$output" -czf "$archive" "$(basename "$stage")"

# The checksum covers the finished archive and sits next to it. Hashing the staged files INTO the
# package meant the manifest could only verify a package someone had already unpacked - and the
# thing anyone is handed, and would want to verify, is the .tar.gz.
(
  cd "$output"
  sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256"
)
printf 'Created self-contained Linux package: %s\n' "$archive"
printf 'Package directory: %s\n' "$stage"
printf 'Build-host glibc: %s\n' "${glibc_version:-unknown}"
