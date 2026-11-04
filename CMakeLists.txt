cmake_minimum_required(VERSION 3.25)

# SAT cross-platform GUI parity contract: shared workflows with explicit platform capability states.

set(SUPPORT_ASSIST_METADATA_FILE "${CMAKE_CURRENT_SOURCE_DIR}/project-metadata.json")
if(NOT EXISTS "${SUPPORT_ASSIST_METADATA_FILE}")
  message(FATAL_ERROR "Project metadata file is missing: ${SUPPORT_ASSIST_METADATA_FILE}")
endif()
file(READ "${SUPPORT_ASSIST_METADATA_FILE}" SUPPORT_ASSIST_METADATA_JSON)

string(JSON SUPPORT_ASSIST_PRODUCT_NAME GET "${SUPPORT_ASSIST_METADATA_JSON}" productName)
string(JSON SUPPORT_ASSIST_PRODUCT_SLUG GET "${SUPPORT_ASSIST_METADATA_JSON}" productSlug)
string(JSON SUPPORT_ASSIST_COMPANY_NAME GET "${SUPPORT_ASSIST_METADATA_JSON}" companyName)
string(JSON SUPPORT_ASSIST_VERSION GET "${SUPPORT_ASSIST_METADATA_JSON}" version)
string(JSON SUPPORT_ASSIST_CMAKE_PROJECT GET "${SUPPORT_ASSIST_METADATA_JSON}" cmakeProject)
string(JSON SUPPORT_ASSIST_EXECUTABLE GET "${SUPPORT_ASSIST_METADATA_JSON}" executableName)
string(JSON SUPPORT_ASSIST_UPGRADE_CODE GET "${SUPPORT_ASSIST_METADATA_JSON}" upgradeCode)
string(JSON SUPPORT_ASSIST_RELEASE_CHANNEL GET "${SUPPORT_ASSIST_METADATA_JSON}" releaseChannel)
string(JSON SUPPORT_ASSIST_BUILD_REVISION GET "${SUPPORT_ASSIST_METADATA_JSON}" buildRevision)
# The 4th component: the build number within the version, starting at 1 for each new version and rising
# with each build of it, shown in About and on the command line (version.buildNumber), plus the build
# date. Kept out of buildRevision, which stays version+"-"+stage for the lifecycle gates.
string(JSON SUPPORT_ASSIST_BUILD_NUMBER GET "${SUPPORT_ASSIST_METADATA_JSON}" buildNumber)
string(JSON SUPPORT_ASSIST_BUILD_DATE GET "${SUPPORT_ASSIST_METADATA_JSON}" buildDate)

project(${SUPPORT_ASSIST_CMAKE_PROJECT} VERSION ${SUPPORT_ASSIST_VERSION} LANGUAGES CXX)

set(SUPPORT_ASSIST_VERSION_QUAD
    "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}.0")
set(SUPPORT_ASSIST_VERSION_COMMA
    "${PROJECT_VERSION_MAJOR},${PROJECT_VERSION_MINOR},${PROJECT_VERSION_PATCH},0")
set(SUPPORT_ASSIST_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(SUPPORT_ASSIST_GENERATED_INCLUDE_DIR "${SUPPORT_ASSIST_GENERATED_DIR}/include")
set(SUPPORT_ASSIST_GENERATED_RESOURCE_DIR "${SUPPORT_ASSIST_GENERATED_DIR}/resources")
file(MAKE_DIRECTORY
     "${SUPPORT_ASSIST_GENERATED_INCLUDE_DIR}/support_assist"
     "${SUPPORT_ASSIST_GENERATED_RESOURCE_DIR}/manifests")

configure_file(
  config/version.hpp.in
  "${SUPPORT_ASSIST_GENERATED_INCLUDE_DIR}/support_assist/version.hpp"
  @ONLY
)

# Data files that follow Veeam's releases (docs/PROPOSAL_5.x_CHECKS.md section 2): embedded as byte
# arrays, so a package is still one executable and nothing beside it can be edited on a customer
# machine. Editing one of them reconfigures, and the generated file changes only when a file does.
set(SUPPORT_ASSIST_DATA_FILES
    config/checks/grpc.json
    config/checks/host-checks.json
    config/checks/health-events.json
    config/checks/links.json
    config/checks/named-pipes.json
    config/checks/object-storage-prices.json
    config/checks/object-storage.json
    config/checks/operation-setup.json
    config/checks/operation-options.json
    config/checks/packet-events.json
    config/checks/port-exhaustion.json
    config/checks/ports.json
    config/checks/postgres-checks.json
    config/checks/scenarios.json
    config/checks/sql-permissions.json
    config/checks/sql-queries.json
    config/checks/sql-shape-notes.json
    config/checks/storage-tests.json
    config/checks/time-zones.json
    config/checks/wmi-health.json)
set(_sat_data_declarations "")
set(_sat_data_table "")
foreach(_sat_data_file IN LISTS SUPPORT_ASSIST_DATA_FILES)
  set(_sat_data_path "${CMAKE_CURRENT_SOURCE_DIR}/${_sat_data_file}")
  if(NOT EXISTS "${_sat_data_path}")
    message(FATAL_ERROR "Data file is missing: ${_sat_data_path}")
  endif()
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_sat_data_path}")
  file(READ "${_sat_data_path}" _sat_data_hex HEX)
  string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," _sat_data_bytes "${_sat_data_hex}")
  get_filename_component(_sat_data_name "${_sat_data_file}" NAME)
  string(MAKE_C_IDENTIFIER "${_sat_data_name}" _sat_data_id)
  string(APPEND _sat_data_declarations
         "static const unsigned char kData_${_sat_data_id}[] = {${_sat_data_bytes}0x00};\n")
  string(APPEND _sat_data_table
         "    {\"${_sat_data_name}\", kData_${_sat_data_id}, sizeof(kData_${_sat_data_id}) - 1},\n")
endforeach()
file(CONFIGURE
     OUTPUT "${SUPPORT_ASSIST_GENERATED_INCLUDE_DIR}/support_assist/embedded_data_files.inc"
     CONTENT "// Generated from SUPPORT_ASSIST_DATA_FILES in CMakeLists.txt; edit the files, not this.\n${_sat_data_declarations}\nstatic const EmbeddedDataFile kEmbeddedDataFiles[] = {\n${_sat_data_table}};\n"
     @ONLY)

set(SUPPORT_ASSIST_APP_MANIFEST
    "${SUPPORT_ASSIST_GENERATED_RESOURCE_DIR}/manifests/SupportAssistTool.manifest")
set(SUPPORT_ASSIST_APP_ICON
    "${CMAKE_CURRENT_SOURCE_DIR}/resources/icons/SupportAssistTool.ico")
set(SUPPORT_ASSIST_RESOURCE_HEADER
    "${CMAKE_CURRENT_SOURCE_DIR}/resources/resource.h")
configure_file(resources/manifests/SupportAssistTool.manifest.in
               "${SUPPORT_ASSIST_APP_MANIFEST}" @ONLY)
configure_file(resources/SupportAssistTool.rc.in
               "${SUPPORT_ASSIST_GENERATED_RESOURCE_DIR}/SupportAssistTool.rc" @ONLY)
set_property(SOURCE "${SUPPORT_ASSIST_GENERATED_RESOURCE_DIR}/SupportAssistTool.rc"
             APPEND PROPERTY OBJECT_DEPENDS
             "${SUPPORT_ASSIST_APP_ICON};${SUPPORT_ASSIST_RESOURCE_HEADER};${SUPPORT_ASSIST_APP_MANIFEST}")

option(SUPPORT_ASSIST_BUILD_TESTS "Build tests" ON)
option(SUPPORT_ASSIST_BUILD_GUI "Build native platform GUI (Win32/X11/Cocoa)" ON)
option(SUPPORT_ASSIST_ENABLE_RE2 "Enable RE2-backed regular expressions" OFF)
option(SUPPORT_ASSIST_ENABLE_LIBARCHIVE "Enable archive search" OFF)
option(SUPPORT_ASSIST_ENABLE_LIBSSH2 "Enable integrated SSH/SFTP" ON)
# Isolated local testing only. A build produced with this ON links a libssh2 known to be affected
# by CVE-2026-55200 and must never be distributed to an engineer or customer.
option(SUPPORT_ASSIST_ALLOW_VULNERABLE_LIBSSH2 "Bypass the libssh2 CVE-2026-55200 floor (NEVER distribute)" OFF)
option(SUPPORT_ASSIST_STRICT_WARNINGS "Treat project warnings as errors" ON)

option(SUPPORT_ASSIST_PORTABLE_RUNTIME "Prepare Linux/macOS release binaries for self-contained runtime packaging" OFF)

# The Object Storage Check (Tools > Storage Tools, Settings > General > Experimental, the CLI's
# objectstorage) sends billed requests and is still experimental, so it is built into test builds only:
# the Debug presets, the figure harnesses and the Qt dev build turn it on; the Release presets and both
# packagers leave it off.
option(SUPPORT_ASSIST_OBJECT_STORAGE_CHECK "Build the experimental Object Storage Check (test builds only)" OFF)
if(SUPPORT_ASSIST_OBJECT_STORAGE_CHECK)
  add_compile_definitions(SUPPORT_ASSIST_OBJECT_STORAGE_CHECK=1)
endif()

# A single-file CLI.
#
# The GUI cannot be one file: Qt is LGPL and static linking it would oblige us to hand the customer
# relinkable objects, which is worse than shipping ./lib. The CLI has no Qt, so it can be exactly
# what a support engineer wants to carry onto a server - one binary, nothing beside it, nothing
# left behind and nothing to forget to delete.
#
# Dependencies must resolve to their static archives, so the library suffix list is narrowed before
# anything is found. Without that, find_package picks the .so and the link fails with
# "attempted static link of dynamic object".
option(SUPPORT_ASSIST_STATIC_CLI "Link the CLI as a single fully static binary (no GUI)" OFF)
if(SUPPORT_ASSIST_STATIC_CLI)
  if(SUPPORT_ASSIST_BUILD_GUI OR SUPPORT_ASSIST_LINUX_QT)
    message(FATAL_ERROR
      "SUPPORT_ASSIST_STATIC_CLI is CLI-only. Qt cannot be linked statically under its LGPL terms; "
      "configure with -DSUPPORT_ASSIST_BUILD_GUI=OFF.")
  endif()
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  set(BUILD_SHARED_LIBS OFF)
  set(OPENSSL_USE_STATIC_LIBS ON)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The Windows presets use vcpkg's x64-windows-static triplet. Match the
# project CRT to those dependencies (/MTd in Debug and /MT otherwise).
# cmake_minimum_required(3.25) selects CMP0091 NEW before project().
if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(ProjectWarnings)

if(WIN32)
  include(CheckCXXSourceCompiles)
  set(_support_assist_saved_required_definitions "${CMAKE_REQUIRED_DEFINITIONS}")
  set(_support_assist_saved_required_includes "${CMAKE_REQUIRED_INCLUDES}")
  set(_support_assist_saved_required_libraries "${CMAKE_REQUIRED_LIBRARIES}")
  set(CMAKE_REQUIRED_DEFINITIONS
      -DWIN32_LEAN_AND_MEAN
      -DNOMINMAX
      -DWINVER=0x0A00
      -D_WIN32_WINNT=0x0A00)
  set(CMAKE_REQUIRED_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/src/core/common")
  set(CMAKE_REQUIRED_LIBRARIES iphlpapi ws2_32)
  check_cxx_source_compiles([[
    #include "system_health_windows_sdk.hpp"
    #include <type_traits>

    int main() {
      static_assert(std::is_pointer_v<PMIB_IF_TABLE2>);
      static_assert(sizeof(MIB_IF_ROW2) > 0);
      PMIB_IF_TABLE2 table = nullptr;
      const auto status = GetIfTable2(&table);
      if (table != nullptr) {
        FreeMibTable(table);
      }
      (void)status;
      return 0;
    }
  ]] SUPPORT_ASSIST_IPHELPER2_COMPILES)
  set(CMAKE_REQUIRED_DEFINITIONS "${_support_assist_saved_required_definitions}")
  set(CMAKE_REQUIRED_INCLUDES "${_support_assist_saved_required_includes}")
  set(CMAKE_REQUIRED_LIBRARIES "${_support_assist_saved_required_libraries}")
  unset(_support_assist_saved_required_definitions)
  unset(_support_assist_saved_required_includes)
  unset(_support_assist_saved_required_libraries)
  if(NOT SUPPORT_ASSIST_IPHELPER2_COMPILES)
    message(FATAL_ERROR
      "The selected Windows SDK/compiler cannot compile the required IP Helper 2 API through "
      "system_health_windows_sdk.hpp. Required prerequisites are winsock2.h, ws2ipdef.h, "
      "windows.h, then iphlpapi.h; do not include netioapi.h directly. Review "
      "CMakeFiles/CMakeError.log for the compiler diagnostic.")
  endif()
endif()

# SQLite must come from vcpkg's own config package on Windows.
#
# CMake's stock FindSQLite3 module performs a single find_library() with no debug/release
# distinction. Under the vcpkg toolchain that resolved to x64-windows-static/debug/lib/sqlite3.lib,
# so the RELEASE executable linked the DEBUG SQLite - the source of "LINK : warning LNK4098:
# defaultlib 'LIBCMTD' conflicts with use of other libs". A shipping binary carrying both the
# release and debug C runtimes can allocate on one heap and free on the other. Every other
# dependency here (BZip2, LibLZMA, OpenSSL, ZLIB) resolved as a proper optimized/debug pair; SQLite
# was the only one that did not.
#
# unofficial-sqlite3 is vcpkg's exported config package and carries per-configuration imported
# locations. The stock module stays as the fallback for builds that do not use vcpkg.
find_package(unofficial-sqlite3 CONFIG QUIET)
if(TARGET unofficial::sqlite3::sqlite3)
  set(SUPPORT_ASSIST_SQLITE_TARGET unofficial::sqlite3::sqlite3)
else()
  find_package(SQLite3 REQUIRED)
  set(SUPPORT_ASSIST_SQLITE_TARGET SQLite::SQLite3)
endif()
find_package(OpenSSL REQUIRED)
if(NOT WIN32)
  # 0.4.5-dev.4: portable engineer workstations can run the same native SQL
  # permission diagnostic when an ODBC manager is present (unixODBC/iODBC).
  find_package(ODBC QUIET)
endif()
if(SUPPORT_ASSIST_ENABLE_RE2)
  find_package(re2 CONFIG REQUIRED)
endif()
if(SUPPORT_ASSIST_ENABLE_LIBSSH2)
  # vcpkg provides a CMake config target on Windows. Linux distributions often
  # ship libssh2 through pkg-config instead, so support both without making the
  # SSH/SFTP feature a Windows-only accident.
  find_package(libssh2 CONFIG QUIET)
  if(NOT TARGET libssh2::libssh2)
    find_package(Libssh2 CONFIG QUIET)
  endif()
  if(NOT TARGET libssh2::libssh2 AND NOT TARGET Libssh2::libssh2)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
      pkg_check_modules(SUPPORT_ASSIST_LIBSSH2 QUIET IMPORTED_TARGET libssh2)
    endif()
  endif()

  # SAT security gate: CVE-2026-55200 / GHSA-r8mh-x5qv-7gg2 (CVSS 8.1) is an out-of-bounds write
  # in libssh2's ssh2_transport_read(), which fails to enforce upper bounds on the packet_length
  # field. A malicious or compromised SSH server can corrupt memory on the connecting client with
  # no credentials and no user interaction, and a public proof-of-concept exists. Every release up
  # to and including 1.11.1 is affected.
  #
  # The advisory names a FIX COMMIT, not a fixed release: 97acf3df, "transport.c: Additional
  # boundary checks for packet length". Upstream has published nothing since 1.11.1, and master
  # declares itself 1.11.2_DEV, so the fix will ship as 1.11.2 - NOT
  # 1.12.0, which was this floor's previous value and does not exist on any roadmap. A floor of
  # 1.12.0 would have rejected the very release that fixes this.
  #
  # A version number cannot prove a pre-release build contains the fix, because every master
  # snapshot reports 1.11.2 either way. tools/verify_runtime_security.py therefore additionally
  # requires build provenance naming commit 97acf3df; see tools/Build-ThirdParty-Linux.sh.
  #
  # This matters more than usual for SAT: SAT is an SSH client, and ssh_probe_host_key() completes
  # a full key exchange BEFORE the host-key fingerprint is calculated and compared. The explicit
  # host-key trust control therefore provides no protection against this defect - the vulnerable
  # code runs first, against a server the engineer has not trusted yet.
  #
  # Fail closed at configure time rather than shipping a vulnerable binary. The floor is also
  # recorded in config/security/runtime-security-policy.json for the runtime packaging gate.
  # The floor and the required fix commit both come from the security policy, so the configure
  # gate and the packaging gate can never disagree about what "fixed" means.
  set(SUPPORT_ASSIST_LIBSSH2_MINIMUM "1.11.2")
  set(SUPPORT_ASSIST_LIBSSH2_FIX_COMMIT "")
  set(_sat_policy_file "${CMAKE_CURRENT_SOURCE_DIR}/config/security/runtime-security-policy.json")
  if(EXISTS "${_sat_policy_file}")
    file(READ "${_sat_policy_file}" _sat_policy_text)
    string(JSON _sat_floor ERROR_VARIABLE _sat_json_error
           GET "${_sat_policy_text}" components libssh2 minimumVersion)
    if(NOT _sat_json_error AND _sat_floor)
      set(SUPPORT_ASSIST_LIBSSH2_MINIMUM "${_sat_floor}")
    endif()
    string(JSON _sat_commit ERROR_VARIABLE _sat_json_error
           GET "${_sat_policy_text}" components libssh2 requiredFixCommit)
    if(NOT _sat_json_error AND _sat_commit)
      set(SUPPORT_ASSIST_LIBSSH2_FIX_COMMIT "${_sat_commit}")
    endif()
  endif()

  # Did someone build libssh2 from that commit and point us at it? tools/Build-ThirdParty-Linux.sh
  # records what it built in RUNTIME-PROVENANCE.json beside the libraries.
  set(SUPPORT_ASSIST_LIBSSH2_PROVEN_COMMIT "")
  set(_sat_provenance_candidates "")
  foreach(_sat_prefix IN LISTS CMAKE_PREFIX_PATH)
    list(APPEND _sat_provenance_candidates "${_sat_prefix}/RUNTIME-PROVENANCE.json")
  endforeach()
  # The Windows counterpart: ports/libssh2 (the SAT overlay port) installs SAT-PROVENANCE.json into
  # the vcpkg tree recording the commit it built. Same contract, different file, because vcpkg owns
  # the layout there and there is no ./lib prefix to write beside.
  foreach(_sat_vcpkg_root "${VCPKG_INSTALLED_DIR}" "${_VCPKG_INSTALLED_DIR}"
                          "${CMAKE_BINARY_DIR}/vcpkg_installed")
    if(_sat_vcpkg_root AND VCPKG_TARGET_TRIPLET)
      list(APPEND _sat_provenance_candidates
           "${_sat_vcpkg_root}/${VCPKG_TARGET_TRIPLET}/share/libssh2/SAT-PROVENANCE.json")
    endif()
  endforeach()
  foreach(_sat_provenance IN LISTS _sat_provenance_candidates)
    if(EXISTS "${_sat_provenance}")
      file(READ "${_sat_provenance}" _sat_provenance_text)
      string(JSON _sat_built ERROR_VARIABLE _sat_json_error
             GET "${_sat_provenance_text}" components libssh2 sourceCommit)
      if(NOT _sat_json_error AND _sat_built)
        set(SUPPORT_ASSIST_LIBSSH2_PROVEN_COMMIT "${_sat_built}")
      endif()
    endif()
  endforeach()
  set(SUPPORT_ASSIST_LIBSSH2_DETECTED "")
  if(DEFINED libssh2_VERSION AND libssh2_VERSION)
    set(SUPPORT_ASSIST_LIBSSH2_DETECTED "${libssh2_VERSION}")
  elseif(DEFINED Libssh2_VERSION AND Libssh2_VERSION)
    set(SUPPORT_ASSIST_LIBSSH2_DETECTED "${Libssh2_VERSION}")
  elseif(DEFINED SUPPORT_ASSIST_LIBSSH2_VERSION AND SUPPORT_ASSIST_LIBSSH2_VERSION)
    set(SUPPORT_ASSIST_LIBSSH2_DETECTED "${SUPPORT_ASSIST_LIBSSH2_VERSION}")
  endif()

  # A build proven to come from the fix commit is approved regardless of the version it reports.
  # This is the only way to express "contains the fix" for a library whose upstream has published
  # no release containing it - and it is stricter than the version test, not looser, because a
  # 1.11.2_DEV snapshot taken before the fix would pass a version check and fails this one.
  if(SUPPORT_ASSIST_LIBSSH2_FIX_COMMIT AND SUPPORT_ASSIST_LIBSSH2_PROVEN_COMMIT STREQUAL
     SUPPORT_ASSIST_LIBSSH2_FIX_COMMIT)
    message(STATUS "SAT: libssh2 built from reviewed fix commit "
                   "${SUPPORT_ASSIST_LIBSSH2_FIX_COMMIT} (CVE-2026-55200 remediated).")
  elseif(SUPPORT_ASSIST_LIBSSH2_DETECTED)
    if(SUPPORT_ASSIST_LIBSSH2_DETECTED VERSION_LESS SUPPORT_ASSIST_LIBSSH2_MINIMUM
       AND SUPPORT_ASSIST_ALLOW_VULNERABLE_LIBSSH2)
      set(SUPPORT_ASSIST_LIBSSH2_NOT_APPROVED TRUE CACHE INTERNAL "libssh2 below the reviewed floor")
      message(STATUS "SAT security notice acknowledged: libssh2 ${SUPPORT_ASSIST_LIBSSH2_DETECTED} "
                     "is affected by CVE-2026-55200. Packaging remains blocked.")
    elseif(SUPPORT_ASSIST_LIBSSH2_DETECTED VERSION_LESS SUPPORT_ASSIST_LIBSSH2_MINIMUM)
      # Deliberately a warning at compile time, not a fatal error. No package manager publishes a
      # fixed libssh2, because upstream has not released one - vcpkg and the distributions all top
      # out at 1.11.1. Failing the compile would stop all development without improving anything;
      # building the dependency from the fix commit is what actually clears this. This mirrors the existing Linux model, where the dependency gate blocks
      # PACKAGING rather than compiling.
      #
      # The release gate is enforced in packaging/Build-Portable.ps1 and
      # tools/verify_runtime_security.py, which refuse to produce a distributable artifact.
      set(SUPPORT_ASSIST_LIBSSH2_NOT_APPROVED TRUE CACHE INTERNAL "libssh2 below the reviewed floor")
      message(WARNING
        "==================================================================\n"
        "SAT SECURITY NOTICE: libssh2 ${SUPPORT_ASSIST_LIBSSH2_DETECTED} is affected by\n"
        "CVE-2026-55200 (CVSS 8.1). A malicious or compromised SSH server can execute code on\n"
        "the SAT client during key exchange, before host-key trust is evaluated. A public\n"
        "proof-of-concept exists.\n"
        "\n"
        "SAT requires libssh2 >= ${SUPPORT_ASSIST_LIBSSH2_MINIMUM} containing commit 97acf3df.\n"
        "Upstream has published no release with the fix, so no package manager can supply one.\n"
        "\n"
        "  * This binary MUST NOT be distributed to engineers or customers.\n"
        "  * Avoid connecting SAT's SSH/SFTP features to untrusted servers with this build.\n"
        "  * Release packaging is blocked and will refuse to produce an artifact.\n"
        "  * To fix on Linux: bash tools/Build-ThirdParty-Linux.sh, then configure with\n"
        "    -DCMAKE_PREFIX_PATH=<prefix>. It builds libssh2 from the fix commit.\n"
        "  * To fix on Windows: use the overlay port in ports/libssh2 (docs/SAT-LIBSSH2-OVERLAY.md)\n"
        "    built from the same commit. Waiting for vcpkg will not help - there is no release.\n"
        "==================================================================")
    else()
      set(SUPPORT_ASSIST_LIBSSH2_NOT_APPROVED FALSE CACHE INTERNAL "libssh2 meets the reviewed floor")
      message(STATUS "SAT security gate: libssh2 ${SUPPORT_ASSIST_LIBSSH2_DETECTED} satisfies the "
                     "CVE-2026-55200 floor (>= ${SUPPORT_ASSIST_LIBSSH2_MINIMUM})")
    endif()
  else()
    message(WARNING
      "SAT security gate: the libssh2 version could not be determined, so the CVE-2026-55200 floor "
      "(>= ${SUPPORT_ASSIST_LIBSSH2_MINIMUM}) could not be verified. Confirm the linked libssh2 "
      "version before distributing this build.")
  endif()
endif()
if(SUPPORT_ASSIST_ENABLE_LIBARCHIVE)
  # RC2 Hotfix 5: for MSVC/vcpkg static builds, do not rely on
  # LibArchive::LibArchive transitive propagation through SupportAssistCore.
  # SupportAssistCore is a static library, and the final executable is the
  # boundary at which archive.lib and all of its optional codec libraries must
  # be ordered together. Resolve the manifest-mode vcpkg tree here and link the
  # complete closure directly on every final consumer.
  if(MSVC)
    if(NOT DEFINED VCPKG_TARGET_TRIPLET OR "${VCPKG_TARGET_TRIPLET}" STREQUAL "")
      message(FATAL_ERROR "RC2-HF5 requires VCPKG_TARGET_TRIPLET for the MSVC static libarchive build")
    endif()

    set(_support_assist_vcpkg_installed_candidates
        "${CMAKE_BINARY_DIR}/vcpkg_installed")
    if(DEFINED VCPKG_INSTALLED_DIR AND NOT "${VCPKG_INSTALLED_DIR}" STREQUAL "")
      list(APPEND _support_assist_vcpkg_installed_candidates "${VCPKG_INSTALLED_DIR}")
    endif()
    if(DEFINED _VCPKG_INSTALLED_DIR AND NOT "${_VCPKG_INSTALLED_DIR}" STREQUAL "")
      list(APPEND _support_assist_vcpkg_installed_candidates "${_VCPKG_INSTALLED_DIR}")
    endif()
    list(REMOVE_DUPLICATES _support_assist_vcpkg_installed_candidates)

    unset(_support_assist_vcpkg_libarchive_root)
    foreach(_support_assist_vcpkg_installed IN LISTS _support_assist_vcpkg_installed_candidates)
      set(_support_assist_candidate
          "${_support_assist_vcpkg_installed}/${VCPKG_TARGET_TRIPLET}")
      if(EXISTS "${_support_assist_candidate}/lib/archive.lib" AND
         EXISTS "${_support_assist_candidate}/debug/lib/archive.lib" AND
         EXISTS "${_support_assist_candidate}/include/archive.h")
        set(_support_assist_vcpkg_libarchive_root "${_support_assist_candidate}")
        break()
      endif()
    endforeach()

    if(NOT DEFINED _support_assist_vcpkg_libarchive_root)
      message(FATAL_ERROR
        "RC2-HF5 could not locate the vcpkg static libarchive tree for ${VCPKG_TARGET_TRIPLET}. "
        "Checked: ${_support_assist_vcpkg_installed_candidates}")
    endif()

    set(_support_assist_vcpkg_libarchive_release
        "${_support_assist_vcpkg_libarchive_root}/lib/archive.lib")
    set(_support_assist_vcpkg_libarchive_debug
        "${_support_assist_vcpkg_libarchive_root}/debug/lib/archive.lib")
    set(_support_assist_vcpkg_libarchive_include
        "${_support_assist_vcpkg_libarchive_root}/include")

    find_package(ZLIB REQUIRED)
    find_package(BZip2 REQUIRED)
    find_package(LibLZMA REQUIRED)
    find_package(lz4 CONFIG REQUIRED)
    find_package(zstd CONFIG REQUIRED)

    if(NOT TARGET lz4::lz4)
      message(FATAL_ERROR "RC2-HF5 found lz4 but target lz4::lz4 is unavailable")
    endif()

    set(_support_assist_zstd_target "")
    if(TARGET zstd::libzstd_static)
      set(_support_assist_zstd_target zstd::libzstd_static)
    elseif(TARGET zstd::libzstd_shared)
      set(_support_assist_zstd_target zstd::libzstd_shared)
    elseif(TARGET zstd::libzstd)
      set(_support_assist_zstd_target zstd::libzstd)
    endif()
    if(NOT _support_assist_zstd_target)
      message(FATAL_ERROR "RC2-HF5 found zstd but no supported CMake target was exported")
    endif()

    message(STATUS "SAT RC2-HF5 direct-final-link libarchive closure: ACTIVE")
    message(STATUS "SAT RC2-HF5 libarchive root: ${_support_assist_vcpkg_libarchive_root}")
    message(STATUS "SAT RC2-HF5 zstd target: ${_support_assist_zstd_target}")
  else()
    find_package(LibArchive REQUIRED)
  endif()
endif()

function(support_assist_use_embedded_manifest target)
  if(MSVC)
    # Each Windows .rc file already embeds RT_MANIFEST resource 1. Prevent
    # link.exe/mt.exe from generating a second manifest with the same ID.
    target_link_options(${target} PRIVATE /MANIFEST:NO)
  endif()
endfunction()

function(support_assist_link_libarchive_final target)
  if(NOT SUPPORT_ASSIST_ENABLE_LIBARCHIVE)
    return()
  endif()

  if(MSVC)
    # Keep archive.lib immediately ahead of the codec closure on the final link
    # line. Do not hide this behind the static SupportAssistCore interface.
    target_link_libraries(${target} PRIVATE
      "$<$<CONFIG:Debug>:${_support_assist_vcpkg_libarchive_debug}>"
      "$<$<NOT:$<CONFIG:Debug>>:${_support_assist_vcpkg_libarchive_release}>"
      ZLIB::ZLIB
      BZip2::BZip2
      LibLZMA::LibLZMA
      lz4::lz4
      ${_support_assist_zstd_target}
    )
  endif()
endfunction()

# Compile a small declaration-contract target before the main core. This catches
# missing coupled headers and header/implementation schema drift early, before a
# long MSVC build reaches the affected module.
add_library(SupportAssistSourceContracts OBJECT
  src/core/contracts/source_contracts.cpp
  src/core/include/support_assist/tool_catalog.hpp
  src/core/include/support_assist/tool_download.hpp
  src/core/include/support_assist/system_health.hpp
  src/core/include/support_assist/veeam_log_review.hpp
  src/core/include/support_assist/log_highlighting.hpp
  src/core/include/support_assist/debug_log.hpp
  src/core/include/support_assist/product_discovery.hpp
  src/core/include/support_assist/guided_diagnostics.hpp
  src/core/include/support_assist/universal_collection.hpp
  src/core/include/support_assist/archive_browser.hpp
  src/core/include/support_assist/ssh_client.hpp
  src/core/common/system_health_windows_sdk.hpp
)
target_include_directories(SupportAssistSourceContracts PRIVATE
  "${SUPPORT_ASSIST_GENERATED_INCLUDE_DIR}"
  src/core/include
  src/core/common
)
if(WIN32)
  target_compile_definitions(SupportAssistSourceContracts PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    WINVER=0x0A00
    _WIN32_WINNT=0x0A00
  )
endif()
support_assist_set_warnings(SupportAssistSourceContracts)

add_library(SupportAssistCore STATIC)
add_dependencies(SupportAssistCore SupportAssistSourceContracts)
target_sources(SupportAssistCore PRIVATE
  src/core/common/error.cpp
  src/core/common/debug_log.cpp
  src/core/common/license.cpp
  src/core/common/strings.cpp
  src/core/common/time.cpp
  src/core/common/uuid.cpp
  src/core/common/secure_temp.cpp
  src/core/common/system_info.cpp
  src/core/common/product_discovery.cpp
  src/core/common/guided_diagnostics.cpp
  src/core/common/execution_artifact.cpp
  src/core/common/source_provenance.cpp
  src/core/common/environment_report_linux.cpp
  src/core/common/system_health.cpp
  src/core/common/time_check.cpp
  src/core/common/time_zones.cpp
  src/core/common/tool_results.cpp
  src/core/common/json.cpp
  src/core/common/data_files.cpp
  src/core/common/pending_restart.cpp
  src/core/process/veeam_watch.cpp
  src/core/case/case_workspace.cpp
  src/core/case/recent_cases.cpp
  src/core/case/case_review_store.cpp
  src/core/case/case_report.cpp
  src/core/database/sqlite.cpp
  src/core/network/network.cpp
  src/core/network/packet_events.cpp
  src/core/network/service_channel.cpp
  src/core/common/scenarios.cpp
  src/core/network/aws_sigv4.cpp
  src/core/network/object_storage.cpp
  src/core/network/file_transfer.cpp
  src/core/network/ssh_client.cpp
  src/core/network/terminal_screen.cpp
  src/core/network/local_ports.cpp
  src/core/network/firewall.cpp
  src/core/network/name_check.cpp
  src/core/network/udp_exchange.cpp
  src/core/network/sql_browser.cpp
  src/core/common/installed_products.cpp
  src/core/network/port_check.cpp
  src/core/network/quick_scan.cpp
  src/core/process/process_identity.cpp
  src/core/tools/tool_catalog.cpp
  src/core/tools/configured_tools.cpp
  src/core/tools/tool_download.cpp
  src/core/tools/tool_evidence.cpp
  src/core/tools/support_tools.cpp
  src/core/tools/installer_cache_win.cpp
  src/core/tools/named_pipes.cpp
  src/core/wmi/wmi_health.cpp
  src/core/common/host_checks.cpp
  src/core/common/tool_requirements.cpp
  src/core/common/local_accounts.cpp
  src/core/logs/log_collection.cpp
  src/core/logs/universal_collection.cpp
  src/core/logs/collected_evidence.cpp
  src/core/sql/sql_tools.cpp
  src/core/sql/sql_check.cpp
  src/core/sql/postgres_check.cpp
  src/core/sql/sql_catalog.cpp
  src/core/snapshot/schema.cpp
  src/core/snapshot/snapshot_store.cpp
  src/core/registry/registry_path.cpp
  src/core/registry/registry_diff.cpp
  src/core/case/case_report_document.cpp
  src/core/filesystem/filesystem_baseline.cpp
  src/core/filesystem/filesystem_diff.cpp
  src/core/filesystem/volume_check.cpp
  src/core/filesystem/ntfs_mft.cpp
  src/core/filesystem/ntfs_mft_win.cpp
  src/core/filesystem/disk_speed_test.cpp
  src/core/logs/system_error_codes.cpp
    src/core/logs/log_search.cpp
  src/core/logs/archive_browser.cpp
  src/core/logs/log_clock.cpp
  src/core/logs/process_logs.cpp
  src/core/logs/activity_record.cpp
  src/core/logs/log_highlighting.cpp
  src/core/logs/correlation.cpp
  src/core/logs/veeam_log_review.cpp
  src/core/export/export.cpp
)
if(WIN32)
  target_sources(SupportAssistCore PRIVATE
    src/core/registry/registry_scanner_win.cpp
    src/core/filesystem/filesystem_scanner_win.cpp
    src/core/filesystem/hash_win.cpp
    src/core/filesystem/file_lock_win.cpp
    src/core/filesystem/volume_check_win.cpp
    src/core/vss/vss_requester_win.cpp
    src/core/usn/usn_reader_win.cpp
    src/core/filesystem/change_journal_win.cpp
    src/core/security/privilege_win.cpp
    src/core/security/elevated_protocol_win.cpp
    src/core/security/elevated_client_win.cpp
    src/core/logs/event_log_win.cpp
    src/core/process/process_win.cpp
    src/core/process/local_shell_win.cpp
    src/core/process/process_identity_win.cpp
    src/core/network/local_ports_win.cpp
    src/core/network/firewall_win.cpp
    src/core/network/name_check_win.cpp
    src/core/network/quick_scan_win.cpp
    src/core/wmi/wmi_win.cpp
    src/core/sql/sql_odbc_win.cpp
    src/core/common/system_health_win.cpp
    src/core/common/time_check_win.cpp
    src/core/common/pending_restart_win.cpp
    src/core/process/veeam_watch_win.cpp
  )
  target_compile_definitions(SupportAssistCore PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX WINVER=0x0A00 _WIN32_WINNT=0x0A00)
  target_link_libraries(SupportAssistCore PUBLIC advapi32 bcrypt cfgmgr32 crypt32 iphlpapi msi netapi32 ntdll odbc32 ole32 oleaut32 pdh psapi secur32 shell32 shlwapi version vssapi wevtapi winhttp wintrust ws2_32 wbemuuid)
else()
  target_sources(SupportAssistCore PRIVATE
    src/core/registry/registry_scanner_stub.cpp
    src/core/filesystem/filesystem_scanner_posix.cpp
    src/core/filesystem/hash_posix.cpp
    src/core/filesystem/file_lock_posix.cpp
    src/core/filesystem/volume_check_posix.cpp
    src/core/vss/vss_requester_stub.cpp
    src/core/usn/usn_reader_stub.cpp
    src/core/filesystem/change_journal_stub.cpp
    src/core/security/privilege_stub.cpp
    src/core/security/elevated_client_stub.cpp
    src/core/logs/event_log_stub.cpp
    src/core/process/process_posix.cpp
    src/core/process/local_shell_posix.cpp
    src/core/process/process_identity_posix.cpp
    src/core/network/local_ports_posix.cpp
    src/core/network/firewall_posix.cpp
    src/core/network/name_check_posix.cpp
    src/core/network/quick_scan_posix.cpp
    src/core/common/time_check_posix.cpp
    src/core/common/pending_restart_posix.cpp
    src/core/process/veeam_watch_posix.cpp
    src/core/wmi/wmi_stub.cpp
  )
  # tool_requirements.cpp loads the ODBC driver manager to see whether it is there. glibc before 2.34
  # keeps dlopen in libdl.
  target_link_libraries(SupportAssistCore PRIVATE ${CMAKE_DL_LIBS})
  if(ODBC_FOUND)
    # 0.4.5-dev.4: ODBC headers are a developer build prerequisite only.
    # The POSIX implementation resolves the driver manager with dlopen/dlsym
    # when SQL Tools is actually used, so libodbc is not a process-start
    # dependency and cannot prevent the rest of SAT from launching.
    target_sources(SupportAssistCore PRIVATE src/core/sql/sql_odbc_portable.cpp)
    target_compile_definitions(SupportAssistCore PUBLIC SUPPORT_ASSIST_HAS_NATIVE_ODBC=1)
    if(ODBC_INCLUDE_DIRS)
      target_include_directories(SupportAssistCore PRIVATE ${ODBC_INCLUDE_DIRS})
    endif()
    target_link_libraries(SupportAssistCore PRIVATE ${CMAKE_DL_LIBS})
  else()
    target_sources(SupportAssistCore PRIVATE src/core/sql/sql_odbc_stub.cpp)
  endif()
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(SupportAssistCore PRIVATE src/core/common/system_health_linux.cpp)
  elseif(APPLE)
    target_sources(SupportAssistCore PRIVATE src/core/common/system_health_macos.cpp)
  else()
    target_sources(SupportAssistCore PRIVATE src/core/common/system_health_stub.cpp)
  endif()
endif()

target_include_directories(SupportAssistCore PUBLIC
  "${SUPPORT_ASSIST_GENERATED_INCLUDE_DIR}"
  src/core/include
)
# std::thread needs an explicit pthread link on any glibc older than 2.34.
#
# glibc merged libpthread into libc at 2.34, so a build on RHEL 9 / Ubuntu 22.04 or newer links
# without this and the omission is invisible. On the glibc 2.28 base the CLI is built against
# (RHEL/AlmaLinux 8) the linker fails with:
#
#   undefined reference to symbol 'pthread_join@@GLIBC_2.2.5'
#   /lib64/libpthread.so.0: error adding symbols: DSO missing from command line
#
# Threads::Threads resolves to nothing on the newer bases and to -lpthread on the older ones, so it
# is correct everywhere rather than a workaround for one distribution.
find_package(Threads REQUIRED)
target_link_libraries(SupportAssistCore PUBLIC ${SUPPORT_ASSIST_SQLITE_TARGET} OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
if(SUPPORT_ASSIST_ENABLE_LIBSSH2)
  if(TARGET libssh2::libssh2)
    target_compile_definitions(SupportAssistCore PUBLIC SUPPORT_ASSIST_HAS_LIBSSH2=1)
    target_link_libraries(SupportAssistCore PUBLIC libssh2::libssh2)
  elseif(TARGET Libssh2::libssh2)
    target_compile_definitions(SupportAssistCore PUBLIC SUPPORT_ASSIST_HAS_LIBSSH2=1)
    target_link_libraries(SupportAssistCore PUBLIC Libssh2::libssh2)
  elseif(TARGET PkgConfig::SUPPORT_ASSIST_LIBSSH2)
    target_compile_definitions(SupportAssistCore PUBLIC SUPPORT_ASSIST_HAS_LIBSSH2=1)
    target_link_libraries(SupportAssistCore PUBLIC PkgConfig::SUPPORT_ASSIST_LIBSSH2)
  endif()
endif()
if(WIN32)
  # SMB alternate-identity tests use the Windows Multiple Provider Router APIs.
  # Keep Mpr on the shared link interface because the implementation lives in Core.
  target_link_libraries(SupportAssistCore PUBLIC advapi32 bcrypt iphlpapi Mpr)
endif()
if(SUPPORT_ASSIST_ENABLE_RE2)
  target_compile_definitions(SupportAssistCore PUBLIC SUPPORT_ASSIST_HAS_RE2=1)
  target_link_libraries(SupportAssistCore PUBLIC re2::re2)
endif()
if(SUPPORT_ASSIST_ENABLE_LIBARCHIVE)
  target_compile_definitions(SupportAssistCore PUBLIC SUPPORT_ASSIST_HAS_LIBARCHIVE=1)
  if(MSVC)
    # Core needs the headers while compiling archive_browser.cpp, but HF5 links
    # archive.lib and its codec closure only at the final executable boundary.
    target_include_directories(SupportAssistCore PUBLIC "${_support_assist_vcpkg_libarchive_include}")
  else()
    target_link_libraries(SupportAssistCore PUBLIC LibArchive::LibArchive)
  endif()
endif()

support_assist_set_warnings(SupportAssistCore)
support_assist_apply_security_hardening(SupportAssistCore)

if(WIN32 AND SUPPORT_ASSIST_BUILD_GUI)
  # The release product is intentionally one executable. It dispatches to the
  # native GUI with no arguments, CLI commands when arguments are supplied,
  # and a private self-elevated helper mode for narrowly scoped operations.
  add_executable(SupportAssistTool WIN32
    src/gui/main.cpp
    src/gui/app_window.cpp
    src/gui/remote_console.cpp
    src/gui/pane_splits.cpp
    src/gui/file_drop.cpp
    src/gui/running_jobs_window.cpp
    src/gui/command_palette_window.cpp
    src/gui/shortcuts_panel.cpp
    src/gui/report_panel.cpp
    src/gui/vss_writer_picker.cpp
    src/gui/quick_tools.cpp
    src/gui/board_panel.cpp
    src/gui/home_page.cpp
    src/gui/diagnostics_page.cpp
    src/gui/crash_handler_win.cpp
    src/cli/commands.cpp
    src/elevated_helper/pipe_server.cpp
  )
  # gui_shared carries the per-page help articles, so both editions render the same words from one
  # copy rather than each keeping its own and drifting apart.
  # gui_shared carries the help articles and card model both editions render; it includes
  # gui_portable, so Windows needs the same two directories the other frontends already have.
  target_include_directories(SupportAssistTool PRIVATE resources src/gui_portable src/gui_shared)
  # The screenshot harness. Off by default and never present in a shipped build; when on, the
  # application can drive itself through every page and capture each one, which is how the
  # user-guide figures are produced. Windows had no equivalent of the Qt self-check, which is why
  # its figures were captured by hand and went stale.
  option(SUPPORT_ASSIST_UI_SELFCHECK "Build the UI self-check and screenshot harness" OFF)
  if(SUPPORT_ASSIST_UI_SELFCHECK)
    target_compile_definitions(SupportAssistTool PRIVATE SUPPORT_ASSIST_UI_SELFCHECK=1)
  endif()
  # SAT 0.4.6: src/gui/app_window.cpp crossed the COFF 65,535-section limit and MSVC failed with
  # C1128. /bigobj selects the extended object-file format (2^31 sections). It changes only the
  # intermediate object encoding - no code generation, runtime or behaviour difference - and is
  # Microsoft's documented remedy for large translation units. Debug is hit first because each
  # inline/template instantiation becomes its own COMDAT section.
  # This is a scale limit, not a defect: the file is ~24,900 lines. Decomposing the Win32 frontend
  # remains the real fix and is tracked in docs/PROPOSAL_0.4.6.md.
  target_compile_options(SupportAssistTool PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/bigobj>)
  target_link_libraries(SupportAssistTool PRIVATE comctl32 uxtheme dwmapi dbghelp shell32 advapi32 Mpr comdlg32 credui)
  target_compile_definitions(SupportAssistTool PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX WINVER=0x0A00 _WIN32_WINNT=0x0A00
  )
  target_sources(SupportAssistTool PRIVATE "${SUPPORT_ASSIST_GENERATED_RESOURCE_DIR}/SupportAssistTool.rc")
  support_assist_use_embedded_manifest(SupportAssistTool)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND SUPPORT_ASSIST_BUILD_GUI)
  # Linux frontend selection.
  #
  # The historical frontend is raw Xlib with core X11 bitmap fonts: no widget set, no anti-aliased
  # text, and no correct rendering of the UTF-8 machine names and paths SAT reads out of customer
  # evidence. It cannot carry a 19-page casework application, which is why 0.4.9 moves to Qt Widgets
  # (see docs/DESIGN_LINUX_GUI.md for the package-size cost).
  #
  # Both frontends are kept buildable until the Qt edition reaches feature parity, so the Linux
  # build never has a period where it cannot produce a working application. SUPPORT_ASSIST_LINUX_QT
  # selects between them.
  option(SUPPORT_ASSIST_LINUX_QT "Build the Linux frontend on Qt Widgets instead of raw Xlib" OFF)

  if(SUPPORT_ASSIST_LINUX_QT)
    # Qt is linked DYNAMICALLY and shipped beside the binary. Static linking would require a
    # commercial licence or a GPL release; LGPLv3 compliance here rests on the shared libraries
    # remaining replaceable under ./lib, which $ORIGIN/lib already allows.
    find_package(Qt6 6.2 COMPONENTS Widgets Gui Core QUIET)
    if(NOT Qt6_FOUND)
      find_package(Qt5 5.15 COMPONENTS Widgets Gui Core REQUIRED)
      set(SUPPORT_ASSIST_QT_LIBS Qt5::Widgets Qt5::Gui Qt5::Core)
    else()
      set(SUPPORT_ASSIST_QT_LIBS Qt6::Widgets Qt6::Gui Qt6::Core)
    endif()
    set(CMAKE_AUTOMOC ON)
    # AUTORCC compiles sat_resources.qrc into the binary, so the window icon travels with the
    # executable instead of being a file the package could ship without.
    set(CMAKE_AUTORCC ON)
    add_executable(SupportAssistTool
      src/gui_portable/portable_main.cpp
      src/gui_qt/qt_app.cpp
      src/gui_qt/sat_resources.qrc
      src/cli/commands.cpp
    )
    target_include_directories(SupportAssistTool PRIVATE src/gui_portable src/gui_shared src/gui_qt)
    target_link_libraries(SupportAssistTool PRIVATE ${SUPPORT_ASSIST_QT_LIBS})
    target_compile_definitions(SupportAssistTool PRIVATE SUPPORT_ASSIST_LINUX_QT=1)
    # Developer-only shell wiring check. It compiles extra accessors and a synthetic-click routine
    # into the binary, so it is never set for a package build. See run_ui_selfcheck().
    option(SUPPORT_ASSIST_UI_SELFCHECK "Build the Qt shell wiring self-check" OFF)
    if(SUPPORT_ASSIST_UI_SELFCHECK)
      target_compile_definitions(SupportAssistTool PRIVATE SUPPORT_ASSIST_UI_SELFCHECK=1)
    endif()
  else()
    find_package(X11 REQUIRED)
    add_executable(SupportAssistTool
      src/gui_portable/portable_main.cpp
      src/gui_portable/linux_app.cpp
      src/cli/commands.cpp
    )
    target_include_directories(SupportAssistTool PRIVATE src/gui_portable src/gui_shared ${X11_INCLUDE_DIR})
    target_link_libraries(SupportAssistTool PRIVATE ${X11_LIBRARIES})
  endif()
elseif(APPLE AND SUPPORT_ASSIST_BUILD_GUI)
  enable_language(OBJCXX)
  find_library(SUPPORT_ASSIST_COCOA_FRAMEWORK Cocoa REQUIRED)
  find_library(SUPPORT_ASSIST_FOUNDATION_FRAMEWORK Foundation REQUIRED)
  add_executable(SupportAssistTool MACOSX_BUNDLE
    src/gui_portable/portable_main.cpp
    src/gui_portable/macos_app.mm
    src/cli/commands.cpp
  )
  target_include_directories(SupportAssistTool PRIVATE src/gui_portable src/gui_shared)
  target_compile_options(SupportAssistTool PRIVATE $<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>)
  target_link_libraries(SupportAssistTool PRIVATE ${SUPPORT_ASSIST_COCOA_FRAMEWORK} ${SUPPORT_ASSIST_FOUNDATION_FRAMEWORK})
else()
  # Headless builds retain the same product target and executable name while
  # exposing the full shared command-line surface.
  add_executable(SupportAssistTool src/cli/main.cpp src/cli/commands.cpp)
endif()
set_target_properties(SupportAssistTool PROPERTIES OUTPUT_NAME "${SUPPORT_ASSIST_EXECUTABLE}")

# 0.4.5-dev.4 runtime distribution policy:
# - Linux Release packages keep SAT-owned third-party libraries beside the
#   executable in ./lib and search them through $ORIGIN/lib.
# - libstdc++/libgcc are linked statically in the portable Linux release to
#   reduce ABI drift between Debian/Ubuntu and RHEL-family workstations.
# - macOS packages stage non-system dylibs inside Contents/Frameworks and use
#   @executable_path/../Frameworks as the application-local runtime path.
# glibc/the ELF loader on Linux and Apple system frameworks on macOS remain OS
# responsibilities and are never copied into the SAT package.
if(SUPPORT_ASSIST_PORTABLE_RUNTIME AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set_target_properties(SupportAssistTool PROPERTIES
    BUILD_RPATH "\$ORIGIN/lib"
    INSTALL_RPATH "\$ORIGIN/lib")
  target_link_options(SupportAssistTool PRIVATE -static-libgcc -static-libstdc++)
elseif(SUPPORT_ASSIST_PORTABLE_RUNTIME AND APPLE)
  set_target_properties(SupportAssistTool PROPERTIES
    BUILD_RPATH "@executable_path/../Frameworks"
    INSTALL_RPATH "@executable_path/../Frameworks")
endif()

target_link_libraries(SupportAssistTool PRIVATE SupportAssistCore)
support_assist_link_libarchive_final(SupportAssistTool)
support_assist_set_warnings(SupportAssistTool)
support_assist_apply_security_hardening(SupportAssistTool)

if(SUPPORT_ASSIST_BUILD_TESTS)
  enable_testing()
  add_executable(SupportAssistTests
    tests/unit/test_main.cpp
    tests/unit/test_collected_evidence.cpp
    tests/unit/test_local_shell.cpp
    tests/unit/test_configured_tools.cpp
    tests/unit/test_registry_path.cpp
    tests/unit/test_registry_diff.cpp
    tests/unit/test_schema.cpp
    tests/unit/test_export.cpp
    tests/unit/test_log_search.cpp
    tests/unit/test_log_highlighting.cpp
    tests/unit/test_portable_capabilities.cpp
    tests/unit/test_workspace_view_model.cpp
    tests/unit/test_color_scheme.cpp
    tests/unit/test_sha256_sums.cpp
    tests/unit/test_gui_shared_models.cpp
    tests/unit/test_case_evidence.cpp
    tests/unit/test_help_articles.cpp
    tests/unit/test_veeam_log_review.cpp
    tests/unit/test_snapshot_config.cpp
    tests/unit/test_snapshot_comparisons.cpp
    tests/unit/test_filesystem_integration.cpp
    tests/unit/test_filesystem_diff.cpp
    tests/unit/test_time.cpp
    tests/unit/test_case_workspace.cpp
    tests/unit/test_tool_catalog.cpp
    tests/unit/test_network.cpp
    tests/unit/test_local_ports.cpp
    tests/unit/test_quick_scan.cpp
    tests/unit/test_packet_events.cpp
    tests/unit/test_sql_check.cpp
    tests/unit/test_postgres_check.cpp
    tests/unit/test_service_channel.cpp
    tests/unit/test_scenarios.cpp
    tests/unit/test_firewall.cpp
    tests/unit/test_name_check.cpp
    tests/unit/test_time_check.cpp
    tests/unit/test_data_files.cpp
    tests/unit/test_volume_check.cpp
    tests/unit/test_watch_restart.cpp
    tests/unit/test_keyboard_shortcuts.cpp
    tests/unit/test_quick_tool_reports.cpp
    tests/unit/test_connectivity_rows.cpp
    tests/unit/test_disk_speed_test.cpp
    tests/unit/test_time_zones.cpp
    tests/unit/test_log_clock.cpp
    tests/unit/test_process_logs.cpp
    tests/unit/test_activity_view.cpp
    tests/unit/test_activity_record.cpp
    tests/unit/test_environment_detail.cpp
    tests/unit/test_recent_cases.cpp
    tests/unit/test_progress_list.cpp
    tests/unit/test_operation_guide.cpp
    tests/unit/test_sql_browser.cpp
    tests/unit/test_field_choices.cpp
    tests/unit/test_system_differences.cpp
    tests/unit/test_host_checks.cpp
    tests/unit/test_tool_requirements.cpp
    tests/unit/test_change_journal.cpp
    tests/unit/test_ntfs_mft.cpp
    tests/unit/test_quick_check_review.cpp
    tests/unit/test_error_and_bind.cpp
    tests/unit/test_tool_run_profiles.cpp
    tests/unit/test_object_storage.cpp
    tests/unit/test_file_transfer.cpp
    tests/unit/test_home_board.cpp
    tests/unit/test_console_invocation.cpp
    tests/unit/test_guided_diagnostics.cpp
    tests/unit/test_log_collection.cpp
    tests/unit/test_sql_tools.cpp
    tests/unit/test_support_tools.cpp
    tests/unit/test_installer_cache.cpp
    tests/unit/test_named_pipes.cpp
    tests/unit/test_wmi_health.cpp
    tests/unit/test_collection_rows.cpp
    tests/unit/test_system_health.cpp
    tests/unit/test_debug_log.cpp
    tests/unit/test_execution_artifact.cpp
    tests/unit/test_tool_evidence.cpp
    tests/unit/test_correlation.cpp
    tests/unit/test_terminal_screen.cpp
    tests/unit/test_ssh_shell_live.cpp
    tests/unit/test_case_report.cpp
    tests/unit/test_process.cpp
    tests/unit/test_product_discovery.cpp
    tests/unit/test_universal_collection.cpp
    tests/unit/test_tool_download.cpp
    tests/unit/test_license.cpp
    tests/unit/test_db_query.cpp
  )
  target_link_libraries(SupportAssistTests PRIVATE SupportAssistCore)
  # The portable capability model is a header-only contract shared by the Linux and macOS
  # frontends. It is tested on every platform so a change that would put a dead tool category in
  # front of an engineer fails here rather than on their machine.
  target_include_directories(SupportAssistTests PRIVATE src/gui_portable src/gui_shared)
  support_assist_link_libarchive_final(SupportAssistTests)
  if(WIN32)
    target_link_libraries(SupportAssistTests PRIVATE Mpr)
  endif()
  support_assist_set_warnings(SupportAssistTests)
  support_assist_apply_security_hardening(SupportAssistTests)
  add_test(NAME unit COMMAND SupportAssistTests)
endif()

# The SSH/SFTP client self-test.
#
# Not part of the unit suite and not built by default, because it needs a real SSH server to talk
# to - it is an integration check, not a unit test. It exists as a target so the SAME test can be
# run on every platform: SAT's SSH client cannot be verified by unit tests, since the interesting
# behaviour is a real key exchange, a real SFTP subsystem, and a real server refusing a mismatched
# host key. Building it by hand worked on Linux and was impractical on Windows, where the static
# link line runs to ninety libraries.
#
# Enable with -DSUPPORT_ASSIST_BUILD_SSH_SELFTEST=ON, then point it at a server:
#   SupportAssistSshSelfTest <host> <port> <user> <keypath> [remote_dir]
option(SUPPORT_ASSIST_BUILD_SSH_SELFTEST "Build the SSH/SFTP client integration self-test" OFF)
if(SUPPORT_ASSIST_BUILD_SSH_SELFTEST)
  add_executable(SupportAssistSshSelfTest tools/dev/ssh_client_selftest.cpp)
  target_link_libraries(SupportAssistSshSelfTest PRIVATE SupportAssistCore)
  support_assist_link_libarchive_final(SupportAssistSshSelfTest)
  if(WIN32)
    target_link_libraries(SupportAssistSshSelfTest PRIVATE Mpr)
  endif()
  support_assist_set_warnings(SupportAssistSshSelfTest)
  support_assist_apply_security_hardening(SupportAssistSshSelfTest)
endif()

# The database query harness.
#
# Drives the shared query builders (gui_shared/db_console_sql.hpp) against a real database to verify
# SELECT/UPDATE/DELETE and the schema scans end-to-end - the DB console's query logic without the GUI.
# Not a unit test (it needs a live server), so it is a separate opt-in target like the SSH self-test.
#   cmake --preset windows-msvc-debug -DSUPPORT_ASSIST_BUILD_DB_HARNESS=ON
#   db_query_harness psql <psql.exe> 127.0.0.1 5432 VeeamBackup user postgres <password>
option(SUPPORT_ASSIST_BUILD_DB_HARNESS "Build the database query harness" OFF)
if(SUPPORT_ASSIST_BUILD_DB_HARNESS)
  add_executable(db_query_harness tools/dev/db_query_harness.cpp)
  target_link_libraries(db_query_harness PRIVATE SupportAssistCore)
  target_include_directories(db_query_harness PRIVATE src/gui_shared)
  support_assist_link_libarchive_final(db_query_harness)
  if(WIN32)
    target_link_libraries(db_query_harness PRIVATE Mpr)
  endif()
  support_assist_set_warnings(db_query_harness)
  support_assist_apply_security_hardening(db_query_harness)
endif()

# Tests are deliberately never installed or packaged. The customer-facing
# payload contains one executable plus documentation and license material.
install(TARGETS SupportAssistTool RUNTIME DESTINATION .)
install(DIRECTORY docs DESTINATION .)
install(FILES README.md CHANGELOG.md LICENSE THIRD_PARTY_NOTICES.md DESTINATION .)
