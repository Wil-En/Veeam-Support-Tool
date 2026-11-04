# SAT overlay port: libssh2 patched for CVE-2026-55200.
#
# WHY THIS EXISTS
# vcpkg's registry currently provides libssh2 up to 1.11.1, and every version up to and including
# 1.11.1 is affected by CVE-2026-55200 (CVSS 9.2): an integer overflow to out-of-bounds write in
# ssh2_transport_read() during SSH key exchange. A malicious or compromised SSH server can corrupt
# memory on the connecting client with no credentials and no user interaction. A public
# proof-of-concept exists.
#
# SAT is an SSH/SFTP client and ssh_probe_host_key() completes a full key exchange BEFORE the
# host-key fingerprint is computed, so SAT's host-key trust control does not mitigate this.
#
# The upstream fix is commit 97acf3dfda80c91c3a8c9f2372546301d4a1a7a8 (PR #2052), which rejects a
# packet_length above LIBSSH2_PACKET_MAXPAYLOAD before the faulty arithmetic. This port builds
# from a pinned commit at or after that fix. Switch REF to a release tag once upstream publishes
# one that contains the fix, and prefer the official vcpkg port once it carries that release.
#
# HOW TO USE
#   1. Set REF below to the commit you intend to ship (see SAT-LIBSSH2-OVERLAY.md).
#   2. Set SHA512 to the archive hash. If you do not know it, leave the placeholder: vcpkg will
#      fail on the first run and print the actual hash, which you then paste in. This is the
#      documented vcpkg workflow and is self-correcting.
#   3. Build with the overlay active (CMakePresets already points at ${CMAKE_SOURCE_DIR}/ports).

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO libssh2/libssh2
    # Pinned to the upstream commit containing the CVE-2026-55200 bounds check.
    REF 97acf3dfda80c91c3a8c9f2372546301d4a1a7a8
    # SHA512 of https://github.com/libssh2/libssh2/archive/97acf3df...tar.gz (590,947 bytes),
    # taken 2026-08-24. The archive was unpacked and checked before this was pinned: src/transport.c
    # rejects packet_length above LIBSSH2_PACKET_MAXPAYLOAD at three sites, which is the
    # CVE-2026-55200 bounds check. The ref alone was not treated as proof.
    SHA512 2ebb2f20e179651a3b55e039cdcdcddabdf6744f1880028a651014fcd31275e62074c6f5ce8536cb1c574084d9db6bc50f924c840a28c471c3123b94744b893d
    HEAD_REF master
)

vcpkg_check_features(
    OUT_FEATURE_OPTIONS FEATURE_OPTIONS
    FEATURES
        zlib CMAKE_REQUIRE_FIND_PACKAGE_ZLIB
)

if("openssl" IN_LIST FEATURES)
    set(CRYPTO_BACKEND "OpenSSL")
else()
    set(CRYPTO_BACKEND "WinCNG")
endif()

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        ${FEATURE_OPTIONS}
        -DCRYPTO_BACKEND=${CRYPTO_BACKEND}
        -DBUILD_EXAMPLES=OFF
        -DBUILD_TESTING=OFF
        -DENABLE_ZLIB_COMPRESSION=ON
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME libssh2 CONFIG_PATH lib/cmake/libssh2)
vcpkg_fixup_pkgconfig()
vcpkg_copy_pdbs()

file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share"
    "${CURRENT_PACKAGES_DIR}/share/doc"
)

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/COPYING")

# Record WHICH COMMIT was built, so the build and packaging gates can verify the fix is present.
#
# A version number cannot express this. libssh2 at the fix commit still declares 1.11.1 to CMake
# (upstream had not bumped it), while its runtime banner says 1.11.2_DEV - so a version comparison
# calls a genuinely fixed build vulnerable, and would equally pass a 1.11.2_DEV snapshot taken the
# day before the fix landed. The commit is the only thing that actually distinguishes them.
#
# This is the Windows counterpart of RUNTIME-PROVENANCE.json, which tools/Build-ThirdParty-Linux.sh
# writes for the Linux packages. Both are read against requiredFixCommit in
# config/security/runtime-security-policy.json.
file(WRITE "${CURRENT_PACKAGES_DIR}/share/${PORT}/SAT-PROVENANCE.json"
"{\n"
"  \"schemaVersion\": 1,\n"
"  \"builtBy\": \"ports/libssh2 (SAT overlay port)\",\n"
"  \"components\": {\n"
"    \"libssh2\": {\n"
"      \"sourceCommit\": \"97acf3dfda80c91c3a8c9f2372546301d4a1a7a8\",\n"
"      \"sourceUrl\": \"https://github.com/libssh2/libssh2/archive/97acf3dfda80c91c3a8c9f2372546301d4a1a7a8.tar.gz\",\n"
"      \"reason\": \"CVE-2026-55200 is fixed only in this commit; upstream has published no release containing it.\"\n"
"    }\n"
"  }\n"
"}\n")
