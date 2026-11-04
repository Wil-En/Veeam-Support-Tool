#!/usr/bin/env python3
"""The Windows build's linked dependencies against config/security/runtime-security-policy.json.

The Windows program links OpenSSL, libarchive, libssh2 and SQLite statically, so no library file is
left in a package for tools/verify_runtime_security.py to read. This reads the versions vcpkg
installed for the build instead (vcpkg.spdx.json beside each port) and fails when one is below its
floor or outside its required series, as the Linux packager does for its bundled libraries.

    python tools/verify_windows_runtime_security.py [--build out/build/windows-msvc-release]
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTS = {"openssl": "openssl", "libarchive": "libarchive", "libssh2": "libssh2", "sqlite": "sqlite3"}


def version_tuple(text):
    return tuple(int(part) for part in re.findall(r"\d+", text.split("#")[0])[:4])


def at_least(found, minimum):
    a, b = version_tuple(found), version_tuple(minimum)
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) >= b + (0,) * (width - len(b))


def installed_version(build, port):
    spdx = build / "vcpkg_installed" / "x64-windows-static" / "share" / port / "vcpkg.spdx.json"
    if not spdx.is_file():
        return None
    data = json.loads(spdx.read_text(encoding="utf-8"))
    for package in data.get("packages", []):
        if package.get("name") == port:
            return str(package.get("versionInfo", ""))
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", default=str(ROOT / "out" / "build" / "windows-msvc-release"))
    args = parser.parse_args()
    build = Path(args.build)
    policy = json.loads((ROOT / "config" / "security" / "runtime-security-policy.json").read_text(encoding="utf-8"))
    failures = []
    for key, port in PORTS.items():
        rule = policy["components"].get(key)
        if rule is None:
            continue
        found = installed_version(build, port)
        if found is None:
            failures.append(f"{rule['displayName']}: no vcpkg record in {build} (configure and build first)")
            continue
        # A fix that exists only as an upstream commit: the overlay port reports vcpkg's base version, so
        # the commit it was built from (SAT-PROVENANCE.json) is what proves the fix, not the version.
        commit = str(rule.get("requiredFixCommit", "")).strip().lower()
        if commit:
            record = build / "vcpkg_installed" / "x64-windows-static" / "share" / port / "SAT-PROVENANCE.json"
            built = ""
            if record.is_file():
                built = str(json.loads(record.read_text(encoding="utf-8")).get("components", {})
                            .get(key, {}).get("sourceCommit", "")).strip().lower()
            if built != commit:
                failures.append(f"{rule['displayName']} was not built from the required fix commit "
                                f"{rule.get('requiredFixCommitShort', commit[:8])} (built from: {built or 'no record'})")
            else:
                print(f"{rule['displayName']} {found}: built from the fix commit {commit[:8]}")
            continue
        series = str(rule.get("requiredSeries", "")).strip()
        plain = found.split("#")[0]
        if series and not (plain == series or plain.startswith(series + ".")):
            failures.append(f"{rule['displayName']} {found} is outside the required series {series}.x")
        elif not at_least(plain, rule["minimumVersion"]):
            failures.append(f"{rule['displayName']} {found} is below the floor {rule['minimumVersion']}")
        else:
            print(f"{rule['displayName']} {found}: meets {series + '.x, ' if series else ''}{rule['minimumVersion']}")
    if failures:
        print("Windows runtime dependencies fail the security policy:")
        for failure in failures:
            print(" - " + failure)
        return 1
    print("Windows runtime dependencies meet the security policy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
