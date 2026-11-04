# Third-Party Notices

Support Assist Tool links to the following dependencies when enabled. The release owner must preserve the exact notices shipped by the resolved dependency versions.

- SQLite — public-domain dedication / blessing; resolved through vcpkg or the platform package manager.
- RE2 — BSD 3-Clause license; optional regular-expression engine.
- libarchive — BSD 2-Clause license with additional component notices; optional archive reader.
- vcpkg and CMake are build tools and are not bundled automatically.

No NirSoft code, binaries, assets, branding, or reverse-engineered internals are included.

Before release, generate an SBOM from the locked vcpkg graph and append exact versions, package hashes, transitive components, and license texts.

## libssh2

SAT can use libssh2 for the SSH/SFTP Explorer transport. libssh2 is distributed under a BSD-style license; the dependency is obtained through the platform package manager/vcpkg build workflow and remains subject to its upstream license and notices. SAT does not redistribute customer SSH keys or credentials.
