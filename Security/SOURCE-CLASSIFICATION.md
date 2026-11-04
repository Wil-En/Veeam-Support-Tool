# Source classification: SAT 0.5.0.6

Source read: `SAT-v0.5.0-work-src` (frozen, build 0.5.0.6, `buildRevision` 0.5.0-beta.6). Every file in this
review copy is byte-identical to that tree; `SHA256SUMS-review-copy.txt` lists them and
`source-classification.csv` lists every source file with its category and reason.

## Development with AI assistance

AI assistance (Claude Code and Cowork agents) was used throughout development, including writing the code in
`src/`. This split sorts files by purpose. Taking out the development material does not change how the code was
written, and a count of zero AI terms in `src/` shows only that the text does not mention AI.

## Result

| Category | Files | MB | Meaning |
|---|---:|---:|---|
| BUILD-REQUIRED | 380 | 9.0 | Needed to compile SAT. In the review copy. |
| RELEASE-CHAIN | 27 | 10.0 | Not read by the compile. Builds third-party libraries, checks dependency floors or makes packages. In the review copy. |
| AI-DEV | 36 | 0.5 | Written for AI development sessions: instructions, hand-overs, agent coordination. Excluded. |
| QA-TEST | 3212 | 351.4 | Unit tests, QA gates, harnesses and captures. Excluded. |
| DEV-TOOLING | 14 | 0.2 | Developer utilities and wrappers. Excluded. |
| PRODUCT-DOCS | 290 | 28.7 | Developer Bible, guide templates and figures. Excluded, available on request. |
| PROJECT-RECORDS | 180 | 1.9 | Reports, plans, issue lists and old manifests. Excluded. |
| GENERATED | 13267 | 5468.5 | Build output, Python caches and a stray packet capture. Excluded. |

## AI development files (excluded)

- `CLAUDE-AI-PROJECT-HANDOFF.md`
- `CLAUDE-AI-START-HERE.md`
- `CLAUDE.md`
- `CURRENT-PROJECT-HANDOFF-0.4.4-BUILDFIX2.md`
- `CURRENT-PROJECT-HANDOFF-0.4.4-BUILDFIX3.md`
- `CURRENT-PROJECT-HANDOFF-0.4.4-BUILDFIX4.md`
- `CURRENT-PROJECT-HANDOFF-0.4.4-RC2-HOTFIX4.md`
- `CURRENT-PROJECT-HANDOFF-0.4.4-RC2-HOTFIX5.md`
- `CURRENT-PROJECT-HANDOFF-0.4.4-RC2-HOTFIX6.md`
- `CURRENT-PROJECT-HANDOFF-0.4.4-RC2-HOTFIX7.md`
- `CURRENT-PROJECT-HANDOFF-0.4.4-RC2.md`
- `CURRENT-PROJECT-HANDOFF-0.4.4.md`
- `CURRENT-PROJECT-HANDOFF-0.4.5-DEV2.md`
- `CURRENT-PROJECT-HANDOFF-0.4.5-DEV3.md`
- `CURRENT-PROJECT-HANDOFF-0.4.5-DEV4.md`
- `CURRENT-PROJECT-HANDOFF-0.4.5.md`
- `CURRENT-PROJECT-HANDOFF-BUILDFIX13.md`
- `CURRENT-PROJECT-HANDOFF-RC1-HOTFIX1.md`
- `CURRENT-PROJECT-HANDOFF-RC1-HOTFIX2.md`
- `CURRENT-PROJECT-HANDOFF-RC1.md`
- `CURRENT-PROJECT-HANDOFF-RC2.md`
- `CURRENT-PROJECT-HANDOFF.md`
- `HANDOFF-READ-THIS-FIRST.md`
- `PROJECT-CONTINUATION-HISTORY.md`
- `docs/AGENT_BOARD.md`
- `docs/HANDOFF_0.5.0.md`
- `docs/HANDOFF_2026-10-23.md`
- `docs/HANDOFF_AGENT_SWITCH.md`
- `docs/HANDOFF_CLAUDE_CODE.md`
- `docs/LINUX_GUI_SESSION_LOG.md`
- `docs/PLAN_NEXT_SESSION.md`
- `docs/PREREQ_CHECK_AGENT.md`
- `docs/REVIEW_AI_ARTIFACTS.md`
- `docs/developer-bible/WRITING.md`
- `tools/agents/AI_QA_HARNESS.md`
- `tools/agents/README.md`

## Other excluded files that mention AI

Sorted by purpose rather than by these mentions. Counts are term matches, not a reading of each file.

- `PROJECT-RULES.md` (PROJECT-RECORDS, 6)
- `SAT-v0.4.5-Manifest.txt` (PROJECT-RECORDS, 4)
- `SOURCE-FILE-INVENTORY.txt` (PROJECT-RECORDS, 4)
- `SOURCE-SHA256SUMS.txt` (PROJECT-RECORDS, 4)
- `VALIDATION-STATUS.json` (PROJECT-RECORDS, 1)
- `docs/AUDIT_0.4.11.md` (PROJECT-RECORDS, 2)
- `docs/CODE_FINDINGS_FOR_0.5.1.md` (PROJECT-RECORDS, 6)
- `docs/DESIGN_MACOS_GUI.md` (PROJECT-RECORDS, 1)
- `docs/GUI-PARITY-0.4.9.3.md` (PROJECT-RECORDS, 2)
- `docs/GUI_REVIEW_4.x.md` (PROJECT-RECORDS, 1)
- `docs/IDEAS_5.x.md` (PROJECT-RECORDS, 1)
- `docs/ISSUES_0.4.11_FIELD.md` (PROJECT-RECORDS, 1)
- `docs/ISSUES_0.5.0_BETA.md` (PROJECT-RECORDS, 30)
- `docs/OUTSTANDING_REQUESTS.md` (PROJECT-RECORDS, 1)
- `docs/PLAN_0.5.0_BETA.md` (PROJECT-RECORDS, 1)
- `docs/PLAN_RECOVERY_MEDIA.md` (PROJECT-RECORDS, 1)
- `docs/PROPOSAL_0.4.13.md` (PROJECT-RECORDS, 1)
- `docs/PROPOSAL_0.5.x_TOOLS_OVERHAUL.md` (PROJECT-RECORDS, 6)
- `docs/PROPOSAL_4.x.md` (PROJECT-RECORDS, 7)
- `docs/PROPOSAL_RECOVERY_MEDIA.md` (PROJECT-RECORDS, 2)
- `docs/PROPOSAL_SERVICENOW_FORK.md` (PROJECT-RECORDS, 1)
- `docs/PROPOSAL_TIME_CORRELATION.md` (PROJECT-RECORDS, 1)
- `docs/QA-FINDINGS-0.4.9.2.md` (PROJECT-RECORDS, 1)
- `docs/REMAINING_0.5.0.md` (PROJECT-RECORDS, 34)
- `docs/SAT-LIBSSH2-OVERLAY.md` (PROJECT-RECORDS, 1)
- `docs/SECURITY_FINDINGS_0.5.0.md` (PROJECT-RECORDS, 1)
- `docs/TEST_HARNESS_REVIEW_0.4.12.md` (PROJECT-RECORDS, 1)
- `docs/USER_GUIDE_REQUIREMENTS.md` (PROJECT-RECORDS, 2)
- `docs/user-guide/transcripts/cli/diagnostics.txt` (PRODUCT-DOCS, 1)
- `docs/user-guide/transcripts/cli/logs-review.txt` (PRODUCT-DOCS, 1)
- `docs/user-guide/transcripts/cli/logs-search.txt` (PRODUCT-DOCS, 14)
- `tools/Generate-Developer-Bible.py` (DEV-TOOLING, 4)
- `tools/dev/Verify.ps1` (QA-TEST, 2)
- `tools/test_045_source_contracts.py` (QA-TEST, 2)
- `tools/test_no_inference.py` (QA-TEST, 19)
- `qa-out/`: 294 files with matches, listed in the CSV

## AI terms in the review copy

- `docs/user-guide/Support-Assist-Tool-CLI-User-Guide.html` (15)

AI service endpoint names in the review copy: none found.

## Credentials and personal strings

Pattern scan, values not shown. Matches still need reading.

In the review copy:

- `src/core/logs/log_collection.cpp` line 871: literal credential
- `src/core/network/network.cpp` line 2487: literal credential
- `src/core/network/service_channel.cpp` line 445: literal credential
- `src/gui/app_window.cpp` line 30785: literal credential

In excluded files:

- `qa-out/app_window.before-f30.cpp`: literal credential (1)
- `qa-out/app_window.cpp.before-categories`: literal credential (1)
- `qa-out/app_window.cpp.before-restore`: literal credential (1)
- `qa-out/elevated-capture/app_window.cpp.before`: literal credential (1)
- `qa-out/f101/app_window.cpp.before`: literal credential (1)
- `qa-out/f120/app_window.cpp.before-combo`: literal credential (1)
- `qa-out/f120/before/app_window.cpp`: literal credential (1)
- `qa-out/f128/app_window.before.cpp`: literal credential (1)
- `qa-out/f140/app_window.cpp`: literal credential (1)
- `qa-out/f85/app_window.cpp.before-sd-mode`: literal credential (1)
- `qa-out/f85/service_channel.cpp.before-f91`: literal credential (1)
- `qa-out/f92/app_window.cpp.before`: literal credential (1)
- `qa-out/fake-s3/ca-key.pem`: file name (1)
- `qa-out/fake-s3/ca-key.pem`: private key block (1)
- `qa-out/fake-s3/ca.pem`: file name (1)
- `qa-out/fake-s3/cert.pem`: file name (1)
- `qa-out/fake-s3/key.pem`: file name (1)
- `qa-out/fake-s3/key.pem`: private key block (1)
- `qa-out/fake_s3_server.py`: literal credential (1)
- `qa-out/wmi-machine/app_window.cpp.before`: literal credential (1)
- `tests/unit/test_object_storage.cpp`: AWS access key id (2)
- `tests/unit/test_postgres_check.cpp`: literal credential (2)

Account, machine or lab names in the review copy (Willow, wilow, wilster1909, SPECTR, ubu-val):

- `src/core/include/support_assist/collected_evidence.hpp` (1)
- `src/core/include/support_assist/local_accounts.hpp` (1)
- `src/core/include/support_assist/log_clock.hpp` (1)
- `src/core/logs/veeam_log_review.cpp` (1)
- `src/core/network/ssh_client.cpp` (1)
- `src/gui_shared/home_board.hpp` (1)
- `src/gui_shared/system_differences_run.hpp` (1)

## Files in the copy that name an excluded file

179 names in 39 files: 40 on comment lines and 139 in strings, build lists or script commands. 88 of those are the unit test list in `CMakeLists.txt`, which `SUPPORT_ASSIST_BUILD_TESTS=OFF` skips. All are left as they are so the copy stays byte-identical.

- `CHANGELOG.md` (12)
- `CMakeLists.txt` (94)
- `README.md` (21)
- `config/checks/object-storage-prices.json` (1)
- `config/checks/operation-options.json` (1)
- `config/checks/operation-setup.json` (1)
- `config/checks/time-zones.json` (1)
- `packaging/Build-Portable.ps1` (1)
- `src/cli/commands.cpp` (1)
- `src/core/include/support_assist/configured_tools.hpp` (1)
- `src/core/include/support_assist/data_files.hpp` (1)
- `src/core/include/support_assist/disk_speed_test.hpp` (1)
- `src/core/include/support_assist/file_lock.hpp` (1)
- `src/core/include/support_assist/firewall.hpp` (1)
- `src/core/include/support_assist/local_ports.hpp` (1)
- `src/core/include/support_assist/log_clock.hpp` (1)
- `src/core/include/support_assist/name_check.hpp` (1)
- `src/core/include/support_assist/pending_restart.hpp` (1)
- `src/core/include/support_assist/port_check.hpp` (1)
- `src/core/include/support_assist/quick_scan.hpp` (1)
- `src/core/include/support_assist/time_check.hpp` (3)
- `src/core/include/support_assist/time_zones.hpp` (1)
- `src/core/include/support_assist/veeam_watch.hpp` (1)
- `src/core/include/support_assist/volume_check.hpp` (1)
- `src/core/logs/veeam_log_review.cpp` (1)
- `src/gui/app_window.cpp` (5)
- `src/gui/remote_console.cpp` (1)
- `src/gui_portable/linux_app.cpp` (3)
- `src/gui_portable/macos_app.mm` (1)
- `src/gui_qt/qt_app.cpp` (7)
- `src/gui_shared/keyboard_shortcuts.hpp` (2)
- `src/gui_shared/operation_options.hpp` (1)
- `src/gui_shared/workspace_operations.hpp` (2)
- `src/gui_shared/workspace_view_model.hpp` (1)
- `tools/Install-Linux-Build-Prereqs.sh` (1)
- `tools/Package-Linux.sh` (1)
- `tools/Setup-AlmaLinux8-CliBase.sh` (1)
- `tools/Setup-AlmaLinux9-BuildBase.sh` (1)
- `tools/dev/check-object-storage-prices.sh` (1)

Names outside comments and the unit test list:

- `CHANGELOG.md:10`: `docs/SECURITY_REVIEW_0.4.5_DEV4.md`
- `CHANGELOG.md:17`: `tools/security_source_audit.py`
- `CHANGELOG.md:30`: `docs/BUILDING_ALL_PLATFORMS.md`
- `CHANGELOG.md:46`: `docs/PORTABLE_ENGINEER_PARITY_0.4.5.md`
- `CHANGELOG.md:90`: `tests/unit/test_process.cpp`
- `CHANGELOG.md:151`: `tools\Build-Debug.cmd`
- `CHANGELOG.md:151`: `tools\Build-Release.cmd`
- `CHANGELOG.md:176`: `docs/CLI_REFERENCE.md`
- `CHANGELOG.md:310`: `docs/LINUX_BUILD.md`
- `CHANGELOG.md:403`: `tools\Build-Release.cmd`
- `CHANGELOG.md:405`: `tests/unit/test_process.cpp`
- `CHANGELOG.md:633`: `tools\Set-ProjectVersion.ps1`
- `CMakeLists.txt:365`: `docs/SAT-LIBSSH2-OVERLAY.md`
- `CMakeLists.txt:1006`: `tools/dev/ssh_client_selftest.cpp`
- `CMakeLists.txt:1025`: `tools/dev/db_query_harness.cpp`
- `README.md:48`: `docs/CROSS_PLATFORM_BUILD.md`
- `README.md:48`: `docs/LINUX_BUILD.md`
- `README.md:226`: `docs/BUILDING_ALL_PLATFORMS.md`
- `README.md:239`: `docs/BUILDING_ALL_PLATFORMS.md`
- `README.md:239`: `docs/CROSS_PLATFORM_BUILD.md`
- `README.md:239`: `docs/WINDOWS_BUILD_AND_TEST_GUIDE.md`
- `README.md:239`: `docs/WINDOWS_BUILD_POLICY.md`
- `README.md:244`: `docs/developer-bible/Support-Assist-Tool-Developer-Bible.html`
- `README.md:244`: `tools/Generate-Developer-Bible.py`
- `README.md:245`: `docs/LOG_PARSER.md`
- `README.md:246`: `docs/SYSTEM_HEALTH.md`
- `README.md:247`: `docs/VEEAM_PLATFORM_CATALOG.md`
- `README.md:248`: `docs/UNIVERSAL_LOG_COLLECTION.md`
- `README.md:249`: `docs/CROSS_PLATFORM_BUILD.md`
- `README.md:250`: `docs/VALIDATION.md`
- `README.md:256`: `docs/DEVELOPER_GUIDE.md`
- `README.md:257`: `docs/BUILDING_ALL_PLATFORMS.md`
- `README.md:258`: `docs/CLI_REFERENCE.md`
- `README.md:259`: `docs/SECURITY.md`
- `README.md:259`: `docs/PRIVACY.md`
- `README.md:260`: `docs/PORTABLE_ENGINEER_PARITY_0.4.5.md`
- `config/checks/object-storage-prices.json:3`: `tools/update_object_storage_prices.py`
- `config/checks/operation-options.json:3`: `tools/test_operation_options.py`
- `config/checks/operation-setup.json:3`: `tools/test_operation_setup.py`
- `config/checks/time-zones.json:3`: `tools/dev/Generate-TimeZones.ps1`
- `packaging/Build-Portable.ps1:80`: `tools/Generate-Project-Docs.py`
- `src/gui/app_window.cpp:41385`: `docs\\user-guide\\Support-Assist-Tool-User-Guide.html`
- `src/gui_portable/linux_app.cpp:1091`: `docs/CLI_REFERENCE.md`
- `src/gui_portable/linux_app.cpp:1091`: `docs/CROSS_PLATFORM_BUILD.md`
- `src/gui_portable/linux_app.cpp:1091`: `docs/UNIVERSAL_LOG_COLLECTION.md`
- `src/gui_portable/macos_app.mm:828`: `docs/CROSS_PLATFORM_BUILD.md`
- `src/gui_qt/qt_app.cpp:1398`: `docs/DESIGN_LINUX_GUI.md`
- `src/gui_qt/qt_app.cpp:12252`: `docs/DESIGN_LINUX_GUI.md`
- `tools/Package-Linux.sh:178`: `tools/Generate-Project-Docs.py`
- `tools/Setup-AlmaLinux8-CliBase.sh:111`: `tools/dev/Build-On-Alma.sh`
- `tools/Setup-AlmaLinux9-BuildBase.sh:170`: `tools/dev/Build-On-Alma.sh`

## Building the review copy

The Windows presets turn the unit tests on and `tests/` is not in the copy, so the option is set off:

```powershell
$env:VCPKG_ROOT = '<vcpkg checkout>'
cmake --preset windows-msvc-release -B <build folder> -DSUPPORT_ASSIST_BUILD_TESTS=OFF
cmake --build <build folder> --config Release --target SupportAssistTool
```

`tools/Build-Release.ps1` is excluded because it runs the QA gates first. The Linux release presets already
have the tests off. Other than `verify_windows_runtime_security.py`, the release-chain scripts were kept for
review and have not been run from this copy.

## Build check

Run on 2026-11-04 17:09 on Windows, MSVC, preset windows-msvc-release, tests off.

- Configure exit code: 0
- Build exit code (target SupportAssistTool): 0
- `verify_windows_runtime_security.py` exit code: 0
- `SupportAssistTool.exe version`: Support Assist Tool 0.5.0.6 (built 2026-10-28)
- SHA-256 of the program built: 6637FC2A7A3201E4FAC3E600DF88E80B382C50CFBDAC249DA45E90BA204748DC
- Copy after the build: verified 407 files, 0 mismatches, 0 files beyond the checksum list

This shows the Windows release program compiles from the kept files alone. The Linux and macOS builds were not run.
## What the scan matches are

Read directly on 2026-11-04.

- The four credential matches in the review copy are not credentials. Two are a PowerShell regular expression named
  `$secret` that redacts registry values by name (`log_collection.cpp:871`, `app_window.cpp:30785`), one is the
  `%port%` banner placeholder (`network.cpp:2487`) and one is the `SATPING1` HTTP/2 ping payload (`service_channel.cpp:445`).
- The AI term matches in the review copy are all in the CLI guide: 15 matches, 15 of them the folder name
  `Claudesrc` in development paths printed in the guide's command transcripts. That guide is a shipped document, so
  those paths reach users.
- The account, machine and lab names in the review copy are seven source comments: `SPECTR` in five, and an account
  name in `veeam_log_review.cpp:1307` and `ssh_client.cpp:488`. This scan covers only the names listed.
- `tests/unit/test_object_storage.cpp` uses `AKIAIOSFODNN7EXAMPLE`, the sample key from AWS's documentation.
- `qa-out/fake-s3/` holds private keys for a local stand-in server. Its certificate names 127.0.0.1 and expired on
  2026-10-08. Excluded.
- `PktMon.etl` (100 MB, 2026-10-07) is a packet capture in the root of the source tree. It was not opened, may hold
  network traffic from the machine it was taken on, and should not be handed over. Excluded.
