# Support Assist Tool

Support Assist Tool (SAT) is a cross-platform support-engineering utility designed to bring case management, log analysis, diagnostics, evidence review, and technical documentation into a single application.

SAT is built around a simple investigation workflow:

**Collect → Review → Diagnose → Correlate → Document**

## Overview

SAT was created to reduce the amount of time support engineers spend switching between log viewers, command-line tools, diagnostic utilities, scripts, notes, and other applications during an investigation.

A SAT case keeps the investigation together as additional evidence is collected and reviewed.

## Features

### Case Management
- Create and reopen case workspaces
- Add evidence throughout an investigation
- Preserve review state, findings, bookmarks, and notes
- Generate technical reports

### Log Analysis
- Structured Veeam log review
- Product and component detection
- Activity and run correlation
- Findings and symptom analysis
- Search and evidence navigation

### Guided Diagnostics
SAT includes guided workflows intended to help investigate common support scenarios involving areas such as:

- Connectivity
- SQL Server
- VSS
- TLS and certificates
- RPC
- Backup performance
- Veeam Agent communication

### Diagnostic Tools

SAT also provides individual diagnostic tools covering:

- Network and transport
- Windows
- SQL Server
- WMI
- VSS
- TLS
- SMB
- RPC
- gRPC
- SSH/SFTP
- File and Registry analysis
- Packet capture
- System and process inspection

## Engineer Review and Live Diagnostics

SAT separates evidence review from operations that interact with a live system.

**Engineer Review** is intended for investigation of collected case evidence.

**Customer / Lab Execution** provides collection and diagnostic capabilities against the system where SAT is running.

This separation allows an engineer to continue analyzing evidence without requiring every diagnostic operation to be performed from the review workstation.

## Platforms

SAT is available for Windows and Linux.

### Windows

- Windows 10 x64
- Windows 11 x64
- Windows Server 2016 or later
- Portable executable
- No installer required
- No Windows service installed
- No application-specific Registry installation footprint

### Linux

Linux builds provide desktop and command-line workflows for supported SAT functionality.

## Portable by Design

SAT is designed to operate as a portable support utility.

For Windows, application dependencies are statically linked into the build, avoiding separate .NET or Microsoft Visual C++ Redistributable requirements.

Some diagnostics require administrative privileges because the underlying Windows operation requires elevation. SAT does not require the entire application to run elevated for normal evidence-review workflows.

## Optional Integrations

SAT can make use of external diagnostic tools when available, including:

- Wireshark / tshark
- Process Monitor
- iPerf3
- SQLCMD
- Windows Packet Monitor
- ETL2PCAPNG
- VSS Trace

These integrations extend SAT's diagnostic capabilities but are not required for its primary case and evidence-review workflows.

## Documentation

Detailed documentation is maintained separately from this README.

### User Guides

The User Guides contain:

- Getting started
- Case workflows
- Log collection
- Log analysis
- Guided diagnostics
- Individual diagnostic tools
- Reports and notes
- Troubleshooting
- Platform-specific behavior

### Developer Documentation

Developer documentation covers:

- Application architecture
- Source layout
- Core components
- Build information
- Platform abstractions
- Parser architecture
- Security-related implementation details
- Internal data structures

## Project Status

Support Assist Tool is under active development.

Features, interfaces, diagnostic coverage, and internal implementation may change as development continues.

## Author

Created and maintained by **Will Engels**.

## Third-Party Components

SAT incorporates or interfaces with open-source software including:

- OpenSSL
- libssh2
- libarchive
- SQLite
- RE2
- Abseil
- zlib
- zstd
- XZ Utils / liblzma
- LZ4
- bzip2

Each component remains subject to its respective license.

## License

MIT License

Copyright (c) 2026 Will Engels

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
