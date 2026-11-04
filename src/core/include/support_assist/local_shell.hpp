#pragma once

// A persistent local shell session: one process, kept alive, fed commands over a pipe.
//
// Why this is not a terminal
// --------------------------
// The remote console and the local console are different problems, and an earlier attempt gave
// them one implementation. SSH to a Linux host returns a VT byte stream - cursor movement, colour,
// `less` redrawing - so the Remote page genuinely needs a terminal emulator, and TerminalScreen
// exists for it.
//
// A local Windows console runs `Get-Service`, `vssadmin list writers`, `sc query`, `type` on a log.
// Those write plain text to a pipe. There are no escape sequences to parse and no screen to
// maintain, so putting a VT emulator in the path would be parsing that never finds anything. That
// reasoning is what led to a pseudo-console here; it was symmetry for its own sake, and it also
// would not have run on Windows Server 2016, which is exactly the kind of machine SAT is carried
// onto.
//
// So: plain bytes in, plain bytes out, over the redirected-pipe machinery SAT already uses.
//
// What the persistence buys
// -------------------------
// SAT could already run one command and show what it printed. Each run was a new process, so
// nothing carried: `cd` did not stick, a variable did not stick, and anything that asked a question
// hung with no way to answer it. Holding one shell open fixes all three, because standard input
// stays connected.
//
// Elevation
// ---------
// The session inherits SAT's own token. It never elevates and never drops privilege, and
// context_label() states which so a command's reach is visible before it is typed. Raising
// privilege stays a separate, explicit UAC prompt that opens a window Windows owns.
//
// The trade-off, stated plainly
// -----------------------------
// Without a console attached, some programs block-buffer their output instead of flushing per
// line, so a long-running command can appear to stall until it finishes. Short diagnostic commands
// - which is what this is for - are unaffected. A program that needs a real terminal is a job for
// the system console, not for SAT.

#include "support_assist/error.hpp"

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

namespace support_assist {

struct LocalShellOptions {
  // Empty selects the default shell: PowerShell where present, otherwise cmd.exe; on Linux and
  // macOS, bash where present, otherwise sh. A POSIX shell runs as a login shell (-l) reading its
  // commands from standard input (-s).
  std::filesystem::path executable;
  std::filesystem::path working_directory;
  // Ask for cmd.exe rather than PowerShell (on POSIX, sh rather than bash) when `executable` is
  // empty.
  bool prefer_cmd = false;
};

struct LocalShell;

// True where a persistent local shell can be hosted at all: Windows (local_shell_win.cpp) and POSIX
// (local_shell_posix.cpp). There is no version floor, because this uses nothing newer than
// redirected pipes.
bool local_shell_supported();

// The account the session runs as and whether it is elevated. Shown in the console header: "what
// can this command do" is the first thing an engineer needs and the last thing they should guess.
std::string local_shell_context_label();

Result<std::shared_ptr<LocalShell>> local_open_shell(const LocalShellOptions& options);

// Non-blocking. Returns whatever has arrived, which is often nothing.
Result<std::string> local_shell_read(LocalShell& shell);

// Bytes are sent verbatim. Callers append their own newline, because answering a prompt is not
// always a whole line.
Status local_shell_write(LocalShell& shell, std::string_view bytes);

// False once the shell has exited.
bool local_shell_connected(const LocalShell& shell);

// Ends the session and reaps the process. Safe to call more than once. A command the session is
// still running ends with it, and so does anything it started in the background: the Windows shell
// runs in a job, the POSIX shell in a process group of its own. This is also how a console stops a
// command that does not finish.
void local_shell_close(LocalShell& shell);

} // namespace support_assist
