#pragma once

// Named Pipes (read-only). On Windows: every pipe in \\.\pipe\ by name, with its current and maximum
// instance counts as the pipe file system lists them. No pipe is opened, connected to or waited on,
// and no handle is read: the list is the directory listing of the pipe namespace. On Linux: the Unix
// domain sockets that have a name, from /proc/net/unix, grouped by path, with the processes holding
// them found from the socket links in /proc/<pid>/fd; no socket is opened or connected to. Names
// SAT recognises (config/checks/named-pipes.json) are marked with their product, purpose and
// service, and a Windows pipe whose name carries a process ID is named by that process.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

// One entry of named-pipes.json.
struct NamedPipeRule {
  std::string pattern;
  std::string platform; // windows or linux; empty for both
  std::string category; // veeam, database or runtime
  std::string product;
  std::string purpose;  // may hold {1}
  std::string service;  // may hold {1}
  std::string process;  // the program expected to hold the pipe, when known
  std::string observed_on;
};

struct NamedPipe {
  std::string name;              // the name after the \\.\pipe\ prefix; on Linux the socket path
  std::int64_t instances = -1;   // current instances; -1 when not known. Linux: sockets with this path
  std::int64_t max_instances = -1; // -1 when not known (always on Linux), 0 when unlimited
  bool known = false;            // a rule matched
  std::string category;
  std::string product;
  std::string purpose;
  std::string service;           // the service the rule names
  std::string service_state;     // running, stopped, ... or "not installed"; empty without a service
  std::uint32_t service_pid = 0;
  std::uint32_t process_id = 0;  // Windows: from {pid} in the name. Linux: the process holding the socket
  std::string process_name;      // that process's program, or the rule's expected program
  std::string process_path;
  std::string process_service;   // the service or systemd unit the process runs, when it runs one
  bool veeam = false;            // a Veeam or database pipe, or a pipe of a Veeam program
  bool listening = false;        // Linux: at least one socket with this path accepts connections
  std::string socket_type;       // Linux: "stream", "datagram", "seqpacket"; empty on Windows
  std::uint32_t other_holders = 0; // Linux: processes besides process_id that hold a socket with this path
};

struct NamedPipesOptions {
  bool veeam_only = false;       // Show: Veeam pipes
};

struct NamedPipesResult {
  std::vector<NamedPipe> pipes;  // Veeam pipes first, then by name
  std::size_t listed = 0;        // every pipe in the namespace; on Linux every socket path
  std::size_t known = 0;
  std::size_t veeam = 0;
  bool veeam_only = false;
  bool sockets = false;          // Linux: the entries are Unix domain sockets, not pipes
  std::string listing_source;    // how the namespace was read
  std::vector<std::string> notes;
};

// One table row, as both the CLI and the Windows GUI show it.
struct NamedPipeRow {
  std::string pipe;
  std::string instances;
  std::string known_as;
  std::string owner;
};

Result<NamedPipesResult> list_named_pipes(const NamedPipesOptions& options, const CancellationToken& cancel,
                                          const ProgressCallback& progress = {});

std::vector<NamedPipeRow> named_pipe_rows(const NamedPipesResult& result);
// "126 pipes listed, 22 Veeam or database pipes, 61 named by their process." The same with "sockets"
// on Linux.
std::string named_pipes_summary(const NamedPipesResult& result);

namespace named_pipes_detail {
// "windows" or "linux": the platform whose rules apply on this system.
std::string_view current_platform();
// The rules of named-pipes.json for this platform, in file order.
const std::vector<NamedPipeRule>& rules();
// Every rule of named-pipes.json, whatever its platform.
const std::vector<NamedPipeRule>& all_rules();
// The rules of a JSON text. A non-empty `platform` keeps only the rules for it and the rules that
// name no platform; an empty one keeps every rule.
std::vector<NamedPipeRule> parse_rules(std::string_view json_text, std::string_view platform = {});
// Whether a pipe name matches a pattern (case-insensitive; * any text, {pid} decimal digits).
// `star` receives what the first * stood for and `pid` the {pid} digits (0 when the pattern has none).
bool pattern_matches(std::string_view pattern, std::string_view name, std::string& star, std::uint32_t& pid);
// The first matching rule that applies to `platform` (this platform when empty), or nullptr.
const NamedPipeRule* match_rule(const std::vector<NamedPipeRule>& rules, std::string_view name, std::string& star,
                                std::uint32_t& pid, std::string_view platform = {});
// A rule's text with {1} replaced by the first * capture.
std::string expand(std::string_view text, std::string_view star);
// "2 of unlimited", "1 of 1", "3"; empty when the count is not known.
std::string instances_text(std::int64_t instances, std::int64_t max_instances);
// Whether a program name or path is a Veeam program.
bool is_veeam_program(std::string_view name, std::string_view path);
// Veeam pipes first, then by name, ignoring case.
void sort_pipes(std::vector<NamedPipe>& pipes);

// One line of /proc/net/unix that has a path.
struct UnixSocketEntry {
  std::string path;            // a file path, or an abstract name with the leading @ the kernel shows
  std::uint64_t inode = 0;
  bool listening = false;      // the Flags column holds __SO_ACCEPTCON (0x10000)
  int type = 0;                // 1 stream, 2 datagram, 5 seqpacket
};
// The sockets of one path.
struct UnixSocketGroup {
  std::string path;
  std::int64_t count = 0;
  bool listening = false;      // any of them listens
  std::string types;           // "stream", or "stream, datagram", in the order first seen
  std::vector<std::uint64_t> inodes;
  std::vector<std::uint64_t> listening_inodes;
};
// Reads one line (Num RefCount Protocol Flags Type St Inode Path). False for the header, for a line
// without a path and for a line that is not in that form; `entry` is then empty.
bool parse_proc_net_unix_line(std::string_view line, UnixSocketEntry& entry);
// The sockets grouped by path, in the order the paths first appear.
std::vector<UnixSocketGroup> group_unix_sockets(const std::vector<UnixSocketEntry>& entries);
// "stream", "datagram", "seqpacket"; "type N" for any other.
std::string socket_type_name(int type);
// "3, listening, stream"; "1, datagram".
std::string socket_instances_text(std::int64_t instances, bool listening, std::string_view types);
// The inode of a /proc/<pid>/fd link of the form socket:[12345]; false for any other target.
bool parse_socket_link(std::string_view target, std::uint64_t& inode);
} // namespace named_pipes_detail

} // namespace support_assist
