// Named Pipes: the pipe namespace listed by name, the names SAT recognises marked from
// config/checks/named-pipes.json, and the rows and summary both the CLI and the GUIs show.
// On Windows the listing is a directory read of \\.\pipe\; on Linux it is /proc/net/unix with the
// holders read from /proc/<pid>/fd. No pipe or socket is opened.
#include "support_assist/named_pipes.hpp"

#include "support_assist/data_files.hpp"
#include "support_assist/json.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/veeam_watch.hpp"

#include <algorithm>
#include <charconv>
#include <map>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include "support_assist/process_identity.hpp"

#include <dirent.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <set>
#endif

namespace support_assist {

namespace {

Error pipes_error(std::string operation, std::string message, std::int64_t code = 0) {
  Error error;
  error.component = "Named Pipes";
  error.operation = std::move(operation);
  error.message = std::move(message);
  error.native_code = code;
  return error;
}

[[maybe_unused]] void report(const ProgressCallback& progress, const char* step, std::uint64_t index, std::uint64_t total) {
  if (!progress)
    return;
  ProgressEvent event;
  event.phase = "Named Pipes";
  event.current_scope = step;
  event.processed = index;
  event.total = total;
  progress(event);
}

char lower(char value) {
  return value >= 'A' && value <= 'Z' ? static_cast<char>(value - 'A' + 'a') : value;
}

bool is_digit(char value) {
  return value >= '0' && value <= '9';
}

// Backtracking match of pattern[p..] against name[n..]. On success `stars` holds what each * stood
// for, in pattern order, and `digits` what {pid} stood for.
bool match_from(std::string_view pattern, std::size_t p, std::string_view name, std::size_t n,
                std::vector<std::string>& stars, std::string& digits) {
  if (p == pattern.size())
    return n == name.size();
  if (pattern[p] == '*') {
    for (std::size_t end = name.size() + 1U; end-- > n;) {
      stars.emplace_back(name.substr(n, end - n));
      if (match_from(pattern, p + 1U, name, end, stars, digits))
        return true;
      stars.pop_back();
    }
    return false;
  }
  if (pattern.compare(p, 5U, "{pid}") == 0) {
    std::size_t end = n;
    while (end < name.size() && is_digit(name[end]))
      ++end;
    for (std::size_t stop = end; stop > n; --stop) {
      if (match_from(pattern, p + 5U, name, stop, stars, digits)) {
        digits = std::string(name.substr(n, stop - n));
        return true;
      }
    }
    return false;
  }
  if (n >= name.size() || lower(pattern[p]) != lower(name[n]))
    return false;
  return match_from(pattern, p + 1U, name, n + 1U, stars, digits);
}

[[maybe_unused]] std::string process_label(const WatchItem& process) {
  return process.name.empty() ? std::string("PID ") + std::to_string(process.pid) : process.name;
}

template <typename Number> bool parse_number(std::string_view text, int base, Number& value) {
  if (text.empty())
    return false;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
  return parsed.ec == std::errc() && parsed.ptr == text.data() + text.size();
}

std::string owner_text(const NamedPipe& pipe) {
  std::string text;
  // A service whose state was not read is left out when the process holding the pipe is named.
  if (!pipe.service.empty() && (!pipe.service_state.empty() || pipe.process_name.empty())) {
    text = pipe.service + ", " + (pipe.service_state.empty() ? std::string("state not read") : pipe.service_state);
    if (pipe.service_pid != 0)
      text += ", PID " + std::to_string(pipe.service_pid);
  }
  if (pipe.process_id != 0) {
    if (!text.empty())
      text += "; ";
    if (pipe.process_name.empty()) {
      text += "PID " + std::to_string(pipe.process_id) + ", not running";
    } else {
      text += pipe.process_name + ", PID " + std::to_string(pipe.process_id);
      if (!pipe.process_service.empty())
        text += ", service " + pipe.process_service;
    }
  } else if (!pipe.process_name.empty()) {
    if (!text.empty())
      text += "; ";
    text += pipe.process_name;
  }
  if (pipe.other_holders > 0) {
    if (!text.empty())
      text += "; ";
    text += std::to_string(pipe.other_holders) + (pipe.other_holders == 1U ? " other process holds it"
                                                                           : " other processes hold it");
  }
  return text;
}

} // namespace

namespace named_pipes_detail {

std::string_view current_platform() {
#ifdef _WIN32
  return "windows";
#else
  return "linux";
#endif
}

namespace {

bool rule_applies(const NamedPipeRule& rule, std::string_view platform) {
  return platform.empty() || rule.platform.empty() || ascii_lower(rule.platform) == ascii_lower(platform);
}

} // namespace

std::vector<NamedPipeRule> parse_rules(std::string_view json_text, std::string_view platform) {
  std::vector<NamedPipeRule> parsed;
  auto document = parse_json(json_text);
  if (!document.ok())
    return parsed;
  for (const JsonValue& item : document.value()["rules"].items()) {
    NamedPipeRule rule;
    rule.pattern = item["pattern"].as_string();
    rule.platform = item["platform"].as_string();
    rule.category = item["category"].as_string();
    rule.product = item["product"].as_string();
    rule.purpose = item["purpose"].as_string();
    rule.service = item["service"].as_string();
    rule.process = item["process"].as_string();
    rule.observed_on = item["observed_on"].as_string();
    if (!rule.pattern.empty() && rule_applies(rule, platform))
      parsed.push_back(std::move(rule));
  }
  return parsed;
}

const std::vector<NamedPipeRule>& rules() {
  static const std::vector<NamedPipeRule> loaded =
      parse_rules(embedded_data_file("named-pipes.json"), current_platform());
  return loaded;
}

const std::vector<NamedPipeRule>& all_rules() {
  static const std::vector<NamedPipeRule> loaded = parse_rules(embedded_data_file("named-pipes.json"));
  return loaded;
}

bool pattern_matches(std::string_view pattern, std::string_view name, std::string& star, std::uint32_t& pid) {
  std::vector<std::string> stars;
  std::string digits;
  if (!match_from(pattern, 0U, name, 0U, stars, digits))
    return false;
  star = stars.empty() ? std::string() : std::move(stars.front());
  pid = 0;
  if (!digits.empty() && digits.size() <= 10U) {
    const unsigned long long value = std::stoull(digits);
    pid = value <= 0xFFFFFFFFULL ? static_cast<std::uint32_t>(value) : 0U;
  }
  return true;
}

const NamedPipeRule* match_rule(const std::vector<NamedPipeRule>& from, std::string_view name, std::string& star,
                                std::uint32_t& pid, std::string_view platform) {
  if (platform.empty())
    platform = current_platform();
  for (const NamedPipeRule& rule : from) {
    if (rule_applies(rule, platform) && pattern_matches(rule.pattern, name, star, pid))
      return &rule;
  }
  star.clear();
  pid = 0;
  return nullptr;
}

std::string expand(std::string_view text, std::string_view star) {
  std::string out(text);
  for (std::size_t at = out.find("{1}"); at != std::string::npos; at = out.find("{1}", at + star.size()))
    out.replace(at, 3U, star);
  return out;
}

std::string instances_text(std::int64_t instances, std::int64_t max_instances) {
  if (instances < 0)
    return {};
  std::string text = std::to_string(instances);
  if (max_instances == 0)
    text += " of unlimited";
  else if (max_instances > 0)
    text += " of " + std::to_string(max_instances);
  return text;
}

bool is_veeam_program(std::string_view name, std::string_view path) {
  const std::string lowered_name = ascii_lower(name);
  const std::string lowered_path = ascii_lower(path);
  return lowered_name.rfind("veeam", 0) == 0 || lowered_path.find("\\veeam\\") != std::string::npos;
}

void sort_pipes(std::vector<NamedPipe>& pipes) {
  std::stable_sort(pipes.begin(), pipes.end(), [](const NamedPipe& left, const NamedPipe& right) {
    if (left.veeam != right.veeam)
      return left.veeam;
    return ascii_lower(left.name) < ascii_lower(right.name);
  });
}

bool parse_proc_net_unix_line(std::string_view line, UnixSocketEntry& entry) {
  entry = UnixSocketEntry{};
  while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
    line.remove_suffix(1U);
  std::size_t at = 0;
  const auto skip_blanks = [&] {
    while (at < line.size() && (line[at] == ' ' || line[at] == '\t'))
      ++at;
  };
  const auto next_token = [&](std::string_view& token) {
    skip_blanks();
    if (at >= line.size())
      return false;
    const std::size_t begin = at;
    while (at < line.size() && line[at] != ' ' && line[at] != '\t')
      ++at;
    token = line.substr(begin, at - begin);
    return true;
  };
  // Num: RefCount Protocol Flags Type St Inode, then the path, which may hold spaces.
  std::string_view tokens[7];
  for (std::string_view& token : tokens) {
    if (!next_token(token))
      return false;
  }
  if (tokens[0].size() < 2U || tokens[0].back() != ':')
    return false;
  unsigned flags = 0;
  unsigned type = 0;
  std::uint64_t inode = 0;
  if (!parse_number(tokens[3], 16, flags) || !parse_number(tokens[4], 16, type) || !parse_number(tokens[6], 10, inode))
    return false;
  skip_blanks();
  if (at >= line.size())
    return false;
  entry.path = std::string(line.substr(at));
  entry.inode = inode;
  entry.listening = (flags & 0x10000U) != 0U;
  entry.type = static_cast<int>(type);
  return true;
}

std::string socket_type_name(int type) {
  switch (type) {
  case 1:
    return "stream";
  case 2:
    return "datagram";
  case 5:
    return "seqpacket";
  default:
    return "type " + std::to_string(type);
  }
}

std::vector<UnixSocketGroup> group_unix_sockets(const std::vector<UnixSocketEntry>& entries) {
  std::vector<UnixSocketGroup> groups;
  std::map<std::string, std::size_t> index;
  std::vector<std::vector<int>> types;
  for (const UnixSocketEntry& entry : entries) {
    const auto found = index.find(entry.path);
    std::size_t at = 0;
    if (found == index.end()) {
      at = groups.size();
      index.emplace(entry.path, at);
      groups.emplace_back();
      groups.back().path = entry.path;
      types.emplace_back();
    } else {
      at = found->second;
    }
    UnixSocketGroup& group = groups[at];
    ++group.count;
    group.inodes.push_back(entry.inode);
    if (entry.listening) {
      group.listening = true;
      group.listening_inodes.push_back(entry.inode);
    }
    if (std::find(types[at].begin(), types[at].end(), entry.type) == types[at].end()) {
      types[at].push_back(entry.type);
      group.types += (group.types.empty() ? "" : ", ") + socket_type_name(entry.type);
    }
  }
  return groups;
}

std::string socket_instances_text(std::int64_t instances, bool listening, std::string_view types) {
  std::string text = std::to_string(instances);
  if (listening)
    text += ", listening";
  if (!types.empty())
    text += ", " + std::string(types);
  return text;
}

bool parse_socket_link(std::string_view target, std::uint64_t& inode) {
  constexpr std::string_view prefix = "socket:[";
  if (target.size() <= prefix.size() + 1U || target.compare(0U, prefix.size(), prefix) != 0 || target.back() != ']')
    return false;
  return parse_number(target.substr(prefix.size(), target.size() - prefix.size() - 1U), 10, inode);
}

} // namespace named_pipes_detail

std::vector<NamedPipeRow> named_pipe_rows(const NamedPipesResult& result) {
  std::vector<NamedPipeRow> rows;
  rows.reserve(result.pipes.size());
  for (const NamedPipe& pipe : result.pipes) {
    NamedPipeRow row;
    row.pipe = pipe.name;
    row.instances = pipe.socket_type.empty()
                        ? named_pipes_detail::instances_text(pipe.instances, pipe.max_instances)
                        : named_pipes_detail::socket_instances_text(pipe.instances, pipe.listening, pipe.socket_type);
    if (pipe.known)
      row.known_as = pipe.purpose.empty() ? pipe.product : pipe.product + ": " + pipe.purpose;
    row.owner = owner_text(pipe);
    rows.push_back(std::move(row));
  }
  return rows;
}

std::string named_pipes_summary(const NamedPipesResult& result) {
  std::size_t named = 0;
  for (const NamedPipe& pipe : result.pipes) {
    if (pipe.process_id != 0 && !pipe.process_name.empty())
      ++named;
  }
  const std::string noun = result.sockets ? "socket" : "pipe";
  std::string text = std::to_string(result.listed) + " " + noun + (result.listed == 1U ? " listed, " : "s listed, ") +
                     std::to_string(result.veeam) + " Veeam or database " + noun + (result.veeam == 1U ? ", " : "s, ") +
                     std::to_string(named) + " named by their process";
  if (result.veeam_only)
    text += "; showing the Veeam " + noun + "s";
  return text;
}

#ifdef _WIN32

namespace {

struct ListedPipe {
  std::string name;
  std::int64_t instances = -1;
  std::int64_t max_instances = -1;
};

// The pipe file system lists each pipe's current instances as its end of file and its maximum
// instances as its allocation size (-1 for unlimited). Read through the directory handle of the
// namespace; FindFirstFileW gives the names and current instances when that handle cannot be read.
bool list_by_directory_handle(std::vector<ListedPipe>& listed, const CancellationToken& cancel) {
  HANDLE directory = CreateFileW(L"\\\\.\\pipe\\", FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (directory == INVALID_HANDLE_VALUE)
    return false;
  std::vector<unsigned char> buffer(64U * 1024U);
  bool first = true;
  bool read_any = false;
  for (;;) {
    if (cancel.is_cancelled())
      break;
    const FILE_INFO_BY_HANDLE_CLASS kind = first ? FileFullDirectoryRestartInfo : FileFullDirectoryInfo;
    first = false;
    if (GetFileInformationByHandleEx(directory, kind, buffer.data(), static_cast<DWORD>(buffer.size())) == FALSE)
      break;
    read_any = true;
    std::size_t offset = 0;
    for (;;) {
      const auto* entry = reinterpret_cast<const FILE_FULL_DIR_INFO*>(buffer.data() + offset);
      ListedPipe pipe;
      pipe.name = utf8_from_wide(std::wstring_view(entry->FileName, entry->FileNameLength / sizeof(wchar_t)));
      pipe.instances = static_cast<std::int64_t>(entry->EndOfFile.LowPart);
      const auto maximum = static_cast<std::int32_t>(entry->AllocationSize.LowPart);
      pipe.max_instances = maximum < 0 ? 0 : maximum;
      if (!pipe.name.empty())
        listed.push_back(std::move(pipe));
      if (entry->NextEntryOffset == 0)
        break;
      offset += entry->NextEntryOffset;
    }
  }
  CloseHandle(directory);
  return read_any;
}

bool list_by_find_file(std::vector<ListedPipe>& listed, const CancellationToken& cancel, DWORD& failure) {
  WIN32_FIND_DATAW found{};
  HANDLE search = FindFirstFileW(L"\\\\.\\pipe\\*", &found);
  if (search == INVALID_HANDLE_VALUE) {
    failure = GetLastError();
    return false;
  }
  do {
    if (cancel.is_cancelled())
      break;
    ListedPipe pipe;
    pipe.name = utf8_from_wide(found.cFileName);
    pipe.instances = static_cast<std::int64_t>(found.nFileSizeLow);
    if (!pipe.name.empty())
      listed.push_back(std::move(pipe));
  } while (FindNextFileW(search, &found) != FALSE);
  FindClose(search);
  return true;
}

} // namespace

Result<NamedPipesResult> list_named_pipes(const NamedPipesOptions& options, const CancellationToken& cancel,
                                          const ProgressCallback& progress) {
  NamedPipesResult result;
  result.veeam_only = options.veeam_only;
  report(progress, "Listing \\\\.\\pipe\\", 0, 3);
  std::vector<ListedPipe> listed;
  if (list_by_directory_handle(listed, cancel)) {
    result.listing_source = "the pipe namespace's directory listing, with maximum instances";
  } else {
    listed.clear();
    DWORD failure = 0;
    if (!list_by_find_file(listed, cancel, failure))
      return Result<NamedPipesResult>::failure(
          pipes_error("list named pipes", "The pipe namespace \\\\.\\pipe\\ could not be listed.", failure));
    result.listing_source = "FindFirstFile on \\\\.\\pipe\\, without maximum instances";
    result.notes.push_back("Maximum instances were not available; Instances shows the current count only.");
  }
  if (cancel.is_cancelled())
    return Result<NamedPipesResult>::failure(pipes_error("list named pipes", "Cancelled."));
  result.listed = listed.size();

  report(progress, "Reading services and processes", 1, 3);
  const WatchSnapshot snapshot = take_watch_snapshot("");
  if (!snapshot.note.empty())
    result.notes.push_back(snapshot.note);
  std::map<std::uint32_t, const WatchItem*> processes;
  std::map<std::uint32_t, std::string> service_of_pid;
  std::map<std::string, const WatchItem*> services;
  std::map<std::string, std::size_t> running_by_name;
  for (const WatchItem& item : snapshot.items) {
    if (item.kind == WatchKind::process) {
      processes[item.pid] = &item;
      ++running_by_name[ascii_lower(item.name)];
    } else {
      services[ascii_lower(item.name)] = &item;
      if (item.pid != 0 && item.state == "running")
        service_of_pid.emplace(item.pid, item.name);
    }
  }

  report(progress, "Matching known pipe names", 2, 3);
  const auto& known_rules = named_pipes_detail::rules();
  for (ListedPipe& entry : listed) {
    NamedPipe pipe;
    pipe.name = std::move(entry.name);
    pipe.instances = entry.instances;
    pipe.max_instances = entry.max_instances;
    std::string star;
    std::uint32_t pid = 0;
    if (const NamedPipeRule* rule = named_pipes_detail::match_rule(known_rules, pipe.name, star, pid)) {
      pipe.known = true;
      pipe.category = rule->category;
      pipe.product = rule->product;
      pipe.purpose = named_pipes_detail::expand(rule->purpose, star);
      pipe.service = named_pipes_detail::expand(rule->service, star);
      pipe.process_id = pid;
      if (!pipe.service.empty()) {
        const auto service = services.find(ascii_lower(pipe.service));
        if (service == services.end()) {
          pipe.service_state = "not installed";
        } else {
          pipe.service = service->second->name;
          pipe.service_state = service->second->state;
          pipe.service_pid = service->second->state == "running" ? service->second->pid : 0U;
        }
      }
      if (pid != 0) {
        const auto process = processes.find(pid);
        if (process != processes.end()) {
          pipe.process_name = process_label(*process->second);
          pipe.process_path = process->second->path;
          const auto service = service_of_pid.find(pid);
          if (service != service_of_pid.end())
            pipe.process_service = service->second;
        }
      } else if (!rule->process.empty()) {
        const auto running = running_by_name.find(ascii_lower(rule->process));
        const std::size_t count = running == running_by_name.end() ? 0U : running->second;
        pipe.process_name = rule->process + (count == 0U ? std::string(", not running")
                                                         : ", " + std::to_string(count) + " running");
      }
      pipe.veeam = pipe.category == "veeam" || pipe.category == "database" ||
                   ascii_lower(pipe.service).rfind("veeam", 0) == 0 ||
                   (pid != 0 && named_pipes_detail::is_veeam_program(pipe.process_name, pipe.process_path));
    }
    if (pipe.veeam)
      ++result.veeam;
    if (pipe.known)
      ++result.known;
    if (!options.veeam_only || pipe.veeam)
      result.pipes.push_back(std::move(pipe));
  }
  named_pipes_detail::sort_pipes(result.pipes);
  report(progress, "Matching known pipe names", 3, 3);
  return Result<NamedPipesResult>::success(std::move(result));
}

#else

namespace {

using named_pipes_detail::UnixSocketEntry;

// Every line of /proc/net/unix that has a path; `unnamed` counts the sockets without one.
bool read_unix_sockets(std::vector<UnixSocketEntry>& entries, std::size_t& unnamed, const CancellationToken& cancel) {
  std::ifstream input("/proc/net/unix");
  if (!input)
    return false;
  std::string line;
  while (std::getline(input, line)) {
    if (cancel.is_cancelled())
      break;
    if (line.empty() || line.rfind("Num", 0) == 0)
      continue;
    UnixSocketEntry entry;
    if (named_pipes_detail::parse_proc_net_unix_line(line, entry))
      entries.push_back(std::move(entry));
    else
      ++unnamed;
  }
  return true;
}

// The processes holding each wanted socket inode, from the socket:[inode] links in /proc/<pid>/fd.
// `not_readable` counts the processes whose fd folder the account cannot open.
std::map<std::uint64_t, std::set<std::uint32_t>> socket_holders(const std::set<std::uint64_t>& wanted,
                                                                std::size_t& not_readable,
                                                                const CancellationToken& cancel) {
  std::map<std::uint64_t, std::set<std::uint32_t>> holders;
  DIR* proc = opendir("/proc");
  if (proc == nullptr)
    return holders;
  while (const dirent* entry = readdir(proc)) {
    if (cancel.is_cancelled())
      break;
    const std::string pid = entry->d_name;
    if (pid.empty() || pid.find_first_not_of("0123456789") != std::string::npos)
      continue;
    const auto number = static_cast<std::uint32_t>(std::strtoul(pid.c_str(), nullptr, 10));
    const std::string base = "/proc/" + pid + "/fd";
    DIR* fds = opendir(base.c_str());
    if (fds == nullptr) {
      if (errno == EACCES)
        ++not_readable;
      continue;
    }
    while (const dirent* fd = readdir(fds)) {
      if (fd->d_name[0] == '.')
        continue;
      char target[128];
      const ssize_t length = readlink((base + "/" + fd->d_name).c_str(), target, sizeof(target) - 1U);
      if (length <= 0)
        continue;
      std::uint64_t inode = 0;
      if (named_pipes_detail::parse_socket_link(std::string_view(target, static_cast<std::size_t>(length)), inode) &&
          wanted.count(inode) != 0U)
        holders[inode].insert(number);
    }
    closedir(fds);
  }
  closedir(proc);
  return holders;
}

} // namespace

Result<NamedPipesResult> list_named_pipes(const NamedPipesOptions& options, const CancellationToken& cancel,
                                          const ProgressCallback& progress) {
  NamedPipesResult result;
  result.veeam_only = options.veeam_only;
  result.sockets = true;
  report(progress, "Reading /proc/net/unix", 0, 3);
  std::vector<UnixSocketEntry> entries;
  std::size_t unnamed = 0;
  if (!read_unix_sockets(entries, unnamed, cancel))
    return Result<NamedPipesResult>::failure(
        pipes_error("list sockets", "The Unix sockets could not be listed: /proc/net/unix could not be read.", errno));
  if (cancel.is_cancelled())
    return Result<NamedPipesResult>::failure(pipes_error("list sockets", "Cancelled."));
  result.listing_source = "/proc/net/unix, with the holders read from the socket links in /proc/<pid>/fd";
  const std::vector<named_pipes_detail::UnixSocketGroup> groups = named_pipes_detail::group_unix_sockets(entries);
  result.listed = groups.size();
  if (unnamed > 0U)
    result.notes.push_back(std::to_string(unnamed) + (unnamed == 1U ? " socket has" : " sockets have") +
                           " no name (connections and unnamed sockets) and " +
                           (unnamed == 1U ? "is" : "are") + " not listed.");

  report(progress, "Finding the process holding each socket", 1, 3);
  std::set<std::uint64_t> wanted;
  for (const auto& group : groups)
    wanted.insert(group.inodes.begin(), group.inodes.end());
  std::size_t not_readable = 0;
  const auto holders = socket_holders(wanted, not_readable, cancel);
  if (cancel.is_cancelled())
    return Result<NamedPipesResult>::failure(pipes_error("list sockets", "Cancelled."));
  if (not_readable > 0U && geteuid() != 0)
    result.notes.push_back(std::to_string(not_readable) +
                           " processes of other accounts could not be read; run SAT as root to name their sockets.");

  report(progress, "Matching known socket names", 2, 3);
  const ProcessDirectory processes = ProcessDirectory::capture();
  std::map<std::string, std::uint32_t> unit_pids;      // systemd unit -> a process in its cgroup
  std::map<std::string, std::size_t> running_by_name;
  for (const ProcessIdentity& process : processes.all()) {
    ++running_by_name[ascii_lower(process.name)];
    std::size_t start = 0;
    while (start < process.services.size()) {
      std::size_t end = process.services.find(',', start);
      if (end == std::string::npos)
        end = process.services.size();
      const std::string unit = ascii_lower(trim(process.services.substr(start, end - start)));
      if (!unit.empty())
        unit_pids.emplace(unit, process.pid);
      start = end + 1U;
    }
  }

  const auto& known_rules = named_pipes_detail::rules();
  for (const auto& group : groups) {
    NamedPipe pipe;
    pipe.name = group.path;
    pipe.instances = group.count;
    pipe.max_instances = -1;
    pipe.listening = group.listening;
    pipe.socket_type = group.types;

    // The process holding the listening socket is the owner, and every other holder is counted.
    // Process 1 holding it too is the init system keeping the socket for its service; it is the
    // owner only when nothing else holds the socket.
    std::set<std::uint32_t> all_holders;
    std::set<std::uint32_t> listening_holders;
    for (const std::uint64_t inode : group.inodes) {
      const auto found = holders.find(inode);
      if (found != holders.end())
        all_holders.insert(found->second.begin(), found->second.end());
    }
    for (const std::uint64_t inode : group.listening_inodes) {
      const auto found = holders.find(inode);
      if (found != holders.end())
        listening_holders.insert(found->second.begin(), found->second.end());
    }
    std::set<std::uint32_t> candidates = listening_holders.empty() ? all_holders : listening_holders;
    if (candidates.size() > 1U && candidates.count(1U) != 0U)
      candidates.erase(1U);
    if (!candidates.empty()) {
      pipe.process_id = *candidates.begin();
      pipe.other_holders = static_cast<std::uint32_t>(all_holders.size() - 1U);
      if (const ProcessIdentity* identity = processes.find(pipe.process_id)) {
        pipe.process_name = identity->name;
        pipe.process_path = identity->path;
        pipe.process_service = identity->services;
      }
    }

    std::string star;
    std::uint32_t pid = 0;
    if (const NamedPipeRule* rule = named_pipes_detail::match_rule(known_rules, pipe.name, star, pid)) {
      pipe.known = true;
      pipe.category = rule->category;
      pipe.product = rule->product;
      pipe.purpose = named_pipes_detail::expand(rule->purpose, star);
      pipe.service = named_pipes_detail::expand(rule->service, star);
      if (!pipe.service.empty()) {
        // Only a unit a process runs in is reported; a unit that is stopped, or an instance unit such
        // as postgresql@16-main, leaves the state empty.
        auto unit = unit_pids.find(ascii_lower(pipe.service));
        if (unit == unit_pids.end())
          unit = unit_pids.find(ascii_lower(pipe.service) + ".service");
        if (unit != unit_pids.end()) {
          pipe.service_state = "running";
          pipe.service_pid = unit->second;
        }
      }
      if (pipe.process_id == 0U && !rule->process.empty()) {
        const auto running = running_by_name.find(ascii_lower(rule->process));
        const std::size_t count = running == running_by_name.end() ? 0U : running->second;
        pipe.process_name = rule->process + (count == 0U ? std::string(", not running")
                                                         : ", " + std::to_string(count) + " running");
      }
    }
    pipe.veeam = (pipe.known && (pipe.category == "veeam" || pipe.category == "database" ||
                                 ascii_lower(pipe.service).rfind("veeam", 0) == 0)) ||
                 (pipe.process_id != 0U && named_pipes_detail::is_veeam_program(pipe.process_name, ""));
    if (pipe.veeam)
      ++result.veeam;
    if (pipe.known)
      ++result.known;
    if (!options.veeam_only || pipe.veeam)
      result.pipes.push_back(std::move(pipe));
  }
  named_pipes_detail::sort_pipes(result.pipes);
  report(progress, "Matching known socket names", 3, 3);
  return Result<NamedPipesResult>::success(std::move(result));
}

#endif

} // namespace support_assist
