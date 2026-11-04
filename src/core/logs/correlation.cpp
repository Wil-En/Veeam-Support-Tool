#include "support_assist/correlation.hpp"

#include "support_assist/strings.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>
#include <set>
#include <utility>

namespace support_assist {
namespace {

// Canonical key names, lower-cased. The same corpus writes jobId and JobId, jobSessionId and
// SessionId, so matching must be case-insensitive and alias-aware or a run splits into two.
struct KeyAlias {
  std::string_view key;
  IdentityKind kind;
};

constexpr std::array<KeyAlias, 12> kKeyAliases{{
    {"jobsessionid", IdentityKind::job_session_id},
    {"sessionid", IdentityKind::job_session_id},
    {"jobid", IdentityKind::job_id},
    {"commandid", IdentityKind::command_id},
    {"pluginmanagerid", IdentityKind::plugin_manager_id},
    {"channelid", IdentityKind::channel_id},
    {"backupid", IdentityKind::backup_id},
    {"backupforrestoreid", IdentityKind::backup_id},
    {"vbrid", IdentityKind::vbr_id},
    {"id", IdentityKind::unknown},
    {"pid", IdentityKind::process_id},
    {"processid", IdentityKind::process_id},
}};

bool is_hex(char c) {
  const auto u = static_cast<unsigned char>(c);
  return std::isdigit(u) != 0 || (std::tolower(u) >= 'a' && std::tolower(u) <= 'f');
}

// A GUID with or without braces. Veeam writes both forms, sometimes in the same file.
bool looks_like_guid(std::string_view text) {
  std::string_view body = text;
  if (body.size() >= 2U && body.front() == '{' && body.back() == '}')
    body = body.substr(1, body.size() - 2U);
  if (body.size() != 36U) return false;
  for (std::size_t index = 0; index < body.size(); ++index) {
    if (index == 8U || index == 13U || index == 18U || index == 23U) {
      if (body[index] != '-') return false;
    } else if (!is_hex(body[index])) {
      return false;
    }
  }
  return true;
}

std::string normalize_guid(std::string_view text) {
  std::string value(text);
  if (value.size() >= 2U && value.front() == '{' && value.back() == '}')
    value = value.substr(1, value.size() - 2U);
  return ascii_lower(value);
}

} // namespace

std::string to_string(IdentityKind value) {
  switch (value) {
  case IdentityKind::job_id: return "Job";
  case IdentityKind::job_session_id: return "Run (job session)";
  case IdentityKind::command_id: return "Command";
  case IdentityKind::plugin_manager_id: return "Plug-in manager";
  case IdentityKind::channel_id: return "Plug-in channel";
  case IdentityKind::backup_id: return "Backup";
  case IdentityKind::vbr_id: return "VBR";
  case IdentityKind::agent_session: return "Data mover session";
  case IdentityKind::process_id: return "Process";
  case IdentityKind::peer_address: return "Peer address";
  case IdentityKind::unknown: return "Unknown";
  }
  return "Unknown";
}

std::string to_string(CorrelationConfidence value) {
  switch (value) {
  case CorrelationConfidence::exact: return "Exact";
  case CorrelationConfidence::strong: return "Strong";
  case CorrelationConfidence::inferred: return "Inferred";
  }
  return "Inferred";
}

IdentityKind identity_kind_for_key(std::string_view key) {
  const std::string folded = ascii_lower(trim(key));
  for (const auto& alias : kKeyAliases) {
    if (folded == alias.key) return alias.kind;
  }
  return IdentityKind::unknown;
}

std::vector<IdentityRef> extract_typed_identities(std::string_view line) {
  std::vector<IdentityRef> found;
  // Shape: "(EGuid) jobSessionId={79b88dc6-...};" - the type marker, a key, '=', a value, ';'.
  // Scanning for the marker first is far cheaper than a general key=value sweep of every line.
  std::size_t cursor = 0;
  while (cursor < line.size()) {
    const std::size_t open = line.find('(', cursor);
    if (open == std::string_view::npos) break;
    const std::size_t close = line.find(')', open);
    if (close == std::string_view::npos) break;
    const std::string marker = ascii_lower(std::string(line.substr(open + 1U, close - open - 1U)));
    cursor = close + 1U;
    if (marker != "eguid" && marker != "edatetime" && marker != "eboolean") continue;

    // key = value, up to ';' or end of line.
    const std::size_t equals = line.find('=', cursor);
    if (equals == std::string_view::npos) break;
    std::string_view key = line.substr(cursor, equals - cursor);
    while (!key.empty() && (key.front() == ' ' || key.front() == '\t')) key.remove_prefix(1);
    while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.remove_suffix(1);

    std::size_t value_end = line.find(';', equals + 1U);
    if (value_end == std::string_view::npos) value_end = line.size();
    std::string_view value = line.substr(equals + 1U, value_end - equals - 1U);
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
    cursor = value_end;

    const IdentityKind kind = identity_kind_for_key(key);
    if (kind == IdentityKind::unknown || value.empty()) continue;
    if (marker == "eguid" && !looks_like_guid(value)) continue;

    IdentityRef ref;
    ref.kind = kind;
    ref.value = marker == "eguid" ? normalize_guid(value) : std::string(value);
    found.push_back(std::move(ref));
  }
  return found;
}

std::vector<IdentityRef> extract_freetext_identities(std::string_view line) {
  std::vector<IdentityRef> found;
  const std::string folded = ascii_lower(line);

  // "Global\VeeamAgent12196" - the cancel/keepalive event name carries the data mover's PID and is
  // often the ONLY identifier shared between the agent log and the orchestrating service.
  if (const std::size_t marker = folded.find("veeamagent"); marker != std::string::npos) {
    std::size_t index = marker + 10U;
    std::string digits;
    while (index < line.size() && std::isdigit(static_cast<unsigned char>(line[index])) != 0)
      digits.push_back(line[index++]);
    if (!digits.empty()) {
      IdentityRef ref;
      ref.kind = IdentityKind::process_id;
      ref.value = digits;
      found.push_back(std::move(ref));
    }
  }

  // "LOG: Initializing log file for process with PID 12196" and similar prose PID statements.
  if (const std::size_t marker = folded.find("pid "); marker != std::string::npos) {
    std::size_t index = marker + 4U;
    while (index < line.size() && line[index] == ' ') ++index;
    std::string digits;
    while (index < line.size() && std::isdigit(static_cast<unsigned char>(line[index])) != 0)
      digits.push_back(line[index++]);
    if (digits.size() >= 2U) {
      IdentityRef ref;
      ref.kind = IdentityKind::process_id;
      ref.value = digits;
      found.push_back(std::move(ref));
    }
  }

  // Bare GUIDs in prose - "client session ({d2350e2c-...})". The agent leg NEVER labels its session
  // identifier, so a key=value extractor misses it entirely. Only claim these when the line reads
  // like a session statement, otherwise every GUID in a log becomes a false identity.
  const bool session_context = folded.find("session") != std::string::npos ||
                               folded.find("agent") != std::string::npos ||
                               folded.find("connect") != std::string::npos;
  if (session_context) {
    for (std::size_t index = 0; index + 36U <= line.size(); ++index) {
      const bool braced = line[index] == '{';
      const std::size_t start = braced ? index + 1U : index;
      if (start + 36U > line.size()) break;
      const std::string_view candidate = line.substr(start, 36U);
      if (!looks_like_guid(candidate)) continue;
      IdentityRef ref;
      ref.kind = IdentityKind::agent_session;
      ref.value = normalize_guid(candidate);
      found.push_back(std::move(ref));
      index = start + 35U;
    }
  }

  // Peer addresses: "[::ffff:172.31.17.182" and "10.0.3.4:2500". Used only to support inferred
  // edges, never to assert an exact one.
  for (std::size_t index = 0; index < line.size(); ++index) {
    if (std::isdigit(static_cast<unsigned char>(line[index])) == 0) continue;
    std::size_t end = index;
    int dots = 0;
    while (end < line.size() &&
           (std::isdigit(static_cast<unsigned char>(line[end])) != 0 || line[end] == '.')) {
      if (line[end] == '.') ++dots;
      ++end;
    }
    if (dots == 3 && end - index >= 7U) {
      IdentityRef ref;
      ref.kind = IdentityKind::peer_address;
      ref.value = std::string(line.substr(index, end - index));
      found.push_back(std::move(ref));
    }
    index = end;
  }
  return found;
}

CorrelationGraph build_correlation_graph(std::vector<IdentityRef> identities) {
  CorrelationGraph graph;

  // The run is the anchor. Group by jobSessionId first, then attach every identifier that shares a
  // source line or file with a run identifier.
  std::map<std::string, CorrelatedRun> runs;
  for (const auto& ref : identities) {
    if (ref.kind != IdentityKind::job_session_id) continue;
    auto& run = runs[ref.value];
    run.job_session_id = ref.value;
    if (run.first_seen_utc_ms == 0 || (ref.timestamp_utc_ms != 0 && ref.timestamp_utc_ms < run.first_seen_utc_ms))
      run.first_seen_utc_ms = ref.timestamp_utc_ms;
    if (ref.timestamp_utc_ms > run.last_seen_utc_ms) run.last_seen_utc_ms = ref.timestamp_utc_ms;
    if (!ref.machine.empty() &&
        std::find(run.machines.begin(), run.machines.end(), ref.machine) == run.machines.end())
      run.machines.push_back(ref.machine);
    run.identities.push_back(ref);
  }

  // Co-location on the same physical line is an EXACT relationship: Veeam emitted both identifiers
  // as one statement about one thing. Co-location in the same file is weaker and is not claimed
  // here; that is the time-window work deferred past this slice.
  std::map<std::pair<std::string, std::uint64_t>, std::vector<const IdentityRef*>> by_line;
  for (const auto& ref : identities)
    by_line[{ref.source_path, ref.line_number}].push_back(&ref);

  for (const auto& [location, refs] : by_line) {
    const IdentityRef* session = nullptr;
    for (const auto* ref : refs) {
      if (ref->kind == IdentityKind::job_session_id) { session = ref; break; }
    }
    if (session == nullptr) continue;
    auto found = runs.find(session->value);
    if (found == runs.end()) continue;
    for (const auto* ref : refs) {
      if (ref == session) continue;
      CorrelationEdge edge;
      edge.from_kind = IdentityKind::job_session_id;
      edge.from_value = session->value;
      edge.to_kind = ref->kind;
      edge.to_value = ref->value;
      edge.confidence = CorrelationConfidence::exact;
      edge.basis = "Emitted on the same log line as the run identifier";
      edge.source_path = ref->source_path;
      edge.line_number = ref->line_number;
      ++found->second.exact_edges;
      found->second.edges.push_back(std::move(edge));
      found->second.identities.push_back(*ref);
      if (!ref->machine.empty() &&
          std::find(found->second.machines.begin(), found->second.machines.end(), ref->machine) ==
              found->second.machines.end())
        found->second.machines.push_back(ref->machine);
    }
  }

  for (auto& [key, run] : runs) {
    static_cast<void>(key);
    // A run's job identity, when one was emitted alongside it.
    for (const auto& ref : run.identities) {
      if (ref.kind == IdentityKind::job_id && run.job_id.empty()) run.job_id = ref.value;
    }
    std::sort(run.machines.begin(), run.machines.end());
    graph.runs.push_back(std::move(run));
  }
  std::sort(graph.runs.begin(), graph.runs.end(),
            [](const CorrelatedRun& left, const CorrelatedRun& right) {
              if (left.first_seen_utc_ms != right.first_seen_utc_ms)
                return left.first_seen_utc_ms < right.first_seen_utc_ms;
              return left.job_session_id < right.job_session_id;
            });

  // Anything never reachable from a run. Reported rather than dropped, because "this evidence is
  // service-scoped and has no owning run by nature" is a real answer, and a bare zero is not.
  std::set<std::string> attached;
  for (const auto& run : graph.runs) {
    for (const auto& ref : run.identities) attached.insert(to_string(ref.kind) + "|" + ref.value);
  }
  for (auto& ref : identities) {
    if (attached.count(to_string(ref.kind) + "|" + ref.value) != 0U) continue;
    graph.unattached.push_back(std::move(ref));
  }
  return graph;
}

} // namespace support_assist
