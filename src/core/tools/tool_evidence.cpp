#include "support_assist/tool_evidence.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <map>
#include <sstream>
#include <system_error>
#include <utility>

namespace support_assist {
namespace {


std::int64_t utc_millis_from_iso(std::string_view text) {
  if (text.empty()) return 0;
  const auto parsed = parse_timestamp(text, DateOrder::iso_only, 0);
  return parsed.has_value() ? parsed->unix_millis : 0;
}

// A tool row reports a problem when its status says so. The vocabulary is the one SAT's own tools
// emit (see result.tsv across the shipped tools), not a guess: FAILED, ERROR, WARNING and the
// Finding marker. PASS/Connected/Accessible/STARTED/GUIDANCE are explicitly not problems.
bool status_is_finding(std::string_view status) {
  const std::string folded = ascii_lower(trim(status));
  if (folded.empty()) return false;
  static constexpr std::array<std::string_view, 8> kFindingStatuses{
      "failed", "fail", "error", "warning", "finding", "timeout", "denied", "unreachable"};
  return std::any_of(kFindingStatuses.begin(), kFindingStatuses.end(),
                     [&](std::string_view candidate) { return folded == candidate; });
}

// result.tsv is a short key=value header, a blank line, a column header row, then tab-separated
// rows. Parsed defensively: a malformed row is skipped rather than failing the whole artifact,
// because one bad tool result must not cost the engineer every other tool's evidence.
std::vector<ToolResultRow> read_result_rows(const std::filesystem::path& path) {
  std::vector<ToolResultRow> rows;
  std::ifstream input(path, std::ios::binary);
  if (!input) return rows;

  std::string line;
  bool past_header = false;
  std::size_t bytes = 0;
  // Bound the read: this may be pointed at customer-supplied content.
  constexpr std::size_t kMaximumResultBytes = 16U * 1024U * 1024U;
  while (std::getline(input, line)) {
    bytes += line.size() + 1U;
    if (bytes > kMaximumResultBytes) break;
    if (!line.empty() && line.back() == '\r') line.pop_back();

    if (!past_header) {
      // The column header row marks the start of the data section.
      if (line.rfind("category\t", 0) == 0) past_header = true;
      continue;
    }
    if (line.empty()) continue;

    ToolResultRow row;
    std::size_t start = 0;
    std::array<std::string*, 4> fields{&row.category, &row.item, &row.details, &row.status};
    for (std::size_t field = 0; field < fields.size(); ++field) {
      const std::size_t tab = line.find('\t', start);
      const bool last = field + 1U == fields.size() || tab == std::string::npos;
      *fields[field] = last ? line.substr(start) : line.substr(start, tab - start);
      if (last) break;
      start = tab + 1U;
    }
    rows.push_back(std::move(row));
  }
  return rows;
}

} // namespace

std::string format_tool_result_tsv(std::string_view tool, ExecutionStatus execution, DiagnosticStatus diagnostic,
                                   std::string_view summary, const std::vector<ToolResultRow>& rows) {
  const auto clean = [](std::string_view value) {
    std::string text(value);
    for (char& character : text) {
      if (character == '\t' || character == '\r' || character == '\n')
        character = ' ';
    }
    return text;
  };
  std::string text = "Support Assist Tool execution result\ntool=" + clean(tool) +
                     "\nexecution_status=" + to_string(execution) + "\ndiagnostic_status=" + to_string(diagnostic) +
                     "\nsummary=" + clean(summary) + "\n\ncategory\titem\tdetails\tstatus\n";
  for (const ToolResultRow& row : rows)
    text += clean(row.category) + '\t' + clean(row.item) + '\t' + clean(row.details) + '\t' + clean(row.status) + '\n';
  return text;
}

std::vector<ToolResultRow> ToolEvidence::finding_rows() const {
  std::vector<ToolResultRow> findings;
  std::copy_if(rows.begin(), rows.end(), std::back_inserter(findings),
               [](const ToolResultRow& row) { return status_is_finding(row.status); });
  return findings;
}

Result<std::vector<ToolEvidence>> load_tool_evidence(const std::filesystem::path& root) {
  auto artifacts = discover_execution_artifacts(root);
  if (!artifacts.ok())
    return Result<std::vector<ToolEvidence>>::failure(artifacts.error());

  std::vector<ToolEvidence> evidence;
  evidence.reserve(artifacts.value().size());
  for (auto& manifest : artifacts.value()) {
    ToolEvidence item;
    item.started_utc_ms = utc_millis_from_iso(manifest.started_utc);
    item.completed_utc_ms = utc_millis_from_iso(manifest.completed_utc);
    item.rows = read_result_rows(manifest.root / "result.tsv");
    item.manifest = std::move(manifest);
    evidence.push_back(std::move(item));
  }
  return Result<std::vector<ToolEvidence>>::success(std::move(evidence));
}

std::vector<ToolEvidenceByMachine> group_tool_evidence_by_machine(std::vector<ToolEvidence> evidence) {
  std::map<std::string, ToolEvidenceByMachine> grouped;
  for (auto& item : evidence) {
    // A manifest with no host still has to land somewhere visible; silently dropping evidence is
    // worse than showing it against an explicit placeholder.
    const std::string host = item.host().empty() ? std::string("UNKNOWN") : item.host();
    auto& bucket = grouped[host];
    bucket.host = host;
    if (bucket.first_activity_utc_ms == 0 ||
        (item.started_utc_ms != 0 && item.started_utc_ms < bucket.first_activity_utc_ms))
      bucket.first_activity_utc_ms = item.started_utc_ms;
    const std::int64_t end = item.completed_utc_ms != 0 ? item.completed_utc_ms : item.started_utc_ms;
    if (end > bucket.last_activity_utc_ms) bucket.last_activity_utc_ms = end;
    if (item.has_finding()) ++bucket.finding_count;
    bucket.evidence.push_back(std::move(item));
  }

  std::vector<ToolEvidenceByMachine> machines;
  machines.reserve(grouped.size());
  for (auto& [host, bucket] : grouped) {
    std::stable_sort(bucket.evidence.begin(), bucket.evidence.end(),
                     [](const ToolEvidence& left, const ToolEvidence& right) {
                       return left.started_utc_ms < right.started_utc_ms;
                     });
    machines.push_back(std::move(bucket));
  }
  std::stable_sort(machines.begin(), machines.end(),
                   [](const ToolEvidenceByMachine& left, const ToolEvidenceByMachine& right) {
                     if (left.first_activity_utc_ms != right.first_activity_utc_ms)
                       return left.first_activity_utc_ms < right.first_activity_utc_ms;
                     return left.host < right.host;
                   });
  return machines;
}

std::vector<ToolTimelineEntry> build_tool_timeline(const std::vector<ToolEvidence>& evidence) {
  std::vector<ToolTimelineEntry> timeline;
  timeline.reserve(evidence.size());
  for (const auto& item : evidence) {
    ToolTimelineEntry entry;
    entry.utc_ms = item.started_utc_ms;
    entry.utc_text = item.manifest.started_utc;
    entry.host = item.host().empty() ? "UNKNOWN" : item.host();
    entry.tool = item.tool();
    entry.status = to_string(item.manifest.execution_status);
    entry.diagnostic = to_string(item.manifest.diagnostic_status);
    entry.summary = item.manifest.summary;
    entry.findings = item.finding_rows();
    entry.finding_count = entry.findings.size();
    entry.source = item.manifest.root;
    timeline.push_back(std::move(entry));
  }
  // Every timestamp here is already UTC from the manifest, so ordering is exact across machines -
  // no offset reconstruction and no assumption that two hosts share a wall clock.
  std::stable_sort(timeline.begin(), timeline.end(),
                   [](const ToolTimelineEntry& left, const ToolTimelineEntry& right) {
                     if (left.utc_ms != right.utc_ms) return left.utc_ms < right.utc_ms;
                     return left.host < right.host;
                   });
  return timeline;
}

std::string render_tool_timeline_note(const std::vector<ToolEvidence>& evidence,
                                      std::string_view machine_filter) {
  const std::string filter = ascii_lower(trim(machine_filter));
  std::ostringstream out;
  const auto machines = group_tool_evidence_by_machine(evidence);

  std::size_t rendered = 0;
  for (const auto& machine : machines) {
    if (!filter.empty() && ascii_lower(machine.host) != filter) continue;
    ++rendered;
    out << "Machine: " << machine.host << '\n';
    out << "  Tool runs: " << machine.evidence.size();
    if (machine.finding_count > 0) out << "  |  With findings: " << machine.finding_count;
    out << '\n';
    if (machine.first_activity_utc_ms != 0) {
      out << "  Window (UTC): " << readable_utc_from_unix_millis(machine.first_activity_utc_ms)
          << "  ->  " << readable_utc_from_unix_millis(machine.last_activity_utc_ms) << '\n';
    }
    out << '\n';
    for (const auto& item : machine.evidence) {
      out << "  [" << item.manifest.started_utc << "] " << item.tool() << '\n';
      out << "    Result: " << to_string(item.manifest.execution_status)
          << "  |  Diagnostic: " << to_string(item.manifest.diagnostic_status) << '\n';
      if (!item.manifest.summary.empty()) out << "    Summary: " << item.manifest.summary << '\n';
      const auto findings = item.finding_rows();
      for (const auto& row : findings) {
        out << "      - " << row.category;
        if (!row.item.empty()) out << " / " << row.item;
        out << " [" << row.status << "]\n";
        if (!row.details.empty()) out << "        " << row.details << '\n';
      }
      // Source attribution matches the log-evidence convention so a reader can go straight to the
      // artifact that produced the claim.
      out << "    Source: " << support_assist::path_to_utf8(item.manifest.root) << '\n';
      out << '\n';
    }
  }
  if (rendered == 0) out << "No SAT tool evidence was found for the requested scope.\n";
  return out.str();
}

} // namespace support_assist
