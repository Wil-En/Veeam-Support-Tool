#pragma once

// Kept quick tool runs in Environment Review and Health Monitor, on both editions: the newest run
// of each tool on each machine. Environment Review lists the checks of how a machine is set up
// (names, time, ports, volumes, object storage), Health Monitor the ones of what it is doing
// (services and processes, file locks). The runs are read from the tool output they keep: on
// Customer / Lab this machine's Log-Collections Tools folder, in Engineer Review the active case's
// logs, where each imported collection carries its own.

#include "environment_review.hpp"

#include "support_assist/system_health.hpp"
#include "support_assist/tool_evidence.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist::gui {

enum class QuickCheckView {
  environment,
  health,
};

// Kept quick tool runs show in Environment Review only; Health Monitor keeps to its own samples.
inline bool quick_check_in_view(std::string_view tool, QuickCheckView view) {
  if (view == QuickCheckView::environment)
    return tool == "Name Check" || tool == "Time Check" || tool == "Local Port Checker" ||
           tool == "Volume Check" || tool == "Object Storage Check" || tool == "File Lock Check";
  return false;
}

// The newest completed run of each of the view's tools on each machine, newest first.
inline std::vector<ToolEvidence> latest_quick_checks(const std::vector<ToolEvidence>& evidence, QuickCheckView view) {
  std::map<std::pair<std::string, std::string>, const ToolEvidence*> newest;
  for (const ToolEvidence& run : evidence) {
    if (!quick_check_in_view(run.tool(), view) || run.manifest.execution_status != ExecutionStatus::completed)
      continue;
    const ToolEvidence*& kept = newest[{run.host(), run.tool()}];
    if (kept == nullptr || run.started_utc_ms > kept->started_utc_ms)
      kept = &run;
  }
  std::vector<ToolEvidence> latest;
  latest.reserve(newest.size());
  for (const auto& entry : newest)
    latest.push_back(*entry.second);
  std::stable_sort(latest.begin(), latest.end(), [](const ToolEvidence& left, const ToolEvidence& right) {
    return left.started_utc_ms > right.started_utc_ms;
  });
  return latest;
}

// The Tools folders under a case's logs: its own (logs/Tools) and each imported collection's
// (logs/<collection>/Tools), three levels down at most, so a large extracted bundle is not walked.
inline std::vector<std::filesystem::path> case_quick_check_roots(const std::filesystem::path& case_logs) {
  std::vector<std::filesystem::path> roots;
  std::error_code error;
  if (case_logs.empty() || !std::filesystem::is_directory(case_logs, error))
    return roots;
  std::filesystem::recursive_directory_iterator walk(
      case_logs, std::filesystem::directory_options::skip_permission_denied, error);
  for (const std::filesystem::recursive_directory_iterator end; !error && walk != end; walk.increment(error)) {
    std::error_code type_error;
    if (!walk->is_directory(type_error))
      continue;
    if (walk->path().filename() == "Tools") {
      roots.push_back(walk->path());
      walk.disable_recursion_pending();
    } else if (walk.depth() >= 2) {
      walk.disable_recursion_pending();
    }
  }
  return roots;
}

// Every kept run under the roots, for latest_quick_checks; a root that cannot be read adds nothing.
inline std::vector<ToolEvidence> load_quick_checks(const std::vector<std::filesystem::path>& roots) {
  std::vector<ToolEvidence> evidence;
  for (const auto& root : roots) {
    std::error_code error;
    if (!std::filesystem::is_directory(root, error))
      continue;
    auto loaded = load_tool_evidence(root);
    if (!loaded.ok())
      continue;
    for (auto& run : loaded.value())
      evidence.push_back(std::move(run));
  }
  return evidence;
}

// "2026-10-12 21:05:00 UTC" from the manifest's "2026-10-12T21:05:00Z".
inline std::string quick_check_when(const ToolEvidence& run) {
  std::string when = run.manifest.started_utc;
  if (when.empty())
    return "time not recorded";
  if (const std::size_t t = when.find('T'); t != std::string::npos)
    when[t] = ' ';
  if (!when.empty() && when.back() == 'Z')
    when.pop_back();
  if (const std::size_t dot = when.find('.'); dot != std::string::npos)
    when.erase(dot);
  return when + " UTC";
}

inline std::string quick_check_outcome(const ToolEvidence& run) {
  switch (run.manifest.diagnostic_status) {
  case DiagnosticStatus::pass: return "Passed";
  case DiagnosticStatus::finding: return "With findings";
  case DiagnosticStatus::neutral:
  case DiagnosticStatus::not_applicable:
  case DiagnosticStatus::unknown: break;
  }
  return "Completed";
}

// One kept run as the detail pane's grid: its rows under Section, Item, Value and Status.
inline std::string quick_check_detail(const ToolEvidence& run) {
  std::string detail = run.tool() + "\n" + std::string(environment::utf8_length(run.tool()), '=') + "\n";
  detail += "Columns:\tSection\tItem\tValue\tStatus\n";
  const auto clean = [](std::string text) {
    std::replace(text.begin(), text.end(), '\t', ' ');
    std::replace(text.begin(), text.end(), '\n', ' ');
    std::replace(text.begin(), text.end(), '\r', ' ');
    return text;
  };
  detail += "Run\t" + quick_check_when(run) + "\t" + clean(run.host()) + "\t" + quick_check_outcome(run) + "\n";
  if (run.rows.empty() && !run.manifest.summary.empty())
    detail += "Result\t" + clean(run.manifest.summary) + "\t\t\n";
  for (const ToolResultRow& row : run.rows)
    detail += clean(row.category) + "\t" + clean(row.item) + "\t" + clean(row.details) + "\t" + clean(row.status) + "\n";
  return detail;
}

// Environment Review's "Quick checks" branch: a node per kept run, the machine named when the runs
// come from more than one. Empty when nothing was kept.
inline std::optional<environment::TopologyNode> quick_checks_node(const std::vector<ToolEvidence>& latest) {
  if (latest.empty())
    return std::nullopt;
  bool several_hosts = false;
  for (const ToolEvidence& run : latest)
    several_hosts = several_hosts || run.host() != latest.front().host();
  environment::TopologyNode node;
  node.label = "Quick checks";
  node.detail = "Quick checks\n============\nColumns:\tTool\tMachine\tRun\tOutcome\tResult\n";
  for (const ToolEvidence& run : latest) {
    std::string label = run.tool();
    if (several_hosts && !run.host().empty())
      label += " on " + run.host();
    if (!run.manifest.summary.empty())
      label += ": " + run.manifest.summary;
    node.detail += run.tool() + "\t" + run.host() + "\t" + quick_check_when(run) + "\t" + quick_check_outcome(run) +
                   "\t" + run.manifest.summary + "\n";
    node.children.push_back({std::move(label), quick_check_detail(run), false, {}});
  }
  return node;
}

// A Health Monitor findings row for a kept run: severity, component, observation, and when.
struct QuickCheckHealthRow {
  HealthSeverity severity = HealthSeverity::informational; // warning: findings; healthy: passed
  std::string component;
  std::string observation;
  std::string detail;
};

inline std::vector<QuickCheckHealthRow> quick_check_health_rows(const std::vector<ToolEvidence>& latest) {
  std::vector<QuickCheckHealthRow> rows;
  for (const ToolEvidence& run : latest) {
    QuickCheckHealthRow row;
    row.severity = run.manifest.diagnostic_status == DiagnosticStatus::finding ? HealthSeverity::warning
                   : run.manifest.diagnostic_status == DiagnosticStatus::pass  ? HealthSeverity::healthy
                                                                               : HealthSeverity::informational;
    row.component = run.tool();
    row.observation = run.manifest.summary.empty() ? quick_check_outcome(run) : run.manifest.summary;
    row.detail = "Last run " + quick_check_when(run);
    if (!run.host().empty())
      row.detail += " on " + run.host();
    const auto findings = run.finding_rows();
    if (!findings.empty()) {
      row.detail += ": " + findings.front().item;
      if (!findings.front().details.empty())
        row.detail += ", " + findings.front().details;
      if (findings.size() > 1U)
        row.detail += " (and " + std::to_string(findings.size() - 1U) + " more)";
    }
    rows.push_back(std::move(row));
  }
  return rows;
}

// Health Monitor's kept runs, read again only when where they come from changes or a run was kept
// (the page redraws on every sample). `host`, when given, keeps the runs of that machine only: a
// saved snapshot is one machine's.
class QuickCheckHealthCache {
public:
  void invalidate() { key_.clear(); }

  const std::vector<QuickCheckHealthRow>& rows(const std::string& key, const std::vector<std::filesystem::path>& roots,
                                               std::string_view host) {
    if (key_.empty() || key != key_) {
      key_ = key.empty() ? std::string("-") : key;
      auto latest = latest_quick_checks(load_quick_checks(roots), QuickCheckView::health);
      if (!host.empty()) {
        const auto folded = [](std::string_view text) {
          std::string out(text);
          std::transform(out.begin(), out.end(), out.begin(),
                         [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
          return out;
        };
        const std::string wanted = folded(host);
        std::erase_if(latest, [&](const ToolEvidence& run) { return folded(run.host()) != wanted; });
      }
      rows_ = quick_check_health_rows(latest);
    }
    return rows_;
  }

private:
  std::string key_;
  std::vector<QuickCheckHealthRow> rows_;
};

} // namespace support_assist::gui
