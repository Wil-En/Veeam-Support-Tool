#include "support_assist/recent_cases.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"

#include <algorithm>
#include <fstream>
#include <string>
#include <system_error>
#include <utility>

namespace support_assist {
namespace {

Error recent_error(std::string operation, const std::filesystem::path& source, std::string message) {
  Error error;
  error.component = "RecentCases";
  error.operation = std::move(operation);
  error.source = path_to_utf8(source);
  error.message = std::move(message);
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

// One case's key: its root as written, ignoring case on Windows, where paths do.
std::string root_key(const std::filesystem::path& root) {
#ifdef _WIN32
  return ascii_lower(path_to_utf8(root));
#else
  return path_to_utf8(root);
#endif
}

Status write_recent_cases(const std::filesystem::path& file, const std::vector<RecentCase>& cases) {
  std::error_code error;
  std::filesystem::create_directories(file.parent_path(), error);
  std::ofstream output(file, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(recent_error("write", file, "The recent cases list could not be written."));
  for (const auto& entry : cases)
    output << entry.opened_unix_ms << '\t' << path_to_utf8(entry.root) << '\n';
  return output ? Status::success()
                : Status::failure(recent_error("write", file, "The recent cases list could not be written."));
}

} // namespace

std::vector<RecentCase> read_recent_cases(const std::filesystem::path& file) {
  std::vector<RecentCase> cases;
  std::ifstream input(file, std::ios::binary);
  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    const std::size_t tab = line.find('\t');
    if (tab == std::string::npos || tab == 0U || tab + 1U >= line.size())
      continue;
    const std::string time = line.substr(0, tab);
    if (time.find_first_not_of("0123456789") != std::string::npos || time.size() > 18U)
      continue;
    cases.push_back({path_from_utf8(line.substr(tab + 1U)), std::stoll(time)});
  }
  std::stable_sort(cases.begin(), cases.end(),
                   [](const auto& left, const auto& right) { return left.opened_unix_ms > right.opened_unix_ms; });
  return cases;
}

Status record_case_opened(const std::filesystem::path& file, const std::filesystem::path& root,
                          std::int64_t opened_unix_ms) {
  auto cases = read_recent_cases(file);
  const std::string key = root_key(root);
  std::erase_if(cases, [&](const RecentCase& entry) { return root_key(entry.root) == key; });
  cases.insert(cases.begin(), RecentCase{root, opened_unix_ms});
  if (cases.size() > kRecentCasesKept)
    cases.resize(kRecentCasesKept);
  return write_recent_cases(file, cases);
}

Status forget_recent_case(const std::filesystem::path& file, const std::filesystem::path& root) {
  std::error_code error;
  if (!std::filesystem::exists(file, error))
    return Status::success();
  auto cases = read_recent_cases(file);
  const std::string key = root_key(root);
  const std::size_t before = cases.size();
  std::erase_if(cases, [&](const RecentCase& entry) { return root_key(entry.root) == key; });
  return cases.size() == before ? Status::success() : write_recent_cases(file, cases);
}

std::vector<const CaseWorkspace*> recent_case_order(const std::vector<CaseWorkspace>& cases,
                                                    const std::vector<RecentCase>& recent) {
  std::vector<const CaseWorkspace*> ordered;
  std::vector<bool> placed(cases.size(), false);
  for (const auto& entry : recent) {
    const std::string key = root_key(entry.root);
    for (std::size_t index = 0; index < cases.size(); ++index) {
      if (!placed[index] && root_key(cases[index].root) == key) {
        ordered.push_back(&cases[index]);
        placed[index] = true;
        break;
      }
    }
  }
  for (std::size_t index = 0; index < cases.size(); ++index) {
    if (!placed[index])
      ordered.push_back(&cases[index]);
  }
  return ordered;
}

} // namespace support_assist
