#include "support_assist/veeam_log_review.hpp"

#include "support_assist/port_check.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/system_error_codes.hpp"
#include "support_assist/system_health.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include "support_assist/version.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>
#endif

namespace support_assist {
namespace {

enum class ReviewEncoding { utf8, utf16le, utf16be };

std::string join_text(const std::vector<std::string>& values, std::string_view separator) {
  std::ostringstream output;
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0U)
      output << separator;
    output << values[index];
  }
  return output.str();
}

struct ReviewLine {
  std::string text;
  std::uint64_t line_number = 0;
  std::uint64_t byte_offset = 0;
};

class ReviewLineReader {
public:
  ReviewLineReader(const std::filesystem::path& path, std::size_t maximum_line_bytes)
      : input_(path, std::ios::binary), maximum_line_bytes_(maximum_line_bytes) {
    unsigned char prefix[3]{};
    input_.read(reinterpret_cast<char*>(prefix), 3);
    const auto count = input_.gcount();
    if (count >= 2 && prefix[0] == 0xff && prefix[1] == 0xfe) {
      encoding_ = ReviewEncoding::utf16le;
      input_.clear();
      input_.seekg(2);
    } else if (count >= 2 && prefix[0] == 0xfe && prefix[1] == 0xff) {
      encoding_ = ReviewEncoding::utf16be;
      input_.clear();
      input_.seekg(2);
    } else {
      encoding_ = ReviewEncoding::utf8;
      input_.clear();
      input_.seekg(count >= 3 && prefix[0] == 0xef && prefix[1] == 0xbb && prefix[2] == 0xbf ? 3
                                                                                           : 0);
    }
  }

  [[nodiscard]] bool good() const {
    return input_.good();
  }

  Result<bool> next(ReviewLine& output) {
    output.text.clear();
    output.byte_offset = tell();
    if (encoding_ == ReviewEncoding::utf8) {
      // SAT-SEC-01: read incrementally and fail as soon as the configured ceiling is
      // exceeded. std::getline grows the destination until it finds a newline or hits EOF, so
      // checking the length afterwards allocated the very memory the limit exists to prevent.
      // A newline-free file - a corrupt log, a truncated binary, or a hostile bundle member -
      // otherwise allocated its entire size before being rejected. The UTF-16 branch below has
      // always bounded correctly; this makes the two paths agree.
      bool saw_any_input = false;
      for (;;) {
        const int next = input_.get();
        if (next == std::char_traits<char>::eof()) {
          if (!saw_any_input)
            return Result<bool>::success(false);
          break;
        }
        saw_any_input = true;
        if (next == '\n')
          break;
        if (output.text.size() >= maximum_line_bytes_)
          return Result<bool>::failure(make_error("line exceeds configured limit"));
        output.text.push_back(static_cast<char>(next));
      }
      if (!saw_any_input && input_.bad())
        return Result<bool>::failure(make_error("read line"));
      if (!output.text.empty() && output.text.back() == '\r')
        output.text.pop_back();
    } else {
      std::u16string text;
      for (;;) {
        char bytes[2]{};
        input_.read(bytes, 2);
        if (input_.gcount() == 0 && input_.eof()) {
          if (text.empty())
            return Result<bool>::success(false);
          break;
        }
        if (input_.gcount() != 2)
          return Result<bool>::failure(make_error("truncated UTF-16 code unit"));
        const auto first = static_cast<unsigned char>(bytes[0]);
        const auto second = static_cast<unsigned char>(bytes[1]);
        const char16_t code_unit =
            encoding_ == ReviewEncoding::utf16le
                ? static_cast<char16_t>(first | (static_cast<unsigned int>(second) << 8U))
                : static_cast<char16_t>((static_cast<unsigned int>(first) << 8U) | second);
        if (code_unit == u'\n')
          break;
        if (code_unit != u'\r')
          text.push_back(code_unit);
        if (text.size() * 2U > maximum_line_bytes_)
          return Result<bool>::failure(make_error("line exceeds configured limit"));
      }
      append_utf8(text, output.text);
    }
    output.line_number = ++line_number_;
    return Result<bool>::success(true);
  }

private:
  [[nodiscard]] std::uint64_t tell() {
    const auto position = input_.tellg();
    if (position < 0)
      return 0;
    return static_cast<std::uint64_t>(position);
  }

  static void append_utf8(const std::u16string& input, std::string& output) {
    for (std::size_t index = 0; index < input.size(); ++index) {
      std::uint32_t code_point = input[index];
      if (code_point >= 0xd800U && code_point <= 0xdbffU) {
        if (index + 1U < input.size()) {
          const auto low = static_cast<std::uint32_t>(input[index + 1U]);
          if (low >= 0xdc00U && low <= 0xdfffU) {
            ++index;
            code_point = 0x10000U + ((code_point - 0xd800U) << 10U) + (low - 0xdc00U);
          } else {
            code_point = 0xfffdU;
          }
        } else {
          code_point = 0xfffdU;
        }
      } else if (code_point >= 0xdc00U && code_point <= 0xdfffU) {
        code_point = 0xfffdU;
      }
      if (code_point <= 0x7fU) {
        output.push_back(static_cast<char>(code_point));
      } else if (code_point <= 0x7ffU) {
        output.push_back(static_cast<char>(0xc0U | (code_point >> 6U)));
        output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
      } else if (code_point <= 0xffffU) {
        output.push_back(static_cast<char>(0xe0U | (code_point >> 12U)));
        output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
      } else {
        output.push_back(static_cast<char>(0xf0U | (code_point >> 18U)));
        output.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
      }
    }
  }

  [[nodiscard]] Error make_error(std::string operation) const {
    Error error;
    error.component = "VeeamLogReview";
    error.operation = std::move(operation);
    error.message = "Unable to read input log";
    error.timestamp_utc = utc_now_iso8601();
    error.correlation_id = make_uuid_v4();
    return error;
  }

  std::ifstream input_;
  ReviewEncoding encoding_ = ReviewEncoding::utf8;
  std::size_t maximum_line_bytes_ = 0;
  std::uint64_t line_number_ = 0;
};

struct ReviewInputFile {
  std::filesystem::path materialized_path;
  std::string display_path;
  std::string bundle_key;
  std::string bundle_display_path;
  std::string manifest_profile;
  std::string manifest_machine_name;
  bool cache_reused = false;
};

struct EvidenceCatalogPath {
  std::string display_path;
  std::string bundle_key;
  std::string bundle_display_path;
  std::uint64_t size_bytes = 0;
  bool indexed = false;
};

// Defined further down beside the component rules; declared here because run and incident
// attribution happens earlier in the file than the rules themselves.
std::vector<std::pair<std::string, std::string>> components_for_file(VeeamEvidenceRole role,
                                                                     std::string_view folded_path);
std::string primary_component_tag(std::string_view display_path);

struct ParsedLogPrefix {
  std::string severity;
  std::string timestamp_original;
  std::optional<std::int64_t> timestamp_utc_ms;
  std::string thread;
  std::string message;
  bool has_structured_prefix = false;
};

struct ActiveIncident {
  VeeamIncidentLocation location;
  std::string severity;
  std::string component;
  std::string summary;
  std::size_t remaining_after = 0;
  bool collecting_after = false;
  // Set when the root line was an action wrapper with no real error text, e.g.
  // "[TryInvoke] Invocation error;". The first following line that carries actual error text is
  // promoted into the summary, because THAT is the error - the wrapper is not.
  bool summary_awaiting_real_error = false;
  VeeamStoryStage story_stage = VeeamStoryStage::none;
};

struct FileParseState {
  // Memoised evidence role for the file being parsed. classify_veeam_evidence_role() performs
  // dozens of string searches and is called from per-LINE code; recomputing it for every line of
  // every file dominated parse time once the classifier grew. The role depends only on the file
  // path, so it is computed once per file here.
  std::optional<VeeamEvidenceRole> cached_role;
  std::deque<std::string> preceding;
  std::optional<ActiveIncident> active_incident;
  std::unordered_map<std::string, std::size_t> incident_indexes;
  std::unordered_map<std::string, std::size_t> retained_locations_by_bucket;
  std::optional<std::size_t> active_session_index;
  bool in_job_settings = false;
  bool capture_job_settings_lines = false;
  bool reading_included_items = false;
  bool reading_excluded_items = false;
  bool reading_job_command_line = false;
  std::string active_network_name;
  std::string active_network_description;
  bool active_network_up = false;
  bool active_network_loopback = false;
  std::string active_volume_id;
  std::string active_vss_provider_id;
  bool reading_volume_mount_points = false;
  bool reading_volume_extents = false;
  std::unordered_map<std::string, std::uint64_t> volume_sizes_by_mount;
};

std::string trim_copy(std::string_view input) {
  while (!input.empty() && std::isspace(static_cast<unsigned char>(input.front())) != 0)
    input.remove_prefix(1);
  while (!input.empty() && std::isspace(static_cast<unsigned char>(input.back())) != 0)
    input.remove_suffix(1);
  return std::string(input);
}

bool equals_folded(std::string_view left, std::string_view right) {
  return ascii_lower(left) == ascii_lower(right);
}

bool contains_folded(std::string_view text, std::string_view needle) {
  return ascii_lower(text).find(ascii_lower(needle)) != std::string::npos;
}

std::optional<std::string> between(std::string_view text,
                                   std::string_view opening,
                                   std::string_view closing,
                                   std::size_t start = 0) {
  const std::size_t begin = text.find(opening, start);
  if (begin == std::string_view::npos)
    return std::nullopt;
  const std::size_t value_begin = begin + opening.size();
  const std::size_t end = text.find(closing, value_begin);
  if (end == std::string_view::npos)
    return std::nullopt;
  return std::string(text.substr(value_begin, end - value_begin));
}

std::optional<std::string> after(std::string_view text, std::string_view marker) {
  const std::size_t position = text.find(marker);
  if (position == std::string_view::npos)
    return std::nullopt;
  return trim_copy(text.substr(position + marker.size()));
}


std::optional<std::uint64_t> uint64_field(std::string_view text, std::string_view marker) {
  const std::size_t position = text.find(marker);
  if (position == std::string_view::npos)
    return std::nullopt;
  std::size_t begin = position + marker.size();
  while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin])) != 0)
    ++begin;
  std::size_t end = begin;
  while (end < text.size() && std::isdigit(static_cast<unsigned char>(text[end])) != 0)
    ++end;
  if (end == begin)
    return std::nullopt;
  std::uint64_t value = 0;
  const auto result = std::from_chars(text.data() + static_cast<std::ptrdiff_t>(begin),
                                      text.data() + static_cast<std::ptrdiff_t>(end), value);
  if (result.ec != std::errc{})
    return std::nullopt;
  return value;
}

std::string format_task_size(std::string_view text) {
  const auto capacity = uint64_field(text, "Capacity =");
  const auto used = uint64_field(text, "UsedSize =");
  const auto objects = uint64_field(text, "objectsCount =");
  if (!capacity && !used && !objects)
    return trim_copy(text);
  constexpr double gib = 1024.0 * 1024.0 * 1024.0;
  std::ostringstream output;
  if (capacity)
    output << "Capacity " << std::fixed << std::setprecision(2) << static_cast<double>(*capacity) / gib << " GiB";
  if (used) {
    if (output.tellp() > 0) output << " | ";
    output << "Used " << std::fixed << std::setprecision(2) << static_cast<double>(*used) / gib << " GiB";
  }
  if (objects) {
    if (output.tellp() > 0) output << " | ";
    output << "Objects " << *objects;
  }
  return output.str();
}

// The account directory in a plug-in collection, e.g.
//   1-MSSQLPluginLogs/SLOWZONE_WEE_SQL_CL2$/MSSQLVBRCommunicationManager.log
//
// The directory immediately under the plug-in log root names the identity that launched the
// plug-in. A trailing '$' marks a computer account, which is the distinction worth surfacing: a
// plug-in running as the machine account rather than as an interactive user explains a whole class
// of permission cases.
//
// The name is sanitised on disk - separators in the real account become underscores - so it is
// reported as written. Only the domain split and the machine-account marker are asserted.
std::string plugin_account_from_path(std::string_view display_path) {
  std::string folded(display_path);
  std::replace(folded.begin(), folded.end(), '\\', '/');
  std::vector<std::string> parts;
  for (std::size_t start = 0; start <= folded.size();) {
    const std::size_t end = folded.find('/', start);
    const std::size_t stop = end == std::string::npos ? folded.size() : end;
    if (stop > start)
      parts.emplace_back(folded.substr(start, stop - start));
    if (end == std::string::npos)
      break;
    start = end + 1U;
  }
  // Need a plug-in log root, an account directory beneath it, and a file beneath that.
  for (std::size_t index = 0; index + 2U < parts.size(); ++index) {
    if (ascii_lower(parts[index]).find("pluginlogs") == std::string::npos)
      continue;
    const std::string& account = parts[index + 1U];
    if (account.empty() || account.find('_') == std::string::npos)
      return {};
    const std::size_t split = account.find('_');
    const std::string domain = account.substr(0, split);
    const std::string name = account.substr(split + 1U);
    if (domain.empty() || name.empty())
      return {};
    std::string described = domain + "\\" + name;
    if (name.back() == '$')
      described += " (computer account)";
    return described;
  }
  return {};
}

bool is_archive_path(const std::filesystem::path& path) {
  const std::string extension = ascii_lower(support_assist::path_to_utf8(path.extension()));
  return extension == ".zip" || extension == ".7z" || extension == ".tar" ||
         extension == ".gz" || extension == ".tgz" || extension == ".bz2" || extension == ".xz";
}

bool is_support_assist_generated_path(const std::filesystem::path& path) {
  const std::string name = ascii_lower(support_assist::path_to_utf8(path.filename()));
  std::string folded = ascii_lower(support_assist::path_to_utf8(path));
  std::replace(folded.begin(), folded.end(), '\\', '/');
  if (folded.find("/.support-assist-parser-cache/") != std::string::npos ||
      folded.find("/.support-assist-log-cache/") != std::string::npos ||
      folded.find("/supportassistreports/") != std::string::npos ||
      folded.find("/windowssupport/") != std::string::npos)
    return true;
  if (name == "bundle-index.json" || name == "case-review-state.json" ||
      name == "case-review-model.sat" || name == "ui-settings.ini" ||
      name == "activity.tsv" || name == "supportassisttool-debug.log")
    return true;
  return name.find("_veeam_log_review_") != std::string::npos ||
         name.starts_with("log-review-");
}

bool is_vaw_service_rotation_file(std::string_view path) {
  const std::string file =
      ascii_lower(support_assist::path_to_utf8(std::filesystem::path(std::string(path)).filename()));
  constexpr std::string_view prefix = "job.veeamendpointbackup";
  if (!file.starts_with(prefix))
    return false;
  std::string_view rest(file);
  rest.remove_prefix(prefix.size());
  if (rest == ".log")
    return true;
  if (!rest.starts_with(".") || !rest.ends_with(".log"))
    return false;
  rest.remove_prefix(1U);
  rest.remove_suffix(4U);
  return !rest.empty() && std::all_of(rest.begin(), rest.end(), [](char ch) {
    return ch >= '0' && ch <= '9';
  });
}

bool is_vaw_endpoint_identity_path(std::string_view path) {
  std::string folded = ascii_lower(path);
  std::replace(folded.begin(), folded.end(), '\\', '/');
  return folded.find("/1-endpoint/") != std::string::npos ||
         folded.find("svc.veeamendpointbackup") != std::string::npos ||
         folded.find("job.veeamendpointbackup") != std::string::npos ||
         folded.find("vaw_vmc") != std::string::npos ||
         (folded.find("collection-manifest.json") != std::string::npos &&
          folded.find("support-assist-tool-vaw") != std::string::npos);
}

bool is_strong_vbr_source_path(std::string_view path) {
  std::string folded = ascii_lower(path);
  std::replace(folded.begin(), folded.end(), '\\', '/');
  const std::size_t separator = folded.find_last_of('/');
  const std::string_view leaf = separator == std::string::npos
                                    ? std::string_view(folded)
                                    : std::string_view(folded).substr(separator + 1U);
  return folded.find("svc.veeambackup") != std::string::npos ||
         folded.find("support-assist-tool-vbr") != std::string::npos ||
         folded.find("vbr-labbundle") != std::string::npos ||
         leaf.starts_with("vbr-") || leaf == "vbr";
}

std::string source_parent(std::string_view source);
std::string normalized_source_path(std::string_view value);

bool is_candidate_log_path(const std::filesystem::path& path) {
  const std::string extension = ascii_lower(support_assist::path_to_utf8(path.extension()));
  return extension == ".log" || extension == ".txt" || extension == ".out" ||
         extension == ".xml" || extension == ".json" || extension == ".csv" ||
         extension.empty();
}

// "Not read by the review:      2 crash dumps, 1 Windows event log" for the report's header, or
// nothing when the review read every file it found.
std::string files_not_read_line(const VeeamLogReviewResult& review) {
  if (review.files_not_read.empty())
    return {};
  std::string kinds;
  for (const auto& [kind, count] : review.files_not_read)
    kinds += (kinds.empty() ? "" : ", ") + std::to_string(count) + " " + kind + (count == 1U ? "" : "s");
  return "Not read by the review:      " + kinds + "\n";
}

std::string review_profile_label(VeeamReviewProfile profile) {
  switch (profile) {
  case VeeamReviewProfile::vaw:
    return "Veeam Agent for Microsoft Windows (VAW)";
  case VeeamReviewProfile::vbr:
    return "Veeam Backup & Replication (VBR)";
  case VeeamReviewProfile::sql_plugin:
    return "Veeam Plug-in for Microsoft SQL Server";
  case VeeamReviewProfile::rman_plugin:
    return "Veeam Plug-in for Oracle RMAN";
  case VeeamReviewProfile::sap_hana_plugin:
    return "Veeam Plug-in for SAP HANA";
  case VeeamReviewProfile::sap_oracle_plugin:
    return "Veeam Plug-in for SAP on Oracle";
  case VeeamReviewProfile::sap_maxdb_plugin:
    return "Veeam Plug-in for SAP MaxDB";
  case VeeamReviewProfile::db2_plugin:
    return "Veeam Plug-in for IBM Db2";
  case VeeamReviewProfile::generic:
    return "Generic customer Veeam log review";
  case VeeamReviewProfile::automatic:
    return "Auto-detect Veeam product profile";
  }
  return "Auto-detect Veeam product profile";
}

std::string expected_product_type(VeeamReviewProfile profile) {
  switch (profile) {
  case VeeamReviewProfile::vaw:
    return "Veeam Agent for Microsoft Windows";
  case VeeamReviewProfile::vbr:
    return "Veeam Backup & Replication";
  case VeeamReviewProfile::sql_plugin:
    return "Veeam Plug-in for Microsoft SQL Server";
  case VeeamReviewProfile::rman_plugin:
    return "Veeam Plug-in for Oracle RMAN";
  case VeeamReviewProfile::sap_hana_plugin:
    return "Veeam Plug-in for SAP HANA";
  case VeeamReviewProfile::sap_oracle_plugin:
    return "Veeam Plug-in for SAP on Oracle";
  case VeeamReviewProfile::sap_maxdb_plugin:
    return "Veeam Plug-in for SAP MaxDB";
  case VeeamReviewProfile::db2_plugin:
    return "Veeam Plug-in for IBM Db2";
  case VeeamReviewProfile::generic:
    return "Veeam product logs (generic customer profile)";
  case VeeamReviewProfile::automatic:
    return "Veeam product logs (auto detect)";
  }
  return "Veeam product logs";
}

std::string folded_path_name(std::string_view path) {
  std::string folded = ascii_lower(path);
  std::replace(folded.begin(), folded.end(), '\\', '/');
  return folded;
}

bool looks_like_ipv4_component(std::string_view value) {
  if (value.empty())
    return false;
  int dots = 0;
  int digits = 0;
  int octet = 0;
  bool have_digit = false;
  for (const char ch : value) {
    if (ch >= '0' && ch <= '9') {
      have_digit = true;
      ++digits;
      octet = octet * 10 + (ch - '0');
      if (octet > 255)
        return false;
      continue;
    }
    if (ch != '.' || !have_digit)
      return false;
    ++dots;
    if (dots > 3)
      return false;
    octet = 0;
    have_digit = false;
  }
  return dots == 3 && have_digit && digits >= 4;
}

bool is_generic_evidence_container_component(std::string_view value) {
  const std::string folded = ascii_lower(value);
  static const std::set<std::string> names{
      "1-endpoint", "2-backup", "endpoint", "backup", "backups", "log", "logs",
      "veeam", "setup", "windowsupport", "windows-support", "mssqlpluginlogs",
      "rmanpluginlogs", "plugins", "plugin", "rescan", "rescans", "repository",
      "repositories", "transport", "service", "services", "job", "jobs",
      "programdata", "program files", "program files (x86)", "utils", "cache"};
  return names.contains(folded);
}

std::optional<std::string> logical_source_partition_component(const std::filesystem::path& relative) {
  if (relative.empty())
    return std::nullopt;
  auto iterator = relative.begin();
  if (iterator == relative.end())
    return std::nullopt;
  const std::string first = iterator->string();
  ++iterator;
  // A file directly in the selected root has no logical child source.
  if (iterator == relative.end())
    return std::nullopt;
  if (first.empty() || first == "." || first == ".." ||
      is_generic_evidence_container_component(first))
    return std::nullopt;
  if (looks_like_ipv4_component(first))
    return first;

  // VBR support exports commonly partition components by hostname/FQDN.  Be
  // deliberately conservative: accept only filesystem-safe host-like labels,
  // and reject generic evidence/category folders above.
  if (first.size() > 255U || first.find_first_of(" /\\") != std::string::npos)
    return std::nullopt;
  const bool host_characters = std::all_of(first.begin(), first.end(), [](char ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
           (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.';
  });
  const bool has_alpha = std::any_of(first.begin(), first.end(), [](char ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
  });
  const bool has_host_punctuation_or_digit = std::any_of(first.begin(), first.end(), [](char ch) {
    return (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.';
  });
  const bool all_alpha_upper = has_alpha && std::all_of(first.begin(), first.end(), [](char ch) {
    return (ch >= 'A' && ch <= 'Z');
  });
  return host_characters && has_alpha && (has_host_punctuation_or_digit || all_alpha_upper)
             ? std::optional<std::string>(first)
             : std::nullopt;
}

bool is_root_service_log(std::string_view folded) {
  return folded.find("svc.veeamendpointbackup") != std::string_view::npos ||
         folded.find("svc.veeambackup") != std::string_view::npos ||
         folded.find("veeam.backup.service") != std::string_view::npos ||
         folded.find("mssqlvbrcommunicationmanager") != std::string_view::npos ||
         folded.find("mssqlpluginbackup") != std::string_view::npos ||
         folded.find("rman") != std::string_view::npos;
}

bool path_is_rescan(std::string_view folded);

std::string display_component(std::string value) {
  std::replace(value.begin(), value.end(), '_', ' ');
  return trim_copy(value);
}

std::vector<std::string> evidence_path_components(std::string_view display_path) {
  std::string logical(display_path);
  if (const std::size_t marker = logical.find('!'); marker != std::string::npos)
    logical = logical.substr(marker + 1U);
  std::replace(logical.begin(), logical.end(), '\\', '/');
  std::vector<std::string> components;
  std::size_t begin = 0;
  while (begin < logical.size()) {
    const std::size_t end = logical.find('/', begin);
    std::string value = logical.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
    if (!value.empty())
      components.push_back(std::move(value));
    if (end == std::string::npos)
      break;
    begin = end + 1U;
  }
  return components;
}

std::string evidence_role(std::string_view display_path) {
  switch (classify_veeam_evidence_role(display_path)) {
  case VeeamEvidenceRole::manifest: return "manifest";
  case VeeamEvidenceRole::service: return "service";
  case VeeamEvidenceRole::scheduler: return "scheduler";
  case VeeamEvidenceRole::vaw_management: return "management";
  case VeeamEvidenceRole::job: return "job";
  case VeeamEvidenceRole::task: return "task";
  case VeeamEvidenceRole::protection_group_rescan: return "rescan";
  case VeeamEvidenceRole::source_data_mover: return "data-mover-source";
  case VeeamEvidenceRole::target_data_mover: return "data-mover-target";
  case VeeamEvidenceRole::data_mover_server: return "data-mover-server";
  case VeeamEvidenceRole::data_mover_repair: return "data-mover-repair";
  case VeeamEvidenceRole::data_mover_check: return "data-mover-check";
  case VeeamEvidenceRole::repository_operation: return "repository-operation";
  case VeeamEvidenceRole::rpc_control: return "rpc-control";
  case VeeamEvidenceRole::plugin: return "plugin";
  case VeeamEvidenceRole::setup: return "setup";
  case VeeamEvidenceRole::system: return "system";
  case VeeamEvidenceRole::user_interface: return "user-action";
  case VeeamEvidenceRole::tool_output: return "tool-output";
  case VeeamEvidenceRole::guest_processing: return "guest-processing";
  case VeeamEvidenceRole::sobr_tier: return "sobr-tier";
  case VeeamEvidenceRole::configuration_backup: return "configuration-backup";
  case VeeamEvidenceRole::restore_operation: return "restore-operation";
  case VeeamEvidenceRole::cloud_plugin: return "cloud-plugin";
  case VeeamEvidenceRole::other: return "other";
  }
  return "other";
}

struct EvidenceHints {
  std::string job_name;
  std::string workload_name;
  std::string category;
  bool protection_group_rescan = false;
  std::string protection_group_name;
};

EvidenceHints evidence_hints(VeeamReviewProfile profile, std::string_view display_path) {
  EvidenceHints hints;
  const auto components = evidence_path_components(display_path);
  if (components.empty())
    return hints;
  const std::string role = evidence_role(display_path);
  hints.category = role;

  auto find_component = [&](std::string_view wanted) -> std::optional<std::size_t> {
    for (std::size_t index = 0; index < components.size(); ++index) {
      if (equals_folded(components[index], wanted))
        return index;
    }
    return std::nullopt;
  };

  if (profile == VeeamReviewProfile::vbr || profile == VeeamReviewProfile::automatic) {
    if (const auto backup = find_component("Backup")) {
      const std::size_t base = *backup;
      if (base + 1U < components.size()) {
        const std::string next_folded = ascii_lower(components[base + 1U]);
        if (next_folded == "rescan" && base + 2U < components.size()) {
          hints.category = "rescan";
          hints.protection_group_rescan = true;
          hints.job_name = display_component(components[base + 2U]);
          const std::string prefix = "rescan of ";
          if (ascii_lower(hints.job_name).starts_with(prefix))
            hints.protection_group_name = trim_copy(hints.job_name.substr(prefix.size()));
          else
            hints.protection_group_name = hints.job_name;
          if (base + 3U < components.size()) {
            const std::string candidate = components[base + 3U];
            if (candidate.find('.') == std::string::npos) {
              hints.workload_name = display_component(candidate);
            } else {
              const std::string folded_candidate = ascii_lower(candidate);
              if (folded_candidate.starts_with("task.") && folded_candidate.ends_with(".log")) {
                hints.workload_name = display_component(
                    candidate.substr(5U, candidate.size() - 5U - 4U));
              }
            }
          }
        } else if (next_folded == "system") {
          hints.category = "system";
          hints.job_name = components.back();
          const std::size_t marker = ascii_lower(hints.job_name).find("job.");
          if (marker != std::string::npos)
            hints.job_name = hints.job_name.substr(marker + 4U);
          const std::size_t ext = ascii_lower(hints.job_name).rfind(".log");
          if (ext != std::string::npos)
            hints.job_name.resize(ext);
          hints.job_name = display_component(hints.job_name);
        } else if (next_folded.starts_with("svc.") || next_folded.find("veeambackup") != std::string::npos) {
          hints.category = "service";
        } else if (next_folded == "utils" || next_folded == "resourcescan") {
          hints.category = "system";
        } else if (next_folded == "plugin") {
          hints.category = "plugin";
          std::string action = "Session";
          if (base + 2U < components.size())
            action = display_component(components[base + 2U]);
          std::string server;
          if (base + 4U < components.size())
            server = display_component(components[base + 4U]);
          hints.job_name = "Plug-in " + action + (server.empty() ? std::string{} : " - " + server);
          hints.workload_name = server;
        } else if (next_folded == "endpoint") {
          hints.category = "endpoint";
          if (base + 2U < components.size() && equals_folded(components[base + 2U], "Backup")) {
            hints.category = "endpoint-backup";
            if (components.size() >= base + 5U) {
              hints.job_name = display_component(components[components.size() - 2U]);
              if (components.size() >= base + 6U)
                hints.workload_name = display_component(components[components.size() - 3U]);
            }
          } else if (base + 2U < components.size() && equals_folded(components[base + 2U], "Restore")) {
            hints.category = "restore";
            hints.job_name = "Endpoint Restore";
            if (components.size() >= base + 5U)
              hints.workload_name = display_component(components[components.size() - 2U]);
          }
        } else if (next_folded == "eprecoveryfilesrestore") {
          hints.category = "restore";
          hints.job_name = "Endpoint File Restore";
        } else if (role == "job" || role == "task" || role == "data-mover" ||
                   role == "data-mover-source" || role == "data-mover-target" ||
                   role == "data-mover-server" || role == "data-mover-repair" ||
                   role == "data-mover-check") {
          hints.job_name = display_component(components[base + 1U]);
          hints.category = role;
          if (base + 2U < components.size()) {
            const std::string candidate = components[base + 2U];
            const std::string candidate_folded = ascii_lower(candidate);
            const bool looks_like_file = candidate_folded.ends_with(".log") ||
                                         candidate_folded.ends_with(".txt") ||
                                         candidate_folded.ends_with(".xml") ||
                                         candidate_folded.ends_with(".zip") ||
                                         candidate_folded.ends_with(".arc");
            if (!looks_like_file) {
              hints.workload_name = display_component(candidate);
            } else {
              const std::string file_name = components.back();
              const std::string file_folded = ascii_lower(file_name);
              if (file_folded.starts_with("agent.")) {
                std::string workload = file_name.substr(6U);
                const std::string workload_folded = ascii_lower(workload);
                for (const std::string_view suffix : {".source.log", ".target.log", ".server.log", ".log"}) {
                  if (workload_folded.ends_with(suffix)) {
                    workload.resize(workload.size() - suffix.size());
                    break;
                  }
                }
                hints.workload_name = display_component(workload);
              } else if (file_folded.starts_with("task.") && file_folded.ends_with(".log")) {
                hints.workload_name = display_component(
                    file_name.substr(5U, file_name.size() - 5U - 4U));
              }
            }
          }
        }
      }
    }
  }

  if (profile == VeeamReviewProfile::vaw) {
    if (const auto endpoint = find_component("1-Endpoint")) {
      if (*endpoint + 1U < components.size()) {
        const std::string next = components[*endpoint + 1U];
        const std::string next_folded = ascii_lower(next);
        const bool job_scoped_role = role == "job" || role == "task" || role == "data-mover" ||
                                     role == "data-mover-source" || role == "data-mover-target" ||
                                     role == "data-mover-server" || role == "data-mover-repair" ||
                                     role == "data-mover-check";
        const bool infrastructure_folder = next_folded == "utils" ||
                                           next_folded == "!configuration" ||
                                           next_folded == "flrsessions" ||
                                           next_folded == "setup";
        // A VAW endpoint bundle contains several infrastructure folders under 1-Endpoint
        // (Utils, !Configuration, FLRSessions, and similar support data). Treat a child
        // directory as a job only when the file itself has a job/task/data-mover role.
        // This prevents path-only fast indexing from fabricating jobs such as "Utils".
        if (job_scoped_role && !infrastructure_folder && !next_folded.ends_with(".log") &&
            !next_folded.ends_with(".txt") && !next_folded.ends_with(".xml")) {
          hints.job_name = display_component(next);
          hints.category = "job-evidence";
        }
      }
    }
  }

  if (profile == VeeamReviewProfile::sql_plugin) {
    const std::string file_name = components.back();
    const std::string folded_file = ascii_lower(file_name);
    if (folded_file.starts_with("job.rescan_of_")) {
      hints.category = "rescan";
      hints.protection_group_rescan = true;
      std::string name = file_name.substr(std::string("Job.").size());
      if (const std::size_t ext = ascii_lower(name).rfind(".log"); ext != std::string::npos)
        name.resize(ext);
      hints.job_name = display_component(name);
      const std::string prefix = "rescan of ";
      if (ascii_lower(hints.job_name).starts_with(prefix))
        hints.protection_group_name = trim_copy(hints.job_name.substr(prefix.size()));
    } else if (folded_file.starts_with("job.")) {
      hints.category = "sql-job";
      std::string name = file_name.substr(std::string("Job.").size());
      if (const std::size_t ext = ascii_lower(name).rfind(".log"); ext != std::string::npos)
        name.resize(ext);
      const std::string lowered = ascii_lower(name);
      for (const std::string_view suffix : {".prepare", ".backup", ".restore", ".finalize"}) {
        if (lowered.ends_with(suffix)) {
          name.resize(name.size() - suffix.size());
          break;
        }
      }
      hints.job_name = display_component(name);
    }
  }
  return hints;
}

bool path_is_rescan(std::string_view folded) {
  return folded.find("/rescan/") != std::string_view::npos ||
         folded.find("job.rescan_of_") != std::string_view::npos ||
         folded.find("resource scan") != std::string_view::npos ||
         folded.find("resourcescan/") != std::string_view::npos;
}

constexpr std::size_t kAutomaticFastIndexFallbackFilesPerSource = 16U;

bool automatic_fast_index_fallback_candidate(std::string_view display_path,
                                             std::uint64_t size_bytes,
                                             std::size_t& selected_fallback_files) {
  if (selected_fallback_files >= kAutomaticFastIndexFallbackFilesPerSource)
    return false;

  // Auto Detect must stay responsive on very large bundles, but it also must not
  // fail simply because a small/unfamiliar evidence set has not yet been assigned
  // a known Veeam role. Sample a small number of otherwise-unclassified files.
  // Prefer files that are small enough to be useful for identity/orientation.
  constexpr std::uint64_t kFallbackMaximumBytes = 64ULL * 1024ULL * 1024ULL;
  if (size_bytes > kFallbackMaximumBytes)
    return false;
  if (classify_veeam_evidence_role(display_path) != VeeamEvidenceRole::other)
    return false;

  ++selected_fallback_files;
  return true;
}

bool is_fast_index_candidate(VeeamReviewProfile profile, std::string_view display_path) {
  const std::string folded = folded_path_name(display_path);
  if (folded.find("collection-manifest.json") != std::string::npos)
    return true;
  const VeeamEvidenceRole role = classify_veeam_evidence_role(display_path);

  switch (profile) {
  case VeeamReviewProfile::vaw:
    // Keep the initial pass deliberately small, but include management and scheduler
    // logs because they define managed/standalone behavior and job lifecycle context.
    if (folded.find("1-endpoint/") == std::string::npos &&
        role != VeeamEvidenceRole::service)
      return false;
    return role == VeeamEvidenceRole::service || role == VeeamEvidenceRole::job ||
           role == VeeamEvidenceRole::vaw_management || role == VeeamEvidenceRole::scheduler ||
           role == VeeamEvidenceRole::rpc_control;
  case VeeamReviewProfile::vbr:
    // Root service, scheduler, job/task and Protection Group rescan logs are the
    // high-value index. Source/target movers stay cataloged but deferred until analysis.
    return role == VeeamEvidenceRole::service || role == VeeamEvidenceRole::scheduler ||
           role == VeeamEvidenceRole::job || role == VeeamEvidenceRole::task ||
           role == VeeamEvidenceRole::protection_group_rescan ||
           folded.find("endpoint/svc.veeamendpointbackup.log") != std::string::npos;
  case VeeamReviewProfile::sql_plugin:
    return role == VeeamEvidenceRole::plugin || role == VeeamEvidenceRole::service ||
           role == VeeamEvidenceRole::job || role == VeeamEvidenceRole::task ||
           role == VeeamEvidenceRole::protection_group_rescan;
  case VeeamReviewProfile::rman_plugin:
    return role == VeeamEvidenceRole::plugin || role == VeeamEvidenceRole::service ||
           role == VeeamEvidenceRole::job || role == VeeamEvidenceRole::task;
  // The Backint-family plug-ins (SAP HANA, SAP on Oracle, SAP MaxDB) and Db2 all write their
  // engineer-facing evidence into /tmp/veeam_plugin_logs on the database server, plus the VBR-side
  // plug-in folder. None of them has a scheduler or a Protection Group rescan of its own, so the
  // index is the plug-in/service/job/task set. Db2 and MaxDB are standalone-only: no rescan role
  // is expected for them, and its absence is not evidence of a problem.
  case VeeamReviewProfile::sap_hana_plugin:
  case VeeamReviewProfile::sap_oracle_plugin:
  case VeeamReviewProfile::sap_maxdb_plugin:
  case VeeamReviewProfile::db2_plugin:
    return role == VeeamEvidenceRole::plugin || role == VeeamEvidenceRole::service ||
           role == VeeamEvidenceRole::job || role == VeeamEvidenceRole::task;
  case VeeamReviewProfile::automatic:
    // Auto Detect is an orientation pass, not a request to deep-scan every file.
    // Use the union of high-value identity/orchestration roles so large VBR
    // bundles still get a responsive preliminary index. The detected source
    // profile is persisted per case source and Full Review remains explicit.
    return role == VeeamEvidenceRole::service || role == VeeamEvidenceRole::scheduler ||
           role == VeeamEvidenceRole::job || role == VeeamEvidenceRole::task ||
           role == VeeamEvidenceRole::plugin || role == VeeamEvidenceRole::vaw_management ||
           role == VeeamEvidenceRole::rpc_control ||
           role == VeeamEvidenceRole::protection_group_rescan;
  case VeeamReviewProfile::generic:
    // Generic evidence has no product boundary, so retain the broad index.
    return true;
  }
  return true;
}

std::string normalize_job_hint(std::string value) {
  value = ascii_lower(value);
  for (char& c : value) {
    if (!(std::isalnum(static_cast<unsigned char>(c)) != 0))
      c = '_';
  }
  while (value.find("__") != std::string::npos)
    value.replace(value.find("__"), 2, "_");
  return value;
}

bool path_matches_selected_run(const VeeamLogReviewOptions& options, std::string_view display_path) {
  if (options.selected_run_key.empty() && options.selected_job_name_hint.empty() &&
      options.selected_source_path_hint.empty())
    return true;
  const std::string folded = folded_path_name(display_path);
  if (is_root_service_log(folded))
    return true;
  if (!options.selected_source_path_hint.empty()) {
    const std::string source = folded_path_name(options.selected_source_path_hint);
    const std::string parent = source_parent(source);
    const bool job_scoped_parent = parent.find("/rescan/") != std::string::npos ||
                                   parent.find("/jobs/") != std::string::npos ||
                                   parent.find("/job/") != std::string::npos ||
                                   (parent.find("/backup/") != std::string::npos &&
                                    parent != source_parent(parent));
    if (job_scoped_parent && !parent.empty() && folded.find(parent) != std::string::npos)
      return true;
  }
  if (!options.selected_job_name_hint.empty()) {
    const std::string hint = normalize_job_hint(options.selected_job_name_hint);
    std::string candidate = folded;
    for (char& c : candidate) {
      if (!(std::isalnum(static_cast<unsigned char>(c)) != 0))
        c = '_';
    }
    if (!hint.empty() && candidate.find(hint) != std::string::npos)
      return true;
  }
  return false;
}

Error review_error(std::string operation,
                   std::string message,
                   const std::filesystem::path& source = {}) {
  Error error;
  error.component = "VeeamLogReview";
  error.operation = std::move(operation);
  error.source = path_to_utf8(source);
  error.message = std::move(message);
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

void emit_console(const ReviewConsoleCallback& console, std::string message) {
  if (console)
    console(message);
}

// SAT-D-01: a file-name component is bounded. Log content reaches this function through
// machine display names, so an unbounded result produced report paths past the filesystem
// NAME_MAX and the report create failed with ENAMETOOLONG. Truncation keeps a short stable
// digest so two different long names cannot collide after clamping.
constexpr std::size_t kMaxFileComponent = 64U;

std::string short_stable_digest(std::string_view value) {
  // FNV-1a 64. Not a security primitive: this only disambiguates truncated file names.
  std::uint64_t hash = 1469598103934665603ULL;
  for (const char character : value) {
    hash ^= static_cast<unsigned char>(character);
    hash *= 1099511628211ULL;
  }
  std::string output;
  output.reserve(8U);
  for (int shift = 28; shift >= 0; shift -= 4)
    output.push_back("0123456789abcdef"[(hash >> shift) & 0xFULL]);
  return output;
}

// SAT-D-01: reject machine-name candidates that cannot be a host name. A malformed or
// label-only header line ("MachineName: [...], OS: [...], CPU: [...]") can otherwise yield the
// header's *label sequence* as the machine name, and that becomes the report file name.
// RFC 1035 bounds a host name at 253 characters with 63 per label; real Veeam machine names are
// far shorter. Anything longer, containing whitespace or bracket/punctuation structure, or
// consisting only of known header labels is a parse artefact rather than an identity.
constexpr std::size_t kMaxMachineNameLength = 253U;

bool plausible_machine_name(std::string_view value) {
  std::string_view trimmed = value;
  while (!trimmed.empty() && std::isspace(static_cast<unsigned char>(trimmed.front())) != 0)
    trimmed.remove_prefix(1);
  while (!trimmed.empty() && std::isspace(static_cast<unsigned char>(trimmed.back())) != 0)
    trimmed.remove_suffix(1);
  if (trimmed.empty() || trimmed.size() > kMaxMachineNameLength)
    return false;
  for (const char character : trimmed) {
    const unsigned char code = static_cast<unsigned char>(character);
    if (code < 32U)
      return false;
    if (character == '[' || character == ']' || character == ',' || character == ';' ||
        character == ':' || character == '(' || character == ')' || character == '\\' ||
        character == '/' || character == '"')
      return false;
    if (std::isspace(code) != 0)
      return false;
  }
  static constexpr std::string_view kHeaderLabels[] = {
      "machinename", "hostname", "os", "cpu", "culture", "utctime", "utc_time",
      "fileversion", "file_version", "assemblyversion", "assembly_version",
      "agentlicensemode", "managementmode", "vbrhostname", "interfacetype",
      "description", "osversion", "modulversion", "moduleversion", "privatefix"};
  std::string folded;
  folded.reserve(trimmed.size());
  for (const char character : trimmed) {
    if (character != '_' && character != '-')
      folded.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
  }
  for (const std::string_view label : kHeaderLabels) {
    if (folded == label)
      return false;
  }
  return true;
}

std::string safe_file_component(std::string value) {
  const std::string original = value;
  for (char& character : value) {
    const unsigned char code = static_cast<unsigned char>(character);
    if (!(std::isalnum(code) != 0 || character == '-' || character == '_'))
      character = '_';
  }
  // Collapse runs so a label sequence cannot inflate the component with separators.
  std::string collapsed;
  collapsed.reserve(value.size());
  for (const char character : value) {
    if (character == '_' && !collapsed.empty() && collapsed.back() == '_')
      continue;
    collapsed.push_back(character);
  }
  while (!collapsed.empty() && collapsed.back() == '_')
    collapsed.pop_back();
  while (!collapsed.empty() && collapsed.front() == '_')
    collapsed.erase(collapsed.begin());
  if (collapsed.empty())
    return "UNKNOWN";
  if (collapsed.size() > kMaxFileComponent) {
    collapsed.resize(kMaxFileComponent - 9U);
    while (!collapsed.empty() && collapsed.back() == '_')
      collapsed.pop_back();
    collapsed += "_" + short_stable_digest(original);
  }
  return collapsed;
}

std::string report_stamp() {
  const std::string value = utc_now_iso8601();
  std::string output;
  output.reserve(value.size());
  for (char character : value) {
    if (std::isdigit(static_cast<unsigned char>(character)) != 0)
      output.push_back(character);
  }
  if (output.size() > 14U)
    output.resize(14U);
  return output;
}

bool is_usable_ipv4(std::string_view address) {
  if (address.empty() || address == "127.0.0.1" || address.starts_with("169.254."))
    return false;
  int dots = 0;
  for (char character : address) {
    if (character == '.')
      ++dots;
    else if (std::isdigit(static_cast<unsigned char>(character)) == 0)
      return false;
  }
  return dots == 3;
}

std::vector<std::string> split_semicolon_values(std::string_view text) {
  std::vector<std::string> values;
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t end = text.find(';', start);
    const std::string value = trim_copy(text.substr(
        start, end == std::string_view::npos ? text.size() - start : end - start));
    if (!value.empty())
      values.push_back(value);
    if (end == std::string_view::npos)
      break;
    start = end + 1U;
  }
  return values;
}

std::string strip_log_prefix(std::string_view line, std::string_view folded) {
  // Older VAW Job.Backup.log files use a columnar prefix such as
  // `[20.09.2023 09:04:00] <01> Info     Backup mode: entire computer`
  // without the newer `Info (1)` marker.  Strip that severity column first so
  // settings/lifecycle rules operate on the actual product message.
  const std::size_t thread_end = line.find('>');
  if (thread_end != std::string_view::npos) {
    const std::string tail = trim_copy(line.substr(thread_end + 1U));
    const std::string folded_tail = ascii_lower(tail);
    for (const std::string_view severity : {std::string_view("info"),
                                            std::string_view("warning"),
                                            std::string_view("warn"),
                                            std::string_view("error"),
                                            std::string_view("fatal"),
                                            std::string_view("debug"),
                                            std::string_view("trace")}) {
      if (!folded_tail.starts_with(severity))
        continue;
      if (folded_tail.size() != severity.size() &&
          std::isspace(static_cast<unsigned char>(folded_tail[severity.size()])) == 0)
        continue;
      // Newer structured lines use `Info (1)` / `Error (1)`. Let the
      // existing parenthesized-prefix parser strip those so `(1)` never
      // becomes part of the product message.
      if (folded_tail.size() > severity.size() + 1U &&
          folded_tail[severity.size()] == ' ' &&
          folded_tail[severity.size() + 1U] == '(')
        continue;
      return trim_copy(std::string_view(tail).substr(severity.size()));
    }
  }

  for (const std::string_view severity : {std::string_view("error ("),
                                          std::string_view("warning ("),
                                          std::string_view("info (")}) {
    const std::size_t start = folded.find(severity);
    if (start == std::string::npos)
      continue;
    const std::size_t closing = line.find(')', start + severity.size());
    if (closing != std::string_view::npos)
      return trim_copy(line.substr(closing + 1U));
  }
  const std::size_t pipe = line.find('|');
  if (pipe != std::string_view::npos)
    return trim_copy(line.substr(pipe + 1U));
  return trim_copy(line);
}

// Some bracket tokens name an ACTION or a generic helper, not a Veeam component. The clearest
// example is [TryInvoke], which is Veeam.Backup.Common.FunctionExtensions.TryInvoke - a retry
// wrapper used all over the product. Reporting "TryInvoke" as the component tells an engineer
// nothing and actively misleads: the real component is whatever service owns the log file, and the
// real error is the exception on the following line, not the words "Invocation error".
//
// Treat these as anonymous so the caller falls back to the owning log file for identity and the
// continuation line for the message.
bool is_action_token(std::string_view token) {
  // Allocation-free on purpose: this runs for every log line that carries a [Component] prefix,
  // which is nearly every Veeam message line. Lowering and trimming into std::string and looking
  // the result up in a std::set<std::string> costs two allocations plus a string-compare tree
  // walk per line - not affordable in the parser hot path.
  while (!token.empty() && (token.front() == ' ' || token.front() == '\t')) token.remove_prefix(1);
  while (!token.empty() && (token.back() == ' ' || token.back() == '\t')) token.remove_suffix(1);
  if (token.empty() || token.size() > 10U) return false;
  static constexpr std::string_view kActionTokens[]{
      "tryinvoke", "invoke", "retry", "trycatch", "execute", "run", "call", "action", "task"};
  for (std::string_view candidate : kActionTokens) {
    if (candidate.size() != token.size()) continue;
    bool equal = true;
    for (std::size_t i = 0; i < token.size(); ++i) {
      const auto c = static_cast<unsigned char>(token[i]);
      if (static_cast<char>(std::tolower(c)) != candidate[i]) { equal = false; break; }
    }
    if (equal) return true;
  }
  return false;
}

// True when an action-wrapper message carries no actual error text - "[TryInvoke] Invocation
// error;" says only that a retry helper threw, which tells an engineer nothing. The real error is
// the exception on the following line.
bool is_placeholder_action_message(std::string_view message) {
  const std::size_t close = message.find(']');
  if (close == std::string_view::npos) return false;
  std::string_view rest = message.substr(close + 1U);
  while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) rest.remove_prefix(1);
  while (!rest.empty() && (rest.back() == ' ' || rest.back() == '\t' || rest.back() == ';' ||
                           rest.back() == '.' || rest.back() == '\r')) rest.remove_suffix(1);
  if (rest.size() > 40U) return false;
  const std::string folded = ascii_lower(rest);
  return folded == "invocation error" || folded == "error" || folded == "exception" ||
         folded == "failed" || folded == "invocation failed" || folded == "operation failed";
}

std::string extract_component(std::string_view message) {
  if (!message.starts_with("["))
    return {};
  const std::size_t end = message.find(']');
  if (end == std::string_view::npos || end > 96U)
    return {};
  std::string token(message.substr(1, end - 1U));
  if (is_action_token(token))
    return {};
  return token;
}

// True only when the line carried a bracket token that names an action rather than a component.
// Distinguishing this from "no bracket token at all" matters: a line with no token has always had
// an empty component and grouping depends on that, so only the action case gets a substitute.
bool has_action_token_prefix(std::string_view message) {
  if (!message.starts_with("["))
    return false;
  const std::size_t end = message.find(']');
  if (end == std::string_view::npos || end > 96U)
    return false;
  return is_action_token(message.substr(1, end - 1U));
}

// Derives a component name from the log file that produced the line, used when the line itself
// carries no usable component token. Svc.PublicCloudInstanceActualizer.log ->
// "PublicCloudInstanceActualizer", which is both true and useful, where "TryInvoke" was neither.
std::string component_from_source_file(std::string_view source_path) {
  std::string leaf(source_path);
  if (const std::size_t slash = leaf.find_last_of("/\\"); slash != std::string::npos)
    leaf = leaf.substr(slash + 1U);
  if (const std::size_t bang = leaf.find_last_of('!'); bang != std::string::npos)
    leaf = leaf.substr(bang + 1U);
  // Strip a trailing extension and any rotation index (Job.Backup.3.log -> Job.Backup).
  while (true) {
    const std::size_t dot = leaf.find_last_of('.');
    if (dot == std::string::npos) break;
    const std::string tail = ascii_lower(leaf.substr(dot + 1U));
    const bool numeric = !tail.empty() &&
                         std::all_of(tail.begin(), tail.end(),
                                     [](unsigned char c) { return std::isdigit(c) != 0; });
    if (tail == "log" || tail == "txt" || numeric) {
      leaf = leaf.substr(0, dot);
      continue;
    }
    break;
  }
  // UI.Tray-Willow is the tray log for one signed-in user. The account name is a rotation suffix,
  // not part of the component, and leaving it in splits the same component per user.
  if (ascii_lower(leaf).starts_with("ui.tray")) {
    if (const std::size_t dash = leaf.find('-'); dash != std::string::npos)
      leaf = leaf.substr(0, dash);
  }
  // Drop the Veeam file-role prefix so the component reads as the component, not the file.
  for (std::string_view prefix : {"svc.", "job.", "task.", "agent.", "util."}) {
    if (ascii_lower(leaf).starts_with(prefix)) {
      leaf = leaf.substr(prefix.size());
      break;
    }
  }
  return trim_copy(leaf);
}

// Names an untagged line by the Veeam log family that owns it, and ONLY when the file name is a
// recognised family. "Unable to open page." carries no [Component] token but comes out of
// UI.Tray-<user>.log, so it is the tray UI reporting it, not the backup job.
//
// Deliberately not "derive a component from whatever the file is called": that splits one finding
// into one group per file, so the same "WARN|Input TCP stream was closed" appearing in several
// agent logs stops merging and the occurrence counts fragment. Grouping is keyed on the component,
// so anything returned here must be stable across every file that legitimately shares a signature
// - which rotation indices and per-user suffixes are already stripped to achieve.
std::string component_from_known_log_family(std::string_view source_path) {
  std::string leaf(source_path);
  if (const std::size_t slash = leaf.find_last_of("/\\"); slash != std::string::npos)
    leaf = leaf.substr(slash + 1U);
  if (const std::size_t bang = leaf.find_last_of('!'); bang != std::string::npos)
    leaf = leaf.substr(bang + 1U);
  const std::string folded = ascii_lower(leaf);
  static constexpr std::array<std::string_view, 4> kFamilies{"ui.tray", "ui.", "svc.", "veeam.endpoint."};
  if (std::none_of(kFamilies.begin(), kFamilies.end(),
                   [&](std::string_view family) { return folded.starts_with(family); }))
    return {};
  return component_from_source_file(source_path);
}

bool is_stack_continuation(std::string_view message) {
  std::string trimmed = trim_copy(message);
  // Many Veeam components prefix every physical log line with [Component].
  // Treat that prefix as metadata when deciding whether the line is a stack
  // continuation; otherwise "[DataMover] at ..." becomes a second incident.
  if (trimmed.starts_with("[")) {
    const std::size_t close = trimmed.find(']');
    if (close != std::string::npos && close <= 96U)
      trimmed = trim_copy(std::string_view(trimmed).substr(close + 1U));
  }
  const std::string folded = ascii_lower(trimmed);
  return folded.starts_with("at ") || folded.starts_with("---") ||
         folded.starts_with("--->") || folded.starts_with("caused by") ||
         folded.starts_with("inner exception") ||
         folded.starts_with("exception rethrown at") ||
         folded.starts_with("status(") || folded.starts_with("system.") ||
         folded.starts_with("microsoft.") || folded.starts_with("grpc.") ||
         folded.starts_with("veeam.");
}

// Some VBR PostgreSQL failures log the SQL script body with the same structured
// Error prefix as the real exception. Those lines are diagnostic payload, not
// thousands of independent incidents. Keep this deliberately syntax-oriented:
// human-readable PGSQL failures still become root events.
bool is_pgsql_diagnostic_payload(std::string_view message) {
  std::string trimmed = trim_copy(message);
  if (trimmed.starts_with("[")) {
    const std::size_t close = trimmed.find(']');
    if (close != std::string::npos)
      trimmed = trim_copy(std::string_view(trimmed).substr(close + 1U));
  }
  if (trimmed.empty())
    return false;
  const std::string folded = ascii_lower(trimmed);

  // Strong exception/failure text is always a root event, even when it contains
  // SQL vocabulary. PostgreSQL SQLSTATE values are five alphanumeric characters.
  const bool sqlstate = folded.size() >= 6U &&
                        std::isalnum(static_cast<unsigned char>(folded[0])) != 0 &&
                        std::isalnum(static_cast<unsigned char>(folded[1])) != 0 &&
                        std::isalnum(static_cast<unsigned char>(folded[2])) != 0 &&
                        std::isalnum(static_cast<unsigned char>(folded[3])) != 0 &&
                        std::isalnum(static_cast<unsigned char>(folded[4])) != 0 &&
                        folded[5] == ':';
  if (sqlstate || folded.starts_with("failed ") || folded.starts_with("failure ") ||
      folded.starts_with("error ") || folded.starts_with("error:") ||
      folded.starts_with("unable ") || folded.starts_with("cannot ") ||
      folded.starts_with("could not ") || folded.find("exception") != std::string::npos ||
      folded.find("database error:") != std::string::npos)
    return false;

  if (folded.starts_with(",") || folded.starts_with("(") || folded.starts_with(")") ||
      folded.starts_with("$$") || folded.starts_with("--"))
    return true;

  const auto starts_with_sql_keyword = [&folded](std::string_view keyword) {
    if (!folded.starts_with(keyword))
      return false;
    if (folded.size() == keyword.size())
      return true;
    const char next = folded[keyword.size()];
    return std::isspace(static_cast<unsigned char>(next)) != 0 || next == '(' || next == ';' ||
           next == ',' || next == ':';
  };
  constexpr std::string_view kSqlKeywords[]{
      "select", "from", "where", "and", "or", "join", "inner join",
      "left join", "right join", "cross join", "full join", "on", "as",
      "begin", "end", "declare", "returns", "return", "create", "drop",
      "alter", "insert", "update", "delete", "perform", "foreach",
      "loop", "if", "then", "else", "elsif", "with", "case", "when",
      "language", "lock", "execute", "raise", "exception", "values",
      "set", "into", "using", "grant", "revoke", "truncate", "union",
      "having", "group by", "order by", "limit", "offset"};
  for (const auto keyword : kSqlKeywords) {
    if (starts_with_sql_keyword(keyword))
      return true;
  }
  if (folded.starts_with("_"))
    return true;
  // Quoted identifiers and statement terminators are common in emitted script
  // bodies but uncommon as standalone support-facing exception summaries.
  return folded.starts_with("\"") || folded.ends_with(';');
}

ParsedLogPrefix parse_log_prefix(std::string_view line,
                                 std::string_view folded,
                                 DateOrder date_order,
                                 int assumed_offset_minutes) {
  ParsedLogPrefix result;
  const auto timestamp = parse_timestamp(line, date_order, assumed_offset_minutes);
  if (timestamp) {
    result.timestamp_original = timestamp->original_text;
    result.timestamp_utc_ms = timestamp->unix_millis;
  }

  const std::size_t error_marker = folded.find("error (");
  const std::size_t warning_marker = folded.find("warning (");
  const std::size_t info_marker = folded.find("info (");
  if (error_marker != std::string::npos) {
    result.severity = "error";
    result.has_structured_prefix = true;
  } else if (warning_marker != std::string::npos || folded.find("warn|") != std::string::npos) {
    result.severity = "warning";
    result.has_structured_prefix = true;
  } else if (info_marker != std::string::npos || folded.find("info|") != std::string::npos) {
    result.severity = "information";
    result.has_structured_prefix = true;
  } else if (folded.find("fatal|") != std::string::npos || folded.find("error|") != std::string::npos ||
             folded.find(" err|") != std::string::npos ||
             // The C++ plug-in/agent format pads the severity column to four characters: an
             // error is "| ERR |" and a warning is "| WARN|". Match the padded form - matching
             // only " err|" misses every ERR line in this format.
             // WARN and INFO need no padded variant - they are already four characters.
             folded.find(" err |") != std::string::npos) {
    result.severity = "error";
    result.has_structured_prefix = true;
  }

  // Recognize the legacy columnar severity that follows the thread marker.
  // Do this only at the structured prefix boundary so words such as "error"
  // inside an informational message do not change severity.
  const std::size_t legacy_thread_end = line.find('>');
  if (legacy_thread_end != std::string_view::npos) {
    const std::string tail = trim_copy(line.substr(legacy_thread_end + 1U));
    const std::string folded_tail = ascii_lower(tail);
    const auto starts_token = [&](std::string_view token) {
      return folded_tail.starts_with(token) &&
             (folded_tail.size() == token.size() ||
              std::isspace(static_cast<unsigned char>(folded_tail[token.size()])) != 0);
    };
    if (starts_token("error") || starts_token("fatal")) {
      result.severity = "error";
      result.has_structured_prefix = true;
    } else if (starts_token("warning") || starts_token("warn")) {
      result.severity = "warning";
      result.has_structured_prefix = true;
    } else if (starts_token("info") || starts_token("debug") || starts_token("trace")) {
      result.severity = "information";
      result.has_structured_prefix = true;
    }
  }

  const std::size_t thread_begin = line.find('<');
  const std::size_t thread_end =
      thread_begin == std::string_view::npos ? std::string_view::npos : line.find('>', thread_begin);
  if (thread_begin != std::string_view::npos && thread_end != std::string_view::npos)
    result.thread = trim_copy(line.substr(thread_begin + 1U, thread_end - thread_begin - 1U));

  result.message = strip_log_prefix(line, folded);
  return result;
}

bool in_date_range(const VeeamLogReviewOptions& options,
                   const std::optional<std::int64_t>& timestamp) {
  if (!options.from_utc_ms && !options.to_utc_ms)
    return true;
  if (!timestamp)
    return false;
  if (options.from_utc_ms && *timestamp < *options.from_utc_ms)
    return false;
  if (options.to_utc_ms && *timestamp > *options.to_utc_ms)
    return false;
  return true;
}

bool looks_like_guid(std::string_view value) {
  const std::string cleaned = trim_copy(value);
  if (cleaned.size() != 32U && cleaned.size() != 36U)
    return false;
  std::size_t hexadecimal = 0;
  std::size_t dashes = 0;
  for (char character : cleaned) {
    if (character == '-') {
      ++dashes;
      continue;
    }
    if (std::isxdigit(static_cast<unsigned char>(character)) == 0)
      return false;
    ++hexadecimal;
  }
  return hexadecimal == 32U && (dashes == 0U || dashes == 4U);
}

std::string normalize_signature(std::string_view input) {
  std::string output;
  output.reserve(std::min<std::size_t>(input.size(), 320U));
  bool in_number = false;
  for (std::size_t index = 0; index < input.size() && output.size() < 320U;) {
    const char original = input[index];
    if (original == '{' || original == '[') {
      const char closing = original == '{' ? '}' : ']';
      const std::size_t end = input.find(closing, index + 1U);
      if (end != std::string_view::npos) {
        const std::string_view value = input.substr(index + 1U, end - index - 1U);
        output.push_back(original);
        if (looks_like_guid(value)) {
          output += "id";
        } else {
          for (char character : value) {
            if (output.size() >= 319U)
              break;
            output.push_back(static_cast<char>(
                std::tolower(static_cast<unsigned char>(character))));
          }
        }
        output.push_back(closing);
        index = end + 1U;
        in_number = false;
        continue;
      }
    }

    const char character = static_cast<char>(
        std::tolower(static_cast<unsigned char>(original)));
    ++index;
    if (std::isdigit(static_cast<unsigned char>(character)) != 0) {
      if (!in_number)
        output.push_back('#');
      in_number = true;
      continue;
    }
    in_number = false;
    if (std::isspace(static_cast<unsigned char>(character)) != 0) {
      if (!output.empty() && output.back() != ' ')
        output.push_back(' ');
    } else {
      output.push_back(character);
    }
  }
  return trim_copy(output);
}

void set_evidence(std::optional<ReviewEvidence>& destination,
                  std::string value,
                  const ReviewInputFile& file,
                  const ReviewLine& line,
                  ParserConfidence confidence,
                  bool replace_unconfirmed = true) {
  if (value.empty())
    return;
  if (destination) {
    const int existing_rank = static_cast<int>(destination->confidence);
    const int new_rank = static_cast<int>(confidence);
    const bool replacing_unconfirmed =
        replace_unconfirmed && destination->confidence == ParserConfidence::unconfirmed;
    if (!replacing_unconfirmed && new_rank >= existing_rank)
      return;
  }
  destination = ReviewEvidence{std::move(value),
                               file.display_path,
                               file.materialized_path,
                               line.line_number,
                               confidence,
                               line.text};
}

void add_unique_evidence(std::vector<ReviewEvidence>& destination,
                         std::string value,
                         const ReviewInputFile& file,
                         const ReviewLine& line,
                         ParserConfidence confidence) {
  if (value.empty())
    return;
  const auto duplicate = std::find_if(destination.begin(), destination.end(), [&](const auto& item) {
    return equals_folded(item.value, value);
  });
  if (duplicate == destination.end()) {
    destination.push_back(ReviewEvidence{std::move(value),
                                         file.display_path,
                                         file.materialized_path,
                                         line.line_number,
                                         confidence,
                                         line.text});
  }
}

std::optional<std::string> bracket_value_after(std::string_view line, std::string_view marker) {
  const std::size_t marker_position = line.find(marker);
  if (marker_position == std::string_view::npos)
    return std::nullopt;
  const std::size_t opening = line.find('[', marker_position + marker.size());
  if (opening == std::string_view::npos)
    return std::nullopt;
  const std::size_t closing = line.find(']', opening + 1U);
  if (closing == std::string_view::npos)
    return std::nullopt;
  return std::string(line.substr(opening + 1U, closing - opening - 1U));
}

void set_product_type(VeeamLogReviewResult& review,
                      std::string value,
                      ParserConfidence confidence) {
  const auto rank = [](ParserConfidence item) {
    switch (item) {
    case ParserConfidence::verified:
      return 3;
    case ParserConfidence::probable:
      return 2;
    case ParserConfidence::unconfirmed:
      return 1;
    }
    return 0;
  };
  if (rank(confidence) >= rank(review.product_confidence)) {
    review.product_type = std::move(value);
    review.product_confidence = confidence;
  }
}

void parse_machine_metadata(VeeamLogReviewResult& review,
                            FileParseState& state,
                            const ReviewInputFile& file,
                            const ReviewLine& line,
                            std::string_view folded,
                            std::string_view path_folded,
                            VeeamReviewProfile profile) {
  const std::string_view text = line.text;

  // A VAW review may intentionally include VBR/repository logs for related
  // control-plane context. Those infrastructure logs must never overwrite the
  // endpoint identity shown for the Agent machine. Only strong VAW endpoint
  // paths (or the VAW collection manifest itself) are identity authorities.
  if (profile == VeeamReviewProfile::vaw && !is_vaw_endpoint_identity_path(path_folded))
    return;

  if (path_folded.find("collection-manifest.json") != std::string_view::npos) {
    if (const auto value = between(text, "\"collector_machine\": \"", "\""); value && plausible_machine_name(*value)) {
      set_evidence(review.machine.machine_name, *value, file, line, ParserConfidence::verified);
      set_evidence(review.machine.host_name, *value, file, line, ParserConfidence::verified);
    }
    if (const auto value = between(text, "\"profile\": \"", "\"")) {
      if (profile == VeeamReviewProfile::automatic) {
        const auto parsed = parse_veeam_review_profile(*value);
        if (parsed.ok() && parsed.value() != VeeamReviewProfile::generic &&
            parsed.value() != VeeamReviewProfile::automatic) {
          set_product_type(review, expected_product_type(parsed.value()), ParserConfidence::verified);
        }
      }
    }
  }
  if (profile == VeeamReviewProfile::automatic || profile == VeeamReviewProfile::generic) {
    // Product-specific root/service markers outrank generic words such as "agent", which also
    // appear in VBR data-mover logs. This prevents VBR bundles from being misclassified as VAW.
    // VBR evidence is split by STRENGTH, not by whether the words appear anywhere.
    //
    // A PATH is structural: Svc.VeeamBackup*.log, VeeamBackupManager*.log and the Backup\Rescan
    // tree exist only where the backup server itself runs. LINE CONTENT is not: a managed agent
    // names its backup server constantly - "The following repositories have been loaded from Veeam
    // Backup & Replication", "Cannot connect to a backup server ... contact your Veeam Backup &
    // Replication administrator". Rating that mention as verified would turn every managed VAW
    // bundle into a VBR server once product precedence decides ties between path and line-content
    // evidence. Mentioning VBR is not being VBR.
    const bool vbr_installed_here =
        path_folded.find("svc.veeambackup") != std::string::npos ||
        path_folded.find("veeambackupmanager") != std::string::npos ||
        path_folded.find("/backup/rescan/") != std::string::npos;
    const bool vbr_mentioned_only =
        folded.find("veeam backup & replication") != std::string::npos ||
        folded.find("veeam.backup.service") != std::string::npos;
    if (vbr_installed_here || vbr_mentioned_only) {
      set_product_type(review, "Veeam Backup & Replication",
                       vbr_installed_here ? ParserConfidence::verified
                                          : ParserConfidence::probable);
    } else if (folded.find("mssqlplugin") != std::string::npos ||
               path_folded.find("mssqlplugin") != std::string::npos ||
               path_folded.find("mssqlrecoverymanager") != std::string::npos) {
      const bool dedicated_sql_bundle =
          path_folded.find("/1-mssqlpluginlogs/") != std::string::npos ||
          path_folded.find("\\1-mssqlpluginlogs\\") != std::string::npos;
      set_product_type(review,
                       "Veeam Plug-in for Microsoft SQL Server",
                       dedicated_sql_bundle ? ParserConfidence::verified
                                            : ParserConfidence::probable);
    } else if (folded.find("rmanplugin") != std::string::npos ||
               path_folded.find("rmanplugin") != std::string::npos) {
      const bool dedicated_rman_bundle =
          path_folded.find("/1-rmanpluginlogs/") != std::string::npos ||
          path_folded.find("/rmanpluginlogs/") != std::string::npos;
      set_product_type(review, "Veeam Plug-in for Oracle RMAN",
                       dedicated_rman_bundle ? ParserConfidence::verified
                                             : ParserConfidence::probable);
    } else if (folded.find("veeam agent for linux") != std::string::npos) {
      set_product_type(review, "Veeam Agent for Linux", ParserConfidence::verified);
    } else if (folded.find("veeam agent for mac") != std::string::npos) {
      set_product_type(review, "Veeam Agent for Mac", ParserConfidence::verified);
    } else if (folded.find("veeam agent for ibm aix") != std::string::npos ||
               folded.find("veeam agent for aix") != std::string::npos) {
      set_product_type(review, "Veeam Agent for IBM AIX", ParserConfidence::verified);
    } else if (folded.find("veeam agent for oracle solaris") != std::string::npos ||
               folded.find("veeam agent for solaris") != std::string::npos) {
      set_product_type(review, "Veeam Agent for Oracle Solaris", ParserConfidence::verified);
    } else if (folded.find("veeam agent for microsoft windows") != std::string::npos ||
               folded.find("endpoint backup") != std::string::npos ||
               path_folded.find("/1-endpoint/") != std::string::npos ||
               path_folded.find("svc.veeamendpointbackup") != std::string::npos) {
      const bool dedicated_vaw_context =
          path_folded.find("/1-endpoint/") != std::string::npos ||
          path_folded.find("svc.veeamendpointbackup") != std::string::npos ||
          path_folded.find("vaw_vmc") != std::string::npos;
      set_product_type(review,
                       "Veeam Agent for Microsoft Windows",
                       dedicated_vaw_context ? ParserConfidence::verified
                                             : ParserConfidence::probable);
    }
  }
  if (text.find("MachineName: [") != std::string_view::npos) {
    if (const auto value = bracket_value_after(text, "MachineName:"); value && plausible_machine_name(*value))
      set_evidence(review.machine.machine_name, *value, file, line, ParserConfidence::verified);
    if (const auto value = bracket_value_after(text, "HostName:"); value && plausible_machine_name(*value))
      set_evidence(review.machine.host_name, *value, file, line, ParserConfidence::verified);
    if (const auto value = bracket_value_after(text, "OS:"))
      set_evidence(review.machine.operating_system, *value, file, line, ParserConfidence::verified);
    if (const auto value = bracket_value_after(text, "CPU:"))
      set_evidence(
          review.machine.cpu_logical_processors, *value, file, line, ParserConfidence::verified);
  }
  if (text.find("File version: [") != std::string_view::npos) {
    if (const auto value = bracket_value_after(text, "File version:"))
      set_evidence(review.machine.product_version, *value, file, line, ParserConfidence::verified);
    if (const auto value = bracket_value_after(text, "Assembly version:"))
      set_evidence(review.machine.assembly_version, *value, file, line, ParserConfidence::verified);
  }
  if (contains_folded(text, "private fix was not detected"))
    set_evidence(review.machine.private_fix, "Not detected", file, line, ParserConfidence::verified);
  if (text.starts_with("UTC Time:"))
    set_evidence(review.machine.utc_time,
                 trim_copy(text.substr(std::string_view("UTC Time:").size())),
                 file,
                 line,
                 ParserConfidence::verified);
  if (text.starts_with("Culture:")) {
    const auto value = after(text, "Culture:");
    if (value)
      set_evidence(review.machine.culture, *value, file, line, ParserConfidence::verified);
  }
  const VeeamEvidenceRole management_role = classify_veeam_evidence_role(file.display_path);
  const bool authoritative_vaw_management = management_role == VeeamEvidenceRole::vaw_management;
  const std::string management_path = folded_path_name(file.display_path);
  const bool plugin_management_channel =
      management_role == VeeamEvidenceRole::plugin ||
      (management_role == VeeamEvidenceRole::service &&
       (management_path.find("mssql") != std::string::npos ||
        management_path.find("sqlplugin") != std::string::npos) &&
       management_path.find("vbrcommunicationmanager") != std::string::npos);
  if (authoritative_vaw_management && contains_folded(text, "client works in standalone mode"))
    set_evidence(
        review.machine.management_mode, "Standalone", file, line, ParserConfidence::verified);
  if (authoritative_vaw_management) {
    if (const std::size_t marker = folded.find("managementmode:");
        marker != std::string_view::npos) {
      const std::size_t value_begin = marker + std::string_view("managementmode:").size();
      set_evidence(review.machine.management_mode,
                   trim_copy(text.substr(value_begin)),
                   file,
                   line,
                   ParserConfidence::verified);
    }
  }
  // VAW management state is authoritative only in VMC evidence. Plug-in control
  // logs may still identify the VBR host they communicate with; that relationship
  // is management-server metadata, not a VAW management-mode assertion.
  if (authoritative_vaw_management || plugin_management_channel) {
    if (contains_folded(text, "vbrhostname:")) {
      if (const auto value = after(text, "vbrHostName:"))
        set_evidence(review.machine.management_server, *value, file, line, ParserConfidence::verified);
    }
    if (contains_folded(text, "connected to vbr [")) {
      if (const auto value = between(text, "Connected to VBR [", ":"))
        set_evidence(review.machine.management_server, *value, file, line, ParserConfidence::verified);
    }
  }
  if (contains_folded(text, "module version:")) {
    if (const auto value = after(text, "Module version:"))
      set_evidence(review.machine.product_version, *value, file, line, ParserConfidence::probable);
  }
  if (const auto mode = between(text, "<AgentLicenseMode>", "</AgentLicenseMode>"))
    add_unique_evidence(review.machine.license_modes, *mode, file, line, ParserConfidence::probable);
  if (text.find("AgentLicenseMode: ") != std::string_view::npos) {
    if (const auto mode = after(text, "AgentLicenseMode:"))
      add_unique_evidence(review.machine.license_modes, *mode, file, line, ParserConfidence::probable);
  }
  if (contains_folded(text, "os version:")) {
    if (const auto value = after(text, "OS version:"))
      set_evidence(review.machine.operating_system, *value, file, line, ParserConfidence::probable);
  }
  if (contains_folded(text, "iscurrent=true") && text.find("Version=") != std::string_view::npos) {
    const std::size_t start = text.find("Version=") + 8U;
    const std::size_t end = text.find_first_of(" ,)", start);
    set_evidence(review.machine.product_version,
                 std::string(text.substr(start, end == std::string_view::npos ? text.size() - start
                                                                             : end - start)),
                 file,
                 line,
                 ParserConfidence::probable);
  }

  if (text.starts_with("Network Interface, Name:")) {
    state.active_network_name.clear();
    state.active_network_description.clear();
    state.active_network_up = contains_folded(text, "Operational Status: Up");
    state.active_network_loopback = contains_folded(text, "Interface Type: Loopback");
    const auto name = between(text, "Name: ", ", Description:");
    const auto description = between(text, "Description: ", ", Interface Type:");
    if (name)
      state.active_network_name = *name;
    if (description)
      state.active_network_description = *description;
  } else if (text.find("Unicast IPAddresses:") != std::string_view::npos) {
    const auto values = split_semicolon_values(text.substr(text.find(':') + 1U));
    for (const auto& value : values) {
      if (is_usable_ipv4(value)) {
        add_unique_evidence(review.machine.alternate_ip_addresses,
                            value,
                            file,
                            line,
                            state.active_network_up && !state.active_network_loopback
                                ? ParserConfidence::verified
                                : ParserConfidence::probable);
        if (state.active_network_up && !state.active_network_loopback) {
          set_evidence(review.machine.primary_ip, value, file, line, ParserConfidence::verified);
        }
      }
    }
  } else {
    const std::string trimmed = trim_copy(text);
    if (trimmed.starts_with(":>")) {
      const std::string endpoint = trim_copy(trimmed.substr(2U));
      const std::size_t colon = endpoint.rfind(':');
      const std::string address = colon == std::string::npos ? endpoint : endpoint.substr(0, colon);
      if (is_usable_ipv4(address)) {
        add_unique_evidence(
            review.machine.alternate_ip_addresses, address, file, line, ParserConfidence::probable);
        set_evidence(review.machine.primary_ip, address, file, line, ParserConfidence::probable);
      }
    }
  }
}

std::string quoted_value(std::string_view text, std::string_view marker) {
  const std::size_t start = text.find(marker);
  if (start == std::string_view::npos)
    return {};
  const std::size_t quote = text.find('\'', start + marker.size());
  if (quote == std::string_view::npos)
    return {};
  const std::size_t end = text.find('\'', quote + 1U);
  if (end == std::string_view::npos)
    return {};
  return std::string(text.substr(quote + 1U, end - quote - 1U));
}

std::string bracketed_value(std::string_view text, std::string_view marker) {
  const auto value = bracket_value_after(text, marker);
  return value.value_or(std::string{});
}

void parse_job_settings_line(VeeamJobSettings& settings,
                             FileParseState& state,
                             const ReviewInputFile& file,
                             const ReviewLine& line,
                             const ParsedLogPrefix& prefix) {
  const std::string message = prefix.message;
  const std::string folded = ascii_lower(message);

  const auto begin_settings_capture = [&]() {
    state.in_job_settings = true;
    state.capture_job_settings_lines = false;
    state.reading_included_items = false;
    state.reading_excluded_items = false;
    state.reading_job_command_line = false;
  };
  const auto finish_settings_capture = [&]() {
    state.in_job_settings = false;
    state.capture_job_settings_lines = false;
    state.reading_included_items = false;
    state.reading_excluded_items = false;
    state.reading_job_command_line = false;
  };
  const auto remember_settings_line = [&]() {
    if (!state.capture_job_settings_lines)
      return;
    if (settings.settings_lines.size() < 128U)
      settings.settings_lines.push_back(line.text);
    settings.settings_end_line = line.line_number;
  };

  // VAW 6.x/13.x samples use both a simple "Job Settings" marker and the
  // older explicit begin/end marker.  Keep the source block itself so the
  // Case Dashboard and #note can show what the product actually logged.
  if (folded == "job settings" || folded.find("job settings begin") != std::string::npos) {
    begin_settings_capture();
    return;
  }
  if (folded.find("job settings end") != std::string::npos) {
    finish_settings_capture();
    return;
  }

  if (state.in_job_settings && folded.starts_with("general ")) {
    state.capture_job_settings_lines = true;
    settings.settings_lines.clear();
    settings.settings_source_path = file.display_path;
    settings.settings_materialized_path = file.materialized_path;
    settings.settings_start_line = line.line_number;
    settings.settings_end_line = line.line_number;
  }
  remember_settings_line();

  if (folded.starts_with("backup job description:")) {
    settings.job_description =
        trim_copy(message.substr(std::string("Backup job description:").size()));
  } else if (folded.starts_with("backup mode:")) {
    settings.backup_mode = trim_copy(message.substr(std::string("Backup mode:").size()));
    state.reading_included_items = false;
    state.reading_excluded_items = false;
  } else if (folded == "included items:") {
    state.reading_included_items = true;
    state.reading_excluded_items = false;
  } else if (folded == "excluded items:") {
    state.reading_excluded_items = true;
    state.reading_included_items = false;
  } else if (folded.starts_with("destination ") || folded.starts_with("source ") ||
             folded.starts_with("general ") || folded.starts_with("schedule ") ||
             folded.starts_with("backup cache ") || folded.starts_with("guest processing ")) {
    state.reading_included_items = false;
    state.reading_excluded_items = false;
  } else if (folded == "veeam agent for microsoft windows repository") {
    settings.destination_type = "Veeam Agent for Microsoft Windows repository";
  } else if (folded.starts_with("local folder:")) {
    settings.destination_type = "Local folder";
    settings.destination_path = trim_copy(message.substr(std::string("Local folder:").size()));
    state.reading_included_items = false;
    state.reading_excluded_items = false;
  } else if (folded.starts_with("shared folder:")) {
    settings.destination_type = "Shared folder";
    settings.destination_path = trim_copy(message.substr(std::string("Shared folder:").size()));
  } else if (folded.starts_with("backup server:")) {
    settings.backup_server = trim_copy(message.substr(std::string("Backup server:").size()));
  } else if (folded.starts_with("backup repository:")) {
    settings.backup_repository =
        trim_copy(message.substr(std::string("Backup repository:").size()));
    // The display repository is authoritative for a support note.  Keep the
    // internal path/ID evidence elsewhere; do not let it overwrite this value.
    if (settings.destination_path.empty())
      settings.destination_path = settings.backup_repository;
    if (settings.destination_type.empty())
      settings.destination_type = "Backup repository";
  } else if (folded.starts_with("keep restore points")) {
    settings.retention = message;
  } else if (folded.starts_with("retention days:")) {
    settings.retention = "Retention days: " +
                         trim_copy(message.substr(std::string("Retention days:").size()));
  } else if (folded.starts_with("compression level:")) {
    settings.compression = trim_copy(message.substr(std::string("Compression level:").size()));
  } else if (folded.starts_with("storage optimization:")) {
    settings.storage_optimization =
        trim_copy(message.substr(std::string("Storage optimization:").size()));
  } else if (folded.starts_with("storage encryption:")) {
    settings.encryption = trim_copy(message.substr(std::string("Storage encryption:").size()));
  } else if (folded.starts_with("gfs:")) {
    settings.gfs = trim_copy(message.substr(std::string("GFS:").size()));
  } else if (folded.starts_with("backup cache is ")) {
    settings.backup_cache = trim_copy(message.substr(std::string("Backup cache is ").size()));
  } else if (folded.starts_with("application-aware processing:")) {
    settings.application_processing =
        trim_copy(message.substr(std::string("Application-aware processing:").size()));
  } else if (folded.starts_with("guest file system indexing:")) {
    settings.guest_indexing =
        trim_copy(message.substr(std::string("Guest file system indexing:").size()));
  } else if (folded.starts_with("script processing:")) {
    settings.script_processing =
        trim_copy(message.substr(std::string("Script processing:").size()));
  } else if (folded.starts_with("command line to start the job:")) {
    state.reading_job_command_line = true;
  } else if (state.reading_job_command_line && !message.empty()) {
    settings.command_line = message;
    state.reading_job_command_line = false;
  } else if (folded.starts_with("backup is not scheduled")) {
    settings.schedule = "Manual; automatic scheduling disabled";
  } else if (folded.starts_with("created by ")) {
    const std::size_t at = folded.rfind(" at ");
    if (at == std::string::npos) {
      settings.created_by = trim_copy(message.substr(std::string("Created by ").size()));
    } else {
      settings.created_by =
          trim_copy(message.substr(std::string("Created by ").size(), at - std::string("Created by ").size()));
      settings.created_at = trim_copy(message.substr(at + 4U));
      if (!settings.created_at.empty() && settings.created_at.back() == '.')
        settings.created_at.pop_back();
    }
  } else if (state.reading_included_items && !message.empty()) {
    settings.included_items.push_back(message);
  } else if (state.reading_excluded_items && !message.empty()) {
    settings.excluded_items.push_back(message);
  }

  // The normal VAW settings dump terminates with the run-mode statement.  It
  // is valuable evidence, so include it before closing the retained block.
  if (state.in_job_settings && folded.starts_with("job session is running in ") &&
      folded.ends_with(" mode")) {
    if (!state.capture_job_settings_lines) {
      state.capture_job_settings_lines = true;
      settings.settings_source_path = file.display_path;
      settings.settings_materialized_path = file.materialized_path;
      settings.settings_start_line = line.line_number;
    }
    if (settings.settings_lines.empty() || settings.settings_lines.back() != line.text)
      remember_settings_line();
    finish_settings_capture();
  }
}

void derive_session_identity_from_path(VeeamJobSession& session, std::string_view source_path) {
  // Job.VeeamEndpointBackup[.N].log is a rotated Agent service/orchestration
  // family, not a configured customer backup job name. Treating the filename
  // as a job fabricated entries such as "veeamendpointbackup.7".
  if (is_vaw_service_rotation_file(source_path))
    return;
  const std::string normalized_path = folded_path_name(source_path);
  const std::size_t job_marker = normalized_path.find("job.");
  if (job_marker != std::string::npos) {
    const std::size_t end = normalized_path.find(".log", job_marker);
    std::string derived = normalized_path.substr(
        job_marker + 4U,
        end == std::string::npos ? std::string::npos : end - (job_marker + 4U));
    std::replace(derived.begin(), derived.end(), '_', ' ');
    if (!derived.empty())
      session.job_name = derived;
  }
  if (path_is_rescan(normalized_path)) {
    session.run_kind = "rescan";
    session.protection_group_rescan = true;
    session.job_type = "Protection Group Rescan";
    std::string group = session.job_name;
    const std::string prefix_text = "rescan of ";
    if (ascii_lower(group).starts_with(prefix_text))
      group = trim_copy(group.substr(prefix_text.size()));
    session.protection_group_name = group;
  }
}

std::size_t begin_job_session(VeeamLogReviewResult& review,
                              const ReviewInputFile& file,
                              const ReviewLine& line,
                              const ParsedLogPrefix& prefix) {
  VeeamJobSession session;
  session.job_mode = quoted_value(prefix.message, "Starting job mode:");
  session.source_path = file.display_path;
  session.materialized_path = file.materialized_path;
  session.start_line = line.line_number;
  session.start_timestamp_original = prefix.timestamp_original;
  session.start_utc_ms = prefix.timestamp_utc_ms;
  derive_session_identity_from_path(session, file.display_path);
  review.job_sessions.push_back(std::move(session));
  return review.job_sessions.size() - 1U;
}

VeeamJobSession* current_session(VeeamLogReviewResult& review, FileParseState& state) {
  if (!state.active_session_index || *state.active_session_index >= review.job_sessions.size())
    return nullptr;
  return &review.job_sessions[*state.active_session_index];
}

VeeamJobSession* find_session_by_id(VeeamLogReviewResult& review, std::string_view id) {
  const auto found = std::find_if(review.job_sessions.rbegin(), review.job_sessions.rend(),
                                  [&](const auto& session) { return session.session_id == id; });
  return found == review.job_sessions.rend() ? nullptr : &*found;
}

std::string parser_rule_id(std::string_view category) {
  if (category == "management-mode")
    return "VAW-MANAGEMENT-001";
  if (category == "pex")
    return "VAW-PEX-001";
  if (category == "source-backup-mode")
    return "VAW-BACKUP-MODE-001";
  if (category == "repository-operation")
    return "VEEAM-REPOSITORY-OP-001";
  if (category == "task-total-size")
    return "VEEAM-TASK-SIZE-001";
  if (category == "volume-size")
    return "VAW-VOLUME-SIZE-001";
  if (category == "snapshot-volume")
    return "VAW-VSS-VOLUME-001";
  if (category == "volume-identity")
    return "VAW-VOLUME-IDENTITY-001";
  if (category == "volume-mount-point")
    return "VAW-VOLUME-MOUNT-001";
  if (category == "vss-provider-id")
    return "VAW-VSS-PROVIDER-ID-001";
  if (category == "vss-provider-name")
    return "VAW-VSS-PROVIDER-NAME-001";
  if (category == "vss-provider-type")
    return "VAW-VSS-PROVIDER-TYPE-001";
  if (category == "vss-provider-used")
    return "VAW-VSS-PROVIDER-USED-001";
  if (category == "volume-included")
    return "VAW-VSS-INCLUDED-001";
  if (category == "shadow-copy-volume")
    return "VAW-VSS-SHADOW-001";
  if (category == "disk-extent")
    return "VAW-DISK-EXTENT-001";
  if (category == "control-plane")
    return "VEEAM-CONTROL-001";
  if (category == "volume")
    return "VAW-VOLUME-EVIDENCE-001";
  return "VEEAM-EVIDENCE-001";
}

VeeamRawEvidence make_raw_evidence(const ReviewInputFile& file,
                                   const ReviewLine& line,
                                   const ParsedLogPrefix& prefix,
                                   std::string category) {
  VeeamRawEvidence evidence;
  evidence.source_path = file.display_path;
  evidence.materialized_path = file.materialized_path;
  evidence.line_number = line.line_number;
  evidence.timestamp_original = prefix.timestamp_original;
  evidence.timestamp_utc_ms = prefix.timestamp_utc_ms;
  evidence.role = classify_veeam_evidence_role(file.display_path);
  evidence.rule_id = parser_rule_id(category);
  evidence.category = std::move(category);
  evidence.raw_line = line.text;
  return evidence;
}

bool parse_uint64_after(std::string_view text,
                        std::string_view folded,
                        std::string_view marker,
                        std::uint64_t& value) {
  const std::size_t marker_position = folded.find(marker);
  if (marker_position == std::string_view::npos)
    return false;
  std::size_t begin = marker_position + marker.size();
  while (begin < text.size() && (text[begin] == ' ' || text[begin] == '=' || text[begin] == ':'))
    ++begin;
  std::size_t end = begin;
  while (end < text.size() && std::isdigit(static_cast<unsigned char>(text[end])) != 0)
    ++end;
  if (end == begin)
    return false;
  const auto parsed = std::from_chars(text.data() + begin, text.data() + end, value);
  return parsed.ec == std::errc{} && parsed.ptr == text.data() + end;
}

std::vector<std::string> split_semicolon_fields(std::string_view value) {
  std::vector<std::string> fields;
  std::size_t begin = 0;
  while (begin <= value.size()) {
    const std::size_t end = value.find(';', begin);
    fields.emplace_back(value.substr(begin, end == std::string_view::npos ? value.size() - begin
                                                                         : end - begin));
    if (end == std::string_view::npos)
      break;
    begin = end + 1U;
  }
  return fields;
}

bool is_control_plane_message(std::string_view folded_message) {
  return folded_message.find("connecting to rpc") != std::string_view::npos ||
         folded_message.find("connecting to remote vbr") != std::string_view::npos ||
         folded_message.find("sending shutdown") != std::string_view::npos ||
         folded_message.find("processing shutdown command") != std::string_view::npos ||
         folded_message.find("shutdown received") != std::string_view::npos ||
         folded_message.find("grpc channel") != std::string_view::npos ||
         folded_message.find("rpc connection") != std::string_view::npos;
}

bool is_volume_evidence_message(std::string_view folded_message) {
  return folded_message.find("volumes should be added to snapshot") != std::string_view::npos ||
         folded_message.find("mount point '") != std::string_view::npos ||
         folded_message.find("mount points:") != std::string_view::npos ||
         folded_message.find("file system:") != std::string_view::npos ||
         folded_message.find("extents:") != std::string_view::npos ||
         folded_message.find("using vss provider:") != std::string_view::npos ||
         folded_message.find("volume added to shadow copy set") != std::string_view::npos ||
         folded_message.find("is included in snapshot") != std::string_view::npos ||
         folded_message.find("[epfreespacehelper] volume ['") != std::string_view::npos ||
         (folded_message.find("volume '{") != std::string_view::npos &&
          folded_message.find("provideridtouse") != std::string_view::npos);
}

std::string normalize_volume_id(std::string_view value) {
  std::string id = ascii_lower(trim_copy(value));
  while (!id.empty() && (id.front() == '{' || id.front() == '[' || id.front() == '\\'))
    id.erase(id.begin());
  while (!id.empty() && (id.back() == '}' || id.back() == ']' || id.back() == '\\' ||
                         id.back() == '\'' || id.back() == '"'))
    id.pop_back();
  const std::size_t marker = id.find("volume{");
  if (marker != std::string::npos) {
    id.erase(0, marker + 7U);
    if (!id.empty() && id.back() == '}')
      id.pop_back();
  }
  return id;
}

std::string normalize_mount_point(std::string value) {
  value = trim_copy(value);
  if (value.size() >= 3U && value.front() == '(' && value.back() == ')' &&
      value[value.size() - 2U] == ':') {
    value = value.substr(1U, value.size() - 2U);
  }
  if (value.size() == 2U && value[1] == ':')
    value.push_back('\\');
  return value;
}

VeeamVolumeSnapshotInfo* find_or_create_volume(VeeamJobSession& session,
                                                std::string_view volume_id,
                                                std::string_view mount_point = {}) {
  const std::string normalized_id = normalize_volume_id(volume_id);
  const std::string normalized_mount = normalize_mount_point(std::string(mount_point));
  for (auto& volume : session.snapshot_volumes) {
    if ((!normalized_id.empty() && normalize_volume_id(volume.volume_id) == normalized_id) ||
        (!normalized_mount.empty() && equals_folded(volume.mount_point, normalized_mount))) {
      if (volume.volume_id.empty() && !normalized_id.empty())
        volume.volume_id = normalized_id;
      if (volume.mount_point.empty() && !normalized_mount.empty())
        volume.mount_point = normalized_mount;
      return &volume;
    }
  }
  VeeamVolumeSnapshotInfo volume;
  volume.volume_id = normalized_id;
  volume.mount_point = normalized_mount;
  session.snapshot_volumes.push_back(std::move(volume));
  return &session.snapshot_volumes.back();
}

VeeamVssProviderInfo* find_or_create_provider(VeeamJobSession& session,
                                              std::string_view provider_id) {
  const std::string normalized_id = normalize_volume_id(provider_id);
  for (auto& provider : session.vss_providers) {
    if (normalize_volume_id(provider.provider_id) == normalized_id)
      return &provider;
  }
  VeeamVssProviderInfo provider;
  provider.provider_id = normalized_id;
  session.vss_providers.push_back(std::move(provider));
  return &session.vss_providers.back();
}

const VeeamVssProviderInfo* find_provider(const VeeamJobSession& session,
                                         std::string_view provider_id) {
  const std::string normalized_id = normalize_volume_id(provider_id);
  const auto found = std::find_if(session.vss_providers.begin(), session.vss_providers.end(),
                                  [&](const auto& provider) {
                                    return normalize_volume_id(provider.provider_id) == normalized_id;
                                  });
  return found == session.vss_providers.end() ? nullptr : &*found;
}

void apply_used_provider(VeeamJobSession& session,
                         VeeamVolumeSnapshotInfo* volume,
                         std::string_view provider_id) {
  const std::string normalized_id = normalize_volume_id(provider_id);
  if (normalized_id.empty())
    return;
  session.used_vss_provider_id = normalized_id;
  if (const auto* provider = find_provider(session, normalized_id)) {
    session.used_vss_provider_name = provider->name;
    session.used_vss_provider_type = provider->type;
  }
  if (volume != nullptr) {
    volume->used_provider_id = normalized_id;
    if (const auto* provider = find_provider(session, normalized_id)) {
      volume->used_provider_name = provider->name;
      volume->used_provider_type = provider->type;
    }
  }
}

void append_timeline_event(VeeamLogReviewResult& review,
                           const VeeamRawEvidence& evidence,
                           const VeeamLogReviewOptions& options) {
  if (review.timeline_events.size() >= options.maximum_structured_timeline_events)
    return;
  VeeamTimelineEvent event;
  event.evidence = evidence;
  review.timeline_events.push_back(std::move(event));
}

// A backup file path, cut at the end of the path.
//
// Target.CurrentLink and Target.PrevLinks are followed by an escaped newline and a configuration
// block on the same logical line. Taking everything after the marker captured the block too, which
// put 200 characters of settings into the Backup file field and made the .vbk mentioned in the tail
// override the .vib the run actually wrote.
std::string bounded_backup_path(std::string_view value) {
  std::string text = trim_copy(std::string(value));
  // Escaped newline, as written in the log.
  // The literal two-character sequence backslash-n, which is how the log writes an embedded
  // newline inside one logical line.
  if (const auto at = text.find(std::string(1, char(92)) + "n"); at != std::string::npos)
    text.erase(at);
  if (const auto at = text.find_first_of("\r\n"); at != std::string::npos)
    text.erase(at);
  // Stop just past the backup extension when one is present.
  for (const char* extension : {".vbk", ".vib", ".vrb"}) {
    const auto at = ascii_lower(text).find(extension);
    if (at != std::string::npos) {
      text.erase(at + 4);
      break;
    }
  }
  return trim_copy(text);
}

void parse_job_metadata(VeeamLogReviewResult& review,
                        FileParseState& state,
                        const ReviewInputFile& file,
                        const ReviewLine& line,
                        const ParsedLogPrefix& prefix,
                        std::string_view folded_message,
                        std::string_view folded_path,
                        const VeeamLogReviewOptions& options) {
  if (folded_message.find("starting job mode:") != std::string_view::npos) {
    state.active_session_index = begin_job_session(review, file, line, prefix);
  } else if (folded_message.find("starting job. isretrymode:") != std::string_view::npos) {
    state.active_session_index = begin_job_session(review, file, line, prefix);
    if (auto* started = current_session(review, state)) {
      started->job_mode = folded_message.find("'true'") != std::string_view::npos ? "Retry" : "Normal";
    }
  }

  VeeamJobSession* session = current_session(review, state);
  const bool service_job_log = folded_path.find("job.veeamendpointbackup") != std::string_view::npos;
  const bool structured_session_start =
      folded_message.find("[session] id '") != std::string_view::npos &&
      (folded_message.find("state 'working'") != std::string_view::npos ||
       folded_message.find("state: 'working'") != std::string_view::npos);
  if (!session && prefix.has_structured_prefix && !service_job_log && structured_session_start &&
      folded_path.find("job.") != std::string_view::npos) {
    VeeamJobSession placeholder;
    placeholder.source_path = file.display_path;
    placeholder.materialized_path = file.materialized_path;
    placeholder.start_line = line.line_number;
    placeholder.start_timestamp_original = prefix.timestamp_original;
    placeholder.start_utc_ms = prefix.timestamp_utc_ms;

    derive_session_identity_from_path(placeholder, file.display_path);
    review.job_sessions.push_back(std::move(placeholder));
    state.active_session_index = review.job_sessions.size() - 1U;
    session = current_session(review, state);
  }
  if (!state.cached_role.has_value())
    state.cached_role = classify_veeam_evidence_role(file.display_path);
  const VeeamEvidenceRole file_role = *state.cached_role;

  // Gather correlation identifiers on the single pass over the logs.
  //
  // Gated on two cheap character scans first. The extractors themselves allocate, and running them
  // unconditionally on every line of every file is exactly the per-line cost that made the parser
  // unusable earlier in this line. A line with no '{' and no "(E" carries neither a GUID nor a typed
  // block, so it cannot contain an identifier SAT models.
  if (prefix.message.find('{') != std::string::npos ||
      prefix.message.find("(E") != std::string::npos) {
    auto record = [&](std::vector<IdentityRef> found) {
      for (auto& ref : found) {
        ref.source_path = file.display_path;
        ref.line_number = line.line_number;
        ref.timestamp_utc_ms = prefix.timestamp_utc_ms.value_or(0);
        if (const VeeamJobSession* owning = current_session(review, state); owning != nullptr)
          ref.machine = owning->machine_key;
        review.correlation_identities.push_back(std::move(ref));
      }
    };
    record(extract_typed_identities(prefix.message));
    record(extract_freetext_identities(prefix.message));
  }
  const bool structured_job_evidence =
      folded_message.find("--pex:") != std::string_view::npos ||
      folded_message.find("preparing storages in full mode") != std::string_view::npos ||
      folded_message.find("preparing storages in incremental mode") != std::string_view::npos ||
      folded_message.find("task total size:") != std::string_view::npos ||
      is_volume_evidence_message(folded_message) || is_control_plane_message(folded_message);
  if (!session && file_role == VeeamEvidenceRole::job && structured_job_evidence) {
    state.active_session_index = begin_job_session(review, file, line, prefix);
    session = current_session(review, state);
  }

  if (folded_message.find("managementmode:") != std::string_view::npos) {
    const auto evidence = make_raw_evidence(file, line, prefix, "management-mode");
    append_timeline_event(review, evidence, options);
    if (session != nullptr && session->management_events.size() < options.maximum_raw_evidence_per_run)
      session->management_events.push_back(evidence);
  }
  // --- service-level facts -------------------------------------------------------------------
  //
  // These describe the SERVICE, not this run, and are recorded on the review rather than the
  // session. They are gathered here because this is where every line already passes.

  // The real schedule. Not in the job settings block at all.
  if (folded_message.find("[wakeupmanager]") != std::string_view::npos) {
    review.schedule_info.scheduler_seen = true;
    if (review.schedule_info.source_path.empty()) {
      review.schedule_info.source_path = file.display_path;
      review.schedule_info.line_number = line.line_number;
    }
    if (folded_message.find("creating waitabletimer for ") != std::string_view::npos) {
      if (const auto next = after(prefix.message, "Creating WaitableTimer for "))
        review.schedule_info.next_run_original = trim_copy(*next);
    } else if (folded_message.find("timer expired") != std::string_view::npos) {
      ++review.schedule_info.timer_expiry_count;
      review.schedule_info.last_timer_expiry_original = prefix.timestamp_original;
    }
  }
  if (folded_message.find("[scheduler]") != std::string_view::npos)
    review.schedule_info.scheduler_seen = true;

  // "Starting job 'X', id = '<guid>' by user, mode: 'Normal'". Recorded on the review, not the
  // session: this line is in the service log and the session lives in the job log, so the two are
  // joined later by job id and time.
  if (folded_message.find("starting job '") != std::string_view::npos) {
    VeeamRunTrigger trigger;
    if (folded_message.find(" by user") != std::string_view::npos)
      trigger.trigger = "user";
    else if (folded_message.find(" by scheduler") != std::string_view::npos ||
             folded_message.find(" by schedule") != std::string_view::npos)
      trigger.trigger = "scheduled";
    if (!trigger.trigger.empty()) {
      if (const auto id = between(prefix.message, "id = '", "'"))
        trigger.job_id = *id;
      if (const auto mode = between(prefix.message, "mode: '", "'"))
        trigger.job_mode = *mode;
      trigger.detail = trim_copy(prefix.message);
      trigger.utc_ms = prefix.timestamp_utc_ms;
      review.run_triggers.push_back(std::move(trigger));
    }
  }

  // Service lifetime.
  if (folded_message.find("service started") != std::string_view::npos) {
    ++review.service_activity.service_start_count;
    if (review.service_activity.first_service_start_original.empty())
      review.service_activity.first_service_start_original = prefix.timestamp_original;
    review.service_activity.last_service_start_original = prefix.timestamp_original;
  }

  // Agent job process boundaries: the cleanest process-lifecycle evidence VAW produces.
  if (folded_message.find("veeam agent job started") != std::string_view::npos) {
    VeeamAgentLifecycle run;
    run.started_original = prefix.timestamp_original;
    run.started_utc_ms = prefix.timestamp_utc_ms;
    run.source_path = file.display_path;
    run.start_line = line.line_number;
    review.service_activity.agent_runs.push_back(std::move(run));
  } else if (folded_message.find("veeam agent job stopped") != std::string_view::npos) {
    if (review.service_activity.agent_runs.empty() ||
        !review.service_activity.agent_runs.back().stopped_original.empty()) {
      // A stop with no matching start: still worth recording, so the count is honest.
      VeeamAgentLifecycle run;
      run.source_path = file.display_path;
      review.service_activity.agent_runs.push_back(std::move(run));
    }
    auto& run = review.service_activity.agent_runs.back();
    run.stopped_original = prefix.timestamp_original;
    run.stopped_utc_ms = prefix.timestamp_utc_ms;
    run.stop_line = line.line_number;
  }


  if (!session)
    return;

  if (const std::size_t pex = folded_message.find("--pex:"); pex != std::string_view::npos &&
      session->pex_samples.size() < options.maximum_raw_evidence_per_run) {
    VeeamPexSample sample;
    sample.evidence = make_raw_evidence(file, line, prefix, "pex");
    const std::size_t raw_pex = prefix.message.find("--pex:");
    if (raw_pex != std::string::npos)
      sample.fields = split_semicolon_fields(std::string_view(prefix.message).substr(raw_pex + 6U));
    session->pex_samples.push_back(sample);
    append_timeline_event(review, sample.evidence, options);
  }

  if (folded_message.find("preparing storages in full mode") != std::string_view::npos) {
    session->settings.source_backup_mode = "Full";
    const auto evidence = make_raw_evidence(file, line, prefix, "source-backup-mode");
    append_timeline_event(review, evidence, options);
  } else if (folded_message.find("preparing storages in incremental mode") != std::string_view::npos) {
    session->settings.source_backup_mode = "Incremental";
    const auto evidence = make_raw_evidence(file, line, prefix, "source-backup-mode");
    append_timeline_event(review, evidence, options);
  }

  if (folded_message.find("synthetic full") != std::string_view::npos) {
    session->settings.repository_operation = "Synthetic Full";
    session->settings.resulting_backup_type = "Full";
    const auto evidence = make_raw_evidence(file, line, prefix, "repository-operation");
    append_timeline_event(review, evidence, options);
  }

  if (const std::size_t marker = folded_message.find("task total size:"); marker != std::string_view::npos) {
    const std::size_t value_begin = marker + std::string_view("task total size:").size();
    session->settings.task_total_size = format_task_size(prefix.message.substr(value_begin));
    const auto evidence = make_raw_evidence(file, line, prefix, "task-total-size");
    append_timeline_event(review, evidence, options);
  }

  if (folded_message.find("[epfreespacehelper] volume ['") != std::string_view::npos &&
      folded_message.find("length is ") != std::string_view::npos) {
    const auto name = between(prefix.message, "Volume ['", "'");
    std::uint64_t length = 0;
    if (name && parse_uint64_after(prefix.message, folded_message, "length is ", length)) {
      const std::string mount = normalize_mount_point(*name);
      state.volume_sizes_by_mount[ascii_lower(mount)] = length;
      if (mount.size() >= 2U && mount[1] == ':') {
        auto* volume = find_or_create_volume(*session, {}, mount);
        volume->explicit_size_bytes = length;
        const auto evidence = make_raw_evidence(file, line, prefix, "volume-size");
        if (volume->evidence.size() < options.maximum_raw_evidence_per_run)
          volume->evidence.push_back(evidence);
        append_timeline_event(review, evidence, options);
      }
    }
  }

  if (folded_message.find("provideridtouse") != std::string_view::npos &&
      folded_message.find("mount point '") != std::string_view::npos) {
    const auto volume_id = between(prefix.message, "Volume '{", "}'");
    const auto mount = between(prefix.message, "mount point '", "'");
    const auto provider = between(prefix.message, "providerIdToUse '{", "}'");
    if (volume_id || mount) {
      auto* volume = find_or_create_volume(*session, volume_id.value_or(""), mount.value_or(""));
      if (provider)
        volume->requested_provider_id = normalize_volume_id(*provider);
      if (!volume->mount_point.empty()) {
        const auto found = state.volume_sizes_by_mount.find(ascii_lower(volume->mount_point));
        if (found != state.volume_sizes_by_mount.end())
          volume->explicit_size_bytes = found->second;
      }
      const auto evidence = make_raw_evidence(file, line, prefix, "snapshot-volume");
      if (volume->evidence.size() < options.maximum_raw_evidence_per_run)
        volume->evidence.push_back(evidence);
      append_timeline_event(review, evidence, options);
    }
  }

  if (folded_message.find("\\\\?\\volume{") != std::string_view::npos &&
      folded_message.find("file system:") != std::string_view::npos) {
    const auto volume_id = between(prefix.message, "Volume{", "}");
    if (volume_id) {
      auto* volume = find_or_create_volume(*session, *volume_id);
      state.active_volume_id = normalize_volume_id(*volume_id);
      state.reading_volume_mount_points = false;
      state.reading_volume_extents = false;
      if (const auto fs = between(prefix.message, "file system: ", ","))
        volume->file_system = trim_copy(*fs);
      if (const auto dos = after(prefix.message, "DOS name:"))
        volume->dos_name = trim_copy(*dos);
      const auto evidence = make_raw_evidence(file, line, prefix, "volume-identity");
      if (volume->evidence.size() < options.maximum_raw_evidence_per_run)
        volume->evidence.push_back(evidence);
      append_timeline_event(review, evidence, options);
    }
  } else if (folded_message.find("mount points:") != std::string_view::npos &&
             !state.active_volume_id.empty()) {
    state.reading_volume_mount_points = true;
    state.reading_volume_extents = false;
  } else if (folded_message.find("extents:") != std::string_view::npos &&
             !state.active_volume_id.empty()) {
    state.reading_volume_mount_points = false;
    state.reading_volume_extents = true;
  } else if (state.reading_volume_mount_points && !state.active_volume_id.empty()) {
    const std::string candidate = trim_copy(prefix.message);
    if (candidate.size() >= 2U && candidate[1] == ':') {
      auto* volume = find_or_create_volume(*session, state.active_volume_id, candidate);
      const auto found = state.volume_sizes_by_mount.find(ascii_lower(volume->mount_point));
      if (found != state.volume_sizes_by_mount.end())
        volume->explicit_size_bytes = found->second;
      const auto evidence = make_raw_evidence(file, line, prefix, "volume-mount-point");
      if (volume->evidence.size() < options.maximum_raw_evidence_per_run)
        volume->evidence.push_back(evidence);
      append_timeline_event(review, evidence, options);
    }
  }

  if (folded_message.find("vss id: [{") != std::string_view::npos) {
    if (const auto provider_id = between(prefix.message, "VSS ID: [{", "}]")) {
      state.active_vss_provider_id = normalize_volume_id(*provider_id);
      auto* provider = find_or_create_provider(*session, state.active_vss_provider_id);
      const auto evidence = make_raw_evidence(file, line, prefix, "vss-provider-id");
      if (provider->evidence.size() < options.maximum_raw_evidence_per_run)
        provider->evidence.push_back(evidence);
      append_timeline_event(review, evidence, options);
    }
  } else if (!state.active_vss_provider_id.empty() &&
             folded_message.find("name: [") != std::string_view::npos) {
    if (const auto name = between(prefix.message, "Name: [", "]")) {
      auto* provider = find_or_create_provider(*session, state.active_vss_provider_id);
      provider->name = *name;
      const auto evidence = make_raw_evidence(file, line, prefix, "vss-provider-name");
      if (provider->evidence.size() < options.maximum_raw_evidence_per_run)
        provider->evidence.push_back(evidence);
    }
  } else if (!state.active_vss_provider_id.empty() &&
             folded_message.find("type: [") != std::string_view::npos) {
    if (const auto type = between(prefix.message, "Type: [", "]")) {
      auto* provider = find_or_create_provider(*session, state.active_vss_provider_id);
      provider->type = *type;
      const auto evidence = make_raw_evidence(file, line, prefix, "vss-provider-type");
      if (provider->evidence.size() < options.maximum_raw_evidence_per_run)
        provider->evidence.push_back(evidence);
      state.active_vss_provider_id.clear();
    }
  }

  if (folded_message.find("using vss provider:") != std::string_view::npos) {
    if (const auto provider = between(prefix.message, "Using VSS provider: '{", "}'")) {
      apply_used_provider(*session, nullptr, *provider);
      const auto evidence = make_raw_evidence(file, line, prefix, "vss-provider-used");
      append_timeline_event(review, evidence, options);
    }
  }

  if (folded_message.find(" is included in snapshot") != std::string_view::npos &&
      folded_message.find("volume '\\\\?\\volume{") != std::string_view::npos) {
    if (const auto volume_id = between(prefix.message, "Volume '\\\\?\\Volume{", "}")) {
      auto* volume = find_or_create_volume(*session, *volume_id);
      volume->included_in_snapshot = true;
      const auto evidence = make_raw_evidence(file, line, prefix, "volume-included");
      if (volume->evidence.size() < options.maximum_raw_evidence_per_run)
        volume->evidence.push_back(evidence);
      append_timeline_event(review, evidence, options);
    }
  }

  if (folded_message.find("volume added to shadow copy set") != std::string_view::npos &&
      folded_message.find("provider id '") != std::string_view::npos) {
    const auto volume_id = between(prefix.message, "Volume{", "}");
    const auto provider = between(prefix.message, "provider id '{", "}'");
    if (volume_id && provider) {
      auto* volume = find_or_create_volume(*session, *volume_id);
      volume->included_in_snapshot = true;
      apply_used_provider(*session, volume, *provider);
      const auto evidence = make_raw_evidence(file, line, prefix, "shadow-copy-volume");
      if (volume->evidence.size() < options.maximum_raw_evidence_per_run)
        volume->evidence.push_back(evidence);
      append_timeline_event(review, evidence, options);
    }
  }

  if (is_volume_evidence_message(folded_message) &&
      session->volume_evidence.size() < options.maximum_raw_evidence_per_run) {
    const auto evidence = make_raw_evidence(file, line, prefix, "volume");
    session->volume_evidence.push_back(evidence);
    append_timeline_event(review, evidence, options);
  }

  if (folded_message.find("disk ") != std::string_view::npos &&
      folded_message.find("offset") != std::string_view::npos &&
      folded_message.find("length") != std::string_view::npos &&
      session->disk_extents.size() < options.maximum_raw_evidence_per_run) {
    VeeamDiskExtentEvidence extent;
    extent.evidence = make_raw_evidence(file, line, prefix, "disk-extent");
    std::uint64_t disk = 0;
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
    if (parse_uint64_after(prefix.message, folded_message, "disk ", disk) &&
        parse_uint64_after(prefix.message, folded_message, "offset", offset) &&
        parse_uint64_after(prefix.message, folded_message, "length", length)) {
      extent.disk_number = disk;
      extent.offset_bytes = offset;
      extent.length_bytes = length;
      session->disk_extents.push_back(extent);
      if (!state.active_volume_id.empty()) {
        auto* volume = find_or_create_volume(*session, state.active_volume_id);
        if (volume->extents.size() < options.maximum_raw_evidence_per_run)
          volume->extents.push_back(extent);
      }
      append_timeline_event(review, extent.evidence, options);
    }
  }

  if (is_control_plane_message(folded_message) &&
      session->management_events.size() < options.maximum_raw_evidence_per_run) {
    const auto evidence = make_raw_evidence(file, line, prefix, "control-plane");
    session->management_events.push_back(evidence);
    append_timeline_event(review, evidence, options);
  }

  if (prefix.message.find("[Session] Id '") != std::string::npos) {
    const std::string observed_session_id = quoted_value(prefix.message, "[Session] Id");
    const bool working_state = folded_message.find("state 'working'") != std::string_view::npos ||
                               folded_message.find("state: 'working'") != std::string_view::npos;
    if (working_state && !observed_session_id.empty() &&
        ((!session->session_id.empty() && !equals_folded(session->session_id, observed_session_id)) ||
         session->completion_utc_ms.has_value())) {
      state.active_session_index = begin_job_session(review, file, line, prefix);
      session = current_session(review, state);
    }
    if (session != nullptr && !observed_session_id.empty()) {
      session->session_id = observed_session_id;
      if (working_state) {
        session->start_line = line.line_number;
        session->start_timestamp_original = prefix.timestamp_original;
        session->start_utc_ms = prefix.timestamp_utc_ms;
      }
      // The state itself, kept as written. "WaitingRepository" is the difference between a run that
      // failed while copying and one that never reached the source at all - the single most useful
      // word in the whole run, and it was being discarded.
      if (const auto observed_state = between(prefix.message, "State '", "'"))
        session->last_state = *observed_state;
    }
  } else if (prefix.message.find("Job ID:") != std::string::npos) {
    session->job_id = bracketed_value(prefix.message, "Job ID:");
  } else if (prefix.message.find("Job Name:") != std::string::npos) {
    session->job_name = bracketed_value(prefix.message, "Job Name:");
  } else if (prefix.message.find("Job Mode:") != std::string::npos && session->job_mode.empty()) {
    session->job_mode = bracketed_value(prefix.message, "Job Mode:");
  } else if (prefix.message.find("Job Type:") != std::string::npos) {
    session->job_type = bracketed_value(prefix.message, "Job Type:");
  }

  // Progress for THIS run.
  //
  // The line reads: Job progress: '54%', '213,213,773,824' of '500,104,691,712' bytes,
  // '95,245,552,373' of '173,926,137,856' used bytes, object '0' of '1'.
  // These used to be retained as unattached samples from assorted runs.
  if (folded_message.find("job progress:") != std::string_view::npos) {
    const auto digits_after = [&](std::string_view from, std::size_t at) -> std::uint64_t {
      std::string number;
      for (std::size_t index = at; index < from.size(); ++index) {
        const char character = from[index];
        if (character == ',')
          continue;
        if (character >= '0' && character <= '9') {
          number.push_back(character);
          continue;
        }
        if (!number.empty())
          break;
      }
      if (number.empty() || number.size() > 19)
        return 0;
      return std::strtoull(number.c_str(), nullptr, 10);
    };
    if (const auto percent = between(prefix.message, "Job progress: '", "%'")) {
      session->progress_percent =
          static_cast<std::uint32_t>(std::strtoul(percent->c_str(), nullptr, 10));
      session->progress_seen = true;
    }
    const std::size_t bytes_at = prefix.message.find("%',");
    if (bytes_at != std::string::npos) {
      session->progress_bytes_done = digits_after(prefix.message, bytes_at + 3);
      const std::size_t of_at = prefix.message.find(" of ", bytes_at);
      if (of_at != std::string::npos)
        session->progress_bytes_total = digits_after(prefix.message, of_at + 4);
    }
    const std::size_t used_at = prefix.message.find("bytes, '");
    if (used_at != std::string::npos) {
      session->progress_used_done = digits_after(prefix.message, used_at + 8);
      const std::size_t used_of = prefix.message.find(" of ", used_at);
      if (used_of != std::string::npos)
        session->progress_used_total = digits_after(prefix.message, used_of + 4);
    }
  }

  // The restore point this run chains onto. Target.PrevLinks names the parent .vbk and is what
  // proves an incremental belongs to the full before it.
  if (session->previous_backup_file.empty() &&
      folded_message.find("target.prevlinks") != std::string_view::npos) {
    // Search from PrevLinks onward. The message names the CURRENT file first, so starting at the
    // first "@" returned the file this run wrote rather than the point it chains onto.
    const std::size_t links_at = folded_message.find("target.prevlinks");
    const std::string tail = prefix.message.substr(std::min(links_at, prefix.message.size()));
    if (const auto link = between(tail, "@", ".vbk"))
      session->previous_backup_file = bounded_backup_path(*link + ".vbk");
  }

  if (folded_message.find("backup job name:") != std::string_view::npos) {
    if (const auto value = after(prefix.message, "Backup job name:"))
      session->job_name = *value;
  }
  if (session->job_id.empty()) {
    if (const auto value = between(prefix.message, "JobId=\"", "\""))
      session->job_id = *value;
  }
  if (session->job_name.empty()) {
    if (const auto value = between(prefix.message, "JobName=\"", "\""))
      session->job_name = *value;
  }
  parse_job_settings_line(session->settings, state, file, line, prefix);

  // VAW Job.Backup.log states the source execution mode explicitly.  This is
  // different from the retry/normal orchestration mode and is the useful
  // support-facing Source Backup Mode value.
  if (folded_message.find("job session is running in full mode") != std::string_view::npos) {
    session->settings.source_backup_mode = "Full";
    const auto evidence = make_raw_evidence(file, line, prefix, "source-backup-mode");
    append_timeline_event(review, evidence, options);
  } else if (folded_message.find("job session is running in incremental mode") !=
             std::string_view::npos) {
    session->settings.source_backup_mode = "Incremental";
    const auto evidence = make_raw_evidence(file, line, prefix, "source-backup-mode");
    append_timeline_event(review, evidence, options);
  }

  // Older VAW samples use "Task size" rather than "Task total size".  Keep
  // the complete useful numeric portion instead of reporting Not identified.
  if (folded_message.find("task size: capacity =") != std::string_view::npos) {
    if (const auto value = after(prefix.message, "Task size:"))
      session->settings.task_total_size = format_task_size(*value);
    const auto evidence = make_raw_evidence(file, line, prefix, "task-total-size");
    append_timeline_event(review, evidence, options);
  }

  // DataTransfer.SyncDisk carries the resulting chain file/type.  Prefer the
  // file extension because it is directly visible evidence: VBK = full and
  // VIB = incremental.  Preserve Synthetic Full separately when explicitly
  // logged.
  if (folded_message.find("target.currentlink") != std::string_view::npos ||
      folded_message.find("target.backuptype") != std::string_view::npos) {
    // Classify from the file THIS run wrote, never from the whole message.
    //
    // The message also carries Target.PrevLinks, which names the parent full. Searching the whole
    // message for ".vbk" therefore reported every incremental in a chain as a full - confidently
    // wrong about the one thing the reader is checking.
    const auto current_link = after(prefix.message, "Target.CurrentLink =");
    const std::string written_file =
        current_link ? ascii_lower(bounded_backup_path(*current_link)) : std::string();

    if (written_file.find(".vbk") != std::string::npos ||
        folded_message.find("target.backuptype = {full}") != std::string_view::npos ||
        folded_message.find("target.backuptype={full}") != std::string_view::npos) {
      session->settings.resulting_backup_type = "Full (VBK)";
      if (session->settings.repository_operation.empty())
        session->settings.repository_operation = "Full backup write";
    } else if (written_file.find(".vib") != std::string::npos ||
               folded_message.find("target.backuptype = {trad}") != std::string_view::npos ||
               folded_message.find("target.backuptype={trad}") != std::string_view::npos) {
      session->settings.resulting_backup_type = "Incremental (VIB)";
      if (session->settings.repository_operation.empty())
        session->settings.repository_operation = "Incremental backup write";
    }
    if (current_link && session->backup_file.empty())
      session->backup_file = bounded_backup_path(*current_link);
  }

  if (folded_message.find("job vss settings:") != std::string_view::npos) {
    session->settings.vss_snapshot =
        folded_message.find("enabled: [true]") != std::string_view::npos ? "Enabled" : "Disabled or unknown";
    session->settings.application_processing =
        folded_message.find("applicationprocessingenabled: [true]") != std::string_view::npos ? "Enabled" : "Disabled";
    session->settings.guest_indexing =
        folded_message.find("winguestfsindexingoptions: [enabled: [true]") != std::string_view::npos ? "Enabled" : "Disabled";
  }
  if (prefix.message.find("Task session '") != std::string::npos &&
      prefix.message.find("has been completed") != std::string::npos) {
    session->task_session_id = quoted_value(prefix.message, "Task session");
  }
  if (folded_message.find("finalizing vss snapshot") != std::string_view::npos &&
      folded_message.find("job:") != std::string_view::npos) {
    if (folded_message.find("job: success") != std::string_view::npos)
      session->status = "Success";
    else if (folded_message.find("job: failed") != std::string_view::npos)
      session->status = "Failed";
    else if (folded_message.find("job: warning") != std::string_view::npos)
      session->status = "Warning";
    session->completion_timestamp_original = prefix.timestamp_original;
    session->completion_utc_ms = prefix.timestamp_utc_ms;
    session->completion_line = line.line_number;
  }
  if (folded_message.find("job has been stopped successfully. name:") != std::string_view::npos) {
    if (const auto value = bracket_value_after(prefix.message, "Name:"))
      session->job_name = *value;
    if (const auto value = bracket_value_after(prefix.message, "JobId:"))
      session->job_id = *value;
    if (!session->completion_utc_ms) {
      session->completion_timestamp_original = prefix.timestamp_original;
      session->completion_utc_ms = prefix.timestamp_utc_ms;
      session->completion_line = line.line_number;
    }
  }
  if (prefix.message.find("Job session '") != std::string::npos &&
      prefix.message.find("has been completed") != std::string::npos) {
    const std::string session_id = quoted_value(prefix.message, "Job session");
    VeeamJobSession* completed = find_session_by_id(review, session_id);
    if (!completed)
      completed = session;
    if (completed->session_id.empty())
      completed->session_id = session_id;
    completed->status = quoted_value(prefix.message, "status:");
    completed->completion_timestamp_original = prefix.timestamp_original;
    completed->completion_utc_ms = prefix.timestamp_utc_ms;
    completed->completion_line = line.line_number;
    completed->restore_point_id = bracketed_value(prefix.message, "PointId:");
    if (state.active_session_index &&
        &review.job_sessions[*state.active_session_index] == completed)
      state.active_session_index.reset();
  }
  if (prefix.message.find("FilePath=\"") != std::string::npos) {
    const auto value = between(prefix.message, "FilePath=\"", "\"");
    if (value && contains_folded(*value, ".vb"))
      session->backup_file = *value;
  }
  if (prefix.message.find("Using target repository") != std::string::npos) {
    const auto path = after(prefix.message, ":path=");
    if (path && session->settings.destination_path.empty())
      session->settings.destination_path = trim_copy(*path);
  }
  if (prefix.message.find("restore point") != std::string::npos &&
      folded_message.find("full") != std::string_view::npos) {
    session->restore_point_type = "Full";
  }
}

// SQLiteSchemaUpdate.log records a recursive-descent SQL grammar walking its alternatives. Every
// alternative the grammar rejects is written as a Warning - "[CSymbols] Failed to parse at 344",
// "[COrParser] Failed to parse at 344", "[CConstraintNameDummyParser] Failed to parse at 344" -
// and then the next alternative succeeds and the schema update completes normally. That is the
// parser doing its job, not the schema update failing. Left alone it produced nineteen separate
// warning groups from one file and buried the findings that actually mattered for the run, so the
// whole family collapses into a single entry tagged with the log it came from.
bool is_schema_parser_backtrack(std::string_view source_path, std::string_view summary) {
  if (summary.find("Failed to parse at ") == std::string_view::npos)
    return false;
  return ascii_lower(std::string(source_path)).find("sqliteschemaupdate") != std::string::npos;
}

void add_or_merge_incident(VeeamLogReviewResult& review,
                           FileParseState& state,
                           ActiveIncident&& active,
                           const VeeamLogReviewOptions& options) {
  if (active.location.lines.empty())
    return;
  std::string summary = active.summary.empty()
                            ? strip_log_prefix(active.location.lines.front(),
                                               ascii_lower(active.location.lines.front()))
                            : active.summary;
  if (is_schema_parser_backtrack(active.location.source_path, summary)) {
    active.component = "SQLiteSchemaUpdate";
    summary =
        "SQLite schema update: SQL grammar rejected a candidate rule and continued with the next "
        "one (internal parser backtracking, not a schema update failure)";
  }
  const std::string signature = active.severity + "|" + ascii_lower(active.component) + "|" +
                                normalize_signature(summary);
  std::string retention_bucket = signature + "|";
  if (!active.location.explicit_session_id.empty()) {
    retention_bucket += "session:" + ascii_lower(active.location.explicit_session_id);
  } else if (!active.location.explicit_job_id.empty()) {
    retention_bucket += "job:" + ascii_lower(active.location.explicit_job_id);
  } else if (active.location.timestamp_utc_ms) {
    constexpr std::int64_t kMillisecondsPerHour = 60LL * 60LL * 1000LL;
    retention_bucket += "hour:" +
                        std::to_string(*active.location.timestamp_utc_ms /
                                       kMillisecondsPerHour);
  } else {
    retention_bucket += "unscoped";
  }

  auto& retained_in_bucket = state.retained_locations_by_bucket[retention_bucket];
  const auto indexed = state.incident_indexes.find(signature);
  if (indexed == state.incident_indexes.end()) {
    if (review.incidents.size() >= options.maximum_incidents)
      return;
    VeeamIncident incident;
    incident.id = make_uuid_v4();
    incident.signature = signature;
    incident.severity = active.severity;
    incident.component = active.component;
    incident.story_stage = active.story_stage;
    incident.summary = summary;
    incident.occurrences = 1;
    incident.first_timestamp_original = active.location.timestamp_original;
    incident.last_timestamp_original = active.location.timestamp_original;
    incident.first_utc_ms = active.location.timestamp_utc_ms;
    incident.last_utc_ms = active.location.timestamp_utc_ms;
    incident.locations.push_back(std::move(active.location));
    retained_in_bucket = 1U;
    const std::size_t incident_index = review.incidents.size();
    review.incidents.push_back(std::move(incident));
    state.incident_indexes.emplace(signature, incident_index);
    return;
  }

  VeeamIncident& incident = review.incidents[indexed->second];
  ++incident.occurrences;
  if (active.location.timestamp_utc_ms) {
    if (!incident.first_utc_ms || *active.location.timestamp_utc_ms < *incident.first_utc_ms) {
      incident.first_utc_ms = active.location.timestamp_utc_ms;
      incident.first_timestamp_original = active.location.timestamp_original;
    }
    if (!incident.last_utc_ms || *active.location.timestamp_utc_ms > *incident.last_utc_ms) {
      incident.last_utc_ms = active.location.timestamp_utc_ms;
      incident.last_timestamp_original = active.location.timestamp_original;
    }
  } else if (incident.last_timestamp_original.empty()) {
    incident.last_timestamp_original = active.location.timestamp_original;
  }
  if (retained_in_bucket >= options.maximum_locations_per_incident_per_file) {
    ++incident.locations_omitted;
    return;
  }
  ++retained_in_bucket;
  if (incident.locations.size() >= options.maximum_context_locations_per_incident) {
    active.location.before.clear();
    active.location.after.clear();
    if (active.location.lines.size() > 1U)
      active.location.lines.resize(1U);
  }
  incident.locations.push_back(std::move(active.location));
}

void finalize_active_incident(VeeamLogReviewResult& review,
                              FileParseState& state,
                              const VeeamLogReviewOptions& options) {
  if (!state.active_incident)
    return;
  add_or_merge_incident(review, state, std::move(*state.active_incident), options);
  state.active_incident.reset();
}

bool query_matches(const VeeamLogReviewOptions& options, std::string_view line) {
  if (!options.include_informational_query_matches || options.informational_query.empty())
    return false;
  if (options.case_sensitive_query)
    return line.find(options.informational_query) != std::string_view::npos;
  return contains_folded(line, options.informational_query);
}

void process_incident_line(VeeamLogReviewResult& review,
                           FileParseState& state,
                           const ReviewInputFile& file,
                           const ReviewLine& line,
                           const ParsedLogPrefix& prefix,
                           const VeeamLogReviewOptions& options) {
  const bool selected_warning = prefix.severity == "warning" && options.include_warnings;
  const bool selected_error = prefix.severity == "error";
  const bool selected_query = prefix.severity == "information" && query_matches(options, line.text);
  // Story events: the few Info lines that explain what the run was doing. Without these the review
  // shows only what failed and never what was happening around it, which is the context an engineer
  // otherwise reconstructs by reading the raw log. The profile is resolved per review, so the
  // vocabulary matches the product that produced the log rather than one generic word list.
  const VeeamStoryStage story_stage =
      (prefix.severity == "information" && options.include_story_events)
          ? classify_story_stage(prefix.message, review.profile_used)
          : VeeamStoryStage::none;
  const bool selected_story = story_stage != VeeamStoryStage::none;
  const bool selected = (selected_error || selected_warning || selected_query || selected_story) &&
                        in_date_range(options, prefix.timestamp_utc_ms);

  if (state.active_incident) {
    if (selected && !state.active_incident->collecting_after) {
      const bool same_severity = state.active_incident->severity == prefix.severity;
      const bool same_thread = state.active_incident->location.thread_or_task.empty() ||
                               prefix.thread.empty() ||
                               state.active_incident->location.thread_or_task == prefix.thread;
      const bool pgsql_payload =
          (equals_folded(state.active_incident->component, "PGSQL") ||
           equals_folded(extract_component(prefix.message), "PGSQL")) &&
          is_pgsql_diagnostic_payload(prefix.message);
      const bool continuation = same_severity && same_thread &&
                                (is_stack_continuation(prefix.message) || pgsql_payload ||
                                 prefix.timestamp_original ==
                                     state.active_incident->location.timestamp_original);
      if (continuation) {
        // The root line is sometimes untagged while subsequent stack frames are
        // tagged with the responsible Veeam component. Promote that component
        // onto the incident instead of leaving an otherwise well-correlated stack
        // as "Unclassified". Never replace a component already observed on root.
        if (state.active_incident->component.empty()) {
          const std::string continuation_component = extract_component(prefix.message);
          if (!continuation_component.empty())
            state.active_incident->component = continuation_component;
        }
        // Promote the real error text over an action-wrapper placeholder. Stack frames ("at ...")
        // are skipped: the wanted line is the exception message itself, which in the observed
        // bundles directly follows the wrapper and names the endpoint that failed.
        if (state.active_incident->summary_awaiting_real_error &&
            !is_stack_continuation(prefix.message)) {
          const std::string promoted = trim_copy(prefix.message);
          if (promoted.size() > 12U) {
            state.active_incident->summary = promoted;
            state.active_incident->summary_awaiting_real_error = false;
          }
        }
        if (state.active_incident->location.lines.size() < options.maximum_incident_lines)
          state.active_incident->location.lines.push_back(line.text);
        return;
      }
      finalize_active_incident(review, state, options);
    } else if (!selected) {
      state.active_incident->collecting_after = true;
      if (state.active_incident->remaining_after > 0U) {
        state.active_incident->location.after.push_back(line.text);
        --state.active_incident->remaining_after;
      }
      if (state.active_incident->remaining_after == 0U)
        finalize_active_incident(review, state, options);
    }
  }

  if (selected) {
    // VBR can emit a PostgreSQL script body before/after the actual exception,
    // marking every script line as Error. Orphan SQL payload is retained as
    // surrounding source context but is not promoted to an incident root.
    if (equals_folded(extract_component(prefix.message), "PGSQL") &&
        is_pgsql_diagnostic_payload(prefix.message))
      return;

    ActiveIncident incident;
    incident.severity = (selected_query || selected_story) ? "information" : prefix.severity;
    // A story event is not a problem. Naming it by the stage it advances - "Backup start",
    // "Connection", "Snapshot", "Data transfer", "Backup finished" - lets the review read as a
    // sequence of what happened rather than a list of what broke, and keeps these visibly distinct
    // from errors and warnings in every grouping and count.
    incident.story_stage = story_stage;
    incident.component = extract_component(prefix.message);
    // Only when the line carried an ACTION token do we substitute the owning service. "[TryInvoke]
    // Invocation error" is a retry helper, not a component, and reporting TryInvoke tells an
    // engineer nothing - the useful identity is the service that owns the log, so an Invocation
    // error in Svc.PublicCloudInstanceActualizer.log reads as a public-cloud actualizer problem
    // and is visibly not part of the backup job run it used to be filed against.
    //
    // Lines with no bracket token take the owning Veeam log family as their component instead of
    // showing as Unclassified, but only for recognised families - see
    // component_from_known_log_family() for why an unrestricted file-name fallback breaks grouping.
    if (incident.component.empty() && has_action_token_prefix(prefix.message))
      incident.component = component_from_source_file(file.display_path);
    if (incident.component.empty())
      incident.component = component_from_known_log_family(file.display_path);
    incident.summary = prefix.message;
    // "[TryInvoke] Invocation error;" is a retry helper reporting that something threw. The actual
    // failure - "A connection attempt failed ... (169.254.169.254:80)" - is the next line. Grouping
    // and displaying the wrapper hides the only informative part of the incident.
    incident.summary_awaiting_real_error =
        has_action_token_prefix(prefix.message) && is_placeholder_action_message(prefix.message);
    incident.remaining_after = options.context_after;
    incident.location.source_path = file.display_path;
    incident.location.materialized_path = file.materialized_path;
    incident.location.line_number = line.line_number;
    incident.location.byte_offset = line.byte_offset;
    incident.location.timestamp_original = prefix.timestamp_original;
    incident.location.timestamp_utc_ms = prefix.timestamp_utc_ms;
    incident.location.thread_or_task = prefix.thread;
    if (const VeeamJobSession* session = current_session(review, state)) {
      incident.location.explicit_job_id = session->job_id;
      incident.location.explicit_session_id = session->session_id;
    }
    incident.location.before.assign(state.preceding.begin(), state.preceding.end());
    incident.location.lines.push_back(line.text);
    state.active_incident = std::move(incident);
    if (options.context_after == 0U)
      finalize_active_incident(review, state, options);
  }
}

bool fast_index_line_candidate(std::string_view text) {
  constexpr std::array<std::string_view, 38> markers{{
      "Error", "ERROR", "Warning", "WARNING", "Failed", "FAILED", "Success", "SUCCESS",
      "Completed", "completed", "MachineName", "HostName", "File version", "Product",
      "Version", "ManagementMode", "Management Server", "management server",
      "Network Interface", "Unicast IPAddresses", "Job Settings", "Starting job", "starting job",
      "[Session]", "Session", "session", "Job ID:", "Job Name:", "Job Mode:", "Job Type:",
      "Backup job name:", "Backup Job Name:", "<Oib JobId=", "Module version:",
      "vbrHostName:", "Connected to VBR", "collector_machine", "\"profile\""}};
  return std::any_of(markers.begin(), markers.end(), [&](std::string_view marker) {
    return text.find(marker) != std::string_view::npos;
  });
}

Result<std::uint64_t> parse_review_file(VeeamLogReviewResult& review,
                                        const ReviewInputFile& file,
                                        const VeeamLogReviewOptions& options,
                                        const CancellationToken& cancel) {
  ReviewLineReader reader(file.materialized_path, options.maximum_line_bytes);
  if (!reader.good())
    return Result<std::uint64_t>::failure(
        review_error("open log", "Cannot open log file", file.materialized_path));
  FileParseState state;
  const std::string path_folded = ascii_lower(file.display_path);

  // The account that launched the plug-in is in the path, not in any line, so it is read once per
  // file rather than per line. The evidence line stays 0: it describes the file itself.
  if (const std::string account = plugin_account_from_path(file.display_path); !account.empty()) {
    const ReviewLine path_evidence{};
    add_unique_evidence(review.machine.plugin_accounts, account, file, path_evidence,
                        ParserConfidence::verified);
  }

  ReviewLine line;
  std::uint64_t count = 0;
  for (;;) {
    if (cancel.is_cancelled())
      break;
    auto next = reader.next(line);
    if (!next.ok())
      return Result<std::uint64_t>::failure(next.error());
    if (!next.value())
      break;
    ++count;
    if (options.fast_index_first && !state.active_incident && !state.in_job_settings &&
        !fast_index_line_candidate(line.text)) {
      state.preceding.push_back(line.text);
      while (state.preceding.size() > options.context_before)
        state.preceding.pop_front();
      continue;
    }

    // Time-linked deep reviews may still need to read a large root service log, but lines
    // outside the selected window do not need full lowercase/signature/job processing.
    // Preserve untimestamped identity/configuration lines so machine/product metadata remains available.
    if ((options.from_utc_ms || options.to_utc_ms) &&
        line.text.find("MachineName: [") == std::string::npos &&
        line.text.find("File version: [") == std::string::npos &&
        line.text.find("\"collector_machine\"") == std::string::npos) {
      const auto quick_timestamp =
          parse_timestamp(line.text, options.date_order, options.assumed_timezone_offset_minutes);
      if (quick_timestamp && !in_date_range(options, quick_timestamp->unix_millis))
        continue;
    }

    const std::string folded_line = ascii_lower(line.text);
    const ParsedLogPrefix prefix = parse_log_prefix(
        line.text, folded_line, options.date_order, options.assumed_timezone_offset_minutes);
    const std::string folded_message = ascii_lower(prefix.message);
    parse_machine_metadata(review, state, file, line, folded_line, path_folded, options.profile);
    parse_job_metadata(review, state, file, line, prefix, folded_message, path_folded, options);
    process_incident_line(review, state, file, line, prefix, options);

    state.preceding.push_back(line.text);
    while (state.preceding.size() > options.context_before)
      state.preceding.pop_front();
  }
  finalize_active_incident(review, state, options);
  return Result<std::uint64_t>::success(count);
}

// The kinds of evidence a collection carries that the review does not read, in the order the report
// names them; anything else is counted as an other file.
constexpr std::array<std::pair<std::string_view, std::string_view>, 13> kNotReadKinds{{
    {".dmp", "crash dump"},
    {".mdmp", "crash dump"},
    {".hdmp", "crash dump"},
    {".evtx", "Windows event log"},
    {".evt", "Windows event log"},
    {".etl", "event trace"},
    {".pml", "Process Monitor capture"},
    {".pcap", "network capture"},
    {".pcapng", "network capture"},
    {".cap", "network capture"},
    {".reg", "registry export"},
    {".html", "HTML report"},
    {".htm", "HTML report"},
}};

bool in_windows_support_context(const std::filesystem::path& path) {
  std::string folded = ascii_lower(support_assist::path_to_utf8(path));
  std::replace(folded.begin(), folded.end(), '\\', '/');
  return folded.find("/windowssupport/") != std::string::npos;
}

std::string not_read_kind(const std::filesystem::path& path) {
  const std::string extension = ascii_lower(support_assist::path_to_utf8(path.extension()));
  for (const auto& [suffix, kind] : kNotReadKinds) {
    if (extension == suffix)
      return std::string(kind);
  }
  return "other file";
}

void discover_path(const std::filesystem::path& source,
                   bool recursive,
                   bool search_archives,
                   std::vector<std::filesystem::path>& direct_files,
                   std::vector<std::filesystem::path>& archives,
                   std::uint64_t& nested_archives_skipped,
                   std::map<std::string, std::uint64_t>& not_read) {
  std::error_code error;
  if (std::filesystem::is_regular_file(source, error)) {
    if (is_support_assist_generated_path(source))
      return;
    if (search_archives && is_archive_path(source))
      archives.push_back(source);
    else if (is_candidate_log_path(source))
      direct_files.push_back(source);
    else
      ++not_read[not_read_kind(source)];
    return;
  }
  if (!std::filesystem::is_directory(source, error))
    return;
  if (recursive) {
    for (std::filesystem::recursive_directory_iterator iterator(
             source, std::filesystem::directory_options::skip_permission_denied, error),
         end;
         iterator != end;
         iterator.increment(error)) {
      if (error) {
        error.clear();
        continue;
      }
      if (iterator->is_directory(error)) {
        const std::string directory = ascii_lower(support_assist::path_to_utf8(iterator->path().filename()));
        if (directory == "supportassistreports" || directory == ".support-assist-log-cache" ||
            directory == ".support-assist-parser-cache" || directory == "out" ||
            directory == ".git") {
          iterator.disable_recursion_pending();
        }
        continue;
      }
      if (!iterator->is_regular_file(error))
        continue;
      if (is_support_assist_generated_path(iterator->path())) {
        // Environment Review reads the text files of SAT's Windows context; the event logs, traces
        // and registry exports collected with them are read by nothing, so they are counted.
        if (in_windows_support_context(iterator->path()) && !is_candidate_log_path(iterator->path()))
          ++not_read[not_read_kind(iterator->path())];
        continue;
      }
      if (search_archives && is_archive_path(iterator->path())) {
        // A directory review must behave like reviewing the equivalent outer
        // support ZIP: historical archives nested inside the evidence tree are
        // catalog history, not independent bundles to recursively expand. Only
        // archives placed directly in the user-selected directory are treated
        // as separate archive inputs.
        std::error_code relative_error;
        const auto relative = std::filesystem::relative(iterator->path(), source, relative_error);
        if (!relative_error && relative.has_parent_path() && !relative.parent_path().empty()) {
          ++nested_archives_skipped;
          continue;
        }
        archives.push_back(iterator->path());
      } else if (is_candidate_log_path(iterator->path())) {
        direct_files.push_back(iterator->path());
      } else {
        ++not_read[not_read_kind(iterator->path())];
      }
    }
  } else {
    for (std::filesystem::directory_iterator iterator(
             source, std::filesystem::directory_options::skip_permission_denied, error),
         end;
         iterator != end;
         iterator.increment(error)) {
      if (error) {
        error.clear();
        continue;
      }
      if (!iterator->is_regular_file(error) || is_support_assist_generated_path(iterator->path()))
        continue;
      if (search_archives && is_archive_path(iterator->path()))
        archives.push_back(iterator->path());
      else if (is_candidate_log_path(iterator->path()))
        direct_files.push_back(iterator->path());
      else
        ++not_read[not_read_kind(iterator->path())];
    }
  }
}

#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
class ScopedArchiveReader {
public:
  ScopedArchiveReader() : value_(archive_read_new()) {}
  ~ScopedArchiveReader() {
    if (value_)
      archive_read_free(value_);
  }
  ScopedArchiveReader(const ScopedArchiveReader&) = delete;
  ScopedArchiveReader& operator=(const ScopedArchiveReader&) = delete;
  [[nodiscard]] archive* get() const noexcept {
    return value_;
  }

private:
  archive* value_ = nullptr;
};

// Windows applies MAX_PATH to the extraction path. 240 leaves headroom for the ".partial" style
// suffixes and separators a future change might add, without being so tight that the readable
// mirrored layout is abandoned in ordinary cases.
constexpr std::size_t kWindowsExtractionPathLimit = 240U;

bool extraction_path_within_limit(const std::filesystem::path& path) {
#ifdef _WIN32
  return path.wstring().size() <= kWindowsExtractionPathLimit;
#else
  // POSIX bounds a single NAME at 255 and the total path far higher; the mirrored layout has never
  // been the constraint here, and shortening it on Linux would only make the two editions cache
  // the same bundle under different names.
  static_cast<void>(path);
  return true;
#endif
}

// Where an archive entry is extracted to.
//
// Normally this mirrors the entry's path inside the bundle, which makes the cache readable. When
// that would exceed the platform limit the entry is stored flat, under a digest of its
// bundle-relative path, keeping the extension so the parser still sees a .log. The engineer never
// reads this path - display_path carries "<archive>!<entry inside it>" and is built separately -
// so shortening it costs nothing the user can see, and it is only done when the alternative is
// failing to extract the entry at all.
std::filesystem::path bounded_extraction_path(const std::filesystem::path& archive_cache,
                                              const std::filesystem::path& entry_path) {
  const std::filesystem::path mirrored = archive_cache / entry_path;
  if (extraction_path_within_limit(mirrored)) {
    return mirrored;
  }
  const std::string relative = support_assist::generic_path_to_utf8(entry_path);
  std::string flattened = short_stable_digest(relative);
  const std::string extension = support_assist::path_to_utf8(entry_path.extension());
  // Bound the extension too: it comes from inside the archive and is not trusted to be short.
  flattened += extension.size() <= 8U ? extension : std::string(".log");
  return archive_cache / flattened;
}

bool archive_entry_path_safe(const std::filesystem::path& path) {
  if (path.is_absolute() || path.has_root_name() || path.has_root_directory())
    return false;
  for (const auto& component : path) {
    if (component == "..")
      return false;
  }
  return true;
}

std::string stable_source_fingerprint(const std::filesystem::path& source);

Result<std::vector<ReviewInputFile>> extract_archive_logs(
    const std::filesystem::path& archive_path,
    const std::filesystem::path& cache_directory,
    const VeeamLogReviewOptions& options,
    std::uint64_t& expanded_bytes,
    std::uint64_t& entry_count,
    std::uint64_t& candidate_entries,
    std::uint64_t& deferred_entries,
    std::uint64_t& cache_hits,
    std::uint64_t& unwritable_entries,
    std::string& first_unwritable_detail,
    std::vector<EvidenceCatalogPath>& catalog) {
  ScopedArchiveReader reader;
  if (!reader.get())
    return Result<std::vector<ReviewInputFile>>::failure(
        review_error("allocate archive reader", "Unable to allocate libarchive reader", archive_path));
  archive_read_support_filter_all(reader.get());
  archive_read_support_format_all(reader.get());
#ifdef _WIN32
  if (archive_read_open_filename_w(reader.get(), archive_path.wstring().c_str(), 128U * 1024U) !=
      ARCHIVE_OK) {
#else
  if (archive_read_open_filename(reader.get(), archive_path.string().c_str(), 128U * 1024U) !=
      ARCHIVE_OK) {
#endif
    const char* detail = archive_error_string(reader.get());
    return Result<std::vector<ReviewInputFile>>::failure(review_error(
        "open archive", detail ? detail : "Unable to open archive", archive_path));
  }
  std::vector<ReviewInputFile> files;
  std::size_t automatic_fallback_files = 0;
  // The archive's own folder is named after it so the cache can be read by eye. When the output
  // directory is deep enough that the name itself is what breaks the budget, fall back to the
  // fingerprint alone - still unique per archive, 60-odd characters shorter.
  const std::string fingerprint = stable_source_fingerprint(archive_path);

  // Budget against the path the filesystem will see, not the one that was typed.
  //
  // The cache directory comes from the output path. When that is relative - which is what a support
  // engineer types - the mirrored layout is measured short by the whole current directory, the
  // guard below decides it fits, and Windows then refuses the write. That cost 18 of 166 logs on a
  // real support ZIP, reported only as a parse-error count with no filenames.
  std::error_code absolute_error;
  std::filesystem::path resolved_cache = std::filesystem::absolute(cache_directory, absolute_error);
  if (absolute_error)
    resolved_cache = cache_directory;

  std::filesystem::path archive_cache =
      resolved_cache /
      (safe_file_component(support_assist::path_to_utf8(archive_path.filename())) + "_" + fingerprint);
  if (!extraction_path_within_limit(archive_cache / "1234567890abcdef.log")) {
    archive_cache = resolved_cache / fingerprint;
  }
  archive_entry* entry = nullptr;
  while (true) {
    const int status = archive_read_next_header(reader.get(), &entry);
    if (status == ARCHIVE_EOF)
      break;
    if (status != ARCHIVE_OK) {
      const char* detail = archive_error_string(reader.get());
      return Result<std::vector<ReviewInputFile>>::failure(review_error(
          "read archive entry", detail ? detail : "Unable to read archive entry", archive_path));
    }
    ++entry_count;
    if (entry_count > options.maximum_archive_entries) {
      return Result<std::vector<ReviewInputFile>>::failure(
          review_error("archive limit", "Archive entry limit exceeded", archive_path));
    }
    if (archive_entry_filetype(entry) != AE_IFREG) {
      archive_read_data_skip(reader.get());
      continue;
    }
    const char* raw_name = archive_entry_pathname_utf8(entry);
    if (!raw_name)
      raw_name = archive_entry_pathname(entry);
    const std::filesystem::path entry_path = raw_name ? std::filesystem::path(raw_name)
                                                      : std::filesystem::path("unnamed.log");
    if (!archive_entry_path_safe(entry_path) || !is_candidate_log_path(entry_path)) {
      archive_read_data_skip(reader.get());
      continue;
    }
    ++candidate_entries;
    const std::string display_path =
        support_assist::path_to_utf8(archive_path) + "!" + support_assist::generic_path_to_utf8(entry_path);
    std::string logical_bundle_key = normalized_source_path(support_assist::path_to_utf8(archive_path));
    std::string logical_bundle_display = support_assist::path_to_utf8(archive_path);
    if (const auto partition = logical_source_partition_component(entry_path)) {
      logical_bundle_key += "!source:" + ascii_lower(*partition);
      logical_bundle_display += "!" + *partition;
    }
    const la_int64_t entry_size = archive_entry_size(entry);
    bool index_candidate = !options.fast_index_first ||
                           is_fast_index_candidate(options.profile, display_path);
    if (!index_candidate && options.profile == VeeamReviewProfile::automatic) {
      index_candidate = automatic_fast_index_fallback_candidate(
          display_path,
          entry_size > 0 ? static_cast<std::uint64_t>(entry_size) : 0U,
          automatic_fallback_files);
    }
    const bool index_deferred = options.fast_index_first && !index_candidate;
    const bool selected_deferred = !options.fast_index_first &&
                                   !path_matches_selected_run(options, display_path);
    const bool deferred = index_deferred || selected_deferred;
    catalog.push_back(EvidenceCatalogPath{display_path,
                                          logical_bundle_key,
                                          logical_bundle_display,
                                          entry_size > 0 ? static_cast<std::uint64_t>(entry_size) : 0U,
                                          !deferred});
    if (deferred) {
      ++deferred_entries;
      archive_read_data_skip(reader.get());
      continue;
    }
    const std::filesystem::path destination = bounded_extraction_path(archive_cache, entry_path);
    // A per-entry problem skips THAT entry. It used to abort the whole archive, which threw away
    // every log already extracted beside it and left the review reporting an empty bundle.
    const auto skip_entry = [&](const std::string& reason) {
      ++unwritable_entries;
      if (first_unwritable_detail.empty()) {
        first_unwritable_detail = reason + ": " + support_assist::path_to_utf8(destination);
      }
      archive_read_data_skip(reader.get());
    };

    std::error_code directory_error;
    std::filesystem::create_directories(destination.parent_path(), directory_error);
    if (directory_error) {
      skip_entry(directory_error.message());
      continue;
    }
    if (options.use_persistent_parser_cache && entry_size >= 0) {
      std::error_code cache_error;
      const auto cached_size = std::filesystem::file_size(destination, cache_error);
      if (!cache_error && cached_size == static_cast<std::uint64_t>(entry_size)) {
        archive_read_data_skip(reader.get());
        ++cache_hits;
        files.push_back(ReviewInputFile{destination,
                                        display_path,
                                        logical_bundle_key,
                                        logical_bundle_display,
                                        {},
                                        {},
                                        true});
        continue;
      }
    }
    std::ofstream output(destination, std::ios::binary | std::ios::trunc);
    if (!output) {
      skip_entry("Unable to create extracted log");
      continue;
    }
    std::vector<char> buffer(128U * 1024U);
    bool write_failed = false;
    for (;;) {
      const la_ssize_t read = archive_read_data(reader.get(), buffer.data(), buffer.size());
      if (read == 0)
        break;
      if (read < 0) {
        const char* detail = archive_error_string(reader.get());
        return Result<std::vector<ReviewInputFile>>::failure(review_error(
            "extract archive entry", detail ? detail : "Unable to extract entry", archive_path));
      }
      expanded_bytes += static_cast<std::uint64_t>(read);
      if (expanded_bytes > options.maximum_archive_expanded_bytes) {
        return Result<std::vector<ReviewInputFile>>::failure(
            review_error("archive limit", "Archive expansion limit exceeded", archive_path));
      }
      output.write(buffer.data(), read);
      if (!output) {
        write_failed = true;
        break;
      }
    }
    if (write_failed) {
      // The partial file must not be left where the parser would read it as a complete log.
      output.close();
      std::error_code remove_error;
      std::filesystem::remove(destination, remove_error);
      ++unwritable_entries;
      if (first_unwritable_detail.empty()) {
        first_unwritable_detail =
            "Unable to write extracted log: " + support_assist::path_to_utf8(destination);
      }
      continue;
    }
    files.push_back(ReviewInputFile{destination,
                                    display_path,
                                    logical_bundle_key,
                                    logical_bundle_display,
                                    {},
                                    {},
                                    false});
  }
  return Result<std::vector<ReviewInputFile>>::success(std::move(files));
}
#endif

std::string stable_source_fingerprint(const std::filesystem::path& source) {
  std::error_code error;
  const std::string normalized = normalized_source_path(support_assist::path_to_utf8(source));
  std::uint64_t size = 0;
  if (std::filesystem::is_regular_file(source, error)) {
    error.clear();
    size = std::filesystem::file_size(source, error);
    if (error)
      size = 0;
  }
  error.clear();
  std::int64_t modified = 0;
  const auto write_time = std::filesystem::last_write_time(source, error);
  if (!error)
    modified = static_cast<std::int64_t>(write_time.time_since_epoch().count());

  // This is a cache identity fingerprint, not a cryptographic evidence hash.
  // It intentionally avoids reading multi-gigabyte bundles merely to decide if
  // an existing extracted parser cache can be reused.
  std::ostringstream material;
  material << normalized << '|' << size << '|' << modified;
  const std::string text = material.str();
  std::uint64_t hash = 1469598103934665603ULL;
  for (const char character : text) {
    const auto byte = static_cast<unsigned char>(character);
    hash ^= byte;
    hash *= 1099511628211ULL;
  }
  std::ostringstream output;
  output << std::hex << std::setfill('0') << std::setw(16) << hash;
  return output.str();
}

Status write_bundle_cache_index(VeeamLogReviewResult& review) {
  if (!review.persistent_cache_enabled || review.cache_directory.empty())
    return Status::success();
  std::error_code error;
  std::filesystem::create_directories(review.cache_directory, error);
  if (error)
    return Status::failure(review_error("create parser cache index", error.message(), review.cache_directory));

  review.cache_index_path = review.cache_directory / "bundle-index.json";
  std::filesystem::path temporary = review.cache_index_path;
  temporary += ".tmp";
  std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(review_error("write parser cache index", "Unable to create cache index", temporary));
  output << "{\n"
         << "  \"schema\": 1,\n"
         << "  \"support_assist_version\": \"" << json_escape(std::string(kVersion)) << "\",\n"
         << "  \"updated_utc\": \"" << json_escape(utc_now_iso8601()) << "\",\n"
         << "  \"profile\": \"" << json_escape(to_string(review.profile_used)) << "\",\n"
         << "  \"fast_index\": " << (review.fast_index_used ? "true" : "false") << ",\n"
         << "  \"bundles\": [\n";
  for (std::size_t index = 0; index < review.bundles.size(); ++index) {
    const auto& bundle = review.bundles[index];
    output << "    {\"source\":\"" << json_escape(bundle.source_path)
           << "\",\"display_name\":\"" << json_escape(bundle.display_name)
           << "\",\"fingerprint\":\"" << json_escape(bundle.source_fingerprint)
           << "\",\"bytes\":" << bundle.source_bytes
           << ",\"primary_machine\":\"" << json_escape(bundle.primary_machine_name)
           << "\",\"primary_machine_role\":\"" << json_escape(bundle.primary_machine_role)
           << "\",\"product\":\"" << json_escape(bundle.product_type)
           << "\",\"candidate_files\":" << bundle.candidate_files
           << ",\"indexed_files\":" << bundle.indexed_files
           << ",\"deferred_files\":" << bundle.deferred_files << "}"
           << (index + 1U == review.bundles.size() ? "\n" : ",\n");
  }
  output << "  ]\n}\n";
  output.close();
  if (!output)
    return Status::failure(review_error("write parser cache index", "Unable to flush cache index", temporary));

  std::filesystem::remove(review.cache_index_path, error);
  error.clear();
  std::filesystem::rename(temporary, review.cache_index_path, error);
  if (error) {
    std::filesystem::remove(temporary);
    return Status::failure(review_error("publish parser cache index", error.message(), review.cache_index_path));
  }
  return Status::success();
}

// Without an output path the report goes in SAT's own folder beside the executable, never beside
// the logs: on a customer machine those are Veeam's folders, a folder left there outlives SAT, and
// the next collection gathers it.
std::filesystem::path determine_output_directory(const VeeamLogReviewOptions& options) {
  if (!options.output_path.empty()) {
    if (ascii_lower(support_assist::path_to_utf8(options.output_path.extension())) == ".txt")
      return options.output_path.parent_path();
    return options.output_path;
  }
  return default_review_output_directory();
}

std::filesystem::path determine_report_path(const VeeamLogReviewOptions& options,
                                            const VeeamLogReviewResult& review) {
  if (!options.output_path.empty() &&
      ascii_lower(support_assist::path_to_utf8(options.output_path.extension())) == ".txt") {
    return options.output_path;
  }
  const std::filesystem::path directory = determine_output_directory(options);
  std::string machine = "UNKNOWN";
  if (review.machines.size() > 1U)
    machine = "MULTI_MACHINE_" + std::to_string(review.machines.size());
  else if (!review.machines.empty())
    machine = safe_file_component(review.machines.front().display_name);
  else if (review.machine.machine_name)
    machine = safe_file_component(review.machine.machine_name->value);
  return directory / (machine + "_Veeam_Log_Review_" + report_stamp() + ".txt");
}

int confidence_rank(ParserConfidence value) {
  switch (value) {
  case ParserConfidence::verified:
    return 3;
  case ParserConfidence::probable:
    return 2;
  case ParserConfidence::unconfirmed:
    return 1;
  }
  return 0;
}

void merge_evidence(std::optional<ReviewEvidence>& destination,
                    const std::optional<ReviewEvidence>& source) {
  if (!source)
    return;
  if (!destination || confidence_rank(source->confidence) > confidence_rank(destination->confidence))
    destination = source;
}

void merge_evidence_list(std::vector<ReviewEvidence>& destination,
                         const std::vector<ReviewEvidence>& source) {
  for (const auto& item : source) {
    const auto duplicate = std::find_if(destination.begin(), destination.end(), [&](const auto& existing) {
      return equals_folded(existing.value, item.value);
    });
    if (duplicate == destination.end())
      destination.push_back(item);
  }
}

void merge_machine_summary(VeeamMachineSummary& destination, const VeeamMachineSummary& source) {
  merge_evidence(destination.machine_name, source.machine_name);
  merge_evidence(destination.host_name, source.host_name);
  merge_evidence(destination.primary_ip, source.primary_ip);
  merge_evidence(destination.operating_system, source.operating_system);
  merge_evidence(destination.cpu_logical_processors, source.cpu_logical_processors);
  merge_evidence(destination.product_version, source.product_version);
  merge_evidence(destination.assembly_version, source.assembly_version);
  merge_evidence(destination.management_mode, source.management_mode);
  merge_evidence(destination.management_server, source.management_server);
  merge_evidence_list(destination.plugin_accounts, source.plugin_accounts);
  merge_evidence(destination.culture, source.culture);
  merge_evidence(destination.utc_time, source.utc_time);
  merge_evidence(destination.private_fix, source.private_fix);
  merge_evidence_list(destination.license_modes, source.license_modes);
  merge_evidence_list(destination.alternate_ip_addresses, source.alternate_ip_addresses);
}

std::string machine_display_name(const VeeamMachineSummary& summary) {
  if (summary.machine_name && !summary.machine_name->value.empty())
    return summary.machine_name->value;
  if (summary.host_name && !summary.host_name->value.empty())
    return summary.host_name->value;
  if (summary.primary_ip && !summary.primary_ip->value.empty())
    return summary.primary_ip->value;
  return {};
}

std::string machine_key_from_name(std::string_view name) {
  std::string key = ascii_lower(trim_copy(name));
  std::replace_if(key.begin(), key.end(), [](char value) {
    return !(std::isalnum(static_cast<unsigned char>(value)) != 0 || value == '-' || value == '_' || value == '.');
  }, '_');
  return key.empty() ? std::string{} : "machine:" + key;
}

std::string machine_key_from_summary(const VeeamMachineSummary& summary) {
  return machine_key_from_name(machine_display_name(summary));
}

std::string normalized_source_path(std::string_view source) {
  std::string value = ascii_lower(source);
  std::replace(value.begin(), value.end(), '\\', '/');
  while (value.find("//") != std::string::npos)
    value.replace(value.find("//"), 2, "/");
  return value;
}

std::string source_parent(std::string_view source) {
  std::string value = normalized_source_path(source);
  const std::size_t archive_separator = value.find("::");
  const std::size_t slash = value.find_last_of('/');
  if (slash == std::string::npos || (archive_separator != std::string::npos && slash < archive_separator + 2U))
    return value;
  return value.substr(0, slash + 1U);
}

void append_unique(std::vector<std::string>& values, std::string value) {
  if (value.empty())
    return;
  if (std::find(values.begin(), values.end(), value) == values.end())
    values.push_back(std::move(value));
}

std::string make_run_key(const VeeamJobSession& session, std::size_t fallback_index) {
  const std::string machine = session.machine_key.empty() ? "machine:unknown" : session.machine_key;
  if (!session.session_id.empty())
    return machine + "|session:" + ascii_lower(session.session_id);
  std::ostringstream output;
  output << machine << "|job:" << ascii_lower(session.job_id.empty() ? session.job_name : session.job_id)
         << "|start:" << session.start_utc_ms.value_or(0) << "|source:"
         << normalized_source_path(session.source_path) << "|index:" << fallback_index;
  return output.str();
}

void merge_job_settings(VeeamJobSettings& destination, const VeeamJobSettings& source) {
  auto assign = [](std::string& target, const std::string& value) {
    if (target.empty() && !value.empty())
      target = value;
  };
  assign(destination.backup_mode, source.backup_mode);
  assign(destination.job_description, source.job_description);
  assign(destination.destination_type, source.destination_type);
  assign(destination.destination_path, source.destination_path);
  assign(destination.backup_server, source.backup_server);
  assign(destination.backup_repository, source.backup_repository);
  assign(destination.retention, source.retention);
  assign(destination.compression, source.compression);
  assign(destination.storage_optimization, source.storage_optimization);
  assign(destination.encryption, source.encryption);
  assign(destination.gfs, source.gfs);
  assign(destination.backup_cache, source.backup_cache);
  assign(destination.schedule, source.schedule);
  assign(destination.created_by, source.created_by);
  assign(destination.created_at, source.created_at);
  assign(destination.vss_snapshot, source.vss_snapshot);
  assign(destination.application_processing, source.application_processing);
  assign(destination.guest_indexing, source.guest_indexing);
  assign(destination.script_processing, source.script_processing);
  assign(destination.command_line, source.command_line);
  if (destination.settings_lines.empty() && !source.settings_lines.empty()) {
    destination.settings_source_path = source.settings_source_path;
    destination.settings_materialized_path = source.settings_materialized_path;
    destination.settings_start_line = source.settings_start_line;
    destination.settings_end_line = source.settings_end_line;
    destination.settings_lines = source.settings_lines;
  }
  assign(destination.source_backup_mode, source.source_backup_mode);
  assign(destination.repository_operation, source.repository_operation);
  assign(destination.resulting_backup_type, source.resulting_backup_type);
  assign(destination.task_total_size, source.task_total_size);
  for (const auto& item : source.included_items)
    append_unique(destination.included_items, item);
  for (const auto& item : source.excluded_items)
    append_unique(destination.excluded_items, item);
}

bool same_raw_evidence(const VeeamRawEvidence& left, const VeeamRawEvidence& right) {
  return left.source_path == right.source_path && left.line_number == right.line_number &&
         left.raw_line == right.raw_line;
}

void merge_raw_evidence(std::vector<VeeamRawEvidence>& destination,
                        const std::vector<VeeamRawEvidence>& source) {
  for (const auto& evidence : source) {
    const bool exists = std::any_of(destination.begin(), destination.end(), [&](const auto& item) {
      return same_raw_evidence(item, evidence);
    });
    if (!exists)
      destination.push_back(evidence);
  }
}

bool same_extent(const VeeamDiskExtentEvidence& left, const VeeamDiskExtentEvidence& right) {
  return left.disk_number == right.disk_number && left.offset_bytes == right.offset_bytes &&
         left.length_bytes == right.length_bytes &&
         same_raw_evidence(left.evidence, right.evidence);
}

void merge_extents(std::vector<VeeamDiskExtentEvidence>& destination,
                   const std::vector<VeeamDiskExtentEvidence>& source) {
  for (const auto& extent : source) {
    const bool exists = std::any_of(destination.begin(), destination.end(), [&](const auto& item) {
      return same_extent(item, extent);
    });
    if (!exists)
      destination.push_back(extent);
  }
}

void merge_vss_provider(VeeamVssProviderInfo& destination, const VeeamVssProviderInfo& source) {
  if (destination.provider_id.empty())
    destination.provider_id = source.provider_id;
  if (destination.name.empty())
    destination.name = source.name;
  if (destination.type.empty())
    destination.type = source.type;
  merge_raw_evidence(destination.evidence, source.evidence);
}

void merge_snapshot_volume(VeeamVolumeSnapshotInfo& destination,
                           const VeeamVolumeSnapshotInfo& source) {
  if (destination.volume_id.empty())
    destination.volume_id = source.volume_id;
  if (destination.mount_point.empty())
    destination.mount_point = source.mount_point;
  if (destination.file_system.empty())
    destination.file_system = source.file_system;
  if (destination.dos_name.empty())
    destination.dos_name = source.dos_name;
  if (destination.explicit_size_bytes == 0U)
    destination.explicit_size_bytes = source.explicit_size_bytes;
  if (destination.requested_provider_id.empty())
    destination.requested_provider_id = source.requested_provider_id;
  if (destination.used_provider_id.empty())
    destination.used_provider_id = source.used_provider_id;
  if (destination.used_provider_name.empty())
    destination.used_provider_name = source.used_provider_name;
  if (destination.used_provider_type.empty())
    destination.used_provider_type = source.used_provider_type;
  destination.included_in_snapshot = destination.included_in_snapshot || source.included_in_snapshot;
  merge_extents(destination.extents, source.extents);
  merge_raw_evidence(destination.evidence, source.evidence);
}

void merge_job_session(VeeamJobSession& destination, const VeeamJobSession& source) {
  auto assign = [](std::string& target, const std::string& value) {
    if (target.empty() && !value.empty())
      target = value;
  };
  assign(destination.machine_key, source.machine_key);
  assign(destination.machine_name, source.machine_name);
  assign(destination.job_name, source.job_name);
  assign(destination.job_id, source.job_id);
  assign(destination.session_id, source.session_id);
  assign(destination.task_session_id, source.task_session_id);
  assign(destination.job_mode, source.job_mode);
  assign(destination.job_type, source.job_type);
  assign(destination.status, source.status);
  assign(destination.restore_point_id, source.restore_point_id);
  assign(destination.restore_point_type, source.restore_point_type);
  assign(destination.backup_file, source.backup_file);
  if ((!destination.start_utc_ms || (source.start_utc_ms && *source.start_utc_ms < *destination.start_utc_ms))) {
    destination.start_utc_ms = source.start_utc_ms;
    destination.start_timestamp_original = source.start_timestamp_original;
    destination.start_line = source.start_line;
    destination.source_path = source.source_path;
    destination.materialized_path = source.materialized_path;
  }
  if ((!destination.completion_utc_ms ||
       (source.completion_utc_ms && *source.completion_utc_ms > *destination.completion_utc_ms))) {
    destination.completion_utc_ms = source.completion_utc_ms;
    destination.completion_timestamp_original = source.completion_timestamp_original;
    destination.completion_line = source.completion_line;
  }
  merge_job_settings(destination.settings, source.settings);
  destination.pex_samples.insert(destination.pex_samples.end(), source.pex_samples.begin(), source.pex_samples.end());
  merge_raw_evidence(destination.volume_evidence, source.volume_evidence);
  merge_extents(destination.disk_extents, source.disk_extents);
  merge_raw_evidence(destination.management_events, source.management_events);

  for (const auto& incoming : source.vss_providers) {
    const std::string incoming_id = normalize_volume_id(incoming.provider_id);
    auto found = std::find_if(destination.vss_providers.begin(), destination.vss_providers.end(),
                              [&](const auto& provider) {
                                return normalize_volume_id(provider.provider_id) == incoming_id;
                              });
    if (found == destination.vss_providers.end())
      destination.vss_providers.push_back(incoming);
    else
      merge_vss_provider(*found, incoming);
  }

  for (const auto& incoming : source.snapshot_volumes) {
    const std::string incoming_id = normalize_volume_id(incoming.volume_id);
    const std::string incoming_mount = ascii_lower(normalize_mount_point(incoming.mount_point));
    auto found = std::find_if(destination.snapshot_volumes.begin(), destination.snapshot_volumes.end(),
                              [&](const auto& volume) {
                                const bool id_match = !incoming_id.empty() &&
                                    normalize_volume_id(volume.volume_id) == incoming_id;
                                const bool mount_match = !incoming_mount.empty() &&
                                    ascii_lower(normalize_mount_point(volume.mount_point)) == incoming_mount;
                                return id_match || mount_match;
                              });
    if (found == destination.snapshot_volumes.end())
      destination.snapshot_volumes.push_back(incoming);
    else
      merge_snapshot_volume(*found, incoming);
  }

  assign(destination.used_vss_provider_id, source.used_vss_provider_id);
  assign(destination.used_vss_provider_name, source.used_vss_provider_name);
  assign(destination.used_vss_provider_type, source.used_vss_provider_type);

  if (!destination.used_vss_provider_id.empty()) {
    if (const auto* provider = find_provider(destination, destination.used_vss_provider_id)) {
      if (destination.used_vss_provider_name.empty())
        destination.used_vss_provider_name = provider->name;
      if (destination.used_vss_provider_type.empty())
        destination.used_vss_provider_type = provider->type;
      for (auto& volume : destination.snapshot_volumes) {
        if (!volume.included_in_snapshot || !volume.used_provider_id.empty())
          continue;
        volume.used_provider_id = destination.used_vss_provider_id;
        volume.used_provider_name = destination.used_vss_provider_name;
        volume.used_provider_type = destination.used_vss_provider_type;
      }
    }
  }
}

void carry_forward_job_details(std::vector<VeeamJobSession>& sessions) {
  std::map<std::pair<std::string, std::string>, std::vector<std::size_t>> groups;
  for (std::size_t index = 0; index < sessions.size(); ++index) {
    groups[{sessions[index].machine_key, normalized_source_path(sessions[index].source_path)}].push_back(index);
  }
  for (auto& [key, indices] : groups) {
    static_cast<void>(key);
    std::stable_sort(indices.begin(), indices.end(), [&](std::size_t left, std::size_t right) {
      const auto& lhs = sessions[left];
      const auto& rhs = sessions[right];
      if (lhs.start_utc_ms && rhs.start_utc_ms)
        return *lhs.start_utc_ms < *rhs.start_utc_ms;
      return lhs.start_line < rhs.start_line;
    });
    std::string last_job_name;
    std::string last_job_id;
    std::string last_job_type;
    VeeamJobSettings last_settings;
    for (const std::size_t index : indices) {
      auto& session = sessions[index];
      const bool identity_changed = !session.job_id.empty() && !last_job_id.empty() &&
                                    !equals_folded(session.job_id, last_job_id);
      if (identity_changed) {
        last_job_name.clear();
        last_job_type.clear();
        last_settings = {};
      }
      if (!session.job_name.empty())
        last_job_name = session.job_name;
      else
        session.job_name = last_job_name;
      if (!session.job_id.empty())
        last_job_id = session.job_id;
      else
        session.job_id = last_job_id;
      if (!session.job_type.empty())
        last_job_type = session.job_type;
      else
        session.job_type = last_job_type;
      if (!session.settings.backup_mode.empty() || !session.settings.destination_path.empty() ||
          !session.settings.included_items.empty() || !session.settings.source_backup_mode.empty() ||
          !session.settings.repository_operation.empty() || !session.settings.task_total_size.empty()) {
        last_settings = session.settings;
      } else {
        session.settings = last_settings;
      }
    }
  }

  sessions.erase(std::remove_if(sessions.begin(), sessions.end(), [](const auto& session) {
                   return session.start_line == 0U && session.session_id.empty() &&
                          session.job_id.empty() && session.job_name.empty();
                 }),
                 sessions.end());

  std::vector<VeeamJobSession> merged;
  merged.reserve(sessions.size());
  std::unordered_map<std::string, std::size_t> session_indexes;
  session_indexes.reserve(sessions.size());
  for (const auto& session : sessions) {
    if (!session.session_id.empty()) {
      const std::string key = session.machine_key + "|" + ascii_lower(session.session_id);
      const auto found = session_indexes.find(key);
      if (found != session_indexes.end()) {
        merge_job_session(merged[found->second], session);
        continue;
      }
      session_indexes.emplace(key, merged.size());
    }
    merged.push_back(session);
  }
  sessions = std::move(merged);
  for (std::size_t index = 0; index < sessions.size(); ++index)
    sessions[index].run_key = make_run_key(sessions[index], index);
  std::stable_sort(sessions.begin(), sessions.end(), [](const auto& left, const auto& right) {
    const auto left_time = left.start_utc_ms.value_or(0);
    const auto right_time = right.start_utc_ms.value_or(0);
    if (left_time != right_time)
      return left_time > right_time;
    return left.run_key < right.run_key;
  });
}


std::string classify_related_activity_type(const VeeamJobSession& session) {
  const std::string folded = ascii_lower(session.job_name + " " + session.job_type + " " + session.source_path);
  if (folded.find("retention") != std::string::npos)
    return "Retention / restore-point maintenance";
  if (folded.find("deployer") != std::string::npos || folded.find("deploy") != std::string::npos)
    return "Deployment / component management";
  if (folded.find("databasesynchronizer") != std::string::npos ||
      folded.find("database synchron") != std::string::npos)
    return "Database synchronization";
  if (folded.find("healthcheck") != std::string::npos || folded.find("health check") != std::string::npos)
    return "Health check";
  if (folded.find("deletebackup") != std::string::npos || folded.find("delete backup") != std::string::npos)
    return "Backup deletion / cleanup";
  if (folded.find("backup copy") != std::string::npos)
    return "Backup Copy activity";
  if (folded.find("application aware") != std::string::npos ||
      folded.find("application-aware") != std::string::npos)
    return "Application-aware processing";
  if (folded.find("rescan") != std::string::npos)
    return "Infrastructure rescan";
  if (folded.find("config") != std::string::npos)
    return "Configuration / control activity";
  return "VBR / infrastructure activity";
}

void classify_review_sessions(VeeamLogReviewResult& review,
                              const VeeamLogReviewOptions& options) {
  if (options.profile == VeeamReviewProfile::vbr) {
    for (auto& session : review.job_sessions) {
      if (session.protection_group_rescan || session.run_kind == "rescan" ||
          session.run_kind == "rescan-index") {
        session.run_kind = "rescan";
        session.job_type = "Protection Group / infrastructure rescan";
        continue;
      }

      const std::string folded = ascii_lower(session.job_name + " " + session.job_type + " " +
                                             session.source_path);
      const VeeamEvidenceRole role = classify_veeam_evidence_role(session.source_path);
      const bool maintenance =
          folded.find("bestpractices") != std::string::npos ||
          folded.find("database_maintenance") != std::string::npos ||
          folded.find("databasemaintenance") != std::string::npos ||
          folded.find("database maintenance") != std::string::npos ||
          folded.find("retention") != std::string::npos ||
          folded.find("healthcheck") != std::string::npos ||
          folded.find("health check") != std::string::npos ||
          folded.find("deletebackup") != std::string::npos ||
          folded.find("database resynchron") != std::string::npos ||
          folded.find("databaseresynchronizer") != std::string::npos ||
          folded.find("publishbackuplifecycle") != std::string::npos ||
          folded.find("backup_configuration") != std::string::npos ||
          folded.find("backup configuration") != std::string::npos ||
          folded.find("resource scan") != std::string::npos ||
          folded.find("resourcescan") != std::string::npos ||
          role == VeeamEvidenceRole::service || role == VeeamEvidenceRole::system ||
          role == VeeamEvidenceRole::repository_operation;

      if (maintenance) {
        session.run_kind = "activity";
        session.job_type = classify_related_activity_type(session);
        continue;
      }

      if (role == VeeamEvidenceRole::task) {
        session.run_kind = "activity";
        session.job_type = "Job task / workload processing";
        continue;
      }

      if (folded.find("backupsync") != std::string::npos ||
          folded.find("backup copy") != std::string::npos) {
        session.run_kind = session.index_only ? "backup-index" : "backup";
        session.job_type = "Backup Copy job";
      } else if (folded.find("replica") != std::string::npos ||
                 folded.find("replication") != std::string::npos) {
        session.run_kind = session.index_only ? "backup-index" : "backup";
        session.job_type = "Replication job";
      } else if (role == VeeamEvidenceRole::job) {
        session.run_kind = session.index_only ? "backup-index" : "backup";
        if (session.job_type.empty() || contains_folded(session.job_type, "evidence-only"))
          session.job_type = "Backup / protection job";
      } else {
        session.run_kind = "activity";
        session.job_type = classify_related_activity_type(session);
      }
    }
    return;
  }

  if (options.profile != VeeamReviewProfile::vaw &&
      options.profile != VeeamReviewProfile::automatic)
    return;

  for (auto& session : review.job_sessions) {
    if (session.protection_group_rescan || session.run_kind == "rescan" ||
        session.run_kind == "rescan-index") {
      session.run_kind = "rescan";
      session.job_type = "Infrastructure / Protection Group Rescan";
      continue;
    }

    const auto from_vbr_bundle = std::find_if(
        review.bundles.begin(), review.bundles.end(), [&](const auto& bundle) {
          return bundle.product_type == "Veeam Backup & Replication" &&
                 !bundle.source_path.empty() &&
                 session.source_path.starts_with(bundle.source_path);
        });
    if (from_vbr_bundle != review.bundles.end()) {
      session.run_kind = "activity";
      session.job_type = classify_related_activity_type(session);
      continue;
    }

    const std::string path = folded_path_name(session.source_path);
    const bool direct_job_backup_log =
        path.find("job.backup.log") != std::string::npos &&
        path.find("job.backup_deployer") == std::string::npos &&
        path.find("job.backup_rpc") == std::string::npos;
    const bool vaw_settings_signature =
        contains_folded(session.settings.destination_type, "veeam agent for microsoft windows") ||
        contains_folded(session.settings.command_line, "veeam.endpoint.manager") ||
        (!session.settings.backup_mode.empty() &&
         (!session.settings.source_backup_mode.empty() || !session.settings.settings_lines.empty() ||
          !session.settings.destination_type.empty() || !session.settings.destination_path.empty()));
    const bool endpoint_job_path = direct_job_backup_log &&
                                   (is_vaw_endpoint_identity_path(path) || vaw_settings_signature);

    if (endpoint_job_path || vaw_settings_signature) {
      session.run_kind = session.index_only ? "backup-index" : "backup";
      if (session.job_type.empty() || contains_folded(session.job_type, "evidence-only"))
        session.job_type = "VAW backup job";
      continue;
    }

    // VBR/service logs included alongside a VAW bundle are useful related
    // evidence, but they are not customer backup jobs.  Keep them visible with
    // an explicit activity category so the Job selector and case counts do not
    // misrepresent them as backup runs.
    session.run_kind = "activity";
    session.job_type = classify_related_activity_type(session);
  }
}


bool is_backup_run_record(const VeeamJobSession& session) {
  return !session.protection_group_rescan && session.run_kind != "activity" &&
         session.run_kind != "rescan" && session.run_kind != "rescan-index";
}

bool is_rescan_record(const VeeamJobSession& session) {
  return session.protection_group_rescan || session.run_kind == "rescan" ||
         session.run_kind == "rescan-index";
}


struct FileParseOutcome {
  ReviewInputFile file;
  VeeamLogReviewResult review;
  std::uint64_t size_bytes = 0;
  std::uint64_t lines = 0;
  double elapsed_seconds = 0.0;
  std::optional<Error> error;
  std::string machine_key;
  std::string machine_name;
  std::string machine_role;
};

std::string synthetic_machine_key(std::string_view source) {
  const std::string parent = source_parent(source);
  const std::size_t slash = parent.find_last_of('/', parent.empty() ? 0U : parent.size() - 2U);
  const std::string leaf = slash == std::string::npos ? parent : parent.substr(slash + 1U);
  std::string key = machine_key_from_name(leaf);
  return key.empty() ? "machine:unknown" : "source-" + key;
}

void assign_machine_keys(std::vector<FileParseOutcome>& outcomes,
                         const VeeamLogReviewOptions& options,
                         VeeamLogReviewResult& review) {
  struct Candidate {
    std::string key;
    std::string name;
    int score = 0;
    std::size_t count = 0;
  };

  std::map<std::string, std::map<std::string, Candidate>> bundle_candidates;
  std::map<std::string, std::vector<std::size_t>> bundle_indices;
  std::set<std::string> strong_vbr_bundles;
  std::set<std::string> vbr_backup_server_bundles;
  // Bundles collected FROM a backup server, as opposed to bundles that merely mention one.
  // VBR writes its service logs to C:/ProgramData/Veeam/Backup, so the server's own evidence
  // arrives under a "Backup" directory; VBR logs swept into someone else's collection do not.
  std::set<std::string> vbr_server_root_bundles;

  // SAT collection manifests describe the product/source the collection was
  // created for. A VAW collection can intentionally include VBR service,
  // repository and plug-in evidence, so those related logs must not hijack the
  // source-owner role when Auto Detect is used.
  std::map<std::string, std::string> manifest_product_by_bundle;
  for (const auto& outcome : outcomes) {
    if (folded_path_name(outcome.file.display_path).find("collection-manifest.json") == std::string::npos)
      continue;
    const std::string bundle = outcome.file.bundle_key.empty()
                                   ? source_parent(outcome.file.display_path)
                                   : outcome.file.bundle_key;
    if (!outcome.review.product_type.empty() &&
        outcome.review.product_type.find("product logs") == std::string::npos)
      manifest_product_by_bundle[bundle] = outcome.review.product_type;
  }
  const auto manifest_product = [&](const std::string& bundle) -> std::string {
    const auto found = manifest_product_by_bundle.find(bundle);
    return found == manifest_product_by_bundle.end() ? std::string{} : found->second;
  };

  if (options.profile == VeeamReviewProfile::vaw) {
    for (const auto& outcome : outcomes) {
      const std::string bundle = outcome.file.bundle_key.empty()
                                     ? source_parent(outcome.file.display_path)
                                     : outcome.file.bundle_key;
      const std::string source = outcome.file.bundle_display_path.empty()
                                     ? outcome.file.display_path
                                     : outcome.file.bundle_display_path;
      if (is_strong_vbr_source_path(source))
        strong_vbr_bundles.insert(bundle);
    }
  }

  for (std::size_t index = 0; index < outcomes.size(); ++index) {
    auto& outcome = outcomes[index];
    outcome.machine_name = machine_display_name(outcome.review.machine);
    outcome.machine_key = machine_key_from_summary(outcome.review.machine);
    const std::string bundle = outcome.file.bundle_key.empty()
                                   ? source_parent(outcome.file.display_path)
                                   : outcome.file.bundle_key;
    bundle_indices[bundle].push_back(index);

    const VeeamEvidenceRole identity_role = classify_veeam_evidence_role(outcome.file.display_path);
    const std::string identity_path = folded_path_name(outcome.file.display_path);
    const std::string declared_product = manifest_product(bundle);
    const bool declared_vbr = declared_product == "Veeam Backup & Replication";
    const bool declared_non_vbr = !declared_product.empty() && !declared_vbr;
    if ((options.profile == VeeamReviewProfile::vbr ||
         (options.profile == VeeamReviewProfile::automatic && !declared_non_vbr)) &&
        identity_path.find("svc.veeambackup") != std::string::npos) {
      // The Svc.VeeamBackup file family is itself product/source-owner evidence.
      // Do not require the individual service-log fragment to contain a machine
      // header before identifying the bundle as VBR; rotated fragments often do
      // not repeat that metadata. A non-VBR SAT collection manifest still wins.
      vbr_backup_server_bundles.insert(bundle);
      std::string located = identity_path;
      std::replace(located.begin(), located.end(), '\\', '/');
      if (located.find("/backup/") != std::string::npos)
        vbr_server_root_bundles.insert(bundle);
    }

    if (outcome.machine_key.empty())
      continue;
    if (options.profile == VeeamReviewProfile::vaw && strong_vbr_bundles.contains(bundle))
      continue;
    if ((options.profile == VeeamReviewProfile::vaw ||
         options.profile == VeeamReviewProfile::automatic) &&
        (identity_role == VeeamEvidenceRole::setup ||
         identity_role == VeeamEvidenceRole::rpc_control ||
         folded_path_name(outcome.file.display_path).find("deployer") != std::string::npos)) {
      // Installer/deployer/RPC logs can name a historical or remote target.
      // Preserve the file as evidence, but never let it establish the primary
      // VAW endpoint identity by itself.
      continue;
    }

    auto& candidate = bundle_candidates[bundle][outcome.machine_key];
    candidate.key = outcome.machine_key;
    if (!outcome.machine_name.empty())
      candidate.name = outcome.machine_name;
    ++candidate.count;

    const std::string path = folded_path_name(outcome.file.display_path);
    int score = 10;
    if (path.find("collection-manifest.json") != std::string::npos)
      score += 1000;
    const bool auto_declared_vaw = options.profile == VeeamReviewProfile::automatic &&
                                   declared_product == "Veeam Agent for Microsoft Windows";
    const bool auto_without_manifest = options.profile == VeeamReviewProfile::automatic && declared_product.empty();
    if (options.profile == VeeamReviewProfile::vaw || auto_declared_vaw || auto_without_manifest) {
      if (path.find("svc.veeamendpointbackup") != std::string::npos)
        score += 1800;
      if (path.find("job.veeamendpointbackup") != std::string::npos)
        score += 900;
      if (path.find("/1-endpoint/") != std::string::npos)
        score += 500;
    }
    const bool auto_declared_vbr = options.profile == VeeamReviewProfile::automatic && declared_vbr;
    if (options.profile == VeeamReviewProfile::vbr || auto_declared_vbr || auto_without_manifest) {
      if (path.find("svc.veeambackup") != std::string::npos)
        score += 1600;
      if (path.find("/backup/") != std::string::npos && path.find("/agent.") == std::string::npos)
        score += 200;
    }
    if (options.profile == VeeamReviewProfile::sql_plugin) {
      if (path.find("mssqlpluginbackup") != std::string::npos ||
          path.find("mssqlvbrcommunicationmanager") != std::string::npos)
        score += 500;
    }
    candidate.score = std::max(candidate.score, score);
  }

  std::map<std::string, std::pair<std::string, std::string>> primary_by_bundle;
  for (const auto& [bundle, candidates] : bundle_candidates) {
    const Candidate* best = nullptr;
    for (const auto& [key, candidate] : candidates) {
      static_cast<void>(key);
      if (best == nullptr || candidate.score > best->score ||
          (candidate.score == best->score && candidate.count > best->count) ||
          (candidate.score == best->score && candidate.count == best->count &&
           candidate.key < best->key)) {
        best = &candidate;
      }
    }
    if (best != nullptr)
      primary_by_bundle[bundle] = {best->key, best->name};
  }

  // A SAT-created archive/collection represents one primary endpoint. Apply the
  // strongest bundle identity to every file in that archive/manifested collection.
  // A plain directory may intentionally aggregate logs from several machines and
  // therefore must retain per-file identities unless it contains a SAT manifest.
  std::set<std::string> single_primary_bundles;
  if (options.one_source_one_primary_machine && options.profile != VeeamReviewProfile::generic) {
    for (const auto& [bundle, indices] : bundle_indices) {
      bool single_primary = false;
      for (const std::size_t index : indices) {
        const auto& file = outcomes[index].file;
        const std::string source = file.bundle_display_path.empty() ? bundle : file.bundle_display_path;
        const std::string folded_file = folded_path_name(file.display_path);
        if (is_archive_path(support_assist::path_from_utf8(source)) ||
            folded_file.find("collection-manifest.json") != std::string::npos ||
            ((options.profile == VeeamReviewProfile::vaw ||
              options.profile == VeeamReviewProfile::automatic) &&
             folded_file.find("/1-endpoint/") != std::string::npos) ||
            ((options.profile == VeeamReviewProfile::vbr ||
              options.profile == VeeamReviewProfile::automatic) &&
             vbr_backup_server_bundles.contains(bundle))) {
          single_primary = true;
          break;
        }
      }
      if (single_primary)
        single_primary_bundles.insert(bundle);
    }
  }
  struct ProductAuthority {
    std::string product;
    ParserConfidence confidence = ParserConfidence::unconfirmed;
    int score = 0;
  };
  std::map<std::string, ProductAuthority> product_authority_by_bundle;
  for (const auto& [bundle, indices] : bundle_indices) {
    ProductAuthority best;
    const std::string declared = manifest_product(bundle);
    if (!declared.empty())
      best = ProductAuthority{declared, ParserConfidence::verified, 10000};

    for (const auto index : indices) {
      if (index >= outcomes.size())
        continue;
      const auto& outcome = outcomes[index];
      const auto& observed = outcome.review;
      if (observed.product_type.empty() ||
          observed.product_type.find("product logs") != std::string::npos)
        continue;
      const std::string path = folded_path_name(outcome.file.display_path);
      int score = confidence_rank(observed.product_confidence) * 100;
      if (observed.product_type == "Veeam Agent for Microsoft Windows" &&
          is_vaw_endpoint_identity_path(path)) {
        // In a bundle collected from a backup server, these Endpoint logs belong to the agents that
        // server manages - they are its cargo, not its identity. Withholding the bonus there lets
        // the server's own evidence win its own bundle.
        //
        // Only there. A VAW collection that swept up related VBR service logs keeps the bonus,
        // which is the whole reason the bonus exists.
        if (!vbr_server_root_bundles.contains(bundle))
          score += 900;
      }
      else if (observed.product_type == "Veeam Plug-in for Microsoft SQL Server" &&
               path.find("mssqlplugin") != std::string::npos)
        score += 850;
      else if (observed.product_type == "Veeam Plug-in for Oracle RMAN" &&
               path.find("rman") != std::string::npos)
        score += 850;
      else if (observed.product_type == "Veeam Agent for Linux" ||
               observed.product_type == "Veeam Agent for Mac" ||
               observed.product_type == "Veeam Agent for IBM AIX" ||
               observed.product_type == "Veeam Agent for Oracle Solaris")
        score += 800;
      else if (observed.product_type == "Veeam Backup & Replication" &&
               path.find("svc.veeambackup") != std::string::npos)
        score += 700;

      // A verified protected-endpoint identity outranks related VBR service or
      // transport evidence contained in the same support bundle.  This is the
      // critical distinction between source-owner product and related product.
      if (score > best.score ||
          (score == best.score &&
           confidence_rank(observed.product_confidence) > confidence_rank(best.confidence))) {
        best = ProductAuthority{observed.product_type, observed.product_confidence, score};
      }
    }
    if (vbr_backup_server_bundles.contains(bundle) &&
        (best.score < 700 ||
         (best.product == "Veeam Backup & Replication" &&
          best.confidence != ParserConfidence::verified))) {
      best = ProductAuthority{"Veeam Backup & Replication", ParserConfidence::verified,
                              std::max(best.score, 700)};
    }
    if (!best.product.empty())
      product_authority_by_bundle[bundle] = std::move(best);
  }

  const auto source_owner_product = [&](const std::string& bundle) -> std::string {
    const auto found = product_authority_by_bundle.find(bundle);
    if (found != product_authority_by_bundle.end())
      return found->second.product;
    if (options.profile != VeeamReviewProfile::automatic &&
        options.profile != VeeamReviewProfile::generic)
      return expected_product_type(options.profile);
    return {};
  };

  const auto source_owner_role = [&](const std::string& bundle) -> std::string {
    const std::string product = source_owner_product(bundle);
    if (product == "Veeam Backup & Replication")
      return "Backup Server";
    if (product == "Veeam Agent for Microsoft Windows")
      return "Protected Machine - VAW";
    if (product == "Veeam Agent for Linux")
      return "Protected Machine - VAL";
    if (product == "Veeam Agent for Mac")
      return "Protected Machine - VAM";
    if (product == "Veeam Agent for IBM AIX")
      return "Protected Machine - AIX";
    if (product == "Veeam Agent for Oracle Solaris")
      return "Protected Machine - SOLARIS";
    if (product == "Veeam Plug-in for Microsoft SQL Server")
      return "SQL Plug-in Host";
    if (product == "Veeam Plug-in for Oracle RMAN")
      return "RMAN Plug-in Host";
    if (options.profile == VeeamReviewProfile::vaw)
      return "Protected Machine - VAW";
    if (options.profile == VeeamReviewProfile::sql_plugin)
      return "SQL Plug-in Host";
    if (options.profile == VeeamReviewProfile::rman_plugin)
      return "RMAN Plug-in Host";
    if (options.profile == VeeamReviewProfile::vbr)
      return "VBR Infrastructure Host";
    return "Source Machine";
  };

  std::set<std::string> global_known;
  std::map<std::string, std::string> global_known_names;
  for (const auto& [bundle, primary] : primary_by_bundle) {
    static_cast<void>(bundle);
    if (!primary.first.empty()) {
      global_known.insert(primary.first);
      if (!primary.second.empty())
        global_known_names[primary.first] = primary.second;
    }
  }

  for (auto& outcome : outcomes) {
    const std::string bundle = outcome.file.bundle_key.empty()
                                   ? source_parent(outcome.file.display_path)
                                   : outcome.file.bundle_key;
    if (options.profile == VeeamReviewProfile::vaw && strong_vbr_bundles.contains(bundle)) {
      // A VBR support bundle can contain the backup server's own Endpoint logs.
      // Under a VAW review that host is related infrastructure, not another
      // protected endpoint. Keep its evidence but attach it to the VAW case
      // context instead of exposing it as a second Agent machine.
      outcome.machine_key.clear();
      outcome.machine_name.clear();
    }
    const auto primary = primary_by_bundle.find(bundle);
    if (single_primary_bundles.contains(bundle) && primary != primary_by_bundle.end()) {
      outcome.machine_key = primary->second.first;
      outcome.machine_name = primary->second.second;
    } else if (outcome.machine_key.empty() && primary != primary_by_bundle.end()) {
      outcome.machine_key = primary->second.first;
      outcome.machine_name = primary->second.second;
    }
    if (outcome.machine_key.empty() && global_known.size() == 1U) {
      outcome.machine_key = *global_known.begin();
      const auto global_name = global_known_names.find(outcome.machine_key);
      if (global_name != global_known_names.end())
        outcome.machine_name = global_name->second;
    }
    if (outcome.machine_key.empty()) {
      if (options.profile == VeeamReviewProfile::generic) {
        outcome.machine_key = synthetic_machine_key(outcome.file.bundle_display_path.empty()
                                                        ? outcome.file.display_path
                                                        : outcome.file.bundle_display_path);
      } else {
        // Product-specific parsers must not manufacture a new machine from an
        // archive/folder name. Unresolved supporting evidence remains visibly
        // unassigned until a real endpoint identity can be correlated.
        outcome.machine_key = "machine:unassigned";
        outcome.machine_name = "Unassigned evidence";
      }
    }
    if (outcome.machine_name.empty()) {
      const auto found = primary_by_bundle.find(bundle);
      if (found != primary_by_bundle.end() && !found->second.second.empty())
        outcome.machine_name = found->second.second;
      else
        outcome.machine_name = "Unknown machine";
    }
    outcome.machine_role = source_owner_role(bundle);

    // Attribute the run and every incident line to the component whose log produced it.
    const std::string owning_component = primary_component_tag(outcome.file.display_path);
    for (auto& session : outcome.review.job_sessions) {
      session.machine_key = outcome.machine_key;
      session.machine_name = outcome.machine_name;
      if (session.component_tag.empty())
        session.component_tag = owning_component;
    }
    for (auto& incident : outcome.review.incidents) {
      for (auto& location : incident.locations) {
        location.machine_key = outcome.machine_key;
        location.machine_name = outcome.machine_name;
        if (location.component_tag.empty()) {
          // Prefer the location's own source when it has one: an incident merged from several
          // files must not inherit one file's component for all of its lines.
          location.component_tag = location.source_path.empty()
                                       ? owning_component
                                       : primary_component_tag(location.source_path);
        }
      }
    }
    for (auto& event : outcome.review.timeline_events)
      event.machine_key = outcome.machine_key;
  }

  review.bundles.clear();
  review.bundles.reserve(bundle_indices.size());
  for (const auto& [bundle, indices] : bundle_indices) {
    VeeamBundleSummary summary;
    summary.key = bundle;
    if (!indices.empty()) {
      const auto& first = outcomes[indices.front()];
      summary.source_path = first.file.bundle_display_path.empty() ? first.file.display_path
                                                                   : first.file.bundle_display_path;
      summary.display_name =
          support_assist::path_to_utf8(support_assist::path_from_utf8(summary.source_path).filename());
      if (summary.display_name.empty())
        summary.display_name = summary.source_path;
      const auto primary = primary_by_bundle.find(bundle);
      if (primary != primary_by_bundle.end()) {
        summary.primary_machine_key = primary->second.first;
        summary.primary_machine_name = primary->second.second;
        summary.primary_machine_role = source_owner_role(bundle);
      }
      const auto authority = product_authority_by_bundle.find(bundle);
      if (authority != product_authority_by_bundle.end()) {
        summary.product_type = authority->second.product;
        summary.product_confidence = authority->second.confidence;
      } else {
        // Parser profile is only a fallback interpretation hint. It must never
        // overwrite a verified source-owner product discovered in the evidence.
        summary.product_type = expected_product_type(options.profile);
        summary.product_confidence = ParserConfidence::unconfirmed;
      }
      // Keep the version paired with the product that owns this bundle. A
      // machine may have Agent, VBR and plug-in components on the same host;
      // using one machine-wide version can therefore display the wrong product
      // version in Case Dashboard.
      ParserConfidence version_confidence = ParserConfidence::unconfirmed;
      for (const auto outcome_index : indices) {
        if (outcome_index >= outcomes.size())
          continue;
        const auto& observed = outcomes[outcome_index].review;
        if (observed.product_type != summary.product_type || !observed.machine.product_version)
          continue;
        const auto& version = *observed.machine.product_version;
        if (summary.product_version.empty() ||
            confidence_rank(version.confidence) >= confidence_rank(version_confidence)) {
          summary.product_version = version.value;
          version_confidence = version.confidence;
        }
      }
      summary.candidate_files = indices.size();
      summary.indexed_files = indices.size();
    }
    review.bundles.push_back(std::move(summary));
  }
}


void build_evidence_role_summaries(VeeamLogReviewResult& review,
                                   const std::vector<EvidenceCatalogPath>& catalog) {
  std::map<VeeamEvidenceRole, VeeamEvidenceRoleSummary> summaries;
  for (const auto& item : catalog) {
    const VeeamEvidenceRole role = classify_veeam_evidence_role(item.display_path);
    auto& summary = summaries[role];
    summary.role = role;
    ++summary.candidate_files;
    summary.total_bytes += item.size_bytes;
    if (item.indexed)
      ++summary.scanned_files;
    else
      ++summary.deferred_files;
  }
  review.evidence_roles.clear();
  review.evidence_roles.reserve(summaries.size());
  for (auto& [role, summary] : summaries) {
    static_cast<void>(role);
    review.evidence_roles.push_back(std::move(summary));
  }
  std::stable_sort(review.evidence_roles.begin(), review.evidence_roles.end(), [](const auto& left, const auto& right) {
    if (left.candidate_files != right.candidate_files)
      return left.candidate_files > right.candidate_files;
    return to_string(left.role) < to_string(right.role);
  });
}

void build_job_evidence_groups(VeeamLogReviewResult& review,
                               const std::vector<EvidenceCatalogPath>& catalog,
                               const VeeamLogReviewOptions& options) {
  std::map<std::string, std::pair<std::string, std::string>> bundle_machines;
  std::map<std::string, std::size_t> bundle_indexes;
  for (std::size_t index = 0; index < review.bundles.size(); ++index) {
    auto& bundle = review.bundles[index];
    bundle.candidate_files = 0;
    bundle.indexed_files = 0;
    bundle.deferred_files = 0;
    bundle.source_bytes = 0;
    if (!bundle.source_path.empty())
      bundle.source_fingerprint = stable_source_fingerprint(support_assist::path_from_utf8(bundle.source_path));
    bundle_machines[bundle.key] = {bundle.primary_machine_key, bundle.primary_machine_name};
    bundle_indexes[bundle.key] = index;
  }

  std::map<std::string, VeeamJobEvidenceGroup> groups;
  for (const auto& item : catalog) {
    auto bundle_index = bundle_indexes.find(item.bundle_key);
    if (bundle_index != bundle_indexes.end()) {
      auto& bundle = review.bundles[bundle_index->second];
      ++bundle.candidate_files;
      if (item.indexed)
        ++bundle.indexed_files;
      else
        ++bundle.deferred_files;
      bundle.source_bytes += item.size_bytes;
    }

    const EvidenceHints hints = evidence_hints(options.profile, item.display_path);
    if (hints.job_name.empty())
      continue;
    const std::string group_key = item.bundle_key + "|" + ascii_lower(hints.category) + "|" +
                                  ascii_lower(hints.job_name);
    auto& group = groups[group_key];
    group.bundle_key = item.bundle_key;
    group.job_name = hints.job_name;
    group.category = hints.category.empty() ? "job-evidence" : hints.category;
    group.protection_group_rescan = hints.protection_group_rescan;
    group.protection_group_name = hints.protection_group_name;
    ++group.candidate_files;
    if (item.indexed)
      ++group.indexed_files;
    else
      ++group.deferred_files;
    group.total_bytes += item.size_bytes;
    if (!hints.workload_name.empty())
      append_unique(group.workloads, hints.workload_name);
    if (group.source_paths.size() < 64U)
      append_unique(group.source_paths, item.display_path);
    const auto machine = bundle_machines.find(item.bundle_key);
    if (machine != bundle_machines.end()) {
      group.machine_key = machine->second.first;
      group.machine_name = machine->second.second;
    }
  }

  review.job_evidence_groups.clear();
  review.job_evidence_groups.reserve(groups.size());
  for (auto& [key, group] : groups) {
    static_cast<void>(key);
    review.job_evidence_groups.push_back(std::move(group));
  }
  std::stable_sort(review.job_evidence_groups.begin(), review.job_evidence_groups.end(),
                   [](const auto& left, const auto& right) {
                     if (left.machine_name != right.machine_name)
                       return left.machine_name < right.machine_name;
                     if (left.category != right.category)
                       return left.category < right.category;
                     return left.job_name < right.job_name;
                   });

  // Fast Index evidence groups are candidates, not confirmed sessions. Keep
  // them in job_evidence_groups until structured run metadata is actually
  // observed. This prevents an indexed folder from masquerading as a backup run.
  static_cast<void>(options);

}

void link_job_evidence_groups(VeeamLogReviewResult& review) {
  for (auto& group : review.job_evidence_groups) {
    group.run_keys.clear();
    for (const auto& run : review.job_sessions) {
      if (!group.machine_key.empty() && !run.machine_key.empty() && run.machine_key != group.machine_key)
        continue;
      if (equals_folded(run.job_name, group.job_name) || contains_folded(run.source_path, group.job_name))
        append_unique(group.run_keys, run.run_key);
    }
  }
}


void merge_incident(VeeamLogReviewResult& review,
                    std::unordered_map<std::string, std::size_t>& incident_indexes,
                    VeeamIncident&& incoming,
                    std::size_t maximum_incidents) {
  const auto indexed = incident_indexes.find(incoming.signature);
  if (indexed == incident_indexes.end()) {
    if (review.incidents.size() >= maximum_incidents)
      return;
    const std::size_t incident_index = review.incidents.size();
    incident_indexes.emplace(incoming.signature, incident_index);
    review.incidents.push_back(std::move(incoming));
    return;
  }
  VeeamIncident& incident = review.incidents[indexed->second];
  incident.occurrences += incoming.occurrences;
  incident.locations_omitted += incoming.locations_omitted;
  if (incoming.first_utc_ms &&
      (!incident.first_utc_ms || *incoming.first_utc_ms < *incident.first_utc_ms)) {
    incident.first_utc_ms = incoming.first_utc_ms;
    incident.first_timestamp_original = incoming.first_timestamp_original;
  }
  if (incoming.last_utc_ms &&
      (!incident.last_utc_ms || *incoming.last_utc_ms > *incident.last_utc_ms)) {
    incident.last_utc_ms = incoming.last_utc_ms;
    incident.last_timestamp_original = incoming.last_timestamp_original;
  }
  incident.locations.insert(incident.locations.end(),
                            std::make_move_iterator(incoming.locations.begin()),
                            std::make_move_iterator(incoming.locations.end()));
}

// Components proven by one file's evidence.
//
// Derived from the evidence ROLE the classifier already assigns, plus the structural path markers
// that identify a specific product install. Nothing here fires on a product merely being mentioned
// in a line - see VeeamComponentPresence for why that distinction is the whole point.
//
// A single file can prove more than one component: Agent.Target.log is a repository data mover and
// therefore evidence of a repository, while the backup service log beside it is evidence of the
// backup server. Both are true at once, and the bundle should say so.
std::vector<std::pair<std::string, std::string>> components_for_file(VeeamEvidenceRole role,
                                                                     std::string_view folded_path) {
  std::vector<std::pair<std::string, std::string>> found;
  const auto add = [&](std::string tag, std::string name) {
    for (const auto& item : found) {
      if (item.first == tag)
        return;
    }
    found.emplace_back(std::move(tag), std::move(name));
  };
  const std::string path(folded_path);
  const auto has = [&](std::string_view needle) {
    return path.find(needle) != std::string::npos;
  };

  // --- Backup server -----------------------------------------------------------------------
  // Svc.VeeamBackup*.log and VeeamBackupManager*.log exist only where the backup server runs.
  // Only a path proves the backup server. Deliberately NOT keyed on the rescan or scheduler ROLE:
  // Job.Rescan_of_<host>.log is written by the plug-in on the DATABASE server too, so keying on the
  // role reported "VBR" for a pure SQL plug-in bundle that never saw a backup server.
  if (has("svc.veeambackup") || has("veeambackupmanager") || has("/backup/rescan/"))
    add("VBR", "Veeam Backup & Replication");

  // --- Agents ------------------------------------------------------------------------------
  if (has("svc.veeamendpointbackup") || has("/1-endpoint/") || has("job.veeamendpointbackup") ||
      has("vaw_vmc") || role == VeeamEvidenceRole::vaw_management)
    add("VAW", "Veeam Agent for Microsoft Windows");
  if (has("veeamagentlinux") || has("/var/log/veeam/"))
    add("VAL", "Veeam Agent for Linux");

  // --- Database plug-ins -------------------------------------------------------------------
  if (has("mssqlplugin") || has("mssqlrecoverymanager") || has("mssqlvbrcommunicationmanager") ||
      has("mssqlconfigtool"))
    add("SQL-Plugin", "Veeam Plug-in for Microsoft SQL Server");
  if (has("rmanplugin") || has("oracleproxylogs"))
    add("RMAN-Plugin", "Veeam Plug-in for Oracle RMAN");
  if (has("sapbackintmaxdb") || has("sapmaxdbbackint") || has("sapmaxdbconfigtool"))
    add("MaxDB", "Veeam Plug-in for SAP MaxDB");
  if (has("saporaclebackint") || has("sapbackintoraclemanager"))
    add("SAP-Oracle", "Veeam Plug-in for SAP on Oracle");
  if (has("hdbbackint") || has("sapbackintconfigtool"))
    add("SAP-HANA", "Veeam Plug-in for SAP HANA");
  if (has("db2configtool") || has("veeampluginfordb2"))
    add("Db2", "Veeam Plug-in for IBM Db2");

  // An agent runs its OWN source and target data movers when it backs itself up. Those are the
  // agent, not a separate proxy or repository server, so nothing under an endpoint tree may be read
  // as infrastructure. Without this guard a laptop agent bundle claimed Proxy, Repo and SOBR.
  const bool inside_agent_tree =
      has("/1-endpoint/") || has("/endpoint/") || path.rfind("endpoint/", 0) == 0;

  // --- Repository and tiering ---------------------------------------------------------------
  // The TARGET data mover runs on the repository, so its log is repository evidence.
  if (!inside_agent_tree &&
      (role == VeeamEvidenceRole::target_data_mover || role == VeeamEvidenceRole::repository_operation ||
       role == VeeamEvidenceRole::data_mover_repair || role == VeeamEvidenceRole::data_mover_check))
    add("Repo", "Backup Repository");

  // SOBR tier activity - offload, archival, evacuation - is repository work with no job of its own,
  // the exact case that must stop being attributed to whatever agent happened to be installed.
  //
  // Keyed on the PATH, not on the sobr_tier role. That role also matches "resourcesusage" and
  // "databaseresynchronizer", and RTS.ResourcesUsage.log is ordinary agent telemetry - which made a
  // standalone agent bundle report a scale-out repository.
  if (has("sobr_offload") || has("sobr_archival") || has("evacuatebackupsjob") || has("/sobr/")) {
    add("Repo", "Backup Repository");
    add("SOBR", "Scale-Out Backup Repository Tiering");
  }

  // --- Proxy / transport ---------------------------------------------------------------------
  // The SOURCE data mover runs on the backup proxy. Veeam ships no dedicated proxy log - the user
  // guide describes a proxy as a server ROLE running the Data Mover / Transport Service - so the
  // mover log is the only evidence the proxy role was exercised at all.
  if (!inside_agent_tree && role == VeeamEvidenceRole::source_data_mover)
    add("Proxy", "Backup Proxy (source data mover)");

  // Configuration backup/export outside an agent tree is backup-server maintenance. Guarded,
  // because an AGENT writes Config.ExportImport.log too - verified in a real VAW bundle - so the
  // role alone would have mis-attributed agent config work to the backup server.
  if (!inside_agent_tree && role == VeeamEvidenceRole::configuration_backup)
    add("VBR", "Veeam Backup & Replication");

  // The transport SERVICE running, never its installer: VeeamTransport.msi.log records a setup, not
  // a component doing work.
  const bool installer_log = has(".msi") || has("/setup/");
  if (!installer_log && has("svc.veeamtransport"))
    add("Transport", "Veeam Transport Service");

  return found;
}

// The single component that best describes a path, for attributing a run or an incident line.
//
// components_for_file() can return several tags for one file - a SOBR offload log is both
// repository work and tiering work. For a tag shown beside a run, the most SPECIFIC one carries the
// most meaning, so "SOBR" is preferred over the "Repo" that accompanies it.
std::string primary_component_tag(std::string_view display_path) {
  const auto found = components_for_file(classify_veeam_evidence_role(display_path),
                                         folded_path_name(display_path));
  if (found.empty())
    return {};
  static constexpr std::string_view specific_first[] = {
      "SOBR",     "SQL-Plugin", "RMAN-Plugin", "SAP-HANA", "SAP-Oracle", "MaxDB", "Db2",
      "Repo",     "Proxy",      "Transport",   "VAW",      "VAL",        "VBR"};
  for (const auto& preferred : specific_first) {
    for (const auto& item : found) {
      if (item.first == preferred)
        return item.first;
    }
  }
  return found.front().first;
}


void merge_file_outcome(VeeamLogReviewResult& destination,
                        std::unordered_map<std::string, std::size_t>& incident_indexes,
                        FileParseOutcome&& outcome,
                        const VeeamLogReviewOptions& options) {
  if (confidence_rank(outcome.review.product_confidence) >
      confidence_rank(destination.product_confidence)) {
    destination.product_type = std::move(outcome.review.product_type);
    destination.product_confidence = outcome.review.product_confidence;
  }

  // --- service-level facts -----------------------------------------------------------------
  //
  // Written on the per-file review during parsing, so they must be carried across explicitly.
  // Without this the schedule and the agent lifecycle parse correctly and then vanish.
  {
    const auto& source = outcome.review.schedule_info;
    auto& target = destination.schedule_info;
    if (source.scheduler_seen) {
      target.scheduler_seen = true;
      target.timer_expiry_count += source.timer_expiry_count;
      // Keep the latest of each; files are merged in completion order, not time order.
      if (!source.next_run_original.empty())
        target.next_run_original = source.next_run_original;
      if (!source.last_timer_expiry_original.empty() &&
          source.last_timer_expiry_original > target.last_timer_expiry_original)
        target.last_timer_expiry_original = source.last_timer_expiry_original;
      if (target.source_path.empty()) {
        target.source_path = source.source_path;
        target.line_number = source.line_number;
      }
    }
  }

  {
    const auto& source = outcome.review.service_activity;
    auto& target = destination.service_activity;
    target.service_start_count += source.service_start_count;
    if (!source.first_service_start_original.empty() &&
        (target.first_service_start_original.empty() ||
         source.first_service_start_original < target.first_service_start_original))
      target.first_service_start_original = source.first_service_start_original;
    if (!source.last_service_start_original.empty() &&
        source.last_service_start_original > target.last_service_start_original)
      target.last_service_start_original = source.last_service_start_original;
    target.agent_runs.insert(target.agent_runs.end(), source.agent_runs.begin(),
                             source.agent_runs.end());
  }

  destination.run_triggers.insert(destination.run_triggers.end(),
                                  outcome.review.run_triggers.begin(),
                                  outcome.review.run_triggers.end());

  // Record every component this file proves, attributed to the machine that owns the file. This is
  // additive on purpose: components accumulate, none of them displaces another.
  for (auto& component : components_for_file(classify_veeam_evidence_role(outcome.file.display_path),
                                             folded_path_name(outcome.file.display_path))) {
    auto existing = std::find_if(destination.components.begin(), destination.components.end(),
                                 [&](const VeeamComponentPresence& item) {
                                   return item.tag == component.first &&
                                          item.machine_key == outcome.machine_key;
                                 });
    if (existing == destination.components.end()) {
      VeeamComponentPresence presence;
      presence.tag = component.first;
      presence.display_name = std::move(component.second);
      presence.machine_key = outcome.machine_key;
      presence.machine_name = outcome.machine_name;
      presence.confidence = ParserConfidence::verified;
      destination.components.push_back(std::move(presence));
      existing = std::prev(destination.components.end());
    }
    ++existing->evidence_files;
    if (existing->example_paths.size() < 3U)
      existing->example_paths.push_back(outcome.file.display_path);
  }
  auto machine = std::find_if(destination.machines.begin(), destination.machines.end(),
                              [&](const auto& item) { return item.key == outcome.machine_key; });
  if (machine == destination.machines.end()) {
    VeeamMachineRecord record;
    record.key = outcome.machine_key;
    record.display_name = outcome.machine_name;
    record.role = outcome.machine_role;
    record.summary = outcome.review.machine;
    record.source_paths.push_back(outcome.file.display_path);
    destination.machines.push_back(std::move(record));
  } else {
    merge_machine_summary(machine->summary, outcome.review.machine);
    append_unique(machine->source_paths, outcome.file.display_path);
    if (machine->display_name == "Unknown machine" && outcome.machine_name != "Unknown machine")
      machine->display_name = outcome.machine_name;
    if (machine->role.empty() && !outcome.machine_role.empty())
      machine->role = outcome.machine_role;
  }
  destination.job_sessions.insert(destination.job_sessions.end(),
                                  std::make_move_iterator(outcome.review.job_sessions.begin()),
                                  std::make_move_iterator(outcome.review.job_sessions.end()));
  destination.timeline_events.insert(destination.timeline_events.end(),
                                     std::make_move_iterator(outcome.review.timeline_events.begin()),
                                     std::make_move_iterator(outcome.review.timeline_events.end()));
  for (auto& incident : outcome.review.incidents)
    merge_incident(destination, incident_indexes, std::move(incident),
                   options.maximum_incidents);
}

bool location_in_run_window(const VeeamIncidentLocation& location,
                            const VeeamJobSession& run,
                            const VeeamLogReviewOptions& options) {
  if (location.machine_key != run.machine_key)
    return false;
  if (!location.timestamp_utc_ms || !run.start_utc_ms)
    return false;
  const std::int64_t start = *run.start_utc_ms - std::max<std::int64_t>(0, options.job_window_lead_ms);
  const std::int64_t end = run.completion_utc_ms
                               ? *run.completion_utc_ms + std::max<std::int64_t>(0, options.job_window_tail_ms)
                               : *run.start_utc_ms +
                                     std::max<std::int64_t>(0, options.incomplete_run_tail_ms);
  return *location.timestamp_utc_ms >= start && *location.timestamp_utc_ms <= end;
}

bool source_mentions_run(const VeeamIncidentLocation& location, const VeeamJobSession& run) {
  const std::string source = normalized_source_path(location.source_path);
  if (!run.session_id.empty() && contains_folded(source, run.session_id))
    return true;
  if (!run.job_id.empty() && contains_folded(source, run.job_id))
    return true;
  if (!run.job_name.empty()) {
    std::string normalized_name = ascii_lower(run.job_name);
    std::replace(normalized_name.begin(), normalized_name.end(), ' ', '_');
    if (source.find(normalized_name) != std::string::npos)
      return true;
  }
  return normalized_source_path(run.source_path) == source;
}

void correlate_incidents(VeeamLogReviewResult& review, const VeeamLogReviewOptions& options) {
  std::unordered_map<std::string, const VeeamJobSession*> sessions_by_id;
  std::unordered_map<std::string, std::vector<const VeeamJobSession*>> jobs_by_machine;
  for (const auto& run : review.job_sessions) {
    jobs_by_machine[run.machine_key].push_back(&run);
    if (!run.session_id.empty())
      sessions_by_id[run.machine_key + "|" + ascii_lower(run.session_id)] = &run;
  }
  for (auto& incident : review.incidents) {
    incident.machine_keys.clear();
    incident.job_run_keys.clear();
    for (auto& location : incident.locations) {
      location.correlated_job_run_keys.clear();
      append_unique(incident.machine_keys, location.machine_key);
      const VeeamJobSession* explicit_run = nullptr;
      if (!location.explicit_session_id.empty()) {
        const auto found = sessions_by_id.find(location.machine_key + "|" +
                                               ascii_lower(location.explicit_session_id));
        if (found != sessions_by_id.end())
          explicit_run = found->second;
      }
      if (!explicit_run && !location.explicit_job_id.empty()) {
        const auto found = jobs_by_machine.find(location.machine_key);
        if (found != jobs_by_machine.end()) {
          for (const auto* run : found->second) {
            if (equals_folded(run->job_id, location.explicit_job_id) &&
                location_in_run_window(location, *run, options)) {
              explicit_run = run;
              break;
            }
          }
        }
      }
      if (explicit_run) {
        location.explicit_job_run_key = explicit_run->run_key;
        append_unique(location.correlated_job_run_keys, explicit_run->run_key);
        append_unique(incident.job_run_keys, explicit_run->run_key);
        continue;
      }
      const auto found = jobs_by_machine.find(location.machine_key);
      if (found == jobs_by_machine.end())
        continue;
      for (const auto* run : found->second) {
        if (run == explicit_run)
          continue;
        if (location_in_run_window(location, *run, options) &&
            (source_mentions_run(location, *run) || location.explicit_job_id.empty())) {
          append_unique(location.correlated_job_run_keys, run->run_key);
          append_unique(incident.job_run_keys, run->run_key);
        }
      }
    }
    std::stable_sort(incident.locations.begin(), incident.locations.end(), [](const auto& left, const auto& right) {
      if (left.timestamp_utc_ms && right.timestamp_utc_ms && *left.timestamp_utc_ms != *right.timestamp_utc_ms)
        return *left.timestamp_utc_ms > *right.timestamp_utc_ms;
      if (left.timestamp_utc_ms.has_value() != right.timestamp_utc_ms.has_value())
        return left.timestamp_utc_ms.has_value();
      if (left.source_path != right.source_path)
        return left.source_path < right.source_path;
      return left.line_number < right.line_number;
    });
  }
}

void correlate_timeline_events(VeeamLogReviewResult& review,
                               const VeeamLogReviewOptions& options) {
  for (auto& event : review.timeline_events) {
    const VeeamJobSession* best = nullptr;
    std::int64_t best_distance = std::numeric_limits<std::int64_t>::max();
    for (const auto& run : review.job_sessions) {
      if (!event.machine_key.empty() && !run.machine_key.empty() && event.machine_key != run.machine_key)
        continue;
      const bool same_source = normalized_source_path(event.evidence.source_path) ==
                               normalized_source_path(run.source_path);
      bool in_window = false;
      std::int64_t distance = 0;
      if (event.evidence.timestamp_utc_ms && run.start_utc_ms) {
        const std::int64_t start = *run.start_utc_ms - std::max<std::int64_t>(0, options.job_window_lead_ms);
        const std::int64_t end = run.completion_utc_ms
                                     ? *run.completion_utc_ms + std::max<std::int64_t>(0, options.job_window_tail_ms)
                                     : *run.start_utc_ms +
                                     std::max<std::int64_t>(0, options.incomplete_run_tail_ms);
        in_window = *event.evidence.timestamp_utc_ms >= start && *event.evidence.timestamp_utc_ms <= end;
        distance = std::llabs(*event.evidence.timestamp_utc_ms - *run.start_utc_ms);
      }
      if (!same_source && !in_window)
        continue;
      if (best == nullptr || (same_source && normalized_source_path(best->source_path) !=
                                              normalized_source_path(event.evidence.source_path)) ||
          distance < best_distance) {
        best = &run;
        best_distance = distance;
      }
    }
    if (best != nullptr)
      event.job_run_key = best->run_key;
  }
  std::stable_sort(review.timeline_events.begin(), review.timeline_events.end(), [](const auto& left, const auto& right) {
    if (left.evidence.timestamp_utc_ms && right.evidence.timestamp_utc_ms &&
        left.evidence.timestamp_utc_ms != right.evidence.timestamp_utc_ms)
      return *left.evidence.timestamp_utc_ms > *right.evidence.timestamp_utc_ms;
    if (left.evidence.timestamp_utc_ms.has_value() != right.evidence.timestamp_utc_ms.has_value())
      return left.evidence.timestamp_utc_ms.has_value();
    if (left.evidence.source_path != right.evidence.source_path)
      return left.evidence.source_path < right.evidence.source_path;
    return left.evidence.line_number < right.evidence.line_number;
  });
}

std::size_t automatic_worker_count(std::size_t file_count, std::size_t requested) {
  if (file_count == 0U)
    return 1U;
  if (requested != 0U)
    return std::clamp<std::size_t>(requested, 1U, file_count);
  const std::size_t hardware = std::max<std::size_t>(1U, std::thread::hardware_concurrency());
  return std::clamp<std::size_t>(hardware, 1U, std::min<std::size_t>(8U, file_count));
}

std::string evidence_text(const std::optional<ReviewEvidence>& evidence) {
  if (!evidence)
    return "Not identified";
  return evidence->value + " [" + to_string(evidence->confidence) + "]";
}

std::string canonical_timestamp(const std::optional<std::int64_t>& utc_millis,
                                std::string_view original) {
  if (utc_millis)
    return readable_utc_from_unix_millis(*utc_millis);
  return original.empty() ? "Unknown time" : std::string(original);
}

std::string timezone_offset_text(int offset_minutes) {
  const char sign = offset_minutes < 0 ? '-' : '+';
  const int absolute = std::abs(offset_minutes);
  std::ostringstream output;
  output << "UTC" << sign << std::setfill('0') << std::setw(2) << (absolute / 60)
         << ':' << std::setw(2) << (absolute % 60);
  return output.str();
}

std::string duration_text(const VeeamJobSession& session) {
  if (!session.start_utc_ms || !session.completion_utc_ms ||
      *session.completion_utc_ms < *session.start_utc_ms)
    return "Unknown";
  const std::int64_t total_ms = *session.completion_utc_ms - *session.start_utc_ms;
  const std::int64_t hours = total_ms / 3600000;
  const std::int64_t minutes = (total_ms / 60000) % 60;
  const std::int64_t seconds = (total_ms / 1000) % 60;
  const std::int64_t millis = total_ms % 1000;
  std::ostringstream output;
  output << std::setfill('0') << std::setw(2) << hours << ':' << std::setw(2) << minutes << ':'
         << std::setw(2) << seconds << '.' << std::setw(3) << millis;
  return output.str();
}

void write_evidence_line(std::ostream& output,
                         std::string_view label,
                         const std::optional<ReviewEvidence>& evidence) {
  output << std::left << std::setw(36) << label << evidence_text(evidence) << '\n';
}


// --- case answers block -------------------------------------------------------------------------
//
// One line per question a support engineer actually asks. Every line resolves to a value or says
// it was not found; silence is not an answer, because an omitted line reads as "nothing to report".

void write_answer(std::ostream& output, std::string_view question, const std::string& value,
                  std::string_view absent = "not found in this evidence") {
  output << "  " << std::left << std::setw(36) << std::string(question) << std::right;
  output << (value.empty() ? std::string(absent) : value) << '\n';
}

// The newest session satisfying a predicate.
template <typename Predicate>
const VeeamJobSession* newest_session_where(const VeeamLogReviewResult& review,
                                            Predicate predicate) {
  const VeeamJobSession* best = nullptr;
  for (const auto& session : review.job_sessions) {
    if (!predicate(session))
      continue;
    if (best == nullptr ||
        (session.start_utc_ms.has_value() &&
         (!best->start_utc_ms.has_value() || *session.start_utc_ms > *best->start_utc_ms)))
      best = &session;
  }
  return best;
}

std::string describe_progress(const VeeamJobSession& session) {
  if (!session.progress_seen)
    return {};
  std::string text = std::to_string(session.progress_percent) + "%";
  if (session.progress_bytes_total > 0)
    text += "  (" + format_health_bytes(session.progress_bytes_done) + " of " +
            format_health_bytes(session.progress_bytes_total) + ")";
  if (session.progress_used_total > 0)
    text += ", used " + format_health_bytes(session.progress_used_done) + " of " +
            format_health_bytes(session.progress_used_total);
  return text;
}

// Phrased for a reader, not as the token the log used.
std::string describe_trigger(const VeeamJobSession& session) {
  if (session.trigger == "user")
    return "Manually, by a user";
  if (session.trigger == "scheduled")
    return "By the schedule";
  if (session.trigger == "retry")
    return "Automatic retry of an earlier attempt";
  return {};
}

std::string describe_outcome(const VeeamJobSession& session) {
  if (session.running)
    return "Running now";
  return session.status.empty() ? std::string() : session.status;
}

void write_case_questions(std::ostream& output, const VeeamLogReviewResult& review) {
  output << "CASE QUESTIONS\n"
         << "------------------------------------------------------------\n";

  const VeeamJobSession* latest = newest_session_where(review, [](const VeeamJobSession&) {
    return true;
  });

  // The identity must belong to the machine that owns the run described below.
  //
  // Taking machines.front() printed a SQL Server identity above a VAW job on a mixed bundle. The
  // answers have to describe one machine or they describe nothing.
  const VeeamMachineRecord* machine = nullptr;
  if (latest != nullptr && !latest->machine_key.empty()) {
    for (const auto& candidate : review.machines) {
      if (equals_folded(candidate.key, latest->machine_key)) {
        machine = &candidate;
        break;
      }
    }
  }
  if (machine == nullptr && !review.machines.empty())
    machine = &review.machines.front();

  // A bundle holding several machines is a different kind of answer, and saying which one these
  // lines describe is the difference between a report and a guess.
  if (review.machines.size() > 1U) {
    output << "\n  This bundle holds " << review.machines.size()
           << " machines. The answers below describe "
           << (machine == nullptr ? std::string("the first machine found")
                                  : machine->display_name)
           << ",\n  which owns the most recent run. Use MACHINES FOUND for the others.\n";
  }
  const VeeamJobSession* last_success =
      newest_session_where(review, [](const VeeamJobSession& session) {
        return equals_folded(session.status, "Success");
      });
  const VeeamJobSession* running =
      newest_session_where(review, [](const VeeamJobSession& session) { return session.running; });

  output << "\n  IDENTITY\n";
  // The product must be the one that owns THIS machine's bundle, not the review's overall
  // determination. resolve_bundles already scores this per bundle and pairs the version to it;
  // reading review.product_type instead printed a SQL Server header over a VAW job.
  const VeeamBundleSummary* owning_bundle = nullptr;
  if (machine != nullptr) {
    for (const auto& bundle : review.bundles) {
      if (!bundle.product_type.empty() && equals_folded(bundle.primary_machine_key, machine->key)) {
        owning_bundle = &bundle;
        break;
      }
    }
  }

  std::string product_answer =
      owning_bundle != nullptr ? owning_bundle->product_type : review.product_type;
  // The MACHINE owns the version. A bundle-wide version scan on a VBR bundle returns
  // VeeamAgent.exe's own version - the data mover running on the proxy and the repository - because
  // the mover log is VBR evidence like everything else in the bundle. That is the mover's version,
  // not the backup server's.
  std::string product_version =
      machine == nullptr ? std::string() : evidence_text(machine->summary.product_version);
  if (product_version.empty() && owning_bundle != nullptr)
    product_version = owning_bundle->product_version;
  if (!product_version.empty())
    product_answer += " " + product_version;
  write_answer(output, "Product and version", product_answer);
  write_answer(output, "Management mode",
               machine == nullptr ? std::string() : evidence_text(machine->summary.management_mode),
               "not found (Standalone / Managed / Policy could not be determined)");
  write_answer(output, "Management server",
               machine == nullptr ? std::string() : evidence_text(machine->summary.management_server),
               "none recorded (consistent with Standalone)");
  write_answer(output, "Hostname",
               machine == nullptr ? std::string() : evidence_text(machine->summary.machine_name));
  write_answer(output, "IP address",
               machine == nullptr ? std::string() : evidence_text(machine->summary.primary_ip));
  write_answer(output, "Operating system",
               machine == nullptr ? std::string() : evidence_text(machine->summary.operating_system));
  // Only for collections that record it in the path; a blank line here would be noise everywhere
  // else. Whether the plug-in ran as a user or as the computer account is a first-order question
  // once permissions are in play.
  if (machine != nullptr && !machine->summary.plugin_accounts.empty()) {
    std::string accounts;
    for (const auto& entry : machine->summary.plugin_accounts) {
      if (!accounts.empty())
        accounts += ", ";
      accounts += entry.value;
    }
    write_answer(output, "Plug-in ran as", accounts);
  }

  output << "\n  JOB\n";
  const VeeamJobSettings* settings = latest == nullptr ? nullptr : &latest->settings;
  write_answer(output, "Job name", latest == nullptr ? std::string() : latest->job_name);
  write_answer(output, "Job ID", latest == nullptr ? std::string() : latest->job_id);
  write_answer(output, "Job description",
               settings == nullptr ? std::string() : settings->job_description,
               "none set on the job");
  write_answer(output, "Backup mode",
               settings == nullptr ? std::string() : settings->backup_mode);
  if (settings != nullptr && !settings->included_items.empty()) {
    for (std::size_t index = 0; index < settings->included_items.size(); ++index)
      write_answer(output, index == 0 ? "Included items" : "", settings->included_items[index]);
  } else {
    write_answer(output, "Included items", {});
  }
  write_answer(output, "Destination",
               settings == nullptr
                   ? std::string()
                   : (settings->destination_type.empty()
                          ? settings->destination_path
                          : settings->destination_type + " - " + settings->destination_path));
  write_answer(output, "Retention", settings == nullptr ? std::string() : settings->retention);
  write_answer(output, "Compression", settings == nullptr ? std::string() : settings->compression);
  write_answer(output, "Storage optimization",
               settings == nullptr ? std::string() : settings->storage_optimization);
  write_answer(output, "Encryption", settings == nullptr ? std::string() : settings->encryption);
  write_answer(output, "GFS", settings == nullptr ? std::string() : settings->gfs);
  write_answer(output, "Backup cache", settings == nullptr ? std::string() : settings->backup_cache);
  write_answer(output, "Application processing",
               settings == nullptr ? std::string() : settings->application_processing);
  write_answer(output, "Guest indexing",
               settings == nullptr ? std::string() : settings->guest_indexing);
  write_answer(output, "Command line to start the job",
               settings == nullptr ? std::string() : settings->command_line);

  output << "\n  SCHEDULE\n";
  if (review.schedule_info.scheduler_seen) {
    write_answer(output, "Scheduler", "active");
    write_answer(output, "Next run", review.schedule_info.next_run_original);
    write_answer(output, "Last timer expiry", review.schedule_info.last_timer_expiry_original);
    write_answer(output, "Timer expiries seen",
                 std::to_string(review.schedule_info.timer_expiry_count));
  } else {
    write_answer(output, "Scheduler", {}, "no scheduler activity in this evidence");
  }
  if (settings != nullptr && !settings->schedule.empty())
    write_answer(output, "Schedule (from job settings)", settings->schedule);

  output << "\n  LATEST RUN\n";
  if (latest == nullptr) {
    write_answer(output, "Latest run", {}, "no job runs were identified");
  } else {
    write_answer(output, "Outcome", describe_outcome(*latest));
    write_answer(output, "Started", latest->start_timestamp_original);
    write_answer(output, "Completed",
                 latest->running ? std::string("still running")
                                 : latest->completion_timestamp_original);
    write_answer(output, "Started by", describe_trigger(*latest),
                 "trigger not recorded for this run");
    write_answer(output, "Job mode", latest->job_mode);
    write_answer(output, "Backup type", latest->backup_type,
                 "could not be determined from the target file");
    write_answer(output, "Chains onto", latest->previous_backup_file,
                 "no parent restore point recorded (full, or not logged)");
    write_answer(output, "Furthest state reached", latest->last_state);
    write_answer(output, "Progress reached", describe_progress(*latest),
                 "no progress was logged for this run");
  }

  output << "\n  HISTORY\n";
  if (last_success == nullptr) {
    write_answer(output, "Last successful run", {},
                 "NO SUCCESSFUL RUN in this evidence");
  } else {
    write_answer(output, "Last successful run",
                 last_success->start_timestamp_original + "  -  " + last_success->job_name);
  }
  write_answer(output, "Currently running",
               running == nullptr ? std::string("no")
                                  : running->job_name + " (started " +
                                        running->start_timestamp_original + ")");
  std::size_t succeeded = 0;
  std::size_t failed = 0;
  for (const auto& session : review.job_sessions) {
    if (equals_folded(session.status, "Success"))
      ++succeeded;
    else if (equals_folded(session.status, "Failed"))
      ++failed;
  }
  write_answer(output, "Runs in this evidence",
               std::to_string(review.job_sessions.size()) + " total, " +
                   std::to_string(succeeded) + " succeeded, " + std::to_string(failed) + " failed");
  output << '\n';
}

// What the service is doing when a job is not the thing that is failing.
void write_service_activity(std::ostream& output, const VeeamLogReviewResult& review) {
  const auto& activity = review.service_activity;
  output << "SERVICE ACTIVITY\n"
         << "------------------------------------------------------------\n"
         << "  Findings here belong to no job run. A machine whose jobs all succeed can still have a\n"
         << "  service in trouble, and every other view in this report is job-scoped.\n\n";

  write_answer(output, "Service starts observed",
               activity.service_start_count == 0
                   ? std::string()
                   : std::to_string(activity.service_start_count));
  write_answer(output, "First service start", activity.first_service_start_original);
  write_answer(output, "Most recent service start", activity.last_service_start_original);
  write_answer(output, "Agent job runs observed",
               activity.agent_runs.empty() ? std::string()
                                           : std::to_string(activity.agent_runs.size()));
  if (!activity.agent_runs.empty()) {
    const auto& first = activity.agent_runs.front();
    const auto& last = activity.agent_runs.back();
    write_answer(output, "First agent job start", first.started_original);
    write_answer(output, "Last agent job stop",
                 last.stopped_original.empty() ? std::string("still running")
                                               : last.stopped_original);
  }

  output << '\n';
  write_answer(output, "Findings outside any job run",
               std::to_string(activity.standalone_error_count) + " error(s), " +
                   std::to_string(activity.standalone_warning_count) + " warning(s)");
  if (!activity.standalone_errors_by_component.empty()) {
    output << "\n  Service-level errors by component:\n";
    for (const auto& entry : activity.standalone_errors_by_component) {
      output << "    " << std::left << std::setw(34)
             << (entry.first.empty() ? std::string("Unclassified") : entry.first) << std::right
             << entry.second << '\n';
    }
  }
  if (!activity.service_only_components.empty()) {
    output << "\n  Components that ONLY ever fail outside a job run:\n";
    for (const auto& component : activity.service_only_components)
      output << "    " << component << '\n';
    output << "    These are service-side problems. A job-by-job review will never surface them.\n";
  }
  output << '\n';
}


// Facts that need the finished review rather than a single line.
void finalize_case_answers(VeeamLogReviewResult& review) {
  for (auto& session : review.job_sessions) {
    // A run with a start and no completion is still going. Reported as "Unknown / incomplete"
    // previously, which reads as a parse failure rather than as a live job.
    session.running = session.start_utc_ms.has_value() && !session.completion_utc_ms.has_value() &&
                      session.status.empty();

    // Full or incremental, from the target file. The reader should not have to know that .vbk is a
    // full and .vib an incremental.
    // resulting_backup_type comes from the repository operation the product logged, so it beats
    // guessing from a filename.
    if (!session.settings.resulting_backup_type.empty())
      session.backup_type = session.settings.resulting_backup_type;
    if (session.backup_type.empty() && !session.backup_file.empty()) {
      const std::string folded = ascii_lower(session.backup_file);
      if (folded.find(".vbk") != std::string::npos)
        session.backup_type = "Full";
      else if (folded.find(".vib") != std::string::npos)
        session.backup_type = "Incremental";
    }

    // Settings are written per run, and a run that dies early writes fewer of them. Carrying the
    // last known value forward is why the description, the start command and the schedule kept
    // reading empty on the newest run while sitting in an earlier one.
    if (session.trigger.empty() && !session.job_mode.empty() &&
        equals_folded(session.job_mode, "Retry"))
      session.trigger = "retry";
  }

  // Agent lifetimes come from several files in completion order, so sort them into time order
  // before anything reads "first" or "last".
  std::stable_sort(review.service_activity.agent_runs.begin(),
                   review.service_activity.agent_runs.end(),
                   [](const VeeamAgentLifecycle& left, const VeeamAgentLifecycle& right) {
                     if (left.started_utc_ms.has_value() && right.started_utc_ms.has_value())
                       return *left.started_utc_ms < *right.started_utc_ms;
                     return left.started_original < right.started_original;
                   });

  // Join each "Starting job" line to the run it started.
  //
  // Matched on job id, then on the trigger being the closest one at or just before the run's start.
  // A tolerance is needed because the service logs the intent a fraction of a second before the job
  // log records the session opening.
  for (auto& session : review.job_sessions) {
    if (!session.trigger.empty() || !session.start_utc_ms.has_value())
      continue;
    const VeeamRunTrigger* best = nullptr;
    std::int64_t best_gap = 0;
    for (const auto& trigger : review.run_triggers) {
      if (!trigger.utc_ms.has_value())
        continue;
      if (!trigger.job_id.empty() && !session.job_id.empty() &&
          !equals_folded(trigger.job_id, session.job_id))
        continue;
      const std::int64_t gap = *session.start_utc_ms - *trigger.utc_ms;
      // Started at or just before the session opened, within a minute.
      if (gap < -2000 || gap > 60000)
        continue;
      if (best == nullptr || gap < best_gap) {
        best = &trigger;
        best_gap = gap;
      }
    }
    if (best != nullptr) {
      session.trigger = best->trigger;
      session.trigger_detail = best->detail;
      if (session.job_mode.empty())
        session.job_mode = best->job_mode;
    }
  }

  // A scheduled run has no "Starting job ... by user" line at all - the scheduler starts it
  // directly. What it does have is a [WakeupManager] timer expiring immediately before the session
  // opens, which is how test 07 was identified by hand.
  if (review.schedule_info.scheduler_seen &&
      !review.schedule_info.last_timer_expiry_original.empty()) {
    for (auto& session : review.job_sessions) {
      if (!session.trigger.empty())
        continue;
      // Compared as written, because both come from the same product and the same clock.
      const std::string& expiry = review.schedule_info.last_timer_expiry_original;
      if (expiry.size() >= 16 && session.start_timestamp_original.size() >= 16 &&
          expiry.compare(0, 16, session.start_timestamp_original, 0, 16) == 0) {
        session.trigger = "scheduled";
        session.trigger_detail =
            "Scheduler timer expired at " + expiry + "; no user start was recorded";
      }
    }
  }

  // A run is "running" only if nothing newer has started. Sessions from days ago with no recorded
  // completion are abandoned records, not live jobs - the first cut flagged a run from the previous
  // day as currently running.
  std::optional<std::int64_t> newest_start;
  for (const auto& session : review.job_sessions) {
    if (session.start_utc_ms.has_value() &&
        (!newest_start.has_value() || *session.start_utc_ms > *newest_start))
      newest_start = session.start_utc_ms;
  }
  for (auto& session : review.job_sessions) {
    if (!session.running)
      continue;
    if (!newest_start.has_value() || !session.start_utc_ms.has_value() ||
        *session.start_utc_ms != *newest_start)
      session.running = false;
  }

  // Fill gaps in the newest session's settings from the most recent run that recorded them.
  const auto carry_forward = [&](std::string VeeamJobSettings::*field) {
    std::string last_seen;
    for (auto& session : review.job_sessions) {
      if (!(session.settings.*field).empty())
        last_seen = session.settings.*field;
      else if (!last_seen.empty())
        session.settings.*field = last_seen;
    }
  };
  carry_forward(&VeeamJobSettings::job_description);
  carry_forward(&VeeamJobSettings::command_line);
  carry_forward(&VeeamJobSettings::schedule);
  carry_forward(&VeeamJobSettings::backup_cache);
  carry_forward(&VeeamJobSettings::created_by);
  carry_forward(&VeeamJobSettings::created_at);

  // --- service activity ------------------------------------------------------------------------
  //
  // Everything that is NOT attached to a job run. This is the answer to "what is the service doing
  // when a job is not the thing failing".
  auto& activity = review.service_activity;
  std::map<std::string, std::uint32_t> standalone_by_component;
  std::set<std::string> components_in_runs;
  std::set<std::string> components_outside_runs;

  for (const auto& incident : review.incidents) {
    const bool inside_run = !incident.job_run_keys.empty();
    const std::string component =
        incident.component.empty() ? std::string("Unclassified") : incident.component;
    if (inside_run) {
      components_in_runs.insert(component);
      continue;
    }
    components_outside_runs.insert(component);
    const std::uint32_t occurrences =
        incident.occurrences == 0U ? 1U : static_cast<std::uint32_t>(incident.occurrences);
    if (equals_folded(incident.severity, "error")) {
      activity.standalone_error_count += occurrences;
      standalone_by_component[component] += occurrences;
    } else if (equals_folded(incident.severity, "warning")) {
      activity.standalone_warning_count += occurrences;
    }
  }

  activity.standalone_errors_by_component.assign(standalone_by_component.begin(),
                                                 standalone_by_component.end());
  std::stable_sort(activity.standalone_errors_by_component.begin(),
                   activity.standalone_errors_by_component.end(),
                   [](const auto& left, const auto& right) { return left.second > right.second; });

  // A component that only ever fails outside a job run is a service-side problem, and a job-by-job
  // review will never surface it.
  for (const auto& component : components_outside_runs) {
    if (components_in_runs.find(component) == components_in_runs.end())
      activity.service_only_components.push_back(component);
  }
}


// Add the meaning of any system error code in a line, leaving the line itself intact.
//
// Codes appear as "Error code: 0x00000070", "(0x80070070)" or a bare decimal after "error code".
// The decoded meaning is appended in brackets so the product's own words are still quotable.
std::string annotate_system_error_codes(const std::string& text) {
  if (text.empty())
    return text;

  std::string result;
  result.reserve(text.size() + 48);
  std::size_t index = 0;
  std::size_t annotations = 0;

  while (index < text.size()) {
    // Only 0x-prefixed values are unambiguous enough to decode without context; a bare number in
    // log text is far more often a size, a line or a port.
    if (index + 2 < text.size() && text[index] == '0' &&
        (text[index + 1] == 'x' || text[index + 1] == 'X')) {
      std::size_t end = index + 2;
      while (end < text.size() && std::isxdigit(static_cast<unsigned char>(text[end])) != 0)
        ++end;
      const std::size_t digits = end - index - 2;
      if (digits >= 1 && digits <= 8 && annotations < 3) {
        const std::string token = text.substr(index, end - index);
        if (const auto meaning = decode_system_error_text(token); meaning.has_value()) {
          result += token;
          result += " [";
          result += meaning->symbol;
          result += " - ";
          result += meaning->description;
          if (meaning->from_hresult_wrapper)
            result += " (Win32 code inside an HRESULT)";
          result += ']';
          ++annotations;
          index = end;
          continue;
        }
      }
      result.append(text, index, end - index);
      index = end;
      continue;
    }
    result.push_back(text[index]);
    ++index;
  }
  return result;
}

void write_setting(std::ostream& output, std::string_view label, std::string_view value) {
  if (!value.empty())
    output << std::left << std::setw(36) << label << value << '\n';
}

std::string note_evidence_path(std::string_view source_path) {
  std::string source(source_path);
  std::replace(source.begin(), source.end(), '\\', '/');
  if (const std::size_t bang = source.find('!'); bang != std::string::npos) {
    const std::filesystem::path archive(source.substr(0, bang));
    std::string root = path_to_utf8(archive.stem());
    if (root.empty())
      root = support_assist::path_to_utf8(archive.filename());
    return "./" + root + "/" + source.substr(bang + 1U);
  }
  const std::string folded = ascii_lower(source);
  if (const std::size_t marker = folded.find("/logs/"); marker != std::string::npos)
    return "./" + source.substr(marker + 6U);
  return "./" + support_assist::generic_path_to_utf8(support_assist::path_from_utf8(source).filename());
}

std::string note_size(std::uint64_t bytes) {
  constexpr double gib = 1024.0 * 1024.0 * 1024.0;
  constexpr double tib = gib * 1024.0;
  std::ostringstream output;
  if (bytes >= static_cast<std::uint64_t>(tib)) {
    output << std::fixed << std::setprecision(bytes >= static_cast<std::uint64_t>(10.0 * tib) ? 1 : 2)
           << static_cast<double>(bytes) / tib << " TiB";
  } else {
    output << std::fixed << std::setprecision(bytes >= static_cast<std::uint64_t>(10.0 * gib) ? 1 : 2)
           << static_cast<double>(bytes) / gib << " GiB";
  }
  return output.str();
}

std::uint64_t snapshot_volume_size_bytes(const VeeamVolumeSnapshotInfo& volume) {
  if (volume.explicit_size_bytes != 0U)
    return volume.explicit_size_bytes;
  std::uint64_t total = 0U;
  for (const auto& extent : volume.extents) {
    if (std::numeric_limits<std::uint64_t>::max() - total < extent.length_bytes)
      return 0U;
    total += extent.length_bytes;
  }
  return total;
}

bool is_microsoft_software_vss_provider(std::string_view name, std::string_view type) {
  return contains_folded(name, "microsoft software shadow copy provider") ||
         equals_folded(trim_copy(type), "VSS_PROV_SYSTEM");
}

bool is_hardware_vss_provider(std::string_view type) {
  return equals_folded(trim_copy(type), "VSS_PROV_HARDWARE");
}

bool is_vaw_review(const VeeamLogReviewResult& review) {
  return review.profile_used == VeeamReviewProfile::vaw ||
         contains_folded(review.product_type, "agent for microsoft windows");
}

std::string product_name_for_machine(const VeeamLogReviewResult& review,
                                     const VeeamMachineRecord* machine) {
  if (machine != nullptr) {
    if (equals_folded(machine->role, "Protected Machine - VAW"))
      return "Veeam Agent for Microsoft Windows";
    if (equals_folded(machine->role, "Protected Machine - VAL"))
      return "Veeam Agent for Linux";
    if (equals_folded(machine->role, "Protected Machine - VAM"))
      return "Veeam Agent for Mac";
    if (equals_folded(machine->role, "Protected Machine - AIX"))
      return "Veeam Agent for IBM AIX";
    if (equals_folded(machine->role, "Protected Machine - SOLARIS"))
      return "Veeam Agent for Oracle Solaris";
    if (equals_folded(machine->role, "Backup Server"))
      return "Veeam Backup & Replication";
    if (contains_folded(machine->role, "SQL Plug-in"))
      return "Veeam Plug-in for Microsoft SQL Server";
    if (contains_folded(machine->role, "RMAN Plug-in"))
      return "Veeam Plug-in for Oracle RMAN";
  }
  return review.product_type.empty() ? std::string("Not identified") : review.product_type;
}

bool is_vaw_scope(const VeeamLogReviewResult& review, const VeeamMachineRecord* machine) {
  return (machine != nullptr && equals_folded(machine->role, "Protected Machine - VAW")) ||
         is_vaw_review(review);
}

std::string management_mode_note_value(std::string_view value) {
  if (equals_folded(trim_copy(value), "ManagedByVBR"))
    return "Managed By Backup Server (ManagedByVBR)";
  if (equals_folded(trim_copy(value), "Standalone"))
    return "Standalone";
  return std::string(value);
}

std::string evidence_value(const std::optional<ReviewEvidence>& evidence,
                           std::string_view fallback = "Not identified") {
  return evidence && !evidence->value.empty() ? evidence->value : std::string(fallback);
}

} // namespace

std::filesystem::path default_review_output_directory() {
  const std::string executable = current_executable_path();
  if (!executable.empty())
    return path_from_utf8(executable).parent_path() / "Log-Collections" / "Log-Review";
  return std::filesystem::current_path() / "SupportAssistReports";
}

std::string to_string(ParserConfidence value) {
  switch (value) {
  case ParserConfidence::verified:
    return "Verified";
  case ParserConfidence::probable:
    return "Probable";
  case ParserConfidence::unconfirmed:
    return "Unconfirmed";
  }
  return "Unconfirmed";
}

std::string to_string(VeeamReviewProfile value) {
  switch (value) {
  case VeeamReviewProfile::automatic:
    return "auto";
  case VeeamReviewProfile::vaw:
    return "vaw";
  case VeeamReviewProfile::vbr:
    return "vbr";
  case VeeamReviewProfile::sql_plugin:
    return "sql-plugin";
  case VeeamReviewProfile::rman_plugin:
    return "rman-plugin";
  case VeeamReviewProfile::sap_hana_plugin:
    return "sap-hana-plugin";
  case VeeamReviewProfile::sap_oracle_plugin:
    return "sap-oracle-plugin";
  case VeeamReviewProfile::sap_maxdb_plugin:
    return "sap-maxdb-plugin";
  case VeeamReviewProfile::db2_plugin:
    return "db2-plugin";
  case VeeamReviewProfile::generic:
    return "generic";
  }
  return "auto";
}

std::string to_string(VeeamEvidenceRole value) {
  switch (value) {
  case VeeamEvidenceRole::manifest:
    return "Manifest";
  case VeeamEvidenceRole::service:
    return "Service";
  case VeeamEvidenceRole::scheduler:
    return "Scheduler";
  case VeeamEvidenceRole::vaw_management:
    return "VAW Management";
  case VeeamEvidenceRole::job:
    return "Job";
  case VeeamEvidenceRole::task:
    return "Task";
  case VeeamEvidenceRole::protection_group_rescan:
    return "Protection Group Rescan";
  case VeeamEvidenceRole::source_data_mover:
    return "Source Data Mover";
  case VeeamEvidenceRole::target_data_mover:
    return "Target Data Mover";
  case VeeamEvidenceRole::data_mover_server:
    return "Data Mover Server";
  case VeeamEvidenceRole::data_mover_repair:
    return "Data Mover Repair";
  case VeeamEvidenceRole::data_mover_check:
    return "Data Mover Check";
  case VeeamEvidenceRole::repository_operation:
    return "Repository Operation";
  case VeeamEvidenceRole::rpc_control:
    return "RPC/gRPC Control";
  case VeeamEvidenceRole::plugin:
    return "Plug-in";
  case VeeamEvidenceRole::setup:
    return "Setup";
  case VeeamEvidenceRole::system:
    return "System";
  case VeeamEvidenceRole::user_interface:
    return "User Action (UI)";
  case VeeamEvidenceRole::tool_output:
    return "SAT Tool Output";
  case VeeamEvidenceRole::guest_processing:
    return "Guest Processing";
  case VeeamEvidenceRole::sobr_tier:
    return "SOBR Tier";
  case VeeamEvidenceRole::configuration_backup:
    return "Configuration Backup";
  case VeeamEvidenceRole::restore_operation:
    return "Restore Operation";
  case VeeamEvidenceRole::cloud_plugin:
    return "Cloud Plug-In";
  case VeeamEvidenceRole::other:
    return "Other";
  }
  return "Other";
}

std::string to_string(VeeamStoryStage value) {
  switch (value) {
  case VeeamStoryStage::none: return "";
  case VeeamStoryStage::job_start: return "Backup start";
  case VeeamStoryStage::settings: return "Job settings";
  case VeeamStoryStage::connection: return "Connection";
  case VeeamStoryStage::snapshot: return "Snapshot";
  case VeeamStoryStage::guest_processing: return "Guest processing";
  case VeeamStoryStage::transfer: return "Data transfer";
  case VeeamStoryStage::job_end: return "Backup finished";
  }
  return "";
}

VeeamStoryStage classify_story_stage(std::string_view message, VeeamReviewProfile profile) {
  const std::string folded = ascii_lower(trim_copy(message));
  if (folded.empty()) return VeeamStoryStage::none;

  const auto has = [&](std::string_view needle) {
    return folded.find(needle) != std::string::npos;
  };

  // ---- Universal terminal results -------------------------------------------------------------
  // Kept first because a run's outcome matters whichever product produced it, and because
  // "canceled by user" names the person who stopped it - the single most useful line for
  // explaining a cancellation that surfaced as an error on a different machine.
  if (has("operation was canceled by user") || has("operation was cancelled by user") ||
      has("job session has been completed") || has("job finished with") ||
      has("session result:") || has("backup job finished") ||
      has("job has been completed with") || has("processing finished with"))
    return VeeamStoryStage::job_end;

  switch (profile) {
  case VeeamReviewProfile::vaw:
  case VeeamReviewProfile::generic:
  case VeeamReviewProfile::automatic:
    // Veeam Agent for Microsoft Windows. Strings taken from real VAW bundles.
    if (has("starting job.") || has("job session is running in") || has("preparing to start") ||
        has("preparing storages in"))
      return VeeamStoryStage::job_start;
    // "Connecting to agent 'Spectr' ('[::1]:2500;127.0.0.1:2500;192.168.1.45:2500')" carries the
    // host AND every candidate address with the port - exactly the "connection from/where" the
    // story needs, in one line.
    //
    // Deliberately narrow. An earlier version also matched any "connecting to '<addr>'", which
    // pulled in every [TlsSocket] transport retry: measured against a real VAW run that produced
    // the same "Connecting to '[::1]:2500'" line six times for a single logical connection. Those
    // are transport mechanics, not story. Keep the lines that name the peer being connected TO.
    if (has("connecting to agent") || has("agent has been started, id") ||
        has("agent connection addresses"))
      return VeeamStoryStage::connection;
    if (has("snapshot creation. spec xml") || has("volume added to shadow copy set") ||
        has("is included in snapshot") || has("using vss provider") ||
        has("should be added to snapshot"))
      return VeeamStoryStage::snapshot;
    if (has("preparing the [sql server]") || has("preparing the [exchange") ||
        has("preparing the [ntds]") || has("truncation") || has("[veeamguest"))
      return VeeamStoryStage::guest_processing;
    if (has("task total size") || has("task size: capacity") || has("preparing oib in"))
      return VeeamStoryStage::transfer;
    break;

  case VeeamReviewProfile::sql_plugin:
    // Veeam Plug-In for Microsoft SQL Server. The plug-in announces the exact recovery-manager
    // command line it ran, which states the operation and its switches in one line - the closest
    // thing any profile has to a self-describing job start.
    if (has("start recovery manager cmdline") || has("starting new log") ||
        has("explore all instances and databases"))
      return VeeamStoryStage::job_start;
    if (has("cmdlineparams:") || has("<summary>") || has("<databasesettings") ||
        has("recoverymodel=") || has("logging level:"))
      return VeeamStoryStage::settings;
    if (has("plugin manager port is") || has("channelid") || has("connecting to backup server") ||
        has("vbrcommunicationmanager"))
      return VeeamStoryStage::connection;
    if (has("vdi") || has("virtual device") || has("sqlvdi"))
      return VeeamStoryStage::guest_processing;
    if (has("recovery manager exit code") || has("reader pipe finished"))
      return VeeamStoryStage::job_end;
    break;

  case VeeamReviewProfile::vbr:
    if (has("job session") && (has("started") || has("starting")))
      return VeeamStoryStage::job_start;
    if (has("connecting to") || has("agent connection") || has("data mover") ||
        has("transport service"))
      return VeeamStoryStage::connection;
    if (has("repository") && (has("selected") || has("using")))
      return VeeamStoryStage::settings;
    if (has("snapshot") && (has("creat") || has("taken") || has("removed")))
      return VeeamStoryStage::snapshot;
    if (has("total size") || has("transferred") || has("processed"))
      return VeeamStoryStage::transfer;
    break;

  case VeeamReviewProfile::rman_plugin:
    // Oracle RMAN: RMAN starts the plug-in, the plug-in connects to VBR, and data movers start on
    // the Oracle server and the repository (Veeam's own How-It-Works description).
    if (has("rman") && (has("start") || has("channel")))
      return VeeamStoryStage::job_start;
    if (has("connecting to") || has("backup server"))
      return VeeamStoryStage::connection;
    if (has("backup piece") || has("bytes"))
      return VeeamStoryStage::transfer;
    break;

  // ---------------------------------------------------------------------------------------------
  // Backint-family and Db2 skeletons.
  //
  // These are deliberately thin. Every token below is either a documented Veeam log file name or a
  // string shared with the plug-in framework that the SQL plug-in already proves out (the config
  // file load, the VBR host/port pair, the certificate handshake). Nothing here is extrapolated
  // from the SQL switches, because these plug-ins do not run a Veeam backup executable at all -
  // the backup is commanded by Backint, BRTools or native db2, and the Veeam side only services it.
  //
  // Until real bundles exist for each, treat an unmatched line as "no stage" rather than guessing.
  // ---------------------------------------------------------------------------------------------
  case VeeamReviewProfile::sap_hana_plugin:
    // Backint agent is hdbbackint, symlinked into /hana/shared/<SID>/global/hdb/opt.
    if (has("hdbbackint") || has("backint") || has("sapbackintconfigtool"))
      return VeeamStoryStage::job_start;
    if (has("connecting to") || has("backup server") || has("certificate"))
      return VeeamStoryStage::connection;
    if (has("veeam_config.xml") || has("show-config"))
      return VeeamStoryStage::settings;
    break;

  case VeeamReviewProfile::sap_oracle_plugin:
    // Documented log files: SapOracleBackint.log, SapBackintOracleManager.log, Agent.Source.log.
    // BRTools (brbackup/brarchive) is the commanding side and writes to the SAP directories.
    if (has("saporaclebackint") || has("sapbackintoraclemanager") || has("brbackup") ||
        has("brarchive") || has("rman_util"))
      return VeeamStoryStage::job_start;
    if (has("connecting to") || has("backup server") || has("certificate"))
      return VeeamStoryStage::connection;
    if (has("veeam_config.xml"))
      return VeeamStoryStage::settings;
    break;

  case VeeamReviewProfile::sap_maxdb_plugin:
    // Documented log files: SapBackintMaxDBManager.log, SAPMaxDBConfigTool.log, SapMaxDBBackint.log,
    // Agent.Source.log. Standalone mode only.
    if (has("sapmaxdbbackint") || has("sapbackintmaxdbmanager") || has("dbmcli"))
      return VeeamStoryStage::job_start;
    if (has("connecting to") || has("backup server") || has("certificate"))
      return VeeamStoryStage::connection;
    if (has("sapmaxdbconfigtool") || has("veeam_config.xml"))
      return VeeamStoryStage::settings;
    break;

  case VeeamReviewProfile::db2_plugin:
    // The backup is commanded by native "db2 backup db"; DB2ConfigTool only edits veeam_config.xml
    // and therefore describes configuration, never a run.
    if (has("db2 backup") || has("backup db") || has("vendoropt"))
      return VeeamStoryStage::job_start;
    if (has("connecting to") || has("backup server") || has("certificate"))
      return VeeamStoryStage::connection;
    if (has("db2configtool") || has("veeam_config.xml"))
      return VeeamStoryStage::settings;
    break;
  }
  return VeeamStoryStage::none;
}

std::string to_string(VeeamEventScope value) {
  switch (value) {
  case VeeamEventScope::job_run: return "Job run";
  case VeeamEventScope::infrastructure: return "Infrastructure";
  case VeeamEventScope::service: return "Service";
  case VeeamEventScope::unknown: return "Unscoped";
  }
  return "Unscoped";
}

std::string to_string(VeeamInfrastructureOperation value) {
  switch (value) {
  case VeeamInfrastructureOperation::none: return "";
  case VeeamInfrastructureOperation::protection_group: return "Protection group";
  case VeeamInfrastructureOperation::managed_server: return "Managed server";
  case VeeamInfrastructureOperation::repository: return "Repository";
  case VeeamInfrastructureOperation::agent_deployment: return "Agent deployment";
  case VeeamInfrastructureOperation::configuration_backup: return "Configuration backup";
  case VeeamInfrastructureOperation::licensing: return "Licensing";
  }
  return "";
}

VeeamInfrastructureOperation classify_infrastructure_operation(std::string_view message,
                                                               VeeamEvidenceRole role) {
  const std::string folded = ascii_lower(trim_copy(message));
  const auto has = [&](std::string_view needle) {
    return folded.find(needle) != std::string::npos;
  };

  // Role first where it is already decisive.
  if (role == VeeamEvidenceRole::protection_group_rescan)
    return VeeamInfrastructureOperation::protection_group;
  if (role == VeeamEvidenceRole::configuration_backup)
    return VeeamInfrastructureOperation::configuration_backup;
  if (role == VeeamEvidenceRole::sobr_tier)
    return VeeamInfrastructureOperation::repository;

  // Vocabulary taken from the real VBR bundles: "Rescan of <group>' , id '<guid>'",
  // "[Rescan of <group>] was started", "PROTECTION GROUP CONFIGURATION", "PROTECTION GROUP USAGE".
  if (has("protection group") || has("rescan of "))
    return VeeamInfrastructureOperation::protection_group;
  if (has("managed server") || has("adding server") || has("add server") ||
      has("server has been added") || has("cannot connect to host") ||
      has("failed to connect to the managed"))
    return VeeamInfrastructureOperation::managed_server;
  if (has("repository") || has("extent") || has("sobr"))
    return VeeamInfrastructureOperation::repository;
  if (has("deploy") || has("upgrade component") || has("installing transport") ||
      has("push install") || has("veeamdeployment"))
    return VeeamInfrastructureOperation::agent_deployment;
  if (has("license"))
    return VeeamInfrastructureOperation::licensing;
  return VeeamInfrastructureOperation::none;
}

VeeamEventScope classify_event_scope(std::string_view message,
                                     VeeamEvidenceRole role,
                                     bool has_run_context) {
  // Roles that are never run-scoped, whatever the text says. A watchdog or an installer line inside
  // a job directory still is not part of the run.
  switch (role) {
  case VeeamEvidenceRole::protection_group_rescan:
  case VeeamEvidenceRole::configuration_backup:
  case VeeamEvidenceRole::sobr_tier:
  case VeeamEvidenceRole::setup:
    return VeeamEventScope::infrastructure;
  case VeeamEvidenceRole::service:
  case VeeamEvidenceRole::rpc_control:
  case VeeamEvidenceRole::system:
    // A service log can still carry infrastructure work, so ask before settling for "service".
    if (classify_infrastructure_operation(message, role) != VeeamInfrastructureOperation::none)
      return VeeamEventScope::infrastructure;
    return VeeamEventScope::service;
  default:
    break;
  }

  // The parser having bound this line to a job session is the strongest signal there is, and it
  // holds across log sources: this is what lets a managed VAW run include lines logged by the VBR
  // server as part of the same story.
  if (has_run_context)
    return VeeamEventScope::job_run;

  if (classify_infrastructure_operation(message, role) != VeeamInfrastructureOperation::none)
    return VeeamEventScope::infrastructure;

  switch (role) {
  case VeeamEvidenceRole::job:
  case VeeamEvidenceRole::task:
  case VeeamEvidenceRole::source_data_mover:
  case VeeamEvidenceRole::target_data_mover:
  case VeeamEvidenceRole::data_mover_server:
  case VeeamEvidenceRole::plugin:
  case VeeamEvidenceRole::guest_processing:
    return VeeamEventScope::job_run;
  case VeeamEvidenceRole::restore_operation:
  case VeeamEvidenceRole::user_interface:
  case VeeamEvidenceRole::tool_output:
    return VeeamEventScope::unknown;
  default:
    return VeeamEventScope::unknown;
  }
}

VeeamEvidenceRole classify_veeam_evidence_role(std::string_view source_path) {
  const std::string folded = folded_path_name(source_path);
  std::string logical = folded;
  if (const auto bang = logical.find('!'); bang != std::string::npos)
    logical = logical.substr(bang + 1U);
  const std::string file =
      ascii_lower(support_assist::path_to_utf8(support_assist::path_from_utf8(logical).filename()));

  if (logical.find("collection-manifest.json") != std::string::npos)
    return VeeamEvidenceRole::manifest;
  // SAT's own Customer/Lab tool output, collected into the bundle under [BundlePaths] Tools=.
  // Matched before the product-log rules because a tool that captured a product log can produce a
  // file whose name would otherwise classify as that product's role, which would silently
  // misattribute SAT-generated evidence to Veeam.
  if (logical.starts_with("tools/") || logical.find("/tools/") != std::string::npos ||
      logical.find("log-collections/tools/") != std::string::npos)
    return VeeamEvidenceRole::tool_output;
  // Console/tray UI logs: what a person did in the product interface. Veeam names these
  // "UI.<component>.log" (VBR console, VAW tray, plug-in UI), and the tray variant carries the
  // operator's account name, e.g. UI.Tray-<user>.log. Matched early for the same reason as above:
  // "UI.Backup.log" would otherwise fall through to the job/backup rules and be filed as job
  // evidence, losing the fact that a human performed the action.
  if (file.starts_with("ui.") || file.find(".ui.log") != std::string::npos ||
      file.starts_with("veeam.backup.ui") || file.find("shell.log") != std::string::npos ||
      logical.find("/ui/") != std::string::npos)
    return VeeamEvidenceRole::user_interface;
  // VBR retention history is a system-maintenance family, not a customer backup job.
  // Keeping it out of the fast job index prevents months of retention runs from
  // overwhelming the Job/Run selector while preserving it for deep review.
  if (logical.starts_with("backup/system/retention/") ||
      logical.find("/backup/system/retention/") != std::string::npos)
    return VeeamEvidenceRole::system;
  // Guest processing / application-aware family, named explicitly by KB1789. These carry VSS
  // writer, transaction-truncation and indexing failures, which are the actual cause behind a
  // large share of "backup completed with warnings" cases. Matched before the generic agent./
  // svc. rules because several of these names would otherwise be swallowed by them.
  if (file.find("guesthelper") != std::string::npos || file.find("guestindexer") != std::string::npos ||
      file.find("guestinteraction") != std::string::npos || file.find("vixproxy") != std::string::npos ||
      file.find("vsssupport") != std::string::npos || file.find("vssproxy") != std::string::npos ||
      file.find("vsshwprovider") != std::string::npos || file == "agent.index.log" ||
      file.starts_with("agent.index."))
    return VeeamEvidenceRole::guest_processing;
  // Scale-out backup repository tier activity, per KB4463's granular SOBR collection list.
  if (file.starts_with("sobr_offload") || file.starts_with("sobr_archival") ||
      file.find("evacuatebackupsjob") != std::string::npos ||
      file.find("resourcesusage") != std::string::npos ||
      file.find("databaseresynchronizer") != std::string::npos ||
      logical.find("/sobr/") != std::string::npos)
    return VeeamEvidenceRole::sobr_tier;
  // Configuration database backup/restore. A failure here is VBR maintenance, not a protected
  // workload, and must not be presented as a customer backup job failing.
  if (file.starts_with("config.") || file.find("configbackup") != std::string::npos ||
      file.find("exportimport") != std::string::npos ||
      file.find("sqliteschemaupdate") != std::string::npos)
    return VeeamEvidenceRole::configuration_backup;
  // Restore-side operations. Kept distinct so a failed recovery is never read as a failed backup.
  if (file.find("recovery") != std::string::npos || file.find("mountvm") != std::string::npos ||
      file.find("veeamflr") != std::string::npos || file.find("veeamsearchdll") != std::string::npos ||
      file.find("flrdrvinstaller") != std::string::npos || file.starts_with("svc.veeammount") ||
      file.find("mountservice") != std::string::npos || file.starts_with("flr_") ||
      file.find("winflr") != std::string::npos || file.find("mount service") != std::string::npos)
    return VeeamEvidenceRole::restore_operation;
  if (logical.starts_with("backup/rescan/") || logical.find("/backup/rescan/") != std::string::npos ||
      file.starts_with("job.rescan") || file.find("rescan_of_") != std::string::npos)
    return VeeamEvidenceRole::protection_group_rescan;
  if (file == "vaw_vmc.log" || file.starts_with("vaw_vmc"))
    return VeeamEvidenceRole::vaw_management;
  if (file.find("scheduler") != std::string::npos ||
      file.find("jobsettings") != std::string::npos ||
      logical.find("/scheduler/") != std::string::npos)
    return VeeamEvidenceRole::scheduler;
  if (file.find("_rpc.log") != std::string::npos || file.find(".rpc.log") != std::string::npos ||
      file.starts_with("rpc.") || file.find("grpc") != std::string::npos ||
      logical.find("/grpc/") != std::string::npos || logical.find("/yarp/") != std::string::npos)
    return VeeamEvidenceRole::rpc_control;
  if (file.starts_with("agent.")) {
    // Repair and check FIRST. Veeam names these Agent.<obj>.Target.Repair.log and
    // Agent.<obj>.CheckTarget.Check.log - the word "Target" is in both - so testing ".target"
    // first swallowed every repair log as an ordinary target mover, and data-mover-repair never
    // appeared in a single report across three VBR bundles.
    if (file.find("repair") != std::string::npos)
      return VeeamEvidenceRole::data_mover_repair;
    if (file.find("checktarget") != std::string::npos || file.find(".check") != std::string::npos)
      return VeeamEvidenceRole::data_mover_check;
    if (file.find(".source") != std::string::npos)
      return VeeamEvidenceRole::source_data_mover;
    if (file.find(".target") != std::string::npos)
      return VeeamEvidenceRole::target_data_mover;
    if (file.find(".server") != std::string::npos)
      return VeeamEvidenceRole::data_mover_server;
  }
  if (file.find("transform") != std::string::npos || file.find("vbkmanager") != std::string::npos ||
      file.find("fileoperation") != std::string::npos || file.find("synthetic") != std::string::npos)
    return VeeamEvidenceRole::repository_operation;
  if (file.starts_with("task."))
    return VeeamEvidenceRole::task;
  // Managed-agent run session records, e.g.
  // Backup/Endpoint/Backup/Managed/<id>/<host>/<job>/Session.log. The correlation model doc
  // establishes jobSessionId as the primary correlation key, and these files ARE the session
  // record for a run, so they belong in the job/run index rather than being discarded as
  // unclassified. Plug-in session logs already reach the plugin role via their /Plugin/ path.
  if (file == "session.log" || file.starts_with("session.")) {
    if (logical.find("/backup/") != std::string::npos || logical.starts_with("backup/"))
      return VeeamEvidenceRole::job;
    return VeeamEvidenceRole::service;
  }
  if (file.starts_with("job.")) {
    const std::size_t backup_marker = logical.find("backup/");
    if (backup_marker != std::string::npos) {
      const std::string_view relative(logical.data() + backup_marker + 7U,
                                      logical.size() - backup_marker - 7U);
      const auto separators = static_cast<std::size_t>(
          std::count(relative.begin(), relative.end(), '/'));
      // VBR commonly stores a parent job log at Backup/<job>/Job.<job>.log and
      // per-workload child logs at Backup/<job>/<workload>/Job.<workload>.log.
      // The child log is task/workload evidence; promoting it to another backup
      // run makes one managed job look like several independent jobs.
      if (separators >= 2U)
        return VeeamEvidenceRole::task;
    }
  }
  if (is_vaw_service_rotation_file(logical))
    return VeeamEvidenceRole::service;
  if (file.starts_with("job.") || file.find("_job.") != std::string::npos ||
      file.find("__job.") != std::string::npos)
    return VeeamEvidenceRole::job;
  // The Veeam Transport Service IS the data mover in Veeam's own terminology, so endpoint
  // transport logs belong with the data-mover family rather than in generic service traffic.
  if (file.starts_with("endpoint.transport") || file.starts_with("veeamtransport.") ||
      file == "svc.veeamtransport.log")
    return VeeamEvidenceRole::data_mover_server;
  if (file.starts_with("svc.") || file.find("_svc.") != std::string::npos ||
      file.find("__svc.") != std::string::npos ||
      file.find("veeam.backup.service") != std::string::npos ||
      file.find("endpointbackup") != std::string::npos ||
      file.find("vbrcommunicationmanager") != std::string::npos ||
      // Long-running VBR background services. Watchdogs alone accounted for a large share of the
      // previously unclassified files in real bundles; they are service-lifecycle evidence and
      // are service-scoped rather than belonging to any one run.
      file.find("watchdog") != std::string::npos ||
      file.find("veeam.standby.service") != std::string::npos ||
      file.find("veeambackupmanager") != std::string::npos ||
      file.find("veeamdeployment") != std::string::npos ||
      file.find("veeamdeployer") != std::string::npos ||
      file.find("brokerservice") != std::string::npos ||
      file.find("dispatcher") != std::string::npos ||
      // VBR 13 "satellite" component services, and the WMI/DIS infrastructure services that
      // appear in every VBR bundle.
      file.starts_with("satellite_") || file.starts_with("wmiserver.") ||
      file.starts_with("disserver.") || file.find("wmiproxy") != std::string::npos)
    return VeeamEvidenceRole::service;
  if (logical.find("mssql") != std::string::npos || logical.find("sqlplugin") != std::string::npos ||
      logical.find("/plugin/") != std::string::npos || logical.find("/plugins/") != std::string::npos ||
      file.find("plugin") != std::string::npos || logical.find("rman") != std::string::npos ||
      file.find("oraclelib") != std::string::npos)
    return VeeamEvidenceRole::plugin;
  // Public-cloud and hypervisor appliance platform services. Deliberately ordered AFTER the
  // plug-in rule: anything living under a /Plugins/ path is plug-in evidence and the existing
  // contract test asserts exactly that for Backup/Plugins/AWS/Veeam.AWS.PlatformSvc.log. This
  // rule therefore only claims cloud platform services that sit outside a plug-in path, which is
  // where they actually appear in the real VBR bundles.
  if (file.find("platformsvc") != std::string::npos || file.find("cloudgate") != std::string::npos ||
      file.find("clouddatastore") != std::string::npos ||
      file.find("cloudprovider") != std::string::npos ||
      file.find("cloudthrottling") != std::string::npos ||
      file.find("publiccloud") != std::string::npos)
    return VeeamEvidenceRole::cloud_plugin;
  if (file.find("setup") != std::string::npos || file.find("install") != std::string::npos ||
      file.find("msi") != std::string::npos)
    return VeeamEvidenceRole::setup;
  if (logical.find("/utils/") != std::string::npos || logical.find("/resourcescan/") != std::string::npos ||
      logical.find("/system/") != std::string::npos || file.find("systeminfo") != std::string::npos)
    return VeeamEvidenceRole::system;
  if (is_root_service_log(folded))
    return VeeamEvidenceRole::service;
  return VeeamEvidenceRole::other;
}

Result<VeeamReviewProfile> parse_veeam_review_profile(std::string_view value) {
  const std::string folded = ascii_lower(trim_copy(value));
  if (folded.empty() || folded == "auto" || folded == "automatic")
    return Result<VeeamReviewProfile>::success(VeeamReviewProfile::automatic);
  if (folded == "vaw" || folded == "agent")
    return Result<VeeamReviewProfile>::success(VeeamReviewProfile::vaw);
  if (folded == "vbr" || folded == "backup" || folded == "backup-replication")
    return Result<VeeamReviewProfile>::success(VeeamReviewProfile::vbr);
  if (folded == "sql" || folded == "sql-plugin" || folded == "mssql")
    return Result<VeeamReviewProfile>::success(VeeamReviewProfile::sql_plugin);
  if (folded == "rman" || folded == "rman-plugin" || folded == "oracle")
    return Result<VeeamReviewProfile>::success(VeeamReviewProfile::rman_plugin);
  if (folded == "sap-hana" || folded == "sap-hana-plugin" || folded == "hana")
    return Result<VeeamReviewProfile>::success(VeeamReviewProfile::sap_hana_plugin);
  if (folded == "sap-oracle" || folded == "sap-oracle-plugin" || folded == "sap-orcl")
    return Result<VeeamReviewProfile>::success(VeeamReviewProfile::sap_oracle_plugin);
  if (folded == "sap-maxdb" || folded == "sap-maxdb-plugin" || folded == "maxdb")
    return Result<VeeamReviewProfile>::success(VeeamReviewProfile::sap_maxdb_plugin);
  if (folded == "db2" || folded == "db2-plugin" || folded == "ibm-db2")
    return Result<VeeamReviewProfile>::success(VeeamReviewProfile::db2_plugin);
  if (folded == "generic" || folded == "custom" || folded == "customer")
    return Result<VeeamReviewProfile>::success(VeeamReviewProfile::generic);
  return Result<VeeamReviewProfile>::failure(
      review_error("parse profile", "Unknown Veeam review profile: " + std::string(value)));
}

const VeeamMachineRecord* find_veeam_machine(const VeeamLogReviewResult& review,
                                             std::string_view machine_key) {
  const auto found = std::find_if(review.machines.begin(), review.machines.end(), [&](const auto& item) {
    return item.key == machine_key;
  });
  return found == review.machines.end() ? nullptr : &*found;
}

const VeeamJobSession* find_veeam_job_run(const VeeamLogReviewResult& review,
                                          std::string_view run_key) {
  const auto found = std::find_if(review.job_sessions.begin(), review.job_sessions.end(), [&](const auto& item) {
    return item.run_key == run_key;
  });
  return found == review.job_sessions.end() ? nullptr : &*found;
}

bool veeam_location_matches_run(const VeeamIncidentLocation& location,
                                const VeeamJobSession& run,
                                const VeeamLogReviewOptions& options) {
  if (location.machine_key != run.machine_key)
    return false;
  if (!location.correlated_job_run_keys.empty()) {
    return std::find(location.correlated_job_run_keys.begin(),
                     location.correlated_job_run_keys.end(),
                     run.run_key) != location.correlated_job_run_keys.end();
  }
  if (!location.explicit_job_run_key.empty())
    return location.explicit_job_run_key == run.run_key;
  if (!location.explicit_session_id.empty() && !run.session_id.empty() &&
      equals_folded(location.explicit_session_id, run.session_id))
    return true;
  if (!location.explicit_job_id.empty() && !run.job_id.empty() &&
      !equals_folded(location.explicit_job_id, run.job_id))
    return false;
  return location_in_run_window(location, run, options);
}

std::vector<const VeeamIncident*> filter_veeam_incidents(
    const VeeamLogReviewResult& review,
    std::string_view machine_key,
    std::string_view run_key,
    const VeeamLogReviewOptions& options) {
  const VeeamJobSession* run = run_key.empty() ? nullptr : find_veeam_job_run(review, run_key);
  std::vector<const VeeamIncident*> output;
  for (const auto& incident : review.incidents) {
    const bool matches = std::any_of(incident.locations.begin(), incident.locations.end(), [&](const auto& location) {
      if (!machine_key.empty() && location.machine_key != machine_key)
        return false;
      return run == nullptr || veeam_location_matches_run(location, *run, options);
    });
    if (matches)
      output.push_back(&incident);
  }
  return output;
}

std::string veeam_ticket_evidence_path(std::string_view source_path) {
  return note_evidence_path(source_path);
}

std::string build_veeam_ticket_note(const VeeamLogReviewResult& review,
                                    std::string_view machine_key,
                                    std::string_view run_key,
                                    std::string_view issue) {
  const VeeamMachineRecord* machine = machine_key.empty() ? nullptr : find_veeam_machine(review, machine_key);
  if (machine == nullptr && review.machines.size() == 1U)
    machine = &review.machines.front();
  const VeeamJobSession* run = run_key.empty() ? nullptr : find_veeam_job_run(review, run_key);

  std::ostringstream note;
  note << "#note\n\nIssue:\n" << issue << "\n\nErrors:\n";

  struct NoteLocation {
    const VeeamIncidentLocation* location = nullptr;
    std::string severity;
  };
  std::vector<NoteLocation> locations;
  VeeamLogReviewOptions filter_options;
  for (const auto& incident : review.incidents) {
    if (incident.severity != "error" && incident.severity != "warning")
      continue;
    for (const auto& location : incident.locations) {
      if (machine != nullptr && location.machine_key != machine->key)
        continue;
      if (run != nullptr && !veeam_location_matches_run(location, *run, filter_options))
        continue;
      locations.push_back(NoteLocation{&location, incident.severity});
    }
  }
  std::stable_sort(locations.begin(), locations.end(), [](const auto& left, const auto& right) {
    if (left.location->timestamp_utc_ms && right.location->timestamp_utc_ms &&
        left.location->timestamp_utc_ms != right.location->timestamp_utc_ms)
      return *left.location->timestamp_utc_ms > *right.location->timestamp_utc_ms;
    if (left.location->timestamp_utc_ms.has_value() != right.location->timestamp_utc_ms.has_value())
      return left.location->timestamp_utc_ms.has_value();
    if (left.location->source_path != right.location->source_path)
      return left.location->source_path < right.location->source_path;
    return left.location->line_number < right.location->line_number;
  });
  if (locations.empty()) {
    note << "None identified in the selected evidence scope.\n";
  } else {
    std::set<std::pair<std::string, std::uint64_t>> emitted;
    for (const auto& item : locations) {
      const auto& location = *item.location;
      if (!emitted.emplace(location.source_path, location.line_number).second)
        continue;
      note << note_evidence_path(location.source_path);
      if (location.line_number != 0U)
        note << ":" << location.line_number;
      note << "\n";
      if (!location.before.empty() || !location.after.empty())
        note << "Context (up to 5 lines before and after matched evidence):\n";
      for (const auto& raw_line : location.before)
        note << raw_line << "\n";
      for (const auto& raw_line : location.lines)
        note << raw_line << "\n";
      for (const auto& raw_line : location.after)
        note << raw_line << "\n";
      note << '\n';
    }
  }

  note << "Machine:\n";
  if (machine != nullptr) {
    note << machine->display_name;
    std::vector<std::string> addresses;
    if (machine->summary.primary_ip)
      append_unique(addresses, machine->summary.primary_ip->value);
    for (const auto& address : machine->summary.alternate_ip_addresses)
      append_unique(addresses, address.value);
    if (!addresses.empty())
      note << " | " << join_text(addresses, ", ");
    note << "\n";
  } else {
    note << "Not identified\n";
  }

  note << "\nManaged Mode:\n";
  if (machine != nullptr && machine->summary.management_mode) {
    const auto& mode = *machine->summary.management_mode;
    note << management_mode_note_value(mode.value) << "\n";
    if (!mode.source_path.empty()) {
      note << note_evidence_path(mode.source_path);
      if (mode.line_number != 0U)
        note << ":" << mode.line_number;
      note << "\n";
    }
    if (!mode.raw_line.empty())
      note << mode.raw_line << "\n";
  } else {
    note << "Not identified\n";
  }

  note << "\nOS Version:\n";
  if (machine != nullptr)
    note << evidence_value(machine->summary.operating_system) << "\n";
  else
    note << "Not identified\n";

  note << "\nProduct:\n" << product_name_for_machine(review, machine);
  if (machine != nullptr && machine->summary.product_version)
    note << " | Version: " << machine->summary.product_version->value;
  note << "\n";

  note << "\nBackup Server:\n";
  if (run != nullptr && !run->settings.backup_server.empty()) {
    note << run->settings.backup_server << "\n";
  } else if (machine != nullptr && machine->summary.management_mode &&
             contains_folded(machine->summary.management_mode->value, "standalone")) {
    note << "NA\n";
  } else {
    note << "Not identified\n";
  }

  if (machine != nullptr && machine->summary.management_server) {
    note << "\nManagement Server (bundle evidence):\n"
         << machine->summary.management_server->value << "\n";
  }

  note << "\nRepository:\n";
  if (run != nullptr && (!run->settings.backup_repository.empty() ||
                         !run->settings.destination_path.empty() ||
                         !run->settings.destination_type.empty())) {
    const std::string repository = !run->settings.backup_repository.empty()
                                       ? run->settings.backup_repository
                                       : run->settings.destination_path;
    note << (repository.empty() ? "Not identified" : repository);
    if (!run->settings.destination_type.empty())
      note << " | Type: " << run->settings.destination_type;
    note << "\n";
  } else {
    note << "Not identified\n";
  }

  note << "\nJob Run:\n";
  if (run != nullptr) {
    note << "Job: " << (run->job_name.empty() ? "Not identified" : run->job_name) << "\n";
    if (!run->status.empty())
      note << "Result: " << run->status << "\n";
    if (run->start_utc_ms || !run->start_timestamp_original.empty())
      note << "Start: " << canonical_timestamp(run->start_utc_ms, run->start_timestamp_original) << "\n";
    if (run->completion_utc_ms || !run->completion_timestamp_original.empty())
      note << "End: " << canonical_timestamp(run->completion_utc_ms, run->completion_timestamp_original) << "\n";
    if (!run->session_id.empty())
      note << "Session ID: " << run->session_id << "\n";
    if (!run->task_session_id.empty())
      note << "Task Session ID: " << run->task_session_id << "\n";
  } else {
    note << "Not selected\n";
  }

  note << "\nJob Settings:\n";
  if (run != nullptr) {
    const auto& settings = run->settings;
    if (!settings.settings_lines.empty()) {
      if (!settings.settings_source_path.empty()) {
        note << note_evidence_path(settings.settings_source_path);
        if (settings.settings_start_line != 0U) {
          note << ":" << settings.settings_start_line;
          if (settings.settings_end_line > settings.settings_start_line)
            note << "-" << settings.settings_end_line;
        }
        note << "\n";
      }
      for (const auto& raw_line : settings.settings_lines)
        note << raw_line << "\n";
    } else {
      note << "No retained Job Settings block was identified for this selected run.\n";
    }

    note << "\nParsed Job Settings Summary:\n";
    auto line = [&](std::string_view label, std::string_view value) {
      if (!value.empty())
        note << label << ": " << value << "\n";
    };
    line("Job Type", run->job_type);
    line("Job Description", settings.job_description);
    line("Backup Mode", settings.backup_mode);
    line("Backup Server", settings.backup_server);
    line("Backup Repository", settings.backup_repository);
    line("Retention", settings.retention);
    line("Compression", settings.compression);
    line("Storage Optimization", settings.storage_optimization);
    line("Encryption", settings.encryption);
    line("GFS", settings.gfs);
    line("Backup Cache", settings.backup_cache);
    line("Schedule", settings.schedule);
    line("VSS Snapshot", settings.vss_snapshot);
    line("Application Processing", settings.application_processing);
    line("Guest Indexing", settings.guest_indexing);
    line("Script Processing", settings.script_processing);
    line("Command Line", settings.command_line);
    if (!settings.included_items.empty())
      note << "Included Items: " << join_text(settings.included_items, ", ") << "\n";
    if (!settings.excluded_items.empty())
      note << "Excluded Items: " << join_text(settings.excluded_items, ", ") << "\n";
  } else {
    note << "No job run selected.\n";
  }

  note << "\nSource Backup Mode:\n"
       << (run == nullptr || run->settings.source_backup_mode.empty() ? "Not identified"
                                                                      : run->settings.source_backup_mode)
       << "\n";
  note << "\nRepository Operation:\n"
       << (run == nullptr || run->settings.repository_operation.empty() ? "Not identified"
                                                                         : run->settings.repository_operation)
       << "\n";
  note << "\nResulting Backup:\n";
  if (run == nullptr) {
    note << "Not identified\n";
  } else {
    note << (run->settings.resulting_backup_type.empty() ? "Type not identified"
                                                          : run->settings.resulting_backup_type);
    if (!run->status.empty())
      note << " | Run result: " << run->status;
    if (!run->backup_file.empty())
      note << " | File: " << run->backup_file;
    note << "\n";
  }

  note << "\nTask total size:\n"
       << (run == nullptr || run->settings.task_total_size.empty() ? "Not identified"
                                                                    : run->settings.task_total_size)
       << "\n";

  note << "\nVSS:\n";
  if (run == nullptr || (run->snapshot_volumes.empty() && run->used_vss_provider_id.empty() &&
                         run->used_vss_provider_name.empty())) {
    note << "Not identified\n";
  } else if (run != nullptr) {
    if (!run->used_vss_provider_name.empty())
      note << "Used Provider: " << run->used_vss_provider_name << "\n";
    if (!run->used_vss_provider_type.empty())
      note << "Provider Type: " << run->used_vss_provider_type << "\n";
    if (!run->used_vss_provider_id.empty())
      note << "Provider ID: " << run->used_vss_provider_id << "\n";

    constexpr std::uint64_t kSoftwareVss64TiBLimit =
        64ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
    for (const auto& volume : run->snapshot_volumes) {
      const std::uint64_t size_bytes = snapshot_volume_size_bytes(volume);
      note << "Volume: "
           << (!volume.mount_point.empty() ? volume.mount_point
                                           : (!volume.volume_id.empty() ? volume.volume_id : "Not identified"));
      if (size_bytes != 0U)
        note << " | Size: " << note_size(size_bytes);
      if (!volume.file_system.empty())
        note << " | File System: " << volume.file_system;
      note << "\n";

      const std::string provider_name =
          !volume.used_provider_name.empty() ? volume.used_provider_name : run->used_vss_provider_name;
      const std::string provider_type =
          !volume.used_provider_type.empty() ? volume.used_provider_type : run->used_vss_provider_type;
      if (!provider_name.empty())
        note << "Volume VSS Provider: " << provider_name << "\n";
      if (!provider_type.empty())
        note << "Volume VSS Provider Type: " << provider_type << "\n";

      if (is_vaw_scope(review, machine) && size_bytes > kSoftwareVss64TiBLimit) {
        if (is_microsoft_software_vss_provider(provider_name, provider_type)) {
          note << "SAT Diagnostic Warning: This Veeam Agent for Microsoft Windows backup volume exceeds "
                  "64 TB and the observed run uses the Microsoft software/system VSS provider. The "
                  "supported >64 TB VAW path requires the applicable managed storage-snapshot/hardware "
                  "VSS workflow; a software-VSS fallback is not supported for this volume.\n";
        } else if (is_hardware_vss_provider(provider_type)) {
          note << "SAT Diagnostic Information: This backup volume exceeds 64 TB and the observed run "
                  "uses a hardware VSS provider. Do not apply the software-VSS >64 TB warning to this "
                  "run solely from volume size.\n";
        } else {
          note << "SAT Diagnostic Information: This backup volume exceeds 64 TB, but SAT did not "
                  "resolve the VSS provider as software/system or hardware. Provider compatibility "
                  "requires evidence from the selected run before a warning is asserted.\n";
        }
      }
    }
  }

  note << "\nDisks in Backup:\n";
  if (run == nullptr ||
      (run->volume_evidence.empty() && run->disk_extents.empty() && run->snapshot_volumes.empty())) {
    note << "Not identified\n";
  } else if (run != nullptr) {
    for (const auto& volume : run->snapshot_volumes) {
      const std::uint64_t size_bytes = snapshot_volume_size_bytes(volume);
      note << "Disk/Volume "
           << (!volume.mount_point.empty() ? volume.mount_point
                                           : (!volume.volume_id.empty() ? volume.volume_id : "Not identified"));
      if (size_bytes != 0U)
        note << " | Size: " << note_size(size_bytes);
      note << "\n";
      for (const auto& evidence : volume.evidence)
        note << note_evidence_path(evidence.source_path) << "\n" << evidence.raw_line << "\n";
      for (const auto& extent : volume.extents) {
        note << note_evidence_path(extent.evidence.source_path) << "\n"
             << extent.evidence.raw_line << "\n";
        note << "Derived extent size: " << note_size(extent.length_bytes)
             << " (length=" << extent.length_bytes << " bytes; offset=" << extent.offset_bytes
             << " bytes)\n";
      }
    }

    for (const auto& evidence : run->volume_evidence)
      note << note_evidence_path(evidence.source_path) << "\n" << evidence.raw_line << "\n";

    for (const auto& extent : run->disk_extents) {
      const bool already_attached = std::any_of(
          run->snapshot_volumes.begin(), run->snapshot_volumes.end(), [&](const auto& volume) {
            return std::any_of(volume.extents.begin(), volume.extents.end(), [&](const auto& item) {
              return same_extent(item, extent);
            });
          });
      if (already_attached)
        continue;
      note << note_evidence_path(extent.evidence.source_path) << "\n"
           << extent.evidence.raw_line << "\n";
      note << "Derived extent size: " << note_size(extent.length_bytes)
           << " (length=" << extent.length_bytes << " bytes; offset=" << extent.offset_bytes
           << " bytes)\n";
    }
  }

  note << "\nPEX in run:\n";
  if (run == nullptr || run->pex_samples.empty()) {
    note << "Not identified\n";
  } else {
    // The highest busy percentage in a sample is the bottleneck that sample reports, so the stage
    // that is highest most often across the run is where the job spent its time. Reported before
    // the raw lines because an engineer reads this to answer "which leg is slow" first.
    const auto pex_summary = summarize_pex(run->pex_samples);
    note << "Samples: " << pex_summary.samples;
    if (pex_summary.rated_samples == 0U) {
      note << " (no readable busy percentages)\n";
    } else {
      note << " (" << pex_summary.rated_samples << " with readable busy percentages)\n";
      if (pex_summary.dominant) {
        const auto stage = *pex_summary.dominant;
        const std::string alias = veeam_pex_stage_alias(stage);
        note << "Bottleneck: " << (alias.empty() ? veeam_pex_stage_label(stage) : alias) << " - "
             << veeam_pex_stage_meaning(stage) << " - highest in "
             << pex_summary.stage(stage).bottleneck_samples << " of " << pex_summary.rated_samples
             << " sample(s)\n";
      }
      for (std::size_t index = 0; index < kVeeamPexStageCount; ++index) {
        const auto stage = static_cast<VeeamPexStage>(index);
        const auto& statistics = pex_summary.stage(stage);
        if (statistics.samples == 0U) continue;
        std::string name = veeam_pex_stage_label(stage);
        const std::string alias = veeam_pex_stage_alias(stage);
        if (!alias.empty()) name += " (" + alias + ")";
        if (name.size() < 34U) name.resize(34U, ' ');
        note << "  " << name << " peak " << statistics.peak << "%";
        if (const auto mean = statistics.mean_percent()) note << "  mean " << *mean << "%";
        note << "  highest in " << statistics.bottleneck_samples << " sample(s)\n";
      }
    }
    for (const auto& sample : run->pex_samples)
      note << note_evidence_path(sample.evidence.source_path) << "\n" << sample.evidence.raw_line << "\n";
  }

  note << "\nManagement Events:\n";
  if (run == nullptr || run->management_events.empty()) {
    note << "None identified\n";
  } else {
    for (const auto& event : run->management_events)
      note << note_evidence_path(event.source_path) << "\n" << event.raw_line << "\n";
  }

  if (run != nullptr && !run->job_name.empty() && run->start_utc_ms) {
    const VeeamJobSession* last_known_good = nullptr;
    if (equals_folded(run->status, "Success")) {
      last_known_good = run;
    } else {
      for (const auto& candidate : review.job_sessions) {
        if (&candidate == run || candidate.machine_key != run->machine_key ||
            !equals_folded(candidate.job_name, run->job_name) ||
            !equals_folded(candidate.status, "Success") || !candidate.start_utc_ms ||
            *candidate.start_utc_ms >= *run->start_utc_ms)
          continue;
        if (last_known_good == nullptr ||
            *candidate.start_utc_ms > *last_known_good->start_utc_ms)
          last_known_good = &candidate;
      }
    }
    note << "\nLast Known Good:\n";
    if (last_known_good != nullptr)
      note << canonical_timestamp(last_known_good->start_utc_ms, last_known_good->start_timestamp_original)
           << " | Success\n";
    else
      note << "Not identified\n";
  }

  note << "\nNext Steps:\n";
  return note.str();
}

Result<VeeamLogReviewResult> review_veeam_logs(const VeeamLogReviewOptions& options,
                                               const CancellationToken& cancel,
                                               ProgressCallback progress,
                                               ReviewConsoleCallback console) {
  if (options.sources.empty()) {
    return Result<VeeamLogReviewResult>::failure(
        review_error("validate options", "At least one file, folder, or archive is required"));
  }

  const auto total_started = std::chrono::steady_clock::now();
  VeeamLogReviewResult review;
  review.assumed_timezone_offset_minutes = options.assumed_timezone_offset_minutes;
  review.maximum_report_timeline_occurrences = options.maximum_report_timeline_occurrences;
  review.maximum_report_detailed_incidents = options.maximum_report_detailed_incidents;
  review.profile_used = options.profile;
  review.fast_index_used = options.fast_index_first;
  review.input_sources = options.sources;
  review.parser_profile = review_profile_label(options.profile);
  review.product_type = expected_product_type(options.profile);
  // Parser selection is an interpretation hint, not verified product identity.
  // Product markers observed in the evidence raise this confidence later.
  review.product_confidence = ParserConfidence::unconfirmed;
  review.parser_scope_note = options.fast_index_first
                                 ? "Fast index mode scans high-value identity, service, job, and rescan logs first. "
                                   "Data-mover and other deferred logs are included by a full/deep review."
                                 : "Full/deep review scans the selected evidence scope. Root service logs remain "
                                   "important because orchestration errors can occur outside job-specific files.";

  if (progress)
    progress(ProgressEvent{"Discovering log sources",
                           std::to_string(options.sources.size()) + " configured source(s)",
                           0, 0, 0.0, 0.0});
  const auto discovery_started = std::chrono::steady_clock::now();
  std::vector<std::filesystem::path> direct_paths;
  std::vector<std::filesystem::path> archives;
  std::uint64_t nested_archives_skipped = 0;
  std::map<std::string, std::uint64_t> not_read;
  for (const auto& source : options.sources)
    discover_path(source, options.recursive, options.search_archives, direct_paths, archives,
                  nested_archives_skipped, not_read);
  review.nested_archives_skipped = nested_archives_skipped;
  // In the order of kNotReadKinds, then other files.
  for (const auto& [suffix, kind] : kNotReadKinds) {
    const auto found = not_read.find(std::string(kind));
    if (found == not_read.end())
      continue;
    review.files_not_read.emplace_back(found->first, found->second);
    not_read.erase(found);
  }
  if (const auto other = not_read.find("other file"); other != not_read.end())
    review.files_not_read.emplace_back(other->first, other->second);
  std::sort(direct_paths.begin(), direct_paths.end());
  direct_paths.erase(std::unique(direct_paths.begin(), direct_paths.end()), direct_paths.end());
  std::sort(archives.begin(), archives.end());
  archives.erase(std::unique(archives.begin(), archives.end()), archives.end());
  review.discovery_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - discovery_started).count();
  if (progress)
    progress(ProgressEvent{"Discovery complete",
                           std::to_string(direct_paths.size()) + " direct file(s), " +
                               std::to_string(archives.size()) + " archive(s)",
                           direct_paths.size() + archives.size(), 0,
                           review.discovery_seconds, 0.0});

  const std::filesystem::path output_directory = determine_output_directory(options);
  std::error_code directory_error;
  std::filesystem::create_directories(output_directory, directory_error);
  if (directory_error) {
    return Result<VeeamLogReviewResult>::failure(
        review_error("create report directory", directory_error.message(), output_directory));
  }
  review.persistent_cache_enabled = options.use_persistent_parser_cache;
  review.cache_directory = options.use_persistent_parser_cache
                               ? (options.parser_cache_directory.empty()
                                      ? output_directory / ".support-assist-parser-cache"
                                      : options.parser_cache_directory)
                               : output_directory / ".support-assist-log-cache" / make_uuid_v4();

  std::vector<ReviewInputFile> files;
  std::vector<EvidenceCatalogPath> evidence_catalog;
  files.reserve(direct_paths.size());
  evidence_catalog.reserve(direct_paths.size());
  std::unordered_map<std::string, std::size_t> automatic_fallback_files_by_bundle;
  for (const auto& path : direct_paths) {
    ++review.files_discovered;
    const std::string display = support_assist::path_to_utf8(path);
    std::string bundle_key = normalized_source_path(support_assist::path_to_utf8(path.parent_path()));
    std::string bundle_display = support_assist::path_to_utf8(path.parent_path());
    for (const auto& source : options.sources) {
      std::error_code source_error;
      if (std::filesystem::is_directory(source, source_error)) {
        const std::string source_normalized = normalized_source_path(support_assist::path_to_utf8(source));
        const std::string path_normalized = normalized_source_path(support_assist::path_to_utf8(path));
        if (!source_normalized.empty() && path_normalized.starts_with(source_normalized)) {
          bundle_key = source_normalized;
          bundle_display = path_to_utf8(source);
          std::error_code relative_error;
          const auto relative = std::filesystem::relative(path, source, relative_error);
          if (!relative_error) {
            if (const auto partition = logical_source_partition_component(relative)) {
              bundle_key += "!source:" + ascii_lower(*partition);
              bundle_display = path_to_utf8((source / *partition));
            }
          }
          break;
        }
      } else if (source == path) {
        bundle_key = normalized_source_path(support_assist::path_to_utf8(source));
        bundle_display = path_to_utf8(source);
        break;
      }
    }
    std::error_code size_error;
    const auto raw_size = std::filesystem::file_size(path, size_error);
    bool index_candidate = !options.fast_index_first ||
                           is_fast_index_candidate(options.profile, display);
    if (!index_candidate && options.profile == VeeamReviewProfile::automatic) {
      auto& fallback_count = automatic_fallback_files_by_bundle[bundle_key];
      index_candidate = automatic_fast_index_fallback_candidate(
          display, size_error ? 0U : raw_size, fallback_count);
    }
    const bool index_deferred = options.fast_index_first && !index_candidate;
    const bool selected_deferred = !options.fast_index_first &&
                                   !path_matches_selected_run(options, display);
    const bool deferred = index_deferred || selected_deferred;
    evidence_catalog.push_back(EvidenceCatalogPath{display, bundle_key, bundle_display,
                                                    size_error ? 0U : raw_size, !deferred});
    if (deferred) {
      ++review.files_deferred;
      continue;
    }
    files.push_back(ReviewInputFile{path, display, bundle_key, bundle_display, {}, {}, false});
  }

  // Declared outside the libarchive block because it is READ after the #endif. Inside the block, a
  // build without libarchive does not compile this file at all. Both shipping builds enable
  // libarchive, which is why it was never exercised.
  std::string first_archive_error;

#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
  if (progress && !archives.empty())
    progress(ProgressEvent{"Opening archives", std::to_string(archives.size()) + " archive(s)", 0, 0, 0.0, 0.0});
  const auto archive_started = std::chrono::steady_clock::now();
  std::filesystem::create_directories(review.cache_directory, directory_error);
  if (directory_error) {
    return Result<VeeamLogReviewResult>::failure(
        review_error("create archive cache", directory_error.message(), review.cache_directory));
  }
  struct ArchiveOutcome {
    std::vector<ReviewInputFile> files;
    std::optional<Error> error;
    std::uint64_t expanded_bytes = 0;
    std::uint64_t entries = 0;
    std::uint64_t candidate_entries = 0;
    std::uint64_t deferred_entries = 0;
    std::uint64_t cache_hits = 0;
    std::uint64_t unwritable_entries = 0;
    std::string unwritable_detail;
    std::vector<EvidenceCatalogPath> catalog;
  };
  std::vector<ArchiveOutcome> archive_outcomes(archives.size());
  std::atomic<std::size_t> next_archive{0};
  const std::size_t archive_workers =
      std::min<std::size_t>(4U, automatic_worker_count(archives.size(), options.worker_count));
  auto archive_worker = [&] {
    for (;;) {
      if (cancel.is_cancelled())
        break;
      const std::size_t index = next_archive.fetch_add(1U);
      if (index >= archives.size())
        break;
      auto& outcome = archive_outcomes[index];
      auto extracted = extract_archive_logs(archives[index],
                                            review.cache_directory,
                                            options,
                                            outcome.expanded_bytes,
                                            outcome.entries,
                                            outcome.candidate_entries,
                                            outcome.deferred_entries,
                                            outcome.cache_hits,
                                            outcome.unwritable_entries,
                                            outcome.unwritable_detail,
                                            outcome.catalog);
      if (extracted.ok())
        outcome.files = std::move(extracted.value());
      else
        outcome.error = extracted.error();
    }
  };
  std::vector<std::jthread> archive_threads;
  archive_threads.reserve(archive_workers);
  for (std::size_t index = 0; index < archive_workers; ++index)
    archive_threads.emplace_back(archive_worker);
  archive_threads.clear();

  std::uint64_t total_expanded_bytes = 0;
  std::uint64_t total_entries = 0;
  for (std::size_t index = 0; index < archive_outcomes.size(); ++index) {
    auto& outcome = archive_outcomes[index];
    total_expanded_bytes += outcome.expanded_bytes;
    total_entries += outcome.entries;
    review.files_discovered += outcome.candidate_entries;
    review.files_deferred += outcome.deferred_entries;
    review.parser_cache_hits += outcome.cache_hits;
    // Entries that could not be written are counted as parse errors and named once, so a run that
    // returns fewer logs than the bundle holds says so rather than looking complete.
    if (outcome.unwritable_entries > 0U) {
      review.parse_errors += outcome.unwritable_entries;
      const std::string detail = std::to_string(outcome.unwritable_entries) +
                                 " entr(y/ies) could not be extracted from " +
                                 path_to_utf8(archives[index]) + " | " + outcome.unwritable_detail;
      emit_console(console, detail);
      if (first_archive_error.empty()) {
        first_archive_error = outcome.unwritable_detail;
      }
    }
    evidence_catalog.insert(evidence_catalog.end(),
                            std::make_move_iterator(outcome.catalog.begin()),
                            std::make_move_iterator(outcome.catalog.end()));
    if (total_expanded_bytes > options.maximum_total_archive_expanded_bytes ||
        total_entries > options.maximum_total_archive_entries) {
      return Result<VeeamLogReviewResult>::failure(
          review_error("archive limit", "Combined archive expansion limit exceeded"));
    }
    if (outcome.error) {
      // Keep what DID extract. This used to `continue`, discarding outcome.files wholesale, so one
      // entry that could not be written threw away every log beside it that had been written
      // perfectly well - and the review then reported that the bundle contained nothing.
      ++review.parse_errors;
      const std::string detail =
          "Archive partially read: " + path_to_utf8(archives[index]) + " | " + outcome.error->message;
      emit_console(console, detail);
      // emit_console only reaches a caller that supplied one, and the CLI does not always. Keeping
      // the first message means the reason survives into the failure below when nothing extracted
      // at all - which is the case where the user is told the least and needs it most.
      if (first_archive_error.empty()) {
        first_archive_error = outcome.error->message;
      }
    }
    files.insert(files.end(),
                 std::make_move_iterator(outcome.files.begin()),
                 std::make_move_iterator(outcome.files.end()));
  }
  review.archive_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - archive_started).count();
#else
  if (!archives.empty()) {
    review.parse_errors += archives.size();
    emit_console(console,
                 "Archive inputs were skipped because this build does not include libarchive.");
  }
#endif

  if (files.empty()) {
    // Naming the cause matters more here than anywhere else in the review: "No candidate log files
    // were found" reads as a statement about the customer's bundle, and sends the engineer back to
    // the customer for a new collection when the fault was on this side.
    if (!first_archive_error.empty()) {
      return Result<VeeamLogReviewResult>::failure(review_error(
          "discover logs",
          "No log files could be extracted from the archive(s): " + first_archive_error));
    }
    return Result<VeeamLogReviewResult>::failure(
        review_error("discover logs", "No candidate log files were found"));
  }

  std::sort(files.begin(), files.end(), [](const auto& left, const auto& right) {
    return normalized_source_path(left.display_path) < normalized_source_path(right.display_path);
  });
  const std::size_t workers = automatic_worker_count(files.size(), options.worker_count);
  review.workers_used = workers;
  emit_console(console,
               "Veeam review starting: " + std::to_string(files.size()) +
                   " candidate file(s), " + std::to_string(workers) + " parser worker(s)");
  const auto parse_started = std::chrono::steady_clock::now();
  std::vector<FileParseOutcome> outcomes(files.size());
  for (std::size_t index = 0; index < files.size(); ++index) {
    outcomes[index].file = files[index];
    std::error_code size_error;
    outcomes[index].size_bytes = std::filesystem::file_size(files[index].materialized_path, size_error);
    if (size_error)
      outcomes[index].size_bytes = 0;
  }
  std::atomic<std::size_t> next_index{0};
  std::atomic<std::size_t> completed{0};
  std::atomic<std::uint64_t> parse_errors{0};
  std::mutex callback_mutex;
  auto worker = [&] {
    for (;;) {
      if (cancel.is_cancelled())
        break;
      const std::size_t index = next_index.fetch_add(1U);
      if (index >= outcomes.size())
        break;
      auto& outcome = outcomes[index];
      const auto file_started = std::chrono::steady_clock::now();
      outcome.review.product_type = expected_product_type(options.profile);
      outcome.review.product_confidence = ParserConfidence::unconfirmed;
      outcome.review.parser_profile = review.parser_profile;
      outcome.review.parser_scope_note = review.parser_scope_note;
      auto parsed = parse_review_file(outcome.review, outcome.file, options, cancel);
      if (parsed.ok()) {
        outcome.lines = parsed.value();
      } else {
        outcome.error = parsed.error();
        parse_errors.fetch_add(1U);
      }
      outcome.elapsed_seconds =
          std::chrono::duration<double>(std::chrono::steady_clock::now() - file_started).count();
      const std::size_t done = completed.fetch_add(1U) + 1U;
      const double elapsed =
          std::chrono::duration<double>(std::chrono::steady_clock::now() - parse_started).count();
      std::scoped_lock lock(callback_mutex);
      const std::size_t progress_interval = std::max<std::size_t>(1U, files.size() / 100U);
      const std::size_t console_interval = std::max<std::size_t>(1U, files.size() / 20U);
      if (outcome.error) {
        emit_console(console,
                     "[" + std::to_string(done) + "/" + std::to_string(files.size()) +
                         "] Skipped " + outcome.file.display_path + " | " + outcome.error->message);
      } else if (done == files.size() || done <= 3U || done % console_interval == 0U) {
        emit_console(console,
                     "[" + std::to_string(done) + "/" + std::to_string(files.size()) +
                         "] Parsed " + outcome.file.display_path + " | " +
                         std::to_string(outcome.lines) + " line(s)");
      }
      if (progress &&
          (done == files.size() || done <= 3U || done % progress_interval == 0U ||
           outcome.error.has_value())) {
        progress(ProgressEvent{"Parsing Veeam logs",
                               std::to_string(done) + "/" + std::to_string(files.size()) +
                                   " | " + outcome.file.display_path +
                                   " | " + std::to_string(outcome.lines) + " line(s)",
                               done,
                               parse_errors.load(),
                               elapsed,
                               elapsed > 0.0 ? static_cast<double>(done) / elapsed : 0.0});
      }
    }
  };
  std::vector<std::jthread> threads;
  threads.reserve(workers);
  for (std::size_t index = 0; index < workers; ++index)
    threads.emplace_back(worker);
  threads.clear();
  review.parse_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - parse_started).count();

  if (cancel.is_cancelled())
    review.cancelled = true;
  const auto merge_started = std::chrono::steady_clock::now();
  assign_machine_keys(outcomes, options, review);
  if (!review.bundles.empty()) {
    const std::string first_product = review.bundles.front().product_type;
    const bool one_product = !first_product.empty() &&
        std::all_of(review.bundles.begin(), review.bundles.end(), [&](const auto& bundle) {
          return bundle.product_type == first_product;
        });
    if (one_product) {
      review.product_type = first_product;
      review.product_confidence = review.bundles.front().product_confidence;
      for (const auto& bundle : review.bundles) {
        if (confidence_rank(bundle.product_confidence) > confidence_rank(review.product_confidence))
          review.product_confidence = bundle.product_confidence;
      }
    } else if (review.bundles.size() > 1U) {
      review.product_type = "Multiple Veeam products";
      review.product_confidence = ParserConfidence::verified;
    }
  }
  std::unordered_map<std::string, std::size_t> incident_indexes;
  incident_indexes.reserve(std::min<std::size_t>(options.maximum_incidents, files.size() * 4U));
  review.reviewed_files.reserve(outcomes.size());
  for (auto& outcome : outcomes) {
    VeeamReviewedFile file_record;
    file_record.source_path = outcome.file.display_path;
    file_record.role = classify_veeam_evidence_role(outcome.file.display_path);
    file_record.cache_reused = outcome.file.cache_reused;
    file_record.size_bytes = outcome.size_bytes;
    file_record.lines_scanned = outcome.lines;
    file_record.elapsed_seconds = outcome.elapsed_seconds;
    if (outcome.error)
      file_record.error = outcome.error->message;
    review.reviewed_files.push_back(std::move(file_record));
    review.input_bytes += outcome.size_bytes;
    if (outcome.error) {
      ++review.parse_errors;
      continue;
    }
    ++review.files_scanned;
    review.lines_scanned += outcome.lines;
    merge_file_outcome(review, incident_indexes, std::move(outcome), options);
  }

  // Component presence is decided over EVERY discovered path, not only the files the parser opened.
  //
  // Fast index mode reads a high-value subset and SKIPS the rest before they ever reach `files` -
  // on one lab bundle, 209 of 927. Data-mover logs are exactly what gets deferred, and they are the
  // only evidence a repository or proxy role was exercised, so sweeping `files` found neither.
  // evidence_catalog holds every discovered path, indexed or deferred. Detection is path-based and
  // costs nothing, so it runs over all of it; a component list that is quietly incomplete is worse
  // than no list at all.
  for (const auto& entry : evidence_catalog) {
    for (auto& component : components_for_file(classify_veeam_evidence_role(entry.display_path),
                                               folded_path_name(entry.display_path))) {
      const bool already_known =
          std::any_of(review.components.begin(), review.components.end(),
                      [&](const VeeamComponentPresence& item) { return item.tag == component.first; });
      if (already_known)
        continue;
      VeeamComponentPresence presence;
      presence.tag = component.first;
      presence.display_name = std::move(component.second);
      presence.confidence = ParserConfidence::verified;
      presence.evidence_files = 1U;
      presence.example_paths.push_back(entry.display_path);
      review.components.push_back(std::move(presence));
    }
  }
  std::sort(review.components.begin(), review.components.end(),
            [](const VeeamComponentPresence& left, const VeeamComponentPresence& right) {
              if (left.tag != right.tag)
                return left.tag < right.tag;
              return left.machine_name < right.machine_name;
            });

  build_evidence_role_summaries(review, evidence_catalog);
  build_job_evidence_groups(review, evidence_catalog, options);
  carry_forward_job_details(review.job_sessions);
  classify_review_sessions(review, options);
  link_job_evidence_groups(review);
  if (!review.machines.empty())
    review.machine = review.machines.front().summary;
  review.merge_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - merge_started).count();

  if (progress)
    progress(ProgressEvent{"Correlating findings",
                           std::to_string(review.incidents.size()) + " grouped finding(s), " +
                               std::to_string(review.job_sessions.size()) + " run(s)",
                           review.files_scanned, review.parse_errors, review.elapsed_seconds,
                           review.files_per_second});
  const auto correlation_started = std::chrono::steady_clock::now();
  correlate_incidents(review, options);
  correlate_timeline_events(review, options);
  review.correlation_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - correlation_started).count();

  const auto finalization_started = std::chrono::steady_clock::now();
  review.elapsed_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - total_started).count();
  if (review.elapsed_seconds > 0.0) {
    review.files_per_second = static_cast<double>(review.files_scanned) / review.elapsed_seconds;
    review.lines_per_second = static_cast<double>(review.lines_scanned) / review.elapsed_seconds;
  }
  // Presentation order is newest first. Severity remains a useful secondary
  // grouping signal, but it must not scramble a multi-year case timeline.
  std::stable_sort(review.incidents.begin(), review.incidents.end(), [](const auto& left, const auto& right) {
    const auto left_latest = left.last_utc_ms ? left.last_utc_ms : left.first_utc_ms;
    const auto right_latest = right.last_utc_ms ? right.last_utc_ms : right.first_utc_ms;
    if (left_latest && right_latest && *left_latest != *right_latest)
      return *left_latest > *right_latest;
    if (left_latest.has_value() != right_latest.has_value())
      return left_latest.has_value();
    const int left_rank = left.severity == "error" ? 0 : left.severity == "warning" ? 1 : 2;
    const int right_rank = right.severity == "error" ? 0 : right.severity == "warning" ? 1 : 2;
    if (left_rank != right_rank)
      return left_rank < right_rank;
    if (left.occurrences != right.occurrences)
      return left.occurrences > right.occurrences;
    return left.summary < right.summary;
  });

  std::size_t total_occurrences = 0;
  std::size_t retained_locations = 0;
  for (const auto& incident : review.incidents)
  {
    total_occurrences += static_cast<std::size_t>(incident.occurrences);
    retained_locations += incident.locations.size();
  }
  review.report_timeline_occurrences =
      std::min(retained_locations, review.maximum_report_timeline_occurrences);
  review.report_timeline_truncated =
      total_occurrences > retained_locations ||
      retained_locations > review.maximum_report_timeline_occurrences;

  review.report_detailed_incidents =
      std::min(review.incidents.size(), review.maximum_report_detailed_incidents);
  review.report_incidents_truncated =
      review.incidents.size() > review.maximum_report_detailed_incidents;

  // Everything the CASE QUESTIONS and SERVICE ACTIVITY blocks report: the running flag, backup
  // type, settings carried forward across runs, and the findings that belong to no job at all.
  // Needs the complete review, so it runs here rather than per line.
  finalize_case_answers(review);

  const auto cache_index_status = write_bundle_cache_index(review);
  if (!cache_index_status.ok())
    emit_console(console, "Parser cache index warning: " + cache_index_status.error().message);
  review.finalization_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - finalization_started).count();

  review.report_path = determine_report_path(options, review);
  if (progress)
    progress(ProgressEvent{"Writing review report", support_assist::path_to_utf8(review.report_path),
                           review.files_scanned, review.parse_errors, review.elapsed_seconds,
                           review.files_per_second});
  const auto report_started = std::chrono::steady_clock::now();
  const auto write_status = write_veeam_log_review_report(review, review.report_path);
  review.serialization_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - report_started).count();
  review.report_seconds = review.serialization_seconds;
  review.elapsed_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - total_started).count();
  if (!write_status.ok())
    return Result<VeeamLogReviewResult>::failure(write_status.error());
  if (progress)
    progress(ProgressEvent{"Review complete",
                           std::to_string(review.files_scanned) + "/" +
                               std::to_string(review.files_discovered) + " files scanned | " +
                               std::to_string(review.incidents.size()) + " grouped finding(s)",
                           review.files_scanned, review.parse_errors, review.elapsed_seconds,
                           review.files_per_second});

  std::size_t error_count = 0;
  std::size_t warning_count = 0;
  for (const auto& incident : review.incidents) {
    if (incident.severity == "error")
      ++error_count;
    else if (incident.severity == "warning")
      ++warning_count;
  }
  emit_console(console, "");
  emit_console(console, "Veeam log review completed");
  const std::size_t backup_run_count = static_cast<std::size_t>(std::count_if(
      review.job_sessions.begin(), review.job_sessions.end(), is_backup_run_record));
  const std::size_t rescan_count = static_cast<std::size_t>(std::count_if(
      review.job_sessions.begin(), review.job_sessions.end(), is_rescan_record));
  const std::size_t activity_count = review.job_sessions.size() - backup_run_count - rescan_count;
  emit_console(console,
               std::to_string(review.machines.size()) + " machine(s) | " +
                   std::to_string(backup_run_count) + " backup run(s) | " +
                   std::to_string(activity_count) + " related activity record(s) | " +
                   std::to_string(rescan_count) + " rescan(s) | " +
                   std::to_string(error_count) + " grouped error(s) | " +
                   std::to_string(warning_count) + " grouped warning(s)");
  // PEX records are per-volume transfer performance samples, emitted continuously while data moves.
  // A long-running or aged log holds hundreds to thousands of them per run, and retaining every one
  // buries the rest of the run evidence for no analytical gain: what an engineer needs is the shape
  // of the transfer, not every sample of it.
  //
  // Retain FIRST, three evenly spaced MIDDLE, and LAST per volume. Field 1 is the volume's total
  // size and is stable for the life of that volume's transfer, so it identifies the volume; field 0
  // is percent complete, which gives the ordering. Deeper PEX semantics are future parser work
  // (docs/IDEAS_5.x.md).
  for (auto& session : review.job_sessions) {
    if (session.pex_samples.size() <= 5U) continue;
    std::map<std::string, std::vector<VeeamPexSample>> by_volume;
    for (auto& sample : session.pex_samples) {
      const std::string volume = sample.fields.size() > 1U ? sample.fields[1] : std::string("unknown");
      by_volume[volume].push_back(std::move(sample));
    }
    std::vector<VeeamPexSample> retained;
    for (auto& [volume, samples] : by_volume) {
      static_cast<void>(volume);
      std::stable_sort(samples.begin(), samples.end(),
                       [](const VeeamPexSample& left, const VeeamPexSample& right) {
                         const auto value = [](const VeeamPexSample& s) {
                           if (s.fields.empty()) return -1LL;
                           try { return std::stoll(s.fields[0]); } catch (...) { return -1LL; }
                         };
                         return value(left) < value(right);
                       });
      if (samples.size() <= 5U) {
        for (auto& sample : samples) retained.push_back(std::move(sample));
        continue;
      }
      const std::size_t last = samples.size() - 1U;
      // First, three evenly spaced interior samples, last.
      for (const std::size_t index : {std::size_t{0}, (last * 1U) / 4U, (last * 2U) / 4U,
                                      (last * 3U) / 4U, last})
        retained.push_back(samples[index]);
    }
    session.pex_samples = std::move(retained);
  }

  emit_console(console,
               std::to_string(review.files_scanned) + " file(s) | " +
                   std::to_string(review.lines_scanned) + " line(s) | " +
                   std::to_string(review.workers_used) + " worker(s) | report " +
                   support_assist::path_to_utf8(review.report_path));
  return Result<VeeamLogReviewResult>::success(std::move(review));
}

// One-line roll-up of every component the bundle proves, for the summary header.
//
// A support engineer opening a bundle needs to know what is IN it before anything else. A lone
// "Veeam Agent for Microsoft Windows" is actively misleading for a bundle that is really a backup
// server, a repository and an agent at once.
std::string component_summary_line(const VeeamLogReviewResult& review) {
  if (review.components.empty())
    return "None identified from structural evidence";
  std::vector<std::string> tags;
  for (const auto& component : review.components) {
    if (std::find(tags.begin(), tags.end(), component.tag) == tags.end())
      tags.push_back(component.tag);
  }
  std::sort(tags.begin(), tags.end());
  std::string line;
  for (const auto& tag : tags) {
    if (!line.empty())
      line += ", ";
    line += tag;
  }
  return line;
}

Status write_veeam_log_review_report(const VeeamLogReviewResult& review,
                                     const std::filesystem::path& output_path) {
  std::error_code directory_error;
  if (!output_path.parent_path().empty())
    std::filesystem::create_directories(output_path.parent_path(), directory_error);
  if (directory_error) {
    return Status::failure(
        review_error("create report directory", directory_error.message(), output_path.parent_path()));
  }
  std::filesystem::path temporary = output_path;
  temporary += ".partial";
  std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(review_error("create report", "Unable to create report", temporary));

  const std::size_t backup_run_count = static_cast<std::size_t>(std::count_if(
      review.job_sessions.begin(), review.job_sessions.end(), is_backup_run_record));
  const std::size_t rescan_count = static_cast<std::size_t>(std::count_if(
      review.job_sessions.begin(), review.job_sessions.end(), is_rescan_record));
  const std::size_t activity_count = review.job_sessions.size() - backup_run_count - rescan_count;

  output << ascii_upper(kProductName) << " - VEEAM LOG REVIEW\n"
         << "============================================================\n\n"
         << "QUICK CASE SUMMARY\n"
         << "Generated UTC:               " << utc_now_iso8601() << '\n'
         << "Application Version:         " << kVersion << '\n'
         << "Product Type Found:          " << review.product_type << " ["
         << to_string(review.product_confidence) << "]\n"
         << "Components Found:            " << component_summary_line(review) << '\n'
         << "Parser Profile:              " << review.parser_profile << '\n'
         << "Parser scope:                " << review.parser_scope_note << '\n'
         << "Timestamp assumption:        "
         << timezone_offset_text(review.assumed_timezone_offset_minutes)
         << " when a source timestamp has no explicit offset" << '\n'
         << "Normalized timeline:         UTC (ISO 8601)" << '\n'
         << "Machines identified:         " << review.machines.size() << '\n'
         << "Backup runs identified:      " << backup_run_count << '\n'
         << "Related activities:          " << activity_count << '\n'
         << "Infrastructure rescans:      " << rescan_count << '\n'
         << "Files scanned:               " << review.files_scanned << '\n'
         << "Lines scanned:               " << review.lines_scanned << '\n'
         << "Input bytes:                 " << review.input_bytes << '\n'
         << "Parser workers:              " << review.workers_used << '\n'
         << "Elapsed seconds:             " << std::fixed << std::setprecision(2)
         << review.elapsed_seconds << '\n'
         << "Stage timing (seconds):      discover " << review.discovery_seconds
         << " | archives " << review.archive_seconds
         << " | parse " << review.parse_seconds
         << " | merge " << review.merge_seconds
         << " | correlate " << review.correlation_seconds
         << " | finalize " << review.finalization_seconds
         << " | serialize " << review.serialization_seconds << '\n'
         << "Report write timing:         Available in the completed GUI/CLI result after this file closes\n"
         << "Average throughput:          " << std::fixed << std::setprecision(0)
         << review.lines_per_second << " lines/sec" << '\n'
         << "Files with parse errors:     " << review.parse_errors << '\n'
         // Say what was NOT read. A directory review leaves archives nested in the evidence tree
         // alone on purpose, but reporting only what was scanned implies the bundle was read whole
         // - and on a VBR bundle the unopened remainder is the rotated history.
         << (review.nested_archives_skipped == 0U
                 ? std::string{}
                 : "Archived logs not opened:    " +
                       std::to_string(review.nested_archives_skipped) +
                       " (rotated logs nested in the evidence tree; review that archive"
                       " directly to include them)\n")
         << files_not_read_line(review)
         << "Cancelled:                   " << (review.cancelled ? "Yes" : "No") << "\n\n";

  // The answers first. Seven field tests established that everything below this point is reference
  // material an engineer reads second, if at all.
  write_case_questions(output, review);
  write_service_activity(output, review);

  output << "FILE REVIEW PERFORMANCE\n"
         << "------------------------------------------------------------\n";
  std::vector<const VeeamReviewedFile*> slow_files;
  slow_files.reserve(review.reviewed_files.size());
  for (const auto& file : review.reviewed_files)
    slow_files.push_back(&file);
  std::stable_sort(slow_files.begin(), slow_files.end(), [](const auto* left, const auto* right) {
    return left->elapsed_seconds > right->elapsed_seconds;
  });
  const std::size_t slow_count = std::min<std::size_t>(slow_files.size(), 20U);
  for (std::size_t index = 0; index < slow_count; ++index) {
    const auto& file = *slow_files[index];
    output << index + 1U << ". " << file.source_path
           << " | bytes=" << file.size_bytes
           << " | lines=" << file.lines_scanned
           << " | seconds=" << std::fixed << std::setprecision(2) << file.elapsed_seconds;
    if (!file.error.empty())
      output << " | error=" << file.error;
    output << '\n';
  }
  output << '\n';

  output << "MACHINES FOUND\n"
         << "------------------------------------------------------------\n";
  if (review.machines.empty()) {
    output << "No machine identity was found. Unidentified files remain grouped by source folder.\n\n";
  } else {
    for (std::size_t index = 0; index < review.machines.size(); ++index) {
      const auto& machine = review.machines[index];
      output << "\nMACHINE " << index + 1U << " / " << review.machines.size() << '\n';
      write_setting(output, "Machine key:", machine.key);
      write_setting(output, "Display name:", machine.display_name);
      write_setting(output, "Source role:", machine.role);
      write_evidence_line(output, "Machine Hostname:", machine.summary.machine_name);
      write_evidence_line(output, "Alternate Host Name:", machine.summary.host_name);
      write_evidence_line(output, "IP Address:", machine.summary.primary_ip);
      write_evidence_line(output, "Operating System:", machine.summary.operating_system);
      write_evidence_line(output, "Logical processors:", machine.summary.cpu_logical_processors);
      write_evidence_line(output, "Veeam Version:", machine.summary.product_version);
      write_evidence_line(output, "Management mode:", machine.summary.management_mode);
      write_evidence_line(output, "Management server:", machine.summary.management_server);
      const auto machine_backup_runs = std::count_if(
          review.job_sessions.begin(), review.job_sessions.end(), [&](const auto& run) {
            return run.machine_key == machine.key && is_backup_run_record(run);
          });
      const auto machine_rescans = std::count_if(
          review.job_sessions.begin(), review.job_sessions.end(), [&](const auto& run) {
            return run.machine_key == machine.key && is_rescan_record(run);
          });
      const auto machine_activities = std::count_if(
          review.job_sessions.begin(), review.job_sessions.end(), [&](const auto& run) {
            return run.machine_key == machine.key && run.run_kind == "activity";
          });
      output << std::left << std::setw(36) << "Backup runs:" << machine_backup_runs << '\n'
             << std::left << std::setw(36) << "Related activities:" << machine_activities << '\n'
             << std::left << std::setw(36) << "Infrastructure rescans:" << machine_rescans << '\n'
             << std::left << std::setw(36) << "Identity source files:"
             << machine.source_paths.size() << '\n';
    }
    output << '\n';
  }

  output << "LATEST BACKUP JOB ACROSS BUNDLE\n"
         << "------------------------------------------------------------\n";
  const auto actual = std::find_if(review.job_sessions.begin(), review.job_sessions.end(),
                                   [](const auto& run) {
                                     return is_backup_run_record(run) && !run.index_only;
                                   });
  const auto indexed_backup = std::find_if(review.job_sessions.begin(), review.job_sessions.end(),
                                           [](const auto& run) {
                                             return is_backup_run_record(run);
                                           });
  if (actual == review.job_sessions.end() && indexed_backup == review.job_sessions.end()) {
    output << "No structured backup-job session was identified. Related infrastructure activities, if present, are listed separately below.\n\n";
  } else {
    const VeeamJobSession& session = actual == review.job_sessions.end()
                                         ? *indexed_backup
                                         : *actual;
    if (session.index_only)
      output << "Fast index found job evidence but no structured run metadata; deep review is required for exact run statistics.\n";
    write_setting(output, "Machine:", session.machine_name);
    write_setting(output, "Component:", session.component_tag);
    write_setting(output, "Job name:", session.job_name);
    write_setting(output, "Job ID:", session.job_id);
    write_setting(output, "Session ID:", session.session_id);
    write_setting(output, "Task session ID:", session.task_session_id);
    write_setting(output, "Job mode:", session.job_mode);
    write_setting(output,
                  "Job Type:",
                  !session.settings.backup_mode.empty() ? session.settings.backup_mode
                                                        : session.job_type);
    write_setting(output, "Result:", session.status.empty() ? "Unknown / incomplete" : session.status);
    write_setting(output,
                  "Started:",
                  canonical_timestamp(session.start_utc_ms, session.start_timestamp_original));
    write_setting(output,
                  "Completed:",
                  canonical_timestamp(session.completion_utc_ms,
                                      session.completion_timestamp_original));
    write_setting(output, "Duration:", duration_text(session));
    write_setting(output, "Restore point type:", session.restore_point_type);
    write_setting(output, "Restore point ID:", session.restore_point_id);
    write_setting(output, "Backup file:", session.backup_file);
    output << '\n' << "SOURCE, DESTINATION, AND SETTINGS\n";
    write_setting(output, "Backup mode:", session.settings.backup_mode);
    for (const auto& item : session.settings.included_items)
      write_setting(output, "Included item:", item);
    for (const auto& item : session.settings.excluded_items)
      write_setting(output, "Excluded item:", item);
    write_setting(output, "Destination type:", session.settings.destination_type);
    write_setting(output, "Backup server:", session.settings.backup_server);
    write_setting(output, "Backup repository:", session.settings.backup_repository);
    write_setting(output, "Target Backup Repository / Path:", session.settings.destination_path);
    write_setting(output, "Created by:", session.settings.created_by);
    write_setting(output, "Created at:", session.settings.created_at);
    write_setting(output, "Retention:", session.settings.retention);
    write_setting(output, "Compression:", session.settings.compression);
    write_setting(output, "Storage optimization:", session.settings.storage_optimization);
    write_setting(output, "Encryption:", session.settings.encryption);
    write_setting(output, "GFS:", session.settings.gfs);
    write_setting(output, "Schedule:", session.settings.schedule);
    write_setting(output, "VSS snapshot:", session.settings.vss_snapshot);
    write_setting(output, "Application processing:", session.settings.application_processing);
    write_setting(output, "Guest indexing:", session.settings.guest_indexing);
    output << '\n';
  }

  output << "JOB / WORKLOAD EVIDENCE INDEX\n"
         << "------------------------------------------------------------\n";
  if (review.job_evidence_groups.empty()) {
    output << "No job-scoped evidence folders were identified.\n";
  } else {
    for (std::size_t index = 0; index < review.job_evidence_groups.size(); ++index) {
      const auto& group = review.job_evidence_groups[index];
      output << index + 1U << ". "
             << (group.machine_name.empty() ? "Unknown machine" : group.machine_name) << " | "
             << (group.job_name.empty() ? "Unnamed evidence group" : group.job_name) << " | "
             << group.category << " | files " << group.candidate_files
             << " (indexed " << group.indexed_files << ", deferred " << group.deferred_files << ")"
             << " | workloads " << group.workloads.size()
             << " | runs " << group.run_keys.size() << '\n';
      if (group.protection_group_rescan && !group.protection_group_name.empty())
        output << "    Protection group: " << group.protection_group_name << '\n';
      if (!group.workloads.empty()) {
        output << "    Workloads: ";
        const std::size_t workload_limit = std::min<std::size_t>(group.workloads.size(), 12U);
        for (std::size_t workload = 0; workload < workload_limit; ++workload) {
          if (workload != 0U)
            output << ", ";
          output << group.workloads[workload];
        }
        if (group.workloads.size() > workload_limit)
          output << ", ... (" << group.workloads.size() - workload_limit << " more)";
        output << '\n';
      }
      if (!group.source_paths.empty())
        output << "    Evidence: " << group.source_paths.front() << '\n';
    }
  }
  output << '\n';

  output << "BACKUP / ACTIVITY RUN INDEX (NEWEST FIRST)\n"
         << "------------------------------------------------------------\n";
  if (review.job_sessions.empty()) {
    output << "No structured job attempts identified.\n";
  } else {
    for (std::size_t index = 0; index < review.job_sessions.size(); ++index) {
      const auto& session = review.job_sessions[index];
      const std::string category = is_rescan_record(session)
                                       ? "RESCAN"
                                       : session.run_kind == "activity"
                                             ? "ACTIVITY: " + session.job_type
                                             : "BACKUP";
      // The component tag says WHO performed the run. A SOBR offload and a backup job can appear in
      // the same list, and without it a repository task is indistinguishable from an agent's job.
      const std::string component =
          session.component_tag.empty() ? std::string() : "[" + session.component_tag + "] ";
      output << index + 1U << ". [" << category << "] " << component
             << (session.machine_name.empty() ? "Unknown machine" : session.machine_name) << " | "
             << canonical_timestamp(session.start_utc_ms, session.start_timestamp_original)
             << " | " << (session.job_name.empty() ? session.job_type : session.job_name) << " | "
             << (session.status.empty() ? "Incomplete / unknown" : session.status) << " | "
             << duration_text(session) << " | session "
             << (session.session_id.empty() ? "unknown" : session.session_id) << '\n';
    }
  }
  output << '\n';

  std::unordered_map<std::string, const VeeamJobSession*> report_runs;
  report_runs.reserve(review.job_sessions.size());
  for (const auto& run : review.job_sessions)
    report_runs.emplace(run.run_key, &run);
  const auto report_run_label = [&](std::string_view run_key) {
    const auto found = report_runs.find(std::string(run_key));
    if (found == report_runs.end())
      return std::string(run_key);
    const auto* run = found->second;
    std::string label = run->job_name.empty() ? run->run_key : run->job_name;
    label += " @ " +
             canonical_timestamp(run->start_utc_ms, run->start_timestamp_original);
    if (!run->machine_name.empty())
      label += " on " + run->machine_name;
    return label;
  };

  output << "EVENT TIMELINE - NEWEST FIRST\n"
         << "------------------------------------------------------------\n";
  struct ReportTimelineItem {
    const VeeamIncident* incident = nullptr;
    const VeeamIncidentLocation* location = nullptr;
  };
  std::vector<ReportTimelineItem> timeline;
  for (const auto& incident : review.incidents) {
    for (const auto& location : incident.locations)
      timeline.push_back(ReportTimelineItem{&incident, &location});
  }
  std::stable_sort(timeline.begin(), timeline.end(), [](const auto& left, const auto& right) {
    if (left.location->timestamp_utc_ms && right.location->timestamp_utc_ms &&
        *left.location->timestamp_utc_ms != *right.location->timestamp_utc_ms) {
      return *left.location->timestamp_utc_ms > *right.location->timestamp_utc_ms;
    }
    if (left.location->timestamp_utc_ms.has_value() != right.location->timestamp_utc_ms.has_value())
      return left.location->timestamp_utc_ms.has_value();
    if (left.location->source_path != right.location->source_path)
      return left.location->source_path < right.location->source_path;
    return left.location->line_number < right.location->line_number;
  });
  if (timeline.empty()) {
    output << "No matching events were found.\n";
  } else {
    const std::size_t timeline_limit =
        std::min(timeline.size(), review.maximum_report_timeline_occurrences);
    for (std::size_t index = 0; index < timeline_limit; ++index) {
      const auto& item = timeline[index];
      const auto& incident = *item.incident;
      const auto& location = *item.location;
      std::vector<std::string> run_labels;
      for (const auto& run_key : location.correlated_job_run_keys) {
        std::string label = report_run_label(run_key);
        if (std::find(run_labels.begin(), run_labels.end(), label) == run_labels.end())
          run_labels.push_back(std::move(label));
      }
      output << std::setw(5) << index + 1U << " | "
             << canonical_timestamp(location.timestamp_utc_ms, location.timestamp_original)
             << " | " << (location.machine_name.empty() ? "Unknown machine" : location.machine_name)
             << " | " << (run_labels.empty() ? "Outside identified job run"
                                              : join_text(run_labels, ", "))
             << " | " << ascii_upper(incident.severity)
             << " | " << (incident.component.empty() ? "Unclassified" : incident.component)
             << " | " << incident.summary
             << " | " << location.source_path << ':' << location.line_number << '\n';
    }
    if (timeline.size() > timeline_limit) {
      output << "\nTimeline display bounded at " << timeline_limit << " of " << timeline.size()
             << " occurrences. Grouped counts below remain complete; select an issue in the GUI "
                "to inspect its source locations without generating a multi-gigabyte text report.\n";
    }
  }
  output << '\n';

  output << "GROUPED INCIDENT SUMMARY\n"
         << "------------------------------------------------------------\n";
  if (review.incidents.empty()) {
    output << "No errors, selected warnings, or informational query matches were found.\n";
  } else {
    for (std::size_t index = 0; index < review.incidents.size(); ++index) {
      const auto& incident = review.incidents[index];
      output << index + 1U << ". [" << incident.severity << "] "
             << annotate_system_error_codes(incident.summary)
             << " | occurrences=" << incident.occurrences
             << " | retained-source-locations=" << incident.locations.size();
      if (incident.locations_omitted != 0U)
        output << " | source-locations-omitted=" << incident.locations_omitted;
      if (incident.first_utc_ms || !incident.first_timestamp_original.empty())
        output << " | first="
               << canonical_timestamp(incident.first_utc_ms,
                                      incident.first_timestamp_original);
      if ((incident.last_utc_ms || !incident.last_timestamp_original.empty()) &&
          incident.last_utc_ms != incident.first_utc_ms)
        output << " | last="
               << canonical_timestamp(incident.last_utc_ms,
                                      incident.last_timestamp_original);
      output << " | machines=" << incident.machine_keys.size()
             << " | job-runs=" << incident.job_run_keys.size() << '\n';
    }
  }
  output << '\n';

  output << "ALL INCIDENTS WITH SOURCE CONTEXT\n"
         << "============================================================\n";
  const std::size_t detailed_incident_limit =
      std::min(review.incidents.size(), review.maximum_report_detailed_incidents);
  for (std::size_t incident_index = 0; incident_index < detailed_incident_limit; ++incident_index) {
    const auto& incident = review.incidents[incident_index];
    output << "\nINCIDENT " << incident_index + 1U << " / " << review.incidents.size() << '\n'
           << "Severity:      " << incident.severity << '\n'
           << "Component:     " << (incident.component.empty() ? "Unknown" : incident.component)
           << '\n'
           << "Summary:       " << incident.summary << '\n'
           << "Occurrences:   " << incident.occurrences << '\n'
           << "Source links:  " << incident.locations.size() << " retained";
    if (incident.locations_omitted != 0U)
      output << ", " << incident.locations_omitted << " omitted after per-file sampling";
    output << '\n'
           << "Signature:     " << incident.signature << '\n';
    constexpr std::size_t kMaximumDetailedOccurrences = 20;
    const std::size_t detailed_count =
        std::min(incident.locations.size(), kMaximumDetailedOccurrences);
    for (std::size_t location_index = 0; location_index < detailed_count; ++location_index) {
      const auto& location = incident.locations[location_index];
      output << "\n  OCCURRENCE " << location_index + 1U << '\n'
             << "  Machine:" << (location.machine_name.empty() ? " Unknown" : " " + location.machine_name) << '\n'
             << "  Source: " << location.source_path << '\n'
             << "  Line:   " << location.line_number << '\n'
             << "  Offset: " << location.byte_offset << '\n'
             << "  Time:   "
             << canonical_timestamp(location.timestamp_utc_ms, location.timestamp_original)
             << '\n'
             << "  Job ID: " << location.explicit_job_id << '\n'
             << "  Session:" << (location.explicit_session_id.empty() ? " Not identified"
                                                                       : " " + location.explicit_session_id) << '\n'
             << "  Runs:   ";
      if (location.correlated_job_run_keys.empty()) {
        output << "Outside identified job run\n";
      } else {
        std::vector<std::string> detailed_run_labels;
        detailed_run_labels.reserve(location.correlated_job_run_keys.size());
        for (const auto& run_key : location.correlated_job_run_keys)
          detailed_run_labels.push_back(report_run_label(run_key));
        output << join_text(detailed_run_labels, ", ") << '\n';
      }
      output << "  Thread: " << location.thread_or_task << '\n'
             << "  --- context before ---\n";
      for (const auto& line : location.before)
        output << "  " << line << '\n';
      output << "  --- incident ---\n";
      for (const auto& line : location.lines)
        output << "  " << line << '\n';
      output << "  --- context after ---\n";
      for (const auto& line : location.after)
        output << "  " << line << '\n';
    }
    if (incident.locations.size() > detailed_count) {
      output << "\n  " << incident.locations.size() - detailed_count
             << " additional retained source location(s) omitted from expanded context.\n";
    }
    if (incident.locations_omitted != 0U)
      output << "  " << incident.locations_omitted
             << " repetitive occurrence(s) were counted but not retained as individual source links.\n";
  }
  if (review.incidents.size() > detailed_incident_limit) {
    output << "\nDetailed incident rendering bounded at " << detailed_incident_limit << " of "
           << review.incidents.size()
           << " grouped incidents. Counts and structured evidence remain available in the GUI/case model.\n";
  }
  output.flush();
  if (!output)
    return Status::failure(review_error("write report", "Report stream failed", temporary));
  output.close();

  std::error_code replace_error;
  std::filesystem::remove(output_path, replace_error);
  replace_error.clear();
  std::filesystem::rename(temporary, output_path, replace_error);
  if (replace_error) {
    std::filesystem::remove(temporary, replace_error);
    return Status::failure(review_error("finalize report", replace_error.message(), output_path));
  }
  return Status::success();
}

} // namespace support_assist
