#include "support_assist/case_review_store.hpp"

#include "support_assist/strings.hpp"

#include "support_assist/time.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace support_assist {
namespace {

Error store_error(std::string operation,
                  const std::filesystem::path& source,
                  std::string message) {
  Error error;
  error.component = "case-review-store";
  error.operation = std::move(operation);
  error.source = path_to_utf8(source);
  error.message = std::move(message);
  return error;
}

std::filesystem::path model_path(const CaseWorkspace& workspace) {
  return workspace.parsed / "case-review-model.sat";
}

void sort_review_newest_first(VeeamLogReviewResult& review) {
  std::stable_sort(review.job_sessions.begin(), review.job_sessions.end(), [](const auto& left, const auto& right) {
    if (left.start_utc_ms && right.start_utc_ms && *left.start_utc_ms != *right.start_utc_ms)
      return *left.start_utc_ms > *right.start_utc_ms;
    if (left.start_utc_ms.has_value() != right.start_utc_ms.has_value())
      return left.start_utc_ms.has_value();
    if (left.start_timestamp_original != right.start_timestamp_original)
      return left.start_timestamp_original > right.start_timestamp_original;
    return left.run_key < right.run_key;
  });

  for (auto& incident : review.incidents) {
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

  std::stable_sort(review.timeline_events.begin(), review.timeline_events.end(), [](const auto& left, const auto& right) {
    if (left.evidence.timestamp_utc_ms && right.evidence.timestamp_utc_ms &&
        *left.evidence.timestamp_utc_ms != *right.evidence.timestamp_utc_ms)
      return *left.evidence.timestamp_utc_ms > *right.evidence.timestamp_utc_ms;
    if (left.evidence.timestamp_utc_ms.has_value() != right.evidence.timestamp_utc_ms.has_value())
      return left.evidence.timestamp_utc_ms.has_value();
    if (left.evidence.source_path != right.evidence.source_path)
      return left.evidence.source_path < right.evidence.source_path;
    return left.evidence.line_number < right.evidence.line_number;
  });
}

char hex_digit(unsigned value) {
  return value < 10U ? static_cast<char>('0' + value)
                     : static_cast<char>('A' + (value - 10U));
}

int from_hex(char value) {
  if (value >= '0' && value <= '9')
    return value - '0';
  if (value >= 'a' && value <= 'f')
    return 10 + value - 'a';
  if (value >= 'A' && value <= 'F')
    return 10 + value - 'A';
  return -1;
}

std::string encode(std::string_view value) {
  std::string output;
  output.reserve(value.size());
  for (const char raw : value) {
    const auto ch = static_cast<unsigned char>(raw);
    if (ch == '%' || ch == '\t' || ch == '\r' || ch == '\n' || ch < 0x20U) {
      output.push_back('%');
      output.push_back(hex_digit((ch >> 4U) & 0x0FU));
      output.push_back(hex_digit(ch & 0x0FU));
    } else {
      output.push_back(static_cast<char>(ch));
    }
  }
  return output;
}

std::string decode(std::string_view value) {
  std::string output;
  output.reserve(value.size());
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (value[index] == '%' && index + 2U < value.size()) {
      const int high = from_hex(value[index + 1U]);
      const int low = from_hex(value[index + 2U]);
      if (high >= 0 && low >= 0) {
        output.push_back(static_cast<char>((high << 4) | low));
        index += 2U;
        continue;
      }
    }
    output.push_back(value[index]);
  }
  return output;
}

std::string join(const std::vector<std::string>& values) {
  std::string output;
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0U)
      output.push_back('\n');
    output += values[index];
  }
  return output;
}

std::vector<std::string> split_lines(std::string_view value) {
  std::vector<std::string> values;
  std::istringstream input{std::string(value)};
  std::string line;
  while (std::getline(input, line))
    values.push_back(std::move(line));
  return values;
}

void write_record(std::ostream& output,
                  std::string_view tag,
                  std::initializer_list<std::string> fields) {
  output << tag;
  for (const auto& field : fields)
    output << '\t' << encode(field);
  output << '\n';
}

std::vector<std::string> fields_for(std::string_view line) {
  std::vector<std::string> fields;
  std::size_t begin = 0;
  for (;;) {
    const std::size_t end = line.find('\t', begin);
    fields.push_back(decode(line.substr(begin, end == std::string_view::npos
                                                   ? std::string_view::npos
                                                   : end - begin)));
    if (end == std::string_view::npos)
      break;
    begin = end + 1U;
  }
  return fields;
}

template <typename T>
T number(std::string_view text, T fallback = {}) {
  T value{};
  const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
  return result.ec == std::errc{} ? value : fallback;
}

std::string optional_number(const std::optional<std::int64_t>& value) {
  return value ? std::to_string(*value) : std::string{};
}

std::optional<std::int64_t> parse_optional_i64(std::string_view value) {
  if (value.empty())
    return std::nullopt;
  return number<std::int64_t>(value);
}

std::string evidence_value(const std::optional<ReviewEvidence>& evidence) {
  return evidence ? evidence->value : std::string{};
}

std::optional<ReviewEvidence> make_evidence(std::string value) {
  if (value.empty())
    return std::nullopt;
  ReviewEvidence evidence;
  evidence.value = std::move(value);
  evidence.confidence = ParserConfidence::probable;
  return evidence;
}

void merge_evidence(std::optional<ReviewEvidence>& target,
                    const std::optional<ReviewEvidence>& incoming) {
  if (!target && incoming)
    target = incoming;
}

void merge_machine_summary(VeeamMachineSummary& target,
                           const VeeamMachineSummary& incoming) {
  merge_evidence(target.machine_name, incoming.machine_name);
  merge_evidence(target.host_name, incoming.host_name);
  merge_evidence(target.primary_ip, incoming.primary_ip);
  merge_evidence(target.operating_system, incoming.operating_system);
  merge_evidence(target.cpu_logical_processors, incoming.cpu_logical_processors);
  merge_evidence(target.product_version, incoming.product_version);
  merge_evidence(target.assembly_version, incoming.assembly_version);
  merge_evidence(target.management_mode, incoming.management_mode);
  merge_evidence(target.management_server, incoming.management_server);
  merge_evidence(target.culture, incoming.culture);
  merge_evidence(target.utc_time, incoming.utc_time);
  merge_evidence(target.private_fix, incoming.private_fix);
  const auto append_unique_evidence = [](auto& destination, const auto& source) {
    for (const auto& item : source) {
      if (std::none_of(destination.begin(), destination.end(), [&](const auto& current) {
            return current.value == item.value;
          }))
        destination.push_back(item);
    }
  };
  append_unique_evidence(target.license_modes, incoming.license_modes);
  append_unique_evidence(target.alternate_ip_addresses, incoming.alternate_ip_addresses);
}

std::string run_identity(const VeeamJobSession& run) {
  if (!run.run_key.empty())
    return run.run_key;
  if (!run.session_id.empty())
    return "session:" + run.session_id;
  return run.source_path + ":" + std::to_string(run.start_line);
}

std::string location_identity(const VeeamIncidentLocation& location) {
  return location.source_path + ":" + std::to_string(location.line_number);
}

std::string timeline_identity(const VeeamTimelineEvent& event) {
  return event.evidence.source_path + ":" + std::to_string(event.evidence.line_number) + ":" +
         event.evidence.category + ":" + event.evidence.rule_id;
}

} // namespace

Status save_case_review_model(const CaseWorkspace& workspace,
                              const VeeamLogReviewResult& review) {
  std::error_code error;
  std::filesystem::create_directories(workspace.parsed, error);
  if (error)
    return Status::failure(store_error("create parsed directory", workspace.parsed, error.message()));

  const auto path = model_path(workspace);
  const auto temporary = std::filesystem::path(path) += ".tmp";
  std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(store_error("save model", path, "Could not create case review model"));

  output << "SAT_CASE_REVIEW\t5\n";
  write_record(output, "META", {review.product_type,
                                  std::to_string(static_cast<int>(review.product_confidence)),
                                  review.parser_profile,
                                  review.parser_scope_note,
                                  path_to_utf8(review.report_path),
                                  review.fast_index_used ? "1" : "0",
                                  std::to_string(static_cast<int>(review.profile_used)),
                                  std::to_string(review.files_discovered),
                                  std::to_string(review.files_deferred),
                                  std::to_string(review.files_scanned),
                                  std::to_string(review.lines_scanned),
                                  std::to_string(review.input_bytes),
                                  std::to_string(review.parse_errors),
                                  std::to_string(review.parser_cache_hits),
                                  utc_now_iso8601()});
  for (const auto& source : review.input_sources)
    write_record(output, "SOURCE", {path_to_utf8(source)});

  // v5 persists per-file source coverage and evidence-role summaries as FILE
  // and ROLE records. Earlier model versions store only aggregate counters.
  for (const auto& file : review.reviewed_files) {
    std::ostringstream elapsed;
    elapsed << std::setprecision(17) << file.elapsed_seconds;
    write_record(output, "FILE", {file.source_path,
                                     std::to_string(static_cast<int>(file.role)),
                                     std::to_string(file.size_bytes),
                                     std::to_string(file.lines_scanned),
                                     elapsed.str(), file.error,
                                     file.cache_reused ? "1" : "0"});
  }
  for (const auto& role : review.evidence_roles) {
    write_record(output, "ROLE", {std::to_string(static_cast<int>(role.role)),
                                     std::to_string(role.candidate_files),
                                     std::to_string(role.scanned_files),
                                     std::to_string(role.deferred_files),
                                     std::to_string(role.total_bytes)});
  }

  for (const auto& bundle : review.bundles) {
    write_record(output, "BUNDLE", {bundle.key, bundle.source_path, bundle.display_name,
                                      bundle.primary_machine_key, bundle.primary_machine_name,
                                      bundle.manifest_profile, bundle.product_type,
                                      std::to_string(static_cast<int>(bundle.product_confidence)),
                                      std::to_string(bundle.source_bytes), bundle.source_fingerprint,
                                      std::to_string(bundle.candidate_files),
                                      std::to_string(bundle.indexed_files),
                                      std::to_string(bundle.deferred_files),
                                      bundle.primary_machine_role,
                                      bundle.product_version});
  }

  for (const auto& machine : review.machines) {
    std::vector<std::string> licenses;
    for (const auto& value : machine.summary.license_modes)
      licenses.push_back(value.value);
    std::vector<std::string> alternate_ips;
    for (const auto& value : machine.summary.alternate_ip_addresses)
      alternate_ips.push_back(value.value);
    write_record(output, "MACHINE", {machine.key, machine.display_name,
                                       evidence_value(machine.summary.machine_name),
                                       evidence_value(machine.summary.host_name),
                                       evidence_value(machine.summary.primary_ip),
                                       evidence_value(machine.summary.operating_system),
                                       evidence_value(machine.summary.cpu_logical_processors),
                                       evidence_value(machine.summary.product_version),
                                       evidence_value(machine.summary.assembly_version),
                                       evidence_value(machine.summary.management_mode),
                                       evidence_value(machine.summary.management_server),
                                       evidence_value(machine.summary.culture),
                                       evidence_value(machine.summary.utc_time),
                                       evidence_value(machine.summary.private_fix),
                                       join(licenses), join(alternate_ips), join(machine.source_paths),
                                       machine.role});
  }

  for (const auto& run : review.job_sessions) {
    write_record(output, "RUN", {run.run_kind, run.index_only ? "1" : "0",
                                   run.protection_group_rescan ? "1" : "0",
                                   run.protection_group_name, run.run_key, run.machine_key,
                                   run.machine_name, run.job_name, run.job_id, run.session_id,
                                   run.task_session_id, run.job_mode, run.job_type, run.status,
                                   run.restore_point_id, run.restore_point_type, run.backup_file,
                                   run.source_path, path_to_utf8(run.materialized_path),
                                   std::to_string(run.start_line), std::to_string(run.completion_line),
                                   run.start_timestamp_original, run.completion_timestamp_original,
                                   optional_number(run.start_utc_ms), optional_number(run.completion_utc_ms),
                                   run.settings.backup_mode, join(run.settings.included_items),
                                   join(run.settings.excluded_items), run.settings.destination_type,
                                   run.settings.destination_path, run.settings.retention,
                                   run.settings.compression, run.settings.storage_optimization,
                                   run.settings.encryption, run.settings.gfs, run.settings.schedule,
                                   run.settings.created_by, run.settings.created_at,
                                   run.settings.vss_snapshot, run.settings.application_processing,
                                   run.settings.guest_indexing, run.settings.source_backup_mode,
                                   run.settings.repository_operation,
                                   run.settings.resulting_backup_type, run.settings.task_total_size,
                                   run.settings.job_description, run.settings.backup_server,
                                   run.settings.backup_repository, run.settings.backup_cache,
                                   run.settings.script_processing, run.settings.command_line,
                                   run.settings.settings_source_path,
                                   path_to_utf8(run.settings.settings_materialized_path),
                                   std::to_string(run.settings.settings_start_line),
                                   std::to_string(run.settings.settings_end_line),
                                   join(run.settings.settings_lines),
                                   run.used_vss_provider_id, run.used_vss_provider_name,
                                   run.used_vss_provider_type});
  }

  for (const auto& incident : review.incidents) {
    write_record(output, "INCIDENT", {incident.id, incident.signature, incident.severity,
                                        incident.component, incident.summary,
                                        std::to_string(incident.occurrences),
                                        incident.first_timestamp_original,
                                        incident.last_timestamp_original,
                                        optional_number(incident.first_utc_ms),
                                        optional_number(incident.last_utc_ms),
                                        std::to_string(incident.locations_omitted),
                                        join(incident.machine_keys), join(incident.job_run_keys)});
    for (const auto& location : incident.locations) {
      write_record(output, "LOCATION", {incident.id, location.machine_key, location.machine_name,
                                          location.explicit_job_run_key,
                                          join(location.correlated_job_run_keys),
                                          location.explicit_job_id, location.explicit_session_id,
                                          location.source_path, path_to_utf8(location.materialized_path),
                                          std::to_string(location.line_number),
                                          std::to_string(location.byte_offset),
                                          location.timestamp_original,
                                          optional_number(location.timestamp_utc_ms),
                                          location.thread_or_task, join(location.before),
                                          join(location.lines), join(location.after)});
    }
  }

  for (const auto& event : review.timeline_events) {
    write_record(output, "TIMELINE", {event.evidence.source_path,
                                        path_to_utf8(event.evidence.materialized_path),
                                        std::to_string(event.evidence.line_number),
                                        event.evidence.timestamp_original,
                                        optional_number(event.evidence.timestamp_utc_ms),
                                        to_string(event.evidence.role),
                                        event.evidence.category, event.evidence.rule_id,
                                        event.evidence.raw_line, event.machine_key,
                                        event.job_run_key});
  }
  output.flush();
  if (!output)
    return Status::failure(store_error("save model", path, "Failed while writing case review model"));
  output.close();

  std::filesystem::rename(temporary, path, error);
  if (error) {
    std::filesystem::remove(path, error);
    error.clear();
    std::filesystem::rename(temporary, path, error);
  }
  if (error)
    return Status::failure(store_error("replace model", path, error.message()));
  return Status::success();
}

std::optional<std::filesystem::file_time_type> case_review_model_written(const CaseWorkspace& workspace) {
  // The two places load_case_review_model reads, in its order.
  for (const auto& path : {model_path(workspace), workspace.root / "case-review-model.sat"}) {
    std::error_code error;
    const auto written = std::filesystem::last_write_time(path, error);
    if (!error)
      return written;
  }
  return std::nullopt;
}

Result<VeeamLogReviewResult> load_case_review_model(const CaseWorkspace& workspace) {
  auto path = model_path(workspace);
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    // v0.4.1 compatibility: load the legacy root model when present. New saves
    // are always case-owned under parsed/.
    path = workspace.root / "case-review-model.sat";
    input.clear();
    input.open(path, std::ios::binary);
  }
  if (!input)
    return Result<VeeamLogReviewResult>::failure(
        store_error("load model", path, "No persisted case review model was found"));

  std::string line;
  if (!std::getline(input, line))
    return Result<VeeamLogReviewResult>::failure(
        store_error("load model", path, "Unsupported or damaged case review model"));
  const bool model_v5 = line == "SAT_CASE_REVIEW\t5";
  const bool model_v4 = line == "SAT_CASE_REVIEW\t4";
  const bool model_v3 = line == "SAT_CASE_REVIEW\t3";
  const bool model_v2 = line == "SAT_CASE_REVIEW\t2";
  if (!model_v5 && !model_v4 && !model_v3 && !model_v2)
    return Result<VeeamLogReviewResult>::failure(
        store_error("load model", path, "Unsupported or damaged case review model"));

  VeeamLogReviewResult review;
  std::map<std::string, std::size_t> incidents;
  while (std::getline(input, line)) {
    if (line.empty())
      continue;
    auto fields = fields_for(line);
    if (fields.empty())
      continue;
    const std::string tag = fields.front();
    fields.erase(fields.begin());
    if (tag == "META" && fields.size() >= 14U) {
      review.product_type = fields[0];
      review.product_confidence = static_cast<ParserConfidence>(number<int>(fields[1]));
      review.parser_profile = fields[2];
      review.parser_scope_note = fields[3];
      review.report_path = fields[4];
      review.fast_index_used = fields[5] == "1";
      review.profile_used = static_cast<VeeamReviewProfile>(number<int>(fields[6]));
      review.files_discovered = number<std::uint64_t>(fields[7]);
      review.files_deferred = number<std::uint64_t>(fields[8]);
      review.files_scanned = number<std::uint64_t>(fields[9]);
      review.lines_scanned = number<std::uint64_t>(fields[10]);
      review.input_bytes = number<std::uint64_t>(fields[11]);
      review.parse_errors = number<std::uint64_t>(fields[12]);
      review.parser_cache_hits = number<std::uint64_t>(fields[13]);
      review.persistent_cache_enabled = true;
      review.cache_directory = workspace.parser_cache;
    } else if (tag == "SOURCE" && !fields.empty()) {
      // Written as UTF-8; a review saved by an earlier build read back in the ANSI code page.
      review.input_sources.push_back(path_from_utf8(fields[0]));
    } else if (tag == "FILE" && model_v5 && fields.size() >= 7U) {
      VeeamReviewedFile file;
      file.source_path = fields[0];
      file.role = static_cast<VeeamEvidenceRole>(number<int>(fields[1], static_cast<int>(VeeamEvidenceRole::other)));
      file.size_bytes = number<std::uint64_t>(fields[2]);
      file.lines_scanned = number<std::uint64_t>(fields[3]);
      try { file.elapsed_seconds = fields[4].empty() ? 0.0 : std::stod(fields[4]); } catch (...) { file.elapsed_seconds = 0.0; }
      file.error = fields[5];
      file.cache_reused = fields[6] == "1";
      review.reviewed_files.push_back(std::move(file));
    } else if (tag == "ROLE" && model_v5 && fields.size() >= 5U) {
      VeeamEvidenceRoleSummary role;
      role.role = static_cast<VeeamEvidenceRole>(number<int>(fields[0], static_cast<int>(VeeamEvidenceRole::other)));
      role.candidate_files = number<std::uint64_t>(fields[1]);
      role.scanned_files = number<std::uint64_t>(fields[2]);
      role.deferred_files = number<std::uint64_t>(fields[3]);
      role.total_bytes = number<std::uint64_t>(fields[4]);
      review.evidence_roles.push_back(std::move(role));
    } else if (tag == "BUNDLE" && fields.size() >= 13U) {
      VeeamBundleSummary bundle;
      bundle.key = fields[0]; bundle.source_path = fields[1]; bundle.display_name = fields[2];
      bundle.primary_machine_key = fields[3]; bundle.primary_machine_name = fields[4];
      bundle.manifest_profile = fields[5]; bundle.product_type = fields[6];
      bundle.product_confidence = static_cast<ParserConfidence>(number<int>(fields[7]));
      bundle.source_bytes = number<std::uint64_t>(fields[8]); bundle.source_fingerprint = fields[9];
      bundle.candidate_files = number<std::uint64_t>(fields[10]);
      bundle.indexed_files = number<std::uint64_t>(fields[11]);
      bundle.deferred_files = number<std::uint64_t>(fields[12]);
      if (fields.size() >= 14U)
        bundle.primary_machine_role = fields[13];
      if (fields.size() >= 15U)
        bundle.product_version = fields[14];
      review.bundles.push_back(std::move(bundle));
    } else if (tag == "MACHINE" && fields.size() >= 17U) {
      VeeamMachineRecord machine;
      machine.key = fields[0]; machine.display_name = fields[1];
      machine.summary.machine_name = make_evidence(fields[2]);
      machine.summary.host_name = make_evidence(fields[3]);
      machine.summary.primary_ip = make_evidence(fields[4]);
      machine.summary.operating_system = make_evidence(fields[5]);
      machine.summary.cpu_logical_processors = make_evidence(fields[6]);
      machine.summary.product_version = make_evidence(fields[7]);
      machine.summary.assembly_version = make_evidence(fields[8]);
      machine.summary.management_mode = make_evidence(fields[9]);
      machine.summary.management_server = make_evidence(fields[10]);
      machine.summary.culture = make_evidence(fields[11]);
      machine.summary.utc_time = make_evidence(fields[12]);
      machine.summary.private_fix = make_evidence(fields[13]);
      for (auto& value : split_lines(fields[14])) {
        if (auto evidence = make_evidence(value)) machine.summary.license_modes.push_back(*evidence);
      }
      for (auto& value : split_lines(fields[15])) {
        if (auto evidence = make_evidence(value)) machine.summary.alternate_ip_addresses.push_back(*evidence);
      }
      machine.source_paths = split_lines(fields[16]);
      if (fields.size() >= 18U)
        machine.role = fields[17];
      review.machines.push_back(std::move(machine));
    } else if (tag == "RUN") {
      // RUN records are versioned and densely positional. Do not enter the
      // unchecked field reader with a truncated current-model record: malformed
      // evidence must fail closed instead of becoming undefined vector access or
      // silently shifting VSS/settings columns. v2 had 48 fields; v3/v4 have 59.
      const std::size_t required_run_fields = (model_v5 || model_v4 || model_v3) ? 59U : 48U;
      if (fields.size() < required_run_fields) {
        return Result<VeeamLogReviewResult>::failure(store_error(
            "load model",
            path,
            "Damaged RUN record: expected at least " +
                std::to_string(required_run_fields) + " fields but found " +
                std::to_string(fields.size())));
      }
      VeeamJobSession run;
      std::size_t i = 0;
      run.run_kind = fields[i++]; run.index_only = fields[i++] == "1";
      run.protection_group_rescan = fields[i++] == "1"; run.protection_group_name = fields[i++];
      run.run_key = fields[i++]; run.machine_key = fields[i++]; run.machine_name = fields[i++];
      run.job_name = fields[i++]; run.job_id = fields[i++]; run.session_id = fields[i++];
      run.task_session_id = fields[i++]; run.job_mode = fields[i++]; run.job_type = fields[i++];
      run.status = fields[i++]; run.restore_point_id = fields[i++]; run.restore_point_type = fields[i++];
      run.backup_file = fields[i++]; run.source_path = fields[i++]; run.materialized_path = fields[i++];
      run.start_line = number<std::uint64_t>(fields[i++]); run.completion_line = number<std::uint64_t>(fields[i++]);
      run.start_timestamp_original = fields[i++]; run.completion_timestamp_original = fields[i++];
      run.start_utc_ms = parse_optional_i64(fields[i++]); run.completion_utc_ms = parse_optional_i64(fields[i++]);
      run.settings.backup_mode = fields[i++]; run.settings.included_items = split_lines(fields[i++]);
      run.settings.excluded_items = split_lines(fields[i++]); run.settings.destination_type = fields[i++];
      run.settings.destination_path = fields[i++]; run.settings.retention = fields[i++];
      run.settings.compression = fields[i++]; run.settings.storage_optimization = fields[i++];
      run.settings.encryption = fields[i++]; run.settings.gfs = fields[i++]; run.settings.schedule = fields[i++];
      run.settings.created_by = fields[i++]; run.settings.created_at = fields[i++];
      run.settings.vss_snapshot = fields[i++]; run.settings.application_processing = fields[i++];
      run.settings.guest_indexing = fields[i++]; run.settings.source_backup_mode = fields[i++];
      run.settings.repository_operation = fields[i++]; run.settings.resulting_backup_type = fields[i++];
      run.settings.task_total_size = fields[i++];
      if ((model_v5 || model_v4 || model_v3) && fields.size() >= 59U) {
        run.settings.job_description = fields[i++];
        run.settings.backup_server = fields[i++];
        run.settings.backup_repository = fields[i++];
        run.settings.backup_cache = fields[i++];
        run.settings.script_processing = fields[i++];
        run.settings.command_line = fields[i++];
        run.settings.settings_source_path = fields[i++];
        run.settings.settings_materialized_path = fields[i++];
        run.settings.settings_start_line = number<std::uint64_t>(fields[i++]);
        run.settings.settings_end_line = number<std::uint64_t>(fields[i++]);
        run.settings.settings_lines = split_lines(fields[i++]);
      }
      run.used_vss_provider_id = fields[i++];
      run.used_vss_provider_name = fields[i++]; run.used_vss_provider_type = fields[i++];
      review.job_sessions.push_back(std::move(run));
    } else if (tag == "INCIDENT" && fields.size() >= 13U) {
      VeeamIncident incident;
      incident.id = fields[0]; incident.signature = fields[1]; incident.severity = fields[2];
      incident.component = fields[3]; incident.summary = fields[4];
      incident.occurrences = number<std::uint64_t>(fields[5]);
      incident.first_timestamp_original = fields[6]; incident.last_timestamp_original = fields[7];
      incident.first_utc_ms = parse_optional_i64(fields[8]); incident.last_utc_ms = parse_optional_i64(fields[9]);
      incident.locations_omitted = number<std::uint64_t>(fields[10]);
      incident.machine_keys = split_lines(fields[11]); incident.job_run_keys = split_lines(fields[12]);
      incidents[incident.id] = review.incidents.size();
      review.incidents.push_back(std::move(incident));
    } else if (tag == "LOCATION" && fields.size() >= 17U) {
      const auto found = incidents.find(fields[0]);
      if (found == incidents.end())
        continue;
      VeeamIncidentLocation location;
      location.machine_key = fields[1]; location.machine_name = fields[2];
      location.explicit_job_run_key = fields[3]; location.correlated_job_run_keys = split_lines(fields[4]);
      location.explicit_job_id = fields[5]; location.explicit_session_id = fields[6];
      location.source_path = fields[7]; location.materialized_path = fields[8];
      location.line_number = number<std::uint64_t>(fields[9]); location.byte_offset = number<std::uint64_t>(fields[10]);
      location.timestamp_original = fields[11]; location.timestamp_utc_ms = parse_optional_i64(fields[12]);
      location.thread_or_task = fields[13]; location.before = split_lines(fields[14]);
      location.lines = split_lines(fields[15]); location.after = split_lines(fields[16]);
      review.incidents[found->second].locations.push_back(std::move(location));
    } else if (tag == "TIMELINE" && fields.size() >= 11U) {
      VeeamTimelineEvent event;
      event.evidence.source_path = fields[0]; event.evidence.materialized_path = fields[1];
      event.evidence.line_number = number<std::uint64_t>(fields[2]);
      event.evidence.timestamp_original = fields[3]; event.evidence.timestamp_utc_ms = parse_optional_i64(fields[4]);
      // fields[5] stores the role name for forward compatibility. Role defaults to other
      // when reopening a case because dashboard/review correlation uses category/rule/source identity.
      event.evidence.category = fields[6]; event.evidence.rule_id = fields[7]; event.evidence.raw_line = fields[8];
      event.machine_key = fields[9]; event.job_run_key = fields[10];
      review.timeline_events.push_back(std::move(event));
    }
  }

  if (!input.eof() && input.fail())
    return Result<VeeamLogReviewResult>::failure(store_error("load model", path, "Failed while reading case review model"));
  if (!review.machines.empty())
    review.machine = review.machines.front().summary;
  // Re-sort on load so cases saved by an earlier release immediately adopt the
  // current newest-first presentation contract without requiring a re-parse.
  sort_review_newest_first(review);
  return Result<VeeamLogReviewResult>::success(std::move(review));
}

VeeamLogReviewResult merge_case_review_models(const VeeamLogReviewResult& existing,
                                              const VeeamLogReviewResult& incoming) {
  // Append is evidence-oriented rather than scan-oriented. If the incoming
  // review consists entirely of bundle fingerprints already present in the
  // case, it is the same immutable evidence and must not inflate metrics, runs,
  // or incident occurrence counts merely because the engineer selected it again.
  if (!incoming.bundles.empty()) {
    std::set<std::string> existing_fingerprints;
    for (const auto& bundle : existing.bundles) {
      if (!bundle.source_fingerprint.empty())
        existing_fingerprints.insert(bundle.source_fingerprint);
    }
    const bool fully_fingerprinted =
        std::all_of(incoming.bundles.begin(), incoming.bundles.end(), [](const auto& bundle) {
          return !bundle.source_fingerprint.empty();
        });
    const bool all_already_known =
        fully_fingerprinted &&
        std::all_of(incoming.bundles.begin(), incoming.bundles.end(), [&](const auto& bundle) {
          return existing_fingerprints.contains(bundle.source_fingerprint);
        });
    if (all_already_known)
      return existing;
  }

  VeeamLogReviewResult merged = existing;
  if (merged.product_type.empty()) {
    merged.product_type = incoming.product_type;
  } else if (!incoming.product_type.empty() &&
             merged.product_type != incoming.product_type) {
    merged.product_type = "Multiple Veeam products";
  }
  if (merged.parser_profile.empty()) {
    merged.parser_profile = incoming.parser_profile;
  } else if (!incoming.parser_profile.empty() &&
             merged.parser_profile != incoming.parser_profile) {
    merged.parser_profile = "case-mixed";
  }
  if (merged.parser_scope_note.empty()) merged.parser_scope_note = incoming.parser_scope_note;
  merged.fast_index_used = merged.fast_index_used && incoming.fast_index_used;
  if (!incoming.report_path.empty()) merged.report_path = incoming.report_path;
  merged.files_discovered += incoming.files_discovered;
  merged.files_deferred += incoming.files_deferred;
  merged.files_scanned += incoming.files_scanned;
  merged.lines_scanned += incoming.lines_scanned;
  merged.input_bytes += incoming.input_bytes;
  merged.parse_errors += incoming.parse_errors;
  merged.parser_cache_hits += incoming.parser_cache_hits;
  merged.profile_used = existing.profile_used == incoming.profile_used
                            ? existing.profile_used
                            : VeeamReviewProfile::automatic;
  merged.product_confidence = std::min(merged.product_confidence, incoming.product_confidence);
  merged.persistent_cache_enabled = merged.persistent_cache_enabled || incoming.persistent_cache_enabled;
  if (!incoming.cache_directory.empty()) merged.cache_directory = incoming.cache_directory;

  std::set<std::string> source_keys;
  for (const auto& source : merged.input_sources) source_keys.insert(path_to_utf8(source));
  for (const auto& source : incoming.input_sources)
    if (source_keys.insert(path_to_utf8(source)).second) merged.input_sources.push_back(source);

  std::set<std::string> bundle_fingerprints;
  for (const auto& bundle : merged.bundles)
    if (!bundle.source_fingerprint.empty()) bundle_fingerprints.insert(bundle.source_fingerprint);
  for (const auto& bundle : incoming.bundles) {
    if (!bundle.source_fingerprint.empty() && !bundle_fingerprints.insert(bundle.source_fingerprint).second)
      continue;
    merged.bundles.push_back(bundle);
  }

  // Preserve per-file coverage across append operations. Source path is the
  // stable identity; prefer the incoming record when it represents a deeper
  // scan or carries a resolved error/cache state.
  std::map<std::string, std::size_t> reviewed_file_indexes;
  for (std::size_t index = 0; index < merged.reviewed_files.size(); ++index)
    reviewed_file_indexes[merged.reviewed_files[index].source_path] = index;
  for (const auto& file : incoming.reviewed_files) {
    const auto found = reviewed_file_indexes.find(file.source_path);
    if (found == reviewed_file_indexes.end()) {
      reviewed_file_indexes[file.source_path] = merged.reviewed_files.size();
      merged.reviewed_files.push_back(file);
    } else {
      auto& current = merged.reviewed_files[found->second];
      if (file.lines_scanned >= current.lines_scanned || (!file.error.empty() && current.error.empty()) ||
          (file.error.empty() && !current.error.empty()))
        current = file;
    }
  }
  // Evidence-role summaries contain scan semantics that cannot be reconstructed
  // from VeeamReviewedFile alone (a zero-line file is not necessarily deferred,
  // and an error is not the same thing as deliberate deferral). Preserve the
  // parser-produced counters and aggregate them by role. The immutable-bundle
  // early return above prevents a full duplicate append from inflating them.
  std::map<VeeamEvidenceRole, VeeamEvidenceRoleSummary> role_summaries;
  for (const auto& role : existing.evidence_roles) role_summaries[role.role] = role;
  for (const auto& role : incoming.evidence_roles) {
    auto& target = role_summaries[role.role];
    target.role = role.role;
    target.candidate_files += role.candidate_files;
    target.scanned_files += role.scanned_files;
    target.deferred_files += role.deferred_files;
    target.total_bytes += role.total_bytes;
  }
  merged.evidence_roles.clear();
  for (const auto& [_, role] : role_summaries) merged.evidence_roles.push_back(role);

  std::map<std::string, std::size_t> machine_indexes;
  for (std::size_t index = 0; index < merged.machines.size(); ++index)
    machine_indexes[merged.machines[index].key] = index;
  for (const auto& machine : incoming.machines) {
    const auto found = machine_indexes.find(machine.key);
    if (found == machine_indexes.end()) {
      machine_indexes[machine.key] = merged.machines.size();
      merged.machines.push_back(machine);
      continue;
    }
    auto& target = merged.machines[found->second];
    if (target.display_name.empty() || target.display_name == "Unknown machine")
      target.display_name = machine.display_name;
    if (target.role.empty())
      target.role = machine.role;
    merge_machine_summary(target.summary, machine.summary);
    for (const auto& source : machine.source_paths)
      if (std::find(target.source_paths.begin(), target.source_paths.end(), source) == target.source_paths.end())
        target.source_paths.push_back(source);
  }

  std::map<std::string, std::size_t> run_indexes;
  for (std::size_t index = 0; index < merged.job_sessions.size(); ++index)
    run_indexes[run_identity(merged.job_sessions[index])] = index;
  for (const auto& run : incoming.job_sessions) {
    const std::string identity = run_identity(run);
    const auto found = run_indexes.find(identity);
    if (found == run_indexes.end()) {
      run_indexes[identity] = merged.job_sessions.size();
      merged.job_sessions.push_back(run);
    } else if (merged.job_sessions[found->second].index_only && !run.index_only) {
      merged.job_sessions[found->second] = run;
    }
  }
  std::stable_sort(merged.job_sessions.begin(), merged.job_sessions.end(), [](const auto& left, const auto& right) {
    if (left.start_utc_ms && right.start_utc_ms) return *left.start_utc_ms > *right.start_utc_ms;
    if (left.start_utc_ms) return true;
    if (right.start_utc_ms) return false;
    return left.start_timestamp_original > right.start_timestamp_original;
  });

  std::map<std::string, std::size_t> incident_indexes;
  for (std::size_t index = 0; index < merged.incidents.size(); ++index)
    incident_indexes[merged.incidents[index].signature] = index;
  for (const auto& incident : incoming.incidents) {
    const auto found = incident_indexes.find(incident.signature);
    if (found == incident_indexes.end()) {
      incident_indexes[incident.signature] = merged.incidents.size();
      merged.incidents.push_back(incident);
      continue;
    }
    auto& target = merged.incidents[found->second];
    std::set<std::string> known_locations;
    for (const auto& location : target.locations) known_locations.insert(location_identity(location));
    std::uint64_t duplicate_locations = 0;
    for (const auto& location : incident.locations) {
      if (known_locations.insert(location_identity(location)).second)
        target.locations.push_back(location);
      else
        ++duplicate_locations;
    }
    const std::uint64_t safe_add = incident.occurrences > duplicate_locations
                                       ? incident.occurrences - duplicate_locations
                                       : 0U;
    target.occurrences += safe_add;
    target.locations_omitted += incident.locations_omitted;
    if (!target.first_utc_ms || (incident.first_utc_ms && *incident.first_utc_ms < *target.first_utc_ms)) {
      target.first_utc_ms = incident.first_utc_ms;
      target.first_timestamp_original = incident.first_timestamp_original;
    }
    if (!target.last_utc_ms || (incident.last_utc_ms && *incident.last_utc_ms > *target.last_utc_ms)) {
      target.last_utc_ms = incident.last_utc_ms;
      target.last_timestamp_original = incident.last_timestamp_original;
    }
    for (const auto& key : incident.machine_keys)
      if (std::find(target.machine_keys.begin(), target.machine_keys.end(), key) == target.machine_keys.end())
        target.machine_keys.push_back(key);
    for (const auto& key : incident.job_run_keys)
      if (std::find(target.job_run_keys.begin(), target.job_run_keys.end(), key) == target.job_run_keys.end())
        target.job_run_keys.push_back(key);
  }

  std::set<std::string> timeline_keys;
  for (const auto& event : merged.timeline_events) timeline_keys.insert(timeline_identity(event));
  for (const auto& event : incoming.timeline_events)
    if (timeline_keys.insert(timeline_identity(event)).second) merged.timeline_events.push_back(event);
  std::stable_sort(merged.timeline_events.begin(), merged.timeline_events.end(), [](const auto& left, const auto& right) {
    if (left.evidence.timestamp_utc_ms && right.evidence.timestamp_utc_ms &&
        *left.evidence.timestamp_utc_ms != *right.evidence.timestamp_utc_ms)
      return *left.evidence.timestamp_utc_ms > *right.evidence.timestamp_utc_ms;
    if (left.evidence.timestamp_utc_ms.has_value() != right.evidence.timestamp_utc_ms.has_value())
      return left.evidence.timestamp_utc_ms.has_value();
    if (left.evidence.source_path != right.evidence.source_path)
      return left.evidence.source_path < right.evidence.source_path;
    return left.evidence.line_number < right.evidence.line_number;
  });

  if (!merged.machines.empty())
    merged.machine = merged.machines.front().summary;
  sort_review_newest_first(merged);
  return merged;
}

std::string case_review_regression_reason(const VeeamLogReviewResult& existing,
                                          const VeeamLogReviewResult& incoming) {
  if (!existing.job_sessions.empty() && incoming.job_sessions.empty()) {
    return "job runs collapsed from " + std::to_string(existing.job_sessions.size()) +
           " to 0";
  }

  if (existing.files_discovered >= 20U &&
      incoming.files_discovered * 4U < existing.files_discovered) {
    return "source coverage collapsed from " + std::to_string(existing.files_discovered) +
           " discovered files to " + std::to_string(incoming.files_discovered);
  }

  const auto real_machine_count = [](const VeeamLogReviewResult& review) {
    return static_cast<std::size_t>(std::count_if(
        review.machines.begin(), review.machines.end(), [](const auto& machine) {
          const std::string name = machine.display_name.empty() ? machine.key : machine.display_name;
          return !name.empty() && name != "Unknown machine" && name != "Unassigned evidence";
        }));
  };
  if (real_machine_count(existing) != 0U && real_machine_count(incoming) == 0U)
    return "identified machine evidence collapsed to Unassigned/Unknown evidence";

  if (!existing.input_sources.empty() && !incoming.input_sources.empty()) {
    std::set<std::string> old_sources;
    for (const auto& source : existing.input_sources)
      old_sources.insert(path_to_utf8(source.lexically_normal()));
    bool overlap = false;
    for (const auto& source : incoming.input_sources) {
      if (old_sources.contains(path_to_utf8(source.lexically_normal()))) {
        overlap = true;
        break;
      }
    }
    if (!overlap)
      return "incoming review does not reference any of the saved case source paths";
  }

  return {};
}

} // namespace support_assist
