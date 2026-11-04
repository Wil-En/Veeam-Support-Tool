#include "commands.hpp"

#include "support_assist/case_workspace.hpp"
#include "support_assist/change_journal.hpp"
#include "support_assist/case_review_store.hpp"
#include "support_assist/collected_evidence.hpp"
#include "support_assist/disk_speed_test.hpp"
#include "support_assist/object_storage.hpp"
#include "support_assist/system_health.hpp"
#include "support_assist/elevated.hpp"
#include "support_assist/export.hpp"
#include "support_assist/file_lock.hpp"
#include "support_assist/file_transfer.hpp"
#include "support_assist/filesystem.hpp"
#include "support_assist/guided_diagnostics.hpp"
#include "support_assist/host_checks.hpp"
#include "support_assist/installer_cache.hpp"
#include "support_assist/named_pipes.hpp"
#include "support_assist/log_collection.hpp"
#include "support_assist/product_discovery.hpp"
#include "support_assist/universal_collection.hpp"
#include "support_assist/log_search.hpp"
#include "support_assist/name_check.hpp"
#include "support_assist/network.hpp"
#include "support_assist/packet_events.hpp"
#include "support_assist/service_channel.hpp"
#include "support_assist/scenarios.hpp"
#include "support_assist/pending_restart.hpp"
#include "support_assist/port_check.hpp"
#include "support_assist/postgres_check.hpp"
#include "support_assist/registry.hpp"
#include "support_assist/security.hpp"
#include "support_assist/snapshot_store.hpp"
#include "support_assist/sql_catalog.hpp"
#include "support_assist/sql_check.hpp"
#include "support_assist/sql_tools.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/support_tools.hpp"
#include "support_assist/system_info.hpp"
#include "support_assist/time.hpp"
#include "support_assist/time_check.hpp"
#include "support_assist/tool_catalog.hpp"
#include "support_assist/tool_requirements.hpp"
#include "support_assist/tool_run_profiles.hpp"
#include "support_assist/process.hpp"
#include "support_assist/tool_evidence.hpp"
#include "support_assist/usn.hpp"
#include "support_assist/uuid.hpp"
#include "support_assist/version.hpp"
#include "support_assist/vss.hpp"
#include "support_assist/veeam_log_review.hpp"
#include "support_assist/veeam_watch.hpp"
#include "support_assist/tool_results.hpp"
#include "support_assist/volume_check.hpp"
#include "support_assist/wmi.hpp"
#include "support_assist/wmi_health.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace support_assist::cli {
namespace {

constexpr int kExitSuccess = 0;
constexpr int kExitUnavailable = 2;
constexpr int kExitFindings = 3;
constexpr int kExitUsage = 64;
constexpr int kExitFailure = 70;
constexpr int kExitCancelled = 130;

struct ParsedArguments {
  std::vector<std::string> positionals;
  std::multimap<std::string, std::string> options;
};

ParsedArguments parse_arguments(const std::vector<std::string>& arguments) {
  ParsedArguments parsed;
  for (std::size_t index = 0; index < arguments.size(); ++index) {
    const std::string& argument = arguments[index];
    if (!argument.starts_with("--")) {
      parsed.positionals.push_back(argument);
      continue;
    }

    const std::size_t equals = argument.find('=');
    if (equals != std::string::npos) {
      parsed.options.emplace(argument.substr(2, equals - 2), argument.substr(equals + 1));
      continue;
    }

    const std::string key = argument.substr(2);
    if (index + 1 < arguments.size() && !arguments[index + 1].starts_with("--")) {
      parsed.options.emplace(key, arguments[++index]);
    } else {
      parsed.options.emplace(key, "true");
    }
  }
  return parsed;
}

// Every option name any command reads, plus the few that are handled positionally.
//
// parse_arguments() accepts any --name and stores it, and each command reads only the keys it
// knows; an option missing from this list is silently discarded rather than rejected, so a typo
// changes behaviour instead of failing. tools/test_cli_option_registry.py re-derives this list
// from the option(), options() and flag() call sites and fails when the two drift, so adding a
// new option to a command without registering it here cannot ship.
constexpr std::string_view kKnownOptions[] = {
    "all-interfaces", "arg", "assumed-offset-minutes", "backend", "backup-type", "banner",
    "baseline", "baseline-id", "other", "other-id", "batch-size", "block", "bootable-system-state", "bytes", "cache-dir", "caching", "case",
    "case-sensitive", "channel", "check", "checks", "compare-versions", "component-mode",
    "accept-cost", "addressing", "bucket", "certificate-file", "endpoint", "no-signed", "product", "region",
    "adapter", "email", "iperf3", "ipv6", "link", "mtu", "network-speed", "reduced-to", "share", "storage-result",
    "storage-speed",
    "timestamps",
    "connect-timeout-ms",
    "context", "count", "custom", "database", "date-order", "days", "direct", "direction", "discover-veeam",
    "duration", "engine", "engineer",
    "event-id", "exclude", "expect", "expected-fingerprint", "file", "filter", "find", "folder",
    "folder-by-folder",
    "follow-reparse", "format", "from", "full-scan", "hash", "hash-extension", "hash-max-bytes", "help",
    "maximum-depth", "maximum-objects",
    "hold-seconds", "host", "hydrate-cloud-files", "id", "idle-timeout-ms", "include-user",
    "include-virtual", "input", "interface", "interval-ms", "ip", "json", "keep", "live", "log", "machine", "max-incidents",
    "max-results", "mode", "multi-machine-source", "multiple", "name", "namespace", "no-archive", "no-archives",
    "no-cache", "no-file-id", "no-hash-inference", "no-journal", "no-move-detection", "no-platform-context",
    "no-sat-handshake", "no-sat-payload", "no-system-trust", "no-third-party-errors",
    "no-warnings", "no-windows-context", "note", "notes", "offset", "official-exporters", "outstanding", "output",
    "parent", "partial-file-support", "path", "pattern", "payload", "port", "preset",
    "process", "scenario", "continue", "hours", "logs-only", "account", "against", "config-database", "login", "trust-certificate", "products", "profile", "protocol", "query", "random", "regex", "role", "root",
    "sat-listener",
    "sat-payload",
    "seconds", "security", "select-all-components", "server", "severity", "show-in", "show-sql", "single",
    "single-thread", "size", "sni", "snapshot", "snapshot-id", "source", "state", "state-dir", "stream-count", "streams", "tcp",
    "test", "text", "threads",
    "timeout-ms", "timestamp-tolerance-100ns", "title", "to", "tools-root", "udp", "upgrade-code", "user", "veeam", "version", "view",
    "volume", "warmup", "workers", "write-percent", "writer", "zone",
};

std::optional<std::string> unknown_option(const ParsedArguments& parsed) {
  for (const auto& [key, value] : parsed.options) {
    static_cast<void>(value);
    if (std::find(std::begin(kKnownOptions), std::end(kKnownOptions), key) ==
        std::end(kKnownOptions)) {
      return key;
    }
  }
  return std::nullopt;
}

// Name the option the engineer probably meant. A rejection that does not is only half an answer.
//
// Prefix matching comes first and matters more than edit distance: `--output-dir` for `--output`
// is four edits away, well outside any sane distance bound, but it is an exact prefix and obvious
// to a reader. Suffix-added and suffix-dropped names are the common shape here because so many
// options are compound.
std::optional<std::string> closest_option(std::string_view typed) {
  std::string_view prefix_best;
  for (const auto candidate : kKnownOptions) {
    if (typed.starts_with(candidate) || candidate.starts_with(typed)) {
      // The longest shared prefix is the most specific guess.
      if (candidate.size() > prefix_best.size())
        prefix_best = candidate;
    }
  }
  if (!prefix_best.empty())
    return std::string(prefix_best);

  std::size_t best_distance = 3U;
  std::string_view best;
  for (const auto candidate : kKnownOptions) {
    std::vector<std::size_t> previous(candidate.size() + 1U);
    std::vector<std::size_t> current(candidate.size() + 1U);
    for (std::size_t index = 0; index <= candidate.size(); ++index)
      previous[index] = index;
    for (std::size_t row = 1U; row <= typed.size(); ++row) {
      current[0] = row;
      for (std::size_t column = 1U; column <= candidate.size(); ++column) {
        const std::size_t substitution =
            previous[column - 1U] + (typed[row - 1U] == candidate[column - 1U] ? 0U : 1U);
        current[column] = std::min({previous[column] + 1U, current[column - 1U] + 1U, substitution});
      }
      previous = current;
    }
    if (previous[candidate.size()] < best_distance) {
      best_distance = previous[candidate.size()];
      best = candidate;
    }
  }
  if (best.empty())
    return std::nullopt;
  return std::string(best);
}

std::optional<std::string> option(const ParsedArguments& parsed, std::string_view key) {
  const auto iterator = parsed.options.find(std::string(key));
  if (iterator == parsed.options.end())
    return std::nullopt;
  return iterator->second;
}

std::vector<std::string> options(const ParsedArguments& parsed, std::string_view key) {
  std::vector<std::string> values;
  const auto [begin, end] = parsed.options.equal_range(std::string(key));
  for (auto iterator = begin; iterator != end; ++iterator)
    values.push_back(iterator->second);
  return values;
}

// A path typed on the command line. Arguments arrive as UTF-8 (the Windows entry converts the wide
// command line), and a path built from a narrow string reads the ANSI code page on Windows, so every
// path argument goes through here.
std::filesystem::path argument_path(const std::string& text) {
  return path_from_utf8(text);
}

std::optional<std::filesystem::path> option_path(const ParsedArguments& parsed,
                                                 std::string_view key) {
  const auto value = option(parsed, key);
  if (!value)
    return std::nullopt;
  return argument_path(*value);
}

bool flag(const ParsedArguments& parsed, std::string_view key) {
  const auto value = option(parsed, key);
  if (!value)
    return false;
  const std::string folded = ascii_lower(*value);
  return folded == "true" || folded == "1" || folded == "yes" || folded == "on";
}

template <typename Integer>
Result<Integer> parse_integer(std::string_view text, std::string_view option_name) {
  Integer value{};
  const char* begin = text.data();
  const char* end = text.data() + text.size();
  const auto [position, error_code] = std::from_chars(begin, end, value);
  if (error_code == std::errc{} && position == end) {
    return Result<Integer>::success(value);
  }
  Error error;
  error.component = "CLI";
  error.operation = "parse numeric option";
  error.source = std::string(option_name);
  error.message = "Invalid numeric value: " + std::string(text);
  return Result<Integer>::failure(std::move(error));
}

int fail(const Error& error, int exit_code = kExitFailure) {
  std::cerr << describe_error(error) << '\n';
  return exit_code;
}

void progress_text(const ProgressEvent& event) {
  std::cerr << '\r' << event.phase << " | " << event.processed << " items | " << event.errors
            << " errors | " << static_cast<std::uint64_t>(event.items_per_second) << "/s | "
            << event.current_scope.substr(0, 100) << "    " << std::flush;
}

void finish_progress_line() {
  std::cerr << '\n';
}

#ifdef _WIN32
Result<RegistryView> parse_registry_view(std::string_view value) {
  if (value == "both")
    return Result<RegistryView>::success(RegistryView::both);
  if (value == "32")
    return Result<RegistryView>::success(RegistryView::view32);
  if (value == "64")
    return Result<RegistryView>::success(RegistryView::view64);
  if (value == "native")
    return Result<RegistryView>::success(RegistryView::native);
  Error error;
  error.component = "CLI";
  error.operation = "parse Registry view";
  error.message = "Expected native, 32, 64, or both";
  return Result<RegistryView>::failure(std::move(error));
}
#endif

Result<HashMode> parse_hash_mode(std::string_view value) {
  if (value == "none")
    return Result<HashMode>::success(HashMode::none);
  if (value == "all")
    return Result<HashMode>::success(HashMode::all);
  if (value == "small" || value == "below-size") {
    return Result<HashMode>::success(HashMode::below_size);
  }
  if (value == "extensions")
    return Result<HashMode>::success(HashMode::extensions);
  Error error;
  error.component = "CLI";
  error.operation = "parse hash mode";
  error.message = "Expected none, all, below-size, or extensions";
  return Result<HashMode>::failure(std::move(error));
}

DateOrder parse_date_order(std::string_view value) {
  if (value == "dmy")
    return DateOrder::day_month_year;
  if (value == "mdy")
    return DateOrder::month_day_year;
  if (value == "iso")
    return DateOrder::iso_only;
  if (value == "system")
    return DateOrder::system_locale;
  return DateOrder::automatic;
}

struct SnapshotReference {
  std::filesystem::path path;
  std::string id;
};

Result<SnapshotReference> resolve_snapshot_reference(const ParsedArguments& parsed,
                                                     std::string_view path_option,
                                                     std::string_view id_option) {
  const auto path = option_path(parsed, path_option);
  if (!path) {
    Error error;
    error.component = "CLI";
    error.operation = "resolve snapshot reference";
    error.message = "Missing --" + std::string(path_option);
    return Result<SnapshotReference>::failure(std::move(error));
  }

  auto store = SnapshotStore::open(*path, true);
  if (!store.ok())
    return Result<SnapshotReference>::failure(store.error());
  if (auto status = store.value().validate(); !status.ok()) {
    return Result<SnapshotReference>::failure(status.error());
  }

  std::optional<std::string> id = option(parsed, id_option);
  if (!id) {
    auto first = store.value().latest_complete_snapshot_id();
    if (!first.ok())
      return Result<SnapshotReference>::failure(first.error());
    id = std::move(first.value());
  }

  auto metadata = store.value().metadata(*id);
  if (!metadata.ok())
    return Result<SnapshotReference>::failure(metadata.error());
  return Result<SnapshotReference>::success(SnapshotReference{*path, *id});
}

Result<SnapshotReference> resolve_baseline_reference(const ParsedArguments& parsed) {
  if (option(parsed, "baseline"))
    return resolve_snapshot_reference(parsed, "baseline", "baseline-id");
  if (option(parsed, "snapshot"))
    return resolve_snapshot_reference(parsed, "snapshot", "snapshot-id");

  Error error;
  error.component = "CLI";
  error.operation = "resolve baseline reference";
  error.message = "Missing --baseline";
  return Result<SnapshotReference>::failure(std::move(error));
}

#ifdef _WIN32
Status write_registry_configuration(SnapshotStore& store,
                                    std::string_view snapshot_id,
                                    const std::vector<RegistryScope>& scopes) {
  for (std::size_t index = 0; index < scopes.size(); ++index) {
    RegistryScopeConfig config;
    config.snapshot_id = std::string(snapshot_id);
    config.ordinal = static_cast<std::uint32_t>(index);
    config.hive = scopes[index].hive;
    config.subkey = scopes[index].subkey;
    config.view = scopes[index].view;
    if (auto status = store.add_registry_scope_config(config); !status.ok())
      return status;
  }
  return Status::success();
}
#endif

class TemporarySnapshotFile {
public:
  TemporarySnapshotFile() {
    path_ = std::filesystem::temp_directory_path() /
            ("support-assist-live-" + make_uuid_v4() + ".satsnap");
  }
  ~TemporarySnapshotFile() {
    if (!released_)
      remove_files();
  }
  const std::filesystem::path& path() const noexcept {
    return path_;
  }
  std::filesystem::path release() noexcept {
    released_ = true;
    return path_;
  }

private:
  void remove_files() noexcept {
    std::error_code ignored;
    std::filesystem::remove(path_, ignored);
    // SQLite's -wal/-shm siblings. Concatenate onto the path, not onto path::string(): on
    // MSVC string() converts through the ANSI code page and throws for any name it cannot
    // map. path::operator+= appends in the native encoding.
    for (const char* suffix : {"-wal", "-shm"}) {
      std::filesystem::path sidecar = path_;
      sidecar += suffix;
      std::filesystem::remove(sidecar, ignored);
    }
  }
  std::filesystem::path path_;
  bool released_ = false;
};

#ifdef _WIN32
Result<SnapshotReference> capture_live_registry(const SnapshotReference& baseline,
                                                const CancellationToken& cancel) {
  auto baseline_store = SnapshotStore::open(baseline.path, true);
  if (!baseline_store.ok())
    return Result<SnapshotReference>::failure(baseline_store.error());
  auto configs = baseline_store.value().registry_scope_configs(baseline.id);
  if (!configs.ok())
    return Result<SnapshotReference>::failure(configs.error());

  RegistryScanOptions scan_options;
  for (const auto& config : configs.value()) {
    scan_options.scopes.push_back(RegistryScope{config.hive, config.subkey, config.view});
  }

  TemporarySnapshotFile temporary;
  auto store = SnapshotStore::create(temporary.path());
  if (!store.ok())
    return Result<SnapshotReference>::failure(store.error());
  auto metadata = make_snapshot_metadata(SnapshotKind::registry, "live comparison capture");
  if (auto status = store.value().begin_snapshot(metadata); !status.ok()) {
    return Result<SnapshotReference>::failure(status.error());
  }
  if (auto status = write_registry_configuration(store.value(), metadata.id, scan_options.scopes);
      !status.ok()) {
    return Result<SnapshotReference>::failure(status.error());
  }

  auto summary = scan_registry(store.value(), metadata.id, scan_options, cancel, progress_text);
  finish_progress_line();
  if (!summary.ok()) {
    store.value().finish_snapshot(metadata.id, SnapshotState::failed, 0, 1);
    return Result<SnapshotReference>::failure(summary.error());
  }
  const SnapshotState state =
      summary.value().cancelled ? SnapshotState::cancelled : SnapshotState::complete;
  if (auto status = store.value().finish_snapshot(
          metadata.id, state, summary.value().objects, summary.value().errors);
      !status.ok()) {
    return Result<SnapshotReference>::failure(status.error());
  }
  if (state != SnapshotState::complete) {
    Error error;
    error.component = "CLI";
    error.operation = "capture live Registry comparison";
    error.message = "Live comparison capture was cancelled";
    return Result<SnapshotReference>::failure(std::move(error));
  }

  return Result<SnapshotReference>::success(SnapshotReference{temporary.release(), metadata.id});
}
#endif

Result<SnapshotReference> capture_live_filesystem(const SnapshotReference& baseline,
                                                  const CancellationToken& cancel) {
  std::string baseline_id;
  auto config = load_filesystem_baseline_options(baseline.path, baseline_id);
  if (!config.ok())
    return Result<SnapshotReference>::failure(config.error());
  FilesystemScanOptions scan_options = std::move(config.value());

  TemporarySnapshotFile temporary;
  auto summary = capture_filesystem_baseline(temporary.path(), scan_options, cancel, progress_text);
  finish_progress_line();
  if (!summary.ok()) {
    return Result<SnapshotReference>::failure(summary.error());
  }
  const SnapshotState state = summary.value().state;
  const std::string live_id = summary.value().snapshot_id;
  if (state != SnapshotState::complete) {
    Error error;
    error.component = "CLI";
    error.operation = "capture live filesystem comparison";
    error.message = "Live comparison capture was cancelled";
    return Result<SnapshotReference>::failure(std::move(error));
  }

  return Result<SnapshotReference>::success(SnapshotReference{temporary.release(), live_id});
}

class RetainedTemporaryCleanup {
public:
  explicit RetainedTemporaryCleanup(std::filesystem::path path) : path_(std::move(path)) {}
  ~RetainedTemporaryCleanup() {
    if (path_.empty())
      return;
    std::error_code ignored;
    std::filesystem::remove(path_, ignored);
    // SQLite's -wal/-shm siblings. Concatenate onto the path, not onto path::string(): on
    // MSVC string() converts through the ANSI code page and throws for any name it cannot
    // map. path::operator+= appends in the native encoding.
    for (const char* suffix : {"-wal", "-shm"}) {
      std::filesystem::path sidecar = path_;
      sidecar += suffix;
      std::filesystem::remove(sidecar, ignored);
    }
  }

private:
  std::filesystem::path path_;
};

// Keeps a compare's result in the baseline file for --keep. The compare reads the baseline while it
// runs, so its rows wait in a temporary file and are copied into the baseline when the compare is
// done. The copy runs in batches inside the core's store, one transaction per batch.
class ComparisonKeeper {
public:
  ComparisonKeeper(SnapshotReference baseline, std::string kind, bool live, const SnapshotReference& other)
      : baseline_(std::move(baseline)), kind_(std::move(kind)), live_(live), other_id_(other.id) {
    if (live_) {
      against_ = "now";
    } else {
      std::error_code ignored;
      const std::filesystem::path absolute = std::filesystem::absolute(other.path, ignored);
      against_ = path_to_utf8(absolute.empty() ? other.path : absolute);
      other_name_ = path_to_utf8(other.path.filename());
    }
  }

  Status begin() {
    auto store = SnapshotStore::create(spool_file_.path());
    if (!store.ok())
      return Status::failure(store.error());
    spool_store_.emplace(std::move(store.value()));
    StoredComparison header;
    header.snapshot_id = baseline_.id;
    header.kind = kind_;
    auto id = spool_store_->begin_comparison(header);
    if (!id.ok())
      return Status::failure(id.error());
    spool_id_ = id.value();
    return Status::success();
  }

  // One record of the compare: counted, and kept as a row.
  Status add(const DiffRecord& record) {
    counts_.count(record.kind);
    return add_row(stored_comparison_row(record));
  }

  // A row that comes from the change journal. It is not counted among the compare's kinds; the
  // result line says how many there were. A failure is reported by keep().
  void add_journal_row(StoredComparisonRow row) {
    ++journal_rows_;
    if (auto status = add_row(std::move(row)); !status.ok() && !failure_)
      failure_ = status.error();
  }

  // Copies the rows into the baseline file and records the counts and the result line.
  Status keep() {
    if (failure_)
      return Status::failure(*failure_);
    if (auto status = flush(); !status.ok())
      return status;
    auto target = SnapshotStore::open(baseline_.path, false);
    if (!target.ok())
      return Status::failure(target.error());
    StoredComparison header;
    header.snapshot_id = baseline_.id;
    header.kind = kind_;
    header.against = against_;
    header.against_snapshot_id = other_id_;
    auto id = target.value().begin_comparison(header);
    if (!id.ok())
      return Status::failure(id.error());

    std::optional<Error> copy_failure;
    std::vector<StoredComparisonRow> batch;
    batch.reserve(kBatchRows);
    const auto write_batch = [&]() {
      if (auto status = target.value().add_comparison_rows(id.value(), batch); !status.ok()) {
        copy_failure = status.error();
        return false;
      }
      batch.clear();
      return true;
    };
    auto read = spool_store_->visit_comparison_rows(spool_id_, [&](const StoredComparisonRow& row) {
      batch.push_back(row);
      return batch.size() < kBatchRows || write_batch();
    });
    if (!copy_failure && read.ok() && !batch.empty())
      write_batch();
    if (copy_failure || !read.ok()) {
      static_cast<void>(target.value().delete_comparison(id.value()));
      return Status::failure(copy_failure ? *copy_failure : read.error());
    }
    if (auto status = target.value().finish_comparison(id.value(), counts_, summary()); !status.ok()) {
      static_cast<void>(target.value().delete_comparison(id.value()));
      return status;
    }
    return Status::success();
  }

  const SnapshotReference& baseline() const noexcept {
    return baseline_;
  }

private:
  static constexpr std::size_t kBatchRows = 5000;

  Status add_row(StoredComparisonRow row) {
    pending_.push_back(std::move(row));
    return pending_.size() >= kBatchRows ? flush() : Status::success();
  }
  Status flush() {
    if (pending_.empty())
      return Status::success();
    auto status = spool_store_->add_comparison_rows(spool_id_, pending_);
    pending_.clear();
    return status;
  }
  // "Compared with now: 3 added, 1 removed, 2 changed, 0 moved or renamed."
  std::string summary() const {
    std::string text = "Compared with " + (live_ ? std::string("now") : other_name_) + ": " +
                       comparison_counts_text(counts_);
    if (journal_rows_ > 0) {
      text += " The change journal also listed " + std::to_string(journal_rows_) +
              (journal_rows_ == 1 ? " file or folder" : " files and folders") +
              " created and deleted in between or renamed.";
    }
    return text;
  }

  SnapshotReference baseline_;
  std::string kind_;
  bool live_ = false;
  std::string against_;
  std::string other_name_;
  std::string other_id_;
  TemporarySnapshotFile spool_file_;
  std::optional<SnapshotStore> spool_store_;
  std::int64_t spool_id_ = 0;
  std::vector<StoredComparisonRow> pending_;
  StoredComparisonCounts counts_;
  std::uint64_t journal_rows_ = 0;
  std::optional<Error> failure_;
};

// Stores a finished compare in the baseline file and says so on standard error. Answers kExitSuccess
// or the exit code of the failure.
int keep_comparison(ComparisonKeeper& keeper) {
  if (auto status = keeper.keep(); !status.ok())
    return fail(status.error());
  std::cerr << "Comparison kept in " << path_to_utf8(keeper.baseline().path) << '\n';
  return kExitSuccess;
}

Result<DiffWriter> open_diff_writer(const ParsedArguments& parsed) {
  const auto output = option(parsed, "output");
  if (!output) {
    Error error;
    error.component = "CLI";
    error.operation = "open comparison output";
    error.message = "No --output was supplied";
    return Result<DiffWriter>::failure(std::move(error));
  }
  auto format = parse_export_format(option(parsed, "format").value_or("text"));
  if (!format.ok())
    return Result<DiffWriter>::failure(format.error());
  return DiffWriter::open(argument_path(*output), format.value());
}

template <typename CompareFunction>
int emit_comparison(const ParsedArguments& parsed,
                    const SnapshotReference& before,
                    const SnapshotReference& after,
                    CompareFunction compare,
                    ComparisonKeeper* keeper = nullptr) {
  std::optional<DiffWriter> writer;
  if (option(parsed, "output")) {
    auto opened = open_diff_writer(parsed);
    if (!opened.ok())
      return fail(opened.error(), kExitUsage);
    writer.emplace(std::move(opened.value()));
  }

  const auto callback = [&](const DiffRecord& record) -> Status {
    if (keeper) {
      if (auto status = keeper->add(record); !status.ok())
        return status;
    }
    if (writer)
      return writer->write(record);
    std::cout << to_string(record.kind) << '\t' << record.category << '\t' << record.identity
              << '\t' << record.reason << '\n';
    return Status::success();
  };

  auto result = compare(before.path, before.id, after.path, after.id, callback);
  if (!result.ok())
    return fail(result.error());
  if (writer) {
    if (auto status = writer->finish(); !status.ok())
      return fail(status.error());
  }
  std::cerr << result.value() << " changes\n";
  return result.value() == 0 ? kExitSuccess : kExitFindings;
}

int command_registry_baseline(const ParsedArguments& parsed, const CancellationToken& cancel) {
#ifndef _WIN32
  static_cast<void>(parsed);
  static_cast<void>(cancel);
  Error error;
  error.component = "Registry";
  error.operation = "baseline";
  error.message = "Registry baselines require the Windows build.";
  return fail(error, kExitUnavailable);
#else
  const auto output = option(parsed, "output");
  const auto roots = options(parsed, "root");
  if (!output || roots.empty()) {
    std::cerr << "registry baseline requires at least one --root and --output\n";
    return kExitUsage;
  }

  auto registry_view = parse_registry_view(option(parsed, "view").value_or("both"));
  if (!registry_view.ok())
    return fail(registry_view.error(), kExitUsage);

  RegistryScanOptions scan_options;
  scan_options.include_security = flag(parsed, "security");
  if (auto value = option(parsed, "batch-size")) {
    auto parsed_value = parse_integer<std::size_t>(*value, "batch-size");
    if (!parsed_value.ok())
      return fail(parsed_value.error(), kExitUsage);
    scan_options.batch_size = parsed_value.value();
  }
  for (const auto& root : roots) {
    auto scope = parse_registry_scope(root, registry_view.value());
    if (!scope.ok())
      return fail(scope.error(), kExitUsage);
    scan_options.scopes.push_back(std::move(scope.value()));
  }

  auto store = SnapshotStore::create(argument_path(*output));
  if (!store.ok())
    return fail(store.error());
  std::ostringstream options_json;
  options_json << "{\"view\":\"" << to_string(registry_view.value())
               << "\",\"security\":" << (scan_options.include_security ? "true" : "false")
               << ",\"roots\":[";
  for (std::size_t index = 0; index < roots.size(); ++index) {
    if (index != 0)
      options_json << ',';
    options_json << '"' << json_escape(roots[index]) << '"';
  }
  options_json << "]}";

  auto metadata =
      make_snapshot_metadata(SnapshotKind::registry, "Registry baseline", options_json.str());
  if (auto status = store.value().begin_snapshot(metadata); !status.ok()) {
    return fail(status.error());
  }
  if (auto status = write_registry_configuration(store.value(), metadata.id, scan_options.scopes);
      !status.ok()) {
    return fail(status.error());
  }

  auto result = scan_registry(store.value(), metadata.id, scan_options, cancel, progress_text);
  finish_progress_line();
  if (!result.ok()) {
    store.value().finish_snapshot(metadata.id, SnapshotState::failed, 0, 1);
    return fail(result.error());
  }
  const SnapshotState state =
      result.value().cancelled ? SnapshotState::cancelled : SnapshotState::complete;
  if (auto status = store.value().finish_snapshot(
          metadata.id, state, result.value().objects, result.value().errors);
      !status.ok()) {
    return fail(status.error());
  }
  std::cout << metadata.id << '\n';
  return state == SnapshotState::complete ? kExitSuccess : kExitCancelled;
#endif
}

int command_registry_compare(const ParsedArguments& parsed, const CancellationToken& cancel) {
#ifndef _WIN32
  static_cast<void>(parsed);
  static_cast<void>(cancel);
  Error error;
  error.component = "Registry";
  error.operation = "compare";
  error.message = "Registry comparison requires the Windows build.";
  return fail(error, kExitUnavailable);
#else
  auto before = resolve_baseline_reference(parsed);
  if (!before.ok())
    return fail(before.error(), kExitUsage);

  const auto compare = [&cancel](const auto& before_path,
                                 std::string_view before_id,
                                 const auto& after_path,
                                 std::string_view after_id,
                                 const auto& callback) {
    return compare_registry(before_path, before_id, after_path, after_id, callback, cancel);
  };
  const auto run = [&](const SnapshotReference& after_reference, bool live) -> int {
    std::optional<ComparisonKeeper> keeper;
    if (flag(parsed, "keep")) {
      keeper.emplace(before.value(), "registry", live, after_reference);
      if (auto status = keeper->begin(); !status.ok())
        return fail(status.error());
    }
    const int compared =
        emit_comparison(parsed, before.value(), after_reference, compare, keeper ? &*keeper : nullptr);
    if (!keeper || (compared != kExitSuccess && compared != kExitFindings))
      return compared;
    const int kept = keep_comparison(*keeper);
    return kept != kExitSuccess ? kept : compared;
  };

  if (flag(parsed, "live")) {
    auto live = capture_live_registry(before.value(), cancel);
    if (!live.ok())
      return fail(live.error(), cancel.is_cancelled() ? kExitCancelled : kExitFailure);
    RetainedTemporaryCleanup cleanup(live.value().path);
    return run(live.value(), true);
  }

  auto after = resolve_snapshot_reference(parsed, "other", "other-id");
  if (!after.ok()) {
    std::cerr << "registry compare requires --other or --live\n";
    return fail(after.error(), kExitUsage);
  }
  return run(after.value(), false);
#endif
}

int command_files_baseline(const ParsedArguments& parsed, const CancellationToken& cancel) {
  const auto root = option(parsed, "path");
  const auto output = option(parsed, "output");
  if (!root || !output) {
    std::cerr << "files baseline requires --path and --output\n";
    return kExitUsage;
  }

  FilesystemScanOptions scan_options;
  scan_options.root = argument_path(*root);
  scan_options.exclusions = options(parsed, "exclude");
  scan_options.follow_reparse_points = flag(parsed, "follow-reparse");
#ifdef _WIN32
  // Without it, as administrator on NTFS, the folder is read from the master file table.
  scan_options.try_mft = !flag(parsed, "folder-by-folder");
  scan_options.capture_streams = flag(parsed, "streams");
  scan_options.capture_file_identity = !flag(parsed, "no-file-id");
  scan_options.hydrate_cloud_files = flag(parsed, "hydrate-cloud-files");
#else
  if (flag(parsed, "streams") || flag(parsed, "hydrate-cloud-files") || flag(parsed, "no-file-id")) {
    std::cerr << "--streams, --hydrate-cloud-files and --no-file-id are Windows-only filesystem options\n";
    return kExitUsage;
  }
  scan_options.capture_streams = false;
  scan_options.capture_file_identity = false;
  scan_options.hydrate_cloud_files = false;
#endif
  scan_options.hash_extensions = options(parsed, "hash-extension");

  auto hash_mode = parse_hash_mode(option(parsed, "hash").value_or("none"));
  if (!hash_mode.ok())
    return fail(hash_mode.error(), kExitUsage);
  scan_options.hash_mode = hash_mode.value();

  const auto parse_size_option = [&](std::string_view name, auto& target) -> Status {
    if (const auto value = option(parsed, name)) {
      using Target = std::remove_reference_t<decltype(target)>;
      auto parsed_value = parse_integer<Target>(*value, name);
      if (!parsed_value.ok())
        return Status::failure(parsed_value.error());
      target = parsed_value.value();
    }
    return Status::success();
  };
  if (auto status = parse_size_option("hash-max-bytes", scan_options.hash_size_limit);
      !status.ok()) {
    return fail(status.error(), kExitUsage);
  }
  if (auto status = parse_size_option("maximum-depth", scan_options.maximum_depth); !status.ok()) {
    return fail(status.error(), kExitUsage);
  }
  if (auto status = parse_size_option("maximum-objects", scan_options.maximum_objects);
      !status.ok()) {
    return fail(status.error(), kExitUsage);
  }
  if (auto status = parse_size_option("batch-size", scan_options.batch_size); !status.ok()) {
    return fail(status.error(), kExitUsage);
  }

  std::ostringstream options_json;
  options_json << "{\"path\":\"" << json_escape(*root) << "\",\"hash\":\""
               << to_string(scan_options.hash_mode) << "\",\"follow_reparse\":"
               << (scan_options.follow_reparse_points ? "true" : "false") << '}';

  // The create/begin/configure/scan/finish sequence lives in the core so the CLI, the Windows GUI
  // and the Qt GUI cannot drift apart on what a baseline file contains.
  auto result = capture_filesystem_baseline(argument_path(*output), scan_options, cancel, progress_text,
                                            options_json.str());
  finish_progress_line();
  if (!result.ok())
    return fail(result.error());
  std::cout << result.value().snapshot_id << '\n';
  return result.value().state == SnapshotState::complete ? kExitSuccess : kExitCancelled;
}

// The SHA-256 of each file, read in place and laid out the way certutil -hashfile prints it, so a
// value can be checked against a published checksum by eye as well as with --expect.
int command_files_hash(const ParsedArguments& parsed, const CancellationToken& cancel) {
  const std::vector<std::string> paths = options(parsed, "path");
  const std::vector<std::string> lists = options(parsed, "check");
  if (paths.empty() && lists.empty()) {
    std::cerr << "files hash requires --path FILE or --check SHA256SUMS\n";
    return kExitUsage;
  }
  std::string expected;
  if (const auto text = option(parsed, "expect")) {
    expected = normalize_sha256_text(*text);
    if (expected.empty()) {
      std::cerr << "--expect is not a SHA-256 value: " << *text << '\n';
      return kExitUsage;
    }
  }
  const bool json = flag(parsed, "json");

  bool unreadable = false;
  bool mismatch = false;
  std::ostringstream records;
  for (std::size_t index = 0; index < paths.size(); ++index) {
    if (cancel.is_cancelled())
      return kExitCancelled;
    const std::filesystem::path path = argument_path(paths[index]);
    const std::string name = path_to_utf8(path.filename());
    std::error_code status_error;
    const auto status = std::filesystem::status(path, status_error);
    std::string failure;
    std::string sha256;
    std::uint64_t size = 0;
    if (std::filesystem::is_directory(status)) {
      failure = "This is a folder. files hash reads files.";
    } else if (status.type() == std::filesystem::file_type::not_found ||
               status.type() == std::filesystem::file_type::none) {
      failure = "No file was found at this path.";
    } else if (!std::filesystem::is_regular_file(status)) {
      failure = "This is not a regular file.";
    } else {
      std::error_code size_error;
      const auto measured = std::filesystem::file_size(path, size_error);
      if (!size_error)
        size = static_cast<std::uint64_t>(measured);
      auto hashed = hash_file_sha256(path, cancel);
      if (!hashed.ok()) {
        if (cancel.is_cancelled())
          return kExitCancelled;
        failure = describe_error(hashed.error());
      } else {
        sha256 = hashed.value();
      }
    }
    unreadable = unreadable || !failure.empty();
    const bool matches = !expected.empty() && !sha256.empty() && sha256 == expected;
    mismatch = mismatch || (!expected.empty() && !sha256.empty() && !matches);

    if (json) {
      records << (index == 0 ? "" : ",") << "{\"name\":\"" << json_escape(name)
              << "\",\"path\":\"" << json_escape(path_to_utf8(path)) << "\",\"size_bytes\":" << size
              << ",\"sha256\":\"" << sha256 << "\",\"error\":\"" << json_escape(failure) << "\"";
      if (!expected.empty() && !sha256.empty())
        records << ",\"matches_expected\":" << (matches ? "true" : "false");
      records << '}';
      continue;
    }
    std::cout << (index == 0 ? "" : "\n") << "========================================\n"
              << name << '\n'
              << "========================================\n";
    if (!failure.empty()) {
      std::cout << "Error   " << failure << '\n';
      continue;
    }
    std::cout << "SHA256  " << sha256 << '\n'
              << "Size    " << format_health_bytes(size) << " (" << size << " bytes)\n"
              << "Path    " << path_to_utf8(path) << '\n';
    if (!expected.empty())
      std::cout << "Match   " << (matches ? "yes" : "NO") << ", expected " << expected << '\n';
  }
  // --check: every file a SHA256SUMS list names, looked for beside the list, as sha256sum -c does.
  std::ostringstream checks;
  for (std::size_t list_index = 0; list_index < lists.size(); ++list_index) {
    if (cancel.is_cancelled())
      return kExitCancelled;
    const std::filesystem::path list_path = argument_path(lists[list_index]);
    const std::string list_name = path_to_utf8(list_path.filename());
    std::string failure;
    std::vector<Sha256SumsEntry> entries;
    {
      std::ifstream input(list_path, std::ios::binary);
      if (!input) {
        failure = "The list could not be opened.";
      } else {
        std::string content;
        content.resize(4U * 1024U * 1024U);
        input.read(content.data(), static_cast<std::streamsize>(content.size()));
        content.resize(static_cast<std::size_t>(input.gcount()));
        entries = sha256_sums_from_file_text(content, list_name);
        if (entries.empty())
          failure = "This is not a SHA256SUMS list.";
      }
    }
    if (!json) {
      std::cout << ((paths.empty() && list_index == 0) ? "" : "\n")
                << "========================================\n"
                << list_name << '\n'
                << "========================================\n";
    }
    if (!failure.empty()) {
      unreadable = true;
      if (json) {
        checks << (list_index == 0 ? "" : ",") << "{\"list\":\"" << json_escape(path_to_utf8(list_path))
               << "\",\"error\":\"" << json_escape(failure) << "\",\"entries\":[]}";
      } else {
        std::cout << "Error    " << failure << '\n';
      }
      continue;
    }
    std::size_t passed = 0;
    std::size_t failed = 0;
    std::size_t missing = 0;
    std::size_t not_read = 0;
    std::ostringstream rows;
    for (std::size_t index = 0; index < entries.size(); ++index) {
      if (cancel.is_cancelled())
        return kExitCancelled;
      const auto& entry = entries[index];
      // Only files in the list's folder or below it are read; a name that leads anywhere else is
      // reported and left alone.
      const std::filesystem::path file = sha256_sums_entry_path(list_path.parent_path(), entry.name);
      std::error_code status_error;
      const auto status = file.empty() ? std::filesystem::file_status{}
                                       : std::filesystem::status(file, status_error);
      std::string state;
      std::string sha256;
      std::string error;
      if (file.empty()) {
        state = "NOT READ";
        error = "The name points outside the list's folder.";
        ++not_read;
        unreadable = true;
      } else if (status.type() == std::filesystem::file_type::not_found ||
                 status.type() == std::filesystem::file_type::none) {
        state = "MISSING";
        ++missing;
      } else if (!std::filesystem::is_regular_file(status)) {
        state = "NOT READ";
        error = "This is not a regular file.";
        ++not_read;
        unreadable = true;
      } else {
        auto hashed = hash_file_sha256(file, cancel);
        if (!hashed.ok()) {
          if (cancel.is_cancelled())
            return kExitCancelled;
          state = "NOT READ";
          error = describe_error(hashed.error());
          ++not_read;
          unreadable = true;
        } else {
          sha256 = hashed.value();
          state = sha256 == entry.sha256 ? "OK" : "FAILED";
          ++(sha256 == entry.sha256 ? passed : failed);
        }
      }
      if (json) {
        rows << (index == 0 ? "" : ",") << "{\"name\":\"" << json_escape(entry.name)
             << "\",\"path\":\"" << json_escape(path_to_utf8(file)) << "\",\"expected\":\""
             << entry.sha256 << "\",\"sha256\":\"" << sha256 << "\",\"status\":\"" << state
             << "\",\"error\":\"" << json_escape(error) << "\"}";
        continue;
      }
      std::string label = state;
      label.resize(9U, ' ');
      std::cout << label << entry.name << '\n';
      if (state == "FAILED")
        std::cout << "         expected " << entry.sha256 << "\n         found    " << sha256 << '\n';
      else if (!error.empty())
        std::cout << "         " << error << '\n';
    }
    mismatch = mismatch || failed != 0U || missing != 0U;
    if (json) {
      checks << (list_index == 0 ? "" : ",") << "{\"list\":\"" << json_escape(path_to_utf8(list_path))
             << "\",\"error\":\"\",\"entries\":[" << rows.str() << "]}";
    } else {
      std::cout << entries.size() << " listed: " << passed << " OK, " << failed << " FAILED, "
                << missing << " MISSING, " << not_read << " NOT READ\n";
    }
  }

  if (json) {
    std::cout << "{\"expected\":\"" << expected << "\",\"files\":[" << records.str()
              << "],\"checks\":[" << checks.str() << "]}\n";
  }
  if (unreadable)
    return kExitFailure;
  return mismatch ? kExitFindings : kExitSuccess;
}

// What the NTFS change journal recorded under the baseline's folder between the baseline and the
// other capture, or now: files created and deleted in between, and renames. Printed after the
// compare's own rows; answers how many rows it printed, or -1 when cancelled.
long long print_journal_findings(const SnapshotReference& before, const SnapshotReference& after, bool live,
                                 const CancellationToken& cancel, ComparisonKeeper* keeper = nullptr) {
  if (!kChangeJournalSystem)
    return 0;
  const auto mark_of = [](const SnapshotReference& reference) -> std::optional<ChangeJournalMark> {
    auto store = SnapshotStore::open(reference.path, true);
    if (!store.ok())
      return std::nullopt;
    auto mark = store.value().change_journal_mark(reference.id);
    return mark.ok() ? mark.value() : std::nullopt;
  };
  const std::optional<ChangeJournalMark> start = mark_of(before);
  if (!start) {
    std::cerr << "Change journal: no position was recorded for the baseline (one is recorded when it is captured "
                 "as administrator on NTFS), so files created and removed in between are not listed.\n";
    return 0;
  }
  std::string baseline_id;
  auto scan = load_filesystem_baseline_options(before.path, baseline_id);
  if (!scan.ok())
    return 0;
  ChangeJournalWindow window;
  window.folder = scan.value().root;
  window.start = *start;
  if (!live) {
    const std::optional<ChangeJournalMark> end = mark_of(after);
    if (!end) {
      std::cerr << "Change journal: no position was recorded for the other capture, so files created and removed "
                   "between the two are not listed.\n";
      return 0;
    }
    if (end->journal_id != start->journal_id || !journal_path_equal(end->volume, start->volume)) {
      std::cerr << "Change journal: the two captures were not taken from the same journal.\n";
      return 0;
    }
    if (end->next_usn <= start->next_usn)
      return 0;
    window.end_usn = end->next_usn;
  }
  auto readout = read_change_journal(window, cancel);
  if (!readout.ok()) {
    std::cerr << "Change journal: " << readout.error().message << '\n';
    return 0;
  }
  if (readout.value().cancelled)
    return -1;
  // The live compare's own temporary capture is left out.
  const std::string own = live ? path_to_utf8(after.path.filename()) : std::string();
  long long printed = 0;
  for (const JournalChange& change : readout.value().changes) {
    if (!own.empty() && change.path.size() >= own.size() &&
        journal_path_equal(std::string_view(change.path).substr(change.path.size() - own.size()), own))
      continue;
    if (change.created_and_deleted()) {
      std::cout << "created-and-deleted\tjournal\t" << change.path << "\tcreated "
                << journal_time_text(change.created_time) << ", deleted " << journal_time_text(change.deleted_time)
                << '\n';
      ++printed;
      if (keeper) {
        std::string detail = std::string(change.directory ? "Folder created " : "Created ") +
                             journal_time_text(change.created_time) + ", deleted " +
                             journal_time_text(change.deleted_time);
        if (change.renamed() && !change.renamed_from.empty())
          detail += ", renamed from " + change.renamed_from;
        keeper->add_journal_row({"Created and deleted", change.path, "Recorded by the NTFS change journal", detail});
      }
    } else if (change.renamed()) {
      const std::string from = change.renamed_from.empty() ? std::string("outside the folder") : change.renamed_from;
      std::cout << "renamed\tjournal\t" << change.renamed_to << '\t' << from << " -> " << change.renamed_to
                << ", renamed " << journal_time_text(change.renamed_time) << '\n';
      ++printed;
      if (keeper) {
        keeper->add_journal_row({"Renamed", change.renamed_to, "Recorded by the NTFS change journal",
                                 from + " -> " + change.renamed_to + ", renamed " +
                                     journal_time_text(change.renamed_time)});
      }
    }
  }
  std::cerr << "Change journal: " << readout.value().records_inside << " records under the folder, " << printed
            << " created and deleted or renamed";
  if (readout.value().unplaced > 0)
    std::cerr << ", " << readout.value().unplaced << " records on the volume not matched to a folder";
  if (readout.value().cut_short)
    std::cerr << "; the read stopped at " << readout.value().cut_short_reason;
  std::cerr << '\n';
  return printed;
}

int command_files_compare(const ParsedArguments& parsed, const CancellationToken& cancel) {
  auto before = resolve_baseline_reference(parsed);
  if (!before.ok())
    return fail(before.error(), kExitUsage);

  FilesystemCompareOptions compare_options;
  if (const auto value = option(parsed, "timestamp-tolerance-100ns")) {
    auto parsed_value = parse_integer<std::int64_t>(*value, "timestamp-tolerance-100ns");
    if (!parsed_value.ok())
      return fail(parsed_value.error(), kExitUsage);
    compare_options.timestamp_tolerance_100ns = parsed_value.value();
  }
  compare_options.detect_moves = !flag(parsed, "no-move-detection");
  compare_options.infer_moves_by_hash = !flag(parsed, "no-hash-inference");

  const auto compare = [&](const auto& before_path,
                           std::string_view before_id,
                           const auto& after_path,
                           std::string_view after_id,
                           const auto& callback) {
    return compare_filesystem(
        before_path, before_id, after_path, after_id, compare_options, callback, cancel);
  };

  const auto run = [&](const SnapshotReference& after_reference, bool live) -> int {
    std::optional<ComparisonKeeper> keeper;
    ComparisonKeeper* keep = nullptr;
    if (flag(parsed, "keep")) {
      keeper.emplace(before.value(), "filesystem", live, after_reference);
      if (auto status = keeper->begin(); !status.ok())
        return fail(status.error());
      keep = &*keeper;
    }
    const int compared = emit_comparison(parsed, before.value(), after_reference, compare, keep);
    if (compared != kExitSuccess && compared != kExitFindings)
      return compared;
    long long journal = 0;
    if (!flag(parsed, "no-journal")) {
      journal = print_journal_findings(before.value(), after_reference, live, cancel, keep);
      if (journal < 0)
        return kExitCancelled;
    }
    if (keeper) {
      if (const int kept = keep_comparison(*keeper); kept != kExitSuccess)
        return kept;
    }
    return journal > 0 ? kExitFindings : compared;
  };

  if (flag(parsed, "live")) {
    auto live = capture_live_filesystem(before.value(), cancel);
    if (!live.ok())
      return fail(live.error(), cancel.is_cancelled() ? kExitCancelled : kExitFailure);
    RetainedTemporaryCleanup cleanup(live.value().path);
    return run(live.value(), true);
  }

  auto after = resolve_snapshot_reference(parsed, "other", "other-id");
  if (!after.ok()) {
    std::cerr << "files compare requires --other or --live\n";
    return fail(after.error(), kExitUsage);
  }
  return run(after.value(), false);
}

Status configure_log_time_range(const ParsedArguments& parsed,
                                DateOrder date_order,
                                int assumed_offset_minutes,
                                std::optional<std::int64_t>& from,
                                std::optional<std::int64_t>& to) {
  if (const auto value = option(parsed, "from")) {
    const auto parsed_time = parse_timestamp(*value, date_order, assumed_offset_minutes);
    if (!parsed_time) {
      Error error;
      error.component = "CLI";
      error.operation = "parse --from";
      error.message = "Unable to parse timestamp: " + *value;
      return Status::failure(std::move(error));
    }
    if (parsed_time->ambiguous && date_order == DateOrder::automatic) {
      Error error;
      error.component = "CLI";
      error.operation = "parse --from";
      error.message = "Ambiguous date. Supply --date-order mdy or dmy.";
      return Status::failure(std::move(error));
    }
    from = parsed_time->unix_millis;
  }
  if (const auto value = option(parsed, "to")) {
    const auto parsed_time = parse_timestamp(*value, date_order, assumed_offset_minutes);
    if (!parsed_time) {
      Error error;
      error.component = "CLI";
      error.operation = "parse --to";
      error.message = "Unable to parse timestamp: " + *value;
      return Status::failure(std::move(error));
    }
    if (parsed_time->ambiguous && date_order == DateOrder::automatic) {
      Error error;
      error.component = "CLI";
      error.operation = "parse --to";
      error.message = "Ambiguous date. Supply --date-order mdy or dmy.";
      return Status::failure(std::move(error));
    }
    to = parsed_time->unix_millis;
  }
  return Status::success();
}

int emit_log_matches(const ParsedArguments& parsed, const std::vector<LogMatch>& matches) {
  if (const auto output = option(parsed, "output")) {
    auto format = parse_export_format(option(parsed, "format").value_or("text"));
    if (!format.ok())
      return fail(format.error(), kExitUsage);
    if (auto status = export_log_matches(argument_path(*output), format.value(), matches);
        !status.ok()) {
      return fail(status.error());
    }
  } else {
    for (const auto& match : matches) {
      std::cout << match.source_path << ':' << match.line_number << " [" << match.severity << "] "
                << match.matching_line << '\n';
    }
  }
  return matches.empty() ? kExitSuccess : kExitFindings;
}

int command_logs_search(const ParsedArguments& parsed, const CancellationToken& cancel) {
  LogSearchOptions search_options;
  for (const auto& value : options(parsed, "path"))
    search_options.sources.emplace_back(argument_path(value));
  if (search_options.sources.empty() && flag(parsed, "discover-veeam")) {
    search_options.sources = discover_veeam_sources();
  }
  if (search_options.sources.empty()) {
    std::cerr << "logs search requires --path or --discover-veeam\n";
    return kExitUsage;
  }

  search_options.query = option(parsed, "text").value_or("");
  search_options.case_sensitive = flag(parsed, "case-sensitive");
  search_options.search_archives = !flag(parsed, "no-archives");
  search_options.filename_patterns = options(parsed, "pattern");
  search_options.severities = options(parsed, "severity");
  if (const auto regex = option(parsed, "regex")) {
    search_options.query = *regex;
    search_options.mode = SearchMode::regular_expression;
  }
  if (const auto value = option(parsed, "context")) {
    auto parsed_value = parse_integer<std::size_t>(*value, "context");
    if (!parsed_value.ok())
      return fail(parsed_value.error(), kExitUsage);
    search_options.context_before = parsed_value.value();
    search_options.context_after = parsed_value.value();
  }
  if (const auto value = option(parsed, "max-results")) {
    auto parsed_value = parse_integer<std::size_t>(*value, "max-results");
    if (!parsed_value.ok())
      return fail(parsed_value.error(), kExitUsage);
    search_options.maximum_results = parsed_value.value();
  }
  search_options.date_order = parse_date_order(option(parsed, "date-order").value_or("auto"));
  if (const auto value = option(parsed, "assumed-offset-minutes")) {
    auto parsed_value = parse_integer<int>(*value, "assumed-offset-minutes");
    if (!parsed_value.ok())
      return fail(parsed_value.error(), kExitUsage);
    search_options.assumed_timezone_offset_minutes = parsed_value.value();
  }
  if (auto status = configure_log_time_range(parsed,
                                             search_options.date_order,
                                             search_options.assumed_timezone_offset_minutes,
                                             search_options.from_utc_ms,
                                             search_options.to_utc_ms);
      !status.ok()) {
    return fail(status.error(), kExitUsage);
  }

  std::vector<LogMatch> matches;
  auto result = search_logs(search_options, cancel, progress_text, [&](const LogMatch& match) {
    matches.push_back(match);
    return Status::success();
  });
  finish_progress_line();
  if (!result.ok())
    return fail(result.error());
  return emit_log_matches(parsed, matches);
}

int command_logs_review(const ParsedArguments& parsed, const CancellationToken& cancel) {
  VeeamLogReviewOptions review_options;
  std::optional<CaseWorkspace> case_workspace;
  if (const auto case_root = option(parsed, "case")) {
    auto opened = open_case_workspace(argument_path(*case_root));
    if (!opened.ok())
      return fail(opened.error());
    case_workspace = opened.value();
    review_options.output_path = case_workspace->parsed / "reports";
    review_options.parser_cache_directory = case_workspace->parser_cache;
  }
  for (const auto& value : options(parsed, "path"))
    review_options.sources.emplace_back(argument_path(value));
  if (review_options.sources.empty() && flag(parsed, "discover-veeam"))
    review_options.sources = discover_veeam_sources();
  if (review_options.sources.empty()) {
    std::cerr << "logs review requires --path or --discover-veeam\n";
    return kExitUsage;
  }
  if (const auto output = option(parsed, "output"))
    review_options.output_path = argument_path(*output);
  if (const auto profile = option(parsed, "profile")) {
    auto parsed_profile = parse_veeam_review_profile(*profile);
    if (!parsed_profile.ok())
      return fail(parsed_profile.error(), kExitUsage);
    review_options.profile = parsed_profile.value();
  }
  review_options.fast_index_first = !flag(parsed, "full-scan");
  review_options.one_source_one_primary_machine = !flag(parsed, "multi-machine-source");
  review_options.use_persistent_parser_cache = !flag(parsed, "no-cache");
  if (const auto cache = option(parsed, "cache-dir"))
    review_options.parser_cache_directory = argument_path(*cache);
  review_options.include_warnings = !flag(parsed, "no-warnings");
  review_options.search_archives = !flag(parsed, "no-archives");
  review_options.date_order = parse_date_order(option(parsed, "date-order").value_or("auto"));
  if (const auto value = option(parsed, "assumed-offset-minutes")) {
    auto parsed_value = parse_integer<int>(*value, "assumed-offset-minutes");
    if (!parsed_value.ok())
      return fail(parsed_value.error(), kExitUsage);
    review_options.assumed_timezone_offset_minutes = parsed_value.value();
  }
  if (auto status = configure_log_time_range(parsed,
                                             review_options.date_order,
                                             review_options.assumed_timezone_offset_minutes,
                                             review_options.from_utc_ms,
                                             review_options.to_utc_ms);
      !status.ok()) {
    return fail(status.error(), kExitUsage);
  }
  if (const auto value = option(parsed, "context")) {
    auto parsed_value = parse_integer<std::size_t>(*value, "context");
    if (!parsed_value.ok())
      return fail(parsed_value.error(), kExitUsage);
    review_options.context_before = parsed_value.value();
    review_options.context_after = parsed_value.value();
  }
  if (const auto value = option(parsed, "max-incidents")) {
    auto parsed_value = parse_integer<std::size_t>(*value, "max-incidents");
    if (!parsed_value.ok())
      return fail(parsed_value.error(), kExitUsage);
    review_options.maximum_incidents = parsed_value.value();
  }
  if (flag(parsed, "single-thread")) {
    review_options.worker_count = 1;
  } else if (const auto value = option(parsed, "workers")) {
    auto parsed_value = parse_integer<std::size_t>(*value, "workers");
    if (!parsed_value.ok())
      return fail(parsed_value.error(), kExitUsage);
    if (parsed_value.value() == 0U) {
      std::cerr << "--workers must be at least 1; omit it to use automatic selection\n";
      return kExitUsage;
    }
    review_options.worker_count = parsed_value.value();
  }
  if (const auto query = option(parsed, "find")) {
    review_options.include_informational_query_matches = true;
    review_options.informational_query = *query;
    review_options.case_sensitive_query = flag(parsed, "case-sensitive");
  }

  auto review = review_veeam_logs(review_options, cancel, progress_text);
  finish_progress_line();
  if (!review.ok())
    return fail(review.error());

  const auto& result = review.value();
  if (case_workspace) {
    const auto saved = save_case_review_model(*case_workspace, result);
    if (!saved.ok())
      return fail(saved.error());
    CaseReviewState state;
    state.profile = to_string(review_options.profile);
    for (const auto& source : result.input_sources)
      state.sources.push_back(path_to_utf8(source));
    for (const auto& bundle : result.bundles) {
      CaseReviewSource source;
      source.path = bundle.source_path;
      source.requested_profile = to_string(review_options.profile);
      source.detected_profile = bundle.manifest_profile.empty()
                                    ? to_string(result.profile_used)
                                    : bundle.manifest_profile;
      source.product_type = bundle.product_type;
      source.product_version = bundle.product_version;
      source.source_owner = bundle.primary_machine_name;
      state.source_profiles.push_back(std::move(source));
    }
    state.fast_index = result.fast_index_used;
    state.updated_utc = utc_now_iso8601();
    const auto state_saved = save_case_review_state(*case_workspace, std::move(state));
    if (!state_saved.ok())
      return fail(state_saved.error());
  }
  std::size_t grouped_errors = 0;
  std::size_t grouped_warnings = 0;
  std::size_t backup_runs = 0;
  std::size_t related_activities = 0;
  std::size_t rescans = 0;
  for (const auto& incident : result.incidents) {
    if (incident.severity == "error")
      ++grouped_errors;
    else if (incident.severity == "warning")
      ++grouped_warnings;
  }
  for (const auto& run : result.job_sessions) {
    if (run.protection_group_rescan || run.run_kind == "rescan" ||
        run.run_kind == "rescan-index")
      ++rescans;
    else if (run.run_kind == "activity")
      ++related_activities;
    else
      ++backup_runs;
  }
  if (flag(parsed, "json")) {
    std::cout << "{"
              << "\"profile\":\"" << json_escape(to_string(result.profile_used)) << "\","
              << "\"product\":\"" << json_escape(result.product_type) << "\","
              << "\"confidence\":\"" << json_escape(to_string(result.product_confidence)) << "\","
              << "\"fast_index\":" << (result.fast_index_used ? "true" : "false") << ","
              << "\"files_discovered\":" << result.files_discovered << ","
              << "\"files_scanned\":" << result.files_scanned << ","
              << "\"files_deferred\":" << result.files_deferred << ","
              << "\"lines_scanned\":" << result.lines_scanned << ","
              << "\"parse_errors\":" << result.parse_errors << ","
              << "\"cache_hits\":" << result.parser_cache_hits << ","
              << "\"machine_count\":" << result.machines.size() << ","
              << "\"structured_session_count\":" << result.job_sessions.size() << ","
              << "\"job_run_count\":" << result.job_sessions.size() << ","
              << "\"backup_run_count\":" << backup_runs << ","
              << "\"related_activity_count\":" << related_activities << ","
              << "\"rescan_count\":" << rescans << ","
              << "\"incident_count\":" << result.incidents.size() << ","
              << "\"grouped_errors\":" << grouped_errors << ","
              << "\"grouped_warnings\":" << grouped_warnings << ","
              << "\"input_bytes\":" << result.input_bytes << ","
              << "\"elapsed_seconds\":" << std::fixed << std::setprecision(6)
              << result.elapsed_seconds << ","
              << "\"discovery_seconds\":" << result.discovery_seconds << ","
              << "\"archive_seconds\":" << result.archive_seconds << ","
              << "\"parse_seconds\":" << result.parse_seconds << ","
              << "\"merge_seconds\":" << result.merge_seconds << ","
              << "\"correlation_seconds\":" << result.correlation_seconds << ","
              << "\"finalization_seconds\":" << result.finalization_seconds << ","
              << "\"serialization_seconds\":" << result.serialization_seconds << ","
              << "\"report_detailed_incidents\":" << result.report_detailed_incidents << ","
              << "\"report_incidents_truncated\":"
              << (result.report_incidents_truncated ? "true" : "false") << ","
              << "\"lines_per_second\":" << std::fixed << std::setprecision(1)
              << result.lines_per_second << ","
              << "\"roles\":[";
    for (std::size_t index = 0; index < result.evidence_roles.size(); ++index) {
      if (index != 0U)
        std::cout << ',';
      const auto& role = result.evidence_roles[index];
      std::cout << "{\"role\":\"" << json_escape(to_string(role.role)) << "\","
                << "\"candidate_files\":" << role.candidate_files << ","
                << "\"scanned_files\":" << role.scanned_files << ","
                << "\"deferred_files\":" << role.deferred_files << ","
                << "\"bytes\":" << role.total_bytes << "}";
    }
    std::cout << "],\"machines\":[";
    for (std::size_t index = 0; index < result.machines.size(); ++index) {
      if (index != 0U)
        std::cout << ',';
      const auto& machine = result.machines[index];
      std::cout << "{\"key\":\"" << json_escape(machine.key) << "\","
                << "\"name\":\"" << json_escape(machine.display_name) << "\","
                << "\"role\":\"" << json_escape(machine.role) << "\","
                << "\"source_files\":" << machine.source_paths.size() << "}";
    }
    std::cout << "]}" << '\n';
    return result.cancelled ? kExitCancelled : (result.incidents.empty() ? kExitSuccess : kExitFindings);
  }

  std::cout << "\nVEEAM LOG REVIEW SUMMARY\n"
            << "============================================================\n"
            << "Product Type Found: " << result.product_type << " ["
            << to_string(result.product_confidence) << "]\n"
            << "Machines Identified: " << result.machines.size() << '\n'
            << "Structured Sessions Identified: " << result.job_sessions.size() << '\n'
            << "  Backup Runs: " << backup_runs << '\n'
            << "  Related Activities: " << related_activities << '\n'
            << "  Infrastructure Rescans: " << rescans << '\n';
  for (const auto& machine : result.machines) {
    std::size_t machine_backups = 0;
    std::size_t machine_activities = 0;
    std::size_t machine_rescans = 0;
    for (const auto& run : result.job_sessions) {
      if (run.machine_key != machine.key)
        continue;
      if (run.protection_group_rescan || run.run_kind == "rescan" ||
          run.run_kind == "rescan-index")
        ++machine_rescans;
      else if (run.run_kind == "activity")
        ++machine_activities;
      else
        ++machine_backups;
    }
    std::cout << "  - "
              << (machine.display_name.empty() ? machine.key : machine.display_name);
    if (!machine.role.empty())
      std::cout << " (" << machine.role << ")";
    std::cout << ": " << machine_backups << " backup run(s), "
              << machine_activities << " related activity session(s), "
              << machine_rescans << " rescan(s), " << machine.source_paths.size()
              << " identified source file(s)\n";
  }
  const auto latest_backup = std::find_if(
      result.job_sessions.begin(), result.job_sessions.end(), [](const auto& run) {
        return !run.protection_group_rescan && run.run_kind != "activity" &&
               run.run_kind != "rescan" && run.run_kind != "rescan-index";
      });
  if (latest_backup != result.job_sessions.end()) {
    const auto& latest = *latest_backup;
    const auto timestamp = [](const std::optional<std::int64_t>& utc_millis,
                              std::string_view original) {
      return utc_millis ? iso8601_from_unix_millis(*utc_millis)
                        : (original.empty() ? std::string("Unknown time")
                                            : std::string(original));
    };
    std::cout << "\nLATEST BACKUP JOB\n"
              << "------------------------------------------------------------\n"
              << "Machine: " << (latest.machine_name.empty() ? "Not identified" : latest.machine_name) << '\n'
              << "Job Name: " << (latest.job_name.empty() ? "Not identified" : latest.job_name) << '\n'
              << "Job Type: "
              << (!latest.settings.backup_mode.empty()
                      ? latest.settings.backup_mode
                      : (latest.job_type.empty() ? "Not identified" : latest.job_type))
              << '\n'
              << "Result: " << (latest.status.empty() ? "Unknown" : latest.status) << '\n'
              << "Started: "
              << timestamp(latest.start_utc_ms, latest.start_timestamp_original) << '\n'
              << "Completed: "
              << timestamp(latest.completion_utc_ms, latest.completion_timestamp_original)
              << '\n'
              << "Target Backup Repository / Path: "
              << (latest.settings.destination_path.empty() ? "Not identified"
                                                           : latest.settings.destination_path)
              << '\n';
  }
  std::cout << "\nGrouped Errors: " << grouped_errors << '\n'
            << "Grouped Warnings: " << grouped_warnings << '\n'
            << "Files Reviewed: " << result.files_scanned << '\n'
            << "Lines Reviewed: " << result.lines_scanned << '\n'
            << "Workers Used: " << result.workers_used << '\n'
            << "Elapsed: " << std::fixed << std::setprecision(2)
            << result.elapsed_seconds << " seconds\n"
            << "Throughput: " << std::fixed << std::setprecision(0)
            << result.lines_per_second << " lines/second\n"
            << "Report: " << path_to_utf8(result.report_path) << '\n';
  return result.cancelled ? kExitCancelled : (result.incidents.empty() ? kExitSuccess : kExitFindings);
}

int command_event_log_search(const ParsedArguments& parsed, const CancellationToken& cancel) {
#ifndef _WIN32
  static_cast<void>(parsed);
  static_cast<void>(cancel);
  Error error;
  error.component = "WindowsEventLog";
  error.operation = "search";
  error.message = "Windows Event Log diagnostics require the Windows build.";
  return fail(error, kExitUnavailable);
#else
  WindowsEventLogSearchOptions search_options;
  search_options.channel = option(parsed, "channel").value_or("Veeam Agent");
  search_options.query = option(parsed, "text").value_or("");
  search_options.case_sensitive = flag(parsed, "case-sensitive");
  search_options.severities = options(parsed, "severity");
  for (const auto& value : options(parsed, "event-id")) {
    auto parsed_value = parse_integer<std::uint32_t>(value, "event-id");
    if (!parsed_value.ok())
      return fail(parsed_value.error(), kExitUsage);
    search_options.event_ids.push_back(parsed_value.value());
  }
  if (const auto value = option(parsed, "max-results")) {
    auto parsed_value = parse_integer<std::size_t>(*value, "max-results");
    if (!parsed_value.ok())
      return fail(parsed_value.error(), kExitUsage);
    search_options.maximum_results = parsed_value.value();
  }
  const DateOrder date_order = parse_date_order(option(parsed, "date-order").value_or("auto"));
  int assumed_offset = 0;
  if (const auto value = option(parsed, "assumed-offset-minutes")) {
    auto parsed_value = parse_integer<int>(*value, "assumed-offset-minutes");
    if (!parsed_value.ok())
      return fail(parsed_value.error(), kExitUsage);
    assumed_offset = parsed_value.value();
  }
  if (auto status = configure_log_time_range(
          parsed, date_order, assumed_offset, search_options.from_utc_ms, search_options.to_utc_ms);
      !status.ok()) {
    return fail(status.error(), kExitUsage);
  }

  std::vector<LogMatch> matches;
  auto result =
      search_windows_event_log(search_options, cancel, progress_text, [&](const LogMatch& match) {
        matches.push_back(match);
        return Status::success();
      });
  finish_progress_line();
  if (!result.ok())
    return fail(result.error());
  return emit_log_matches(parsed, matches);
#endif
}

#ifdef _WIN32
void print_vss_details(const VssSessionDetails& details) {
  std::cout << "Session: " << details.session_id << '\n'
            << "Snapshot set: " << details.snapshot_set_id << '\n'
            << "Consistency: " << details.consistency_label << '\n'
            << "Active: " << (details.active ? "yes" : "no") << '\n';
  for (const auto& writer : details.writers) {
    std::cout << "writer\t" << writer.writer_class_id << '\t' << writer.name << '\t'
              << writer.state_name << '\t' << writer.failure_hresult << '\n';
  }
  for (const auto& snapshot : details.snapshots) {
    std::cout << "snapshot\t" << snapshot.snapshot_id << '\t' << snapshot.original_volume << '\t'
              << snapshot.device_object << '\n';
  }
}
#endif

int command_vss(const ParsedArguments& parsed, const CancellationToken& cancel) {
#ifndef _WIN32
  static_cast<void>(parsed);
  static_cast<void>(cancel);
  Error error;
  error.component = "VSS";
  error.operation = "diagnostic";
  error.message = "VSS diagnostics require the Windows build.";
  return fail(error, kExitUnavailable);
#else
  if (parsed.positionals.size() < 2) {
    std::cerr << "vss requires writers or test\n";
    return kExitUsage;
  }
  if (parsed.positionals[1] == "writers") {
    auto result = enumerate_vss_writers();
    if (!result.ok())
      return fail(result.error());
    for (const auto& writer : result.value()) {
      std::cout << writer.writer_class_id << '\t' << writer.writer_instance_id << '\t'
                << writer.name << '\t' << writer.state_name << '\n';
    }
    return kExitSuccess;
  }
  if (parsed.positionals[1] != "test")
    return kExitUsage;

  VssTestOptions test_options;
  test_options.volumes = options(parsed, "volume");
  test_options.enabled_writer_class_ids = options(parsed, "writer");
  test_options.backup_type = option(parsed, "backup-type").value_or("copy") == "full"
                                 ? VssBackupType::full
                                 : VssBackupType::copy;
  test_options.component_mode = flag(parsed, "component-mode");
  test_options.select_all_components = flag(parsed, "select-all-components");
  test_options.backup_bootable_system_state = flag(parsed, "bootable-system-state");
  test_options.partial_file_support = flag(parsed, "partial-file-support");
  if (const auto value = option(parsed, "hold-seconds")) {
    auto parsed_value = parse_integer<std::uint32_t>(*value, "hold-seconds");
    if (!parsed_value.ok())
      return fail(parsed_value.error(), kExitUsage);
    test_options.hold_seconds = parsed_value.value();
  }
  if (test_options.volumes.empty()) {
    std::cerr << "vss test requires at least one --volume\n";
    return kExitUsage;
  }

  if (!flag(parsed, "direct")) {
    auto result = run_vss_test_elevated(test_options, cancel, progress_text);
    finish_progress_line();
    if (!result.ok())
      return fail(result.error());
    print_vss_details(result.value().details);
    if (!result.value().diagnostic_message.empty()) {
      std::cout << "Diagnostic: " << result.value().diagnostic_message << '\n';
    }
    return result.value().backup_succeeded ? kExitSuccess : kExitFailure;
  }

  auto result = create_vss_test_session(test_options, cancel, progress_text);
  finish_progress_line();
  if (!result.ok())
    return fail(result.error());
  auto& session = *result.value();
  print_vss_details(session.details());
  for (std::uint32_t second = 0; second < test_options.hold_seconds && !cancel.is_cancelled();
       ++second) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  auto released = session.release(!cancel.is_cancelled(), progress_text);
  if (!released.ok())
    return fail(released.error());
  return cancel.is_cancelled() ? kExitCancelled : kExitSuccess;
#endif
}

int command_snapshot_inspect(const ParsedArguments& parsed) {
  Result<SnapshotReference> reference =
      option(parsed, "file") ? resolve_snapshot_reference(parsed, "file", "baseline-id")
                             : resolve_baseline_reference(parsed);
  if (!reference.ok())
    return fail(reference.error(), kExitUsage);
  auto store = SnapshotStore::open(reference.value().path, true);
  if (!store.ok())
    return fail(store.error());
  auto metadata = store.value().metadata(reference.value().id);
  if (!metadata.ok())
    return fail(metadata.error());
  const auto& value = metadata.value();
  std::cout << "ID: " << value.id << '\n'
            << "Kind: " << to_string(value.kind) << '\n'
            << "State: " << to_string(value.state) << '\n'
            << "Started: " << value.created_start_utc << '\n'
            << "Completed: " << value.created_end_utc << '\n'
            << "Machine: " << value.machine_name << '\n'
            << "OS: " << value.os_name << ' ' << value.os_version << '\n'
            << "Architecture: " << value.architecture << '\n'
            << "Elevated: " << (value.elevated ? "yes" : "no") << '\n'
            << "Objects: " << value.object_count << '\n'
            << "Errors: " << value.error_count << '\n';
  // How a files capture read its folder, when the file records it.
  if (auto source = store.value().capture_source(reference.value().id); source.ok() && source.value()) {
    std::cout << "Read from: " << (source.value()->source == kCaptureSourceMft ? "NTFS master file table" : "folder by folder");
    if (!source.value()->detail.empty())
      std::cout << " (" << source.value()->detail << ')';
    std::cout << '\n';
  }
  // The compares kept in the file for this capture, newest first.
  auto kept = store.value().comparisons(reference.value().id);
  if (kept.ok()) {
    for (const StoredComparison& comparison : kept.value()) {
      std::cout << "Comparison: " << comparison.created_utc << " against " << comparison.against << ": "
                << (comparison.summary.empty() ? std::string("not finished.") : comparison_counts_text(comparison))
                << '\n';
    }
  }
  return kExitSuccess;
}

int command_snapshots_list(const ParsedArguments& parsed) {
  const std::filesystem::path folder = argument_path(option(parsed, "folder").value_or("."));
  std::error_code error_code;
  if (!std::filesystem::is_directory(folder, error_code)) {
    std::cerr << "Not a directory: " << path_to_utf8(folder) << '\n';
    return kExitUsage;
  }
  std::uint64_t listed = 0;
  for (const auto& entry : std::filesystem::directory_iterator(folder, error_code)) {
    if (error_code)
      break;
    if (!entry.is_regular_file(error_code) || entry.path().extension() != ".satsnap")
      continue;
    auto store = SnapshotStore::open(entry.path(), true);
    if (!store.ok()) {
      std::cerr << path_to_utf8(entry.path()) << "\tinvalid\t" << store.error().message << '\n';
      continue;
    }
    auto validation = store.value().validate();
    if (!validation.ok()) {
      std::cerr << path_to_utf8(entry.path()) << "\tinvalid\t" << validation.error().message << '\n';
      continue;
    }
    auto id = store.value().latest_complete_snapshot_id();
    if (!id.ok())
      continue;
    auto metadata = store.value().metadata(id.value());
    if (!metadata.ok())
      continue;
    std::cout << path_to_utf8(entry.path()) << '\t' << metadata.value().id << '\t'
              << to_string(metadata.value().kind) << '\t' << to_string(metadata.value().state)
              << '\t' << metadata.value().created_start_utc << '\t' << metadata.value().object_count
              << '\n';
    ++listed;
  }
  if (error_code) {
    std::cerr << "Unable to enumerate folder: " << error_code.message() << '\n';
    return kExitFailure;
  }
  std::cerr << listed << " baseline files\n";
  return kExitSuccess;
}

int command_case(const ParsedArguments& parsed) {
  if (parsed.positionals.size() < 2U || parsed.positionals[1] != "create") {
    std::cerr << "case requires: case create --parent DIR --id CASE-ID\n";
    return kExitUsage;
  }
  const auto parent = option(parsed, "parent");
  const auto case_id = option(parsed, "id");
  if (!parent || !case_id) {
    std::cerr << "case create requires --parent and --id\n";
    return kExitUsage;
  }
  CaseWorkspaceOptions workspace_options;
  workspace_options.parent_directory = argument_path(*parent);
  workspace_options.case_id = *case_id;
  workspace_options.title = option(parsed, "title").value_or("");
  workspace_options.engineer = option(parsed, "engineer").value_or("");
  workspace_options.notes = option(parsed, "notes").value_or("");
  auto workspace = create_case_workspace(workspace_options);
  if (!workspace.ok())
    return fail(workspace.error());
  std::cout << "Case workspace created: " << path_to_utf8(workspace.value().root) << '\n'
            << "Logs: " << path_to_utf8(workspace.value().logs) << '\n'
            << "Captures: " << path_to_utf8(workspace.value().captures) << '\n'
            << "Reports: " << path_to_utf8(workspace.value().reports) << '\n'
            << "Parsed: " << path_to_utf8(workspace.value().parsed) << '\n'
            << "Parser cache: " << path_to_utf8(workspace.value().parser_cache) << '\n'
            << "Baselines: " << path_to_utf8(workspace.value().baselines) << '\n';
  return kExitSuccess;
}

// ---- Quick checks: the command-line twins of the mini windows ---------------------------------

std::string joined(const std::vector<std::string>& values, std::string_view separator = ", ") {
  std::string text;
  for (const std::string& value : values) {
    if (!text.empty())
      text += separator;
    text += value;
  }
  return text;
}

std::string owner_text(const LocalPortState& state) {
  if (state.owners.empty())
    return state.found ? "(owner not readable)" : "";
  const LocalSocket& owner = state.owners.front();
  if (owner.pid == 0)
    return "(owner not readable by this account)";
  std::string text = owner.process_name.empty() ? "PID " + std::to_string(owner.pid)
                                                : owner.process_name + " (PID " + std::to_string(owner.pid) + ")";
  if (!owner.services.empty())
    text += " services: " + owner.services;
  return text;
}

void print_port_check(const PortCheckResult& result) {
  for (const PortCheckRow& row : result.rows) {
    std::cout << port_label(row) << '/' << to_string(row.state.protocol) << " | " << to_string(row.verdict);
    if (row.state.listening)
      std::cout << " | on " << joined(row.state.listen_addresses);
    if (const std::string owner = owner_text(row.state); !owner.empty())
      std::cout << " | " << owner;
    if (row.state.connections > 0)
      std::cout << " | connections=" << row.state.connections;
    std::cout << '\n' << "    " << row.explanation << '\n';
    for (const FirewallProfileVerdict& profile : row.firewall.per_profile) {
      std::cout << "    firewall " << profile.profile << ": " << to_string(profile.decision) << ", " << profile.because;
      if (!profile.networks.empty())
        std::cout << " (" << joined(profile.networks) << ")";
      std::cout << '\n';
    }
  }
  if (!result.firewall.product.empty())
    std::cout << "Firewall: " << result.firewall.product << '\n';
  if (!result.firewall.note.empty())
    std::cout << "Note: " << result.firewall.note << '\n';
  if (!result.rows.empty() && !result.rows.front().firewall.note.empty() &&
      result.rows.front().firewall.note != result.firewall.note)
    std::cout << "Note: " << result.rows.front().firewall.note << '\n';
  if (!result.sockets_note.empty())
    std::cout << "Note: " << result.sockets_note << '\n';
}

int command_network_presets() {
  for (const PortPreset& preset : port_presets()) {
    std::cout << preset.id << " | " << preset.name << '\n';
    for (const PortPresetEntry& entry : preset.entries) {
      std::cout << "    " << entry.ports << ' ' << (entry.tcp && entry.udp ? "TCP+UDP" : entry.tcp ? "TCP" : "UDP")
                << " from " << entry.from;
      if (entry.optional)
        std::cout << " (optional)";
      if (entry.dynamic)
        std::cout << " (held only while a job or a failover uses it)";
      if (entry.loopback)
        std::cout << " (loopback only)";
      if (!entry.note.empty())
        std::cout << ": " << entry.note;
      std::cout << '\n';
    }
    if (!preset.source_url.empty())
      std::cout << "    source: " << preset.source_title << ", " << preset.source_url << '\n';
  }
  return kExitSuccess;
}

int command_network_local_ports(const ParsedArguments& parsed) {
  Result<PortCheckResult> result = Result<PortCheckResult>::failure(Error{});
  if (const auto process = option(parsed, "process")) {
    result = check_process_ports(*process);
  } else if (const auto preset_id = option(parsed, "preset")) {
    const auto presets = port_presets();
    const PortPreset* preset = find_port_preset(presets, *preset_id);
    if (preset == nullptr) {
      std::cerr << "No preset named " << *preset_id << ". \"network presets\" lists them.\n";
      return kExitUsage;
    }
    std::vector<std::uint16_t> tcp;
    std::vector<std::uint16_t> udp;
    preset_ports(*preset, tcp, udp);
    result = check_local_ports(tcp, udp, preset_extras(*preset));
  } else {
    if (parsed.positionals.size() < 3U) {
      std::cerr << "network local-ports requires ports (such as 999,123,22-23), --preset ROLE or --process NAME\n";
      return kExitUsage;
    }
    auto ports = parse_port_list(parsed.positionals[2]);
    if (!ports.ok())
      return fail(ports.error(), kExitUsage);
    const bool udp = flag(parsed, "udp");
    const bool tcp = !udp || flag(parsed, "tcp");
    result = check_local_ports(ports.value(), tcp, udp);
  }
  if (!result.ok())
    return fail(result.error());
  if (flag(parsed, "json"))
    std::cout << tool_json::port_check(result.value()) << '\n';
  else
    print_port_check(result.value());
  return kExitSuccess;
}

std::string dns_answer_text(const std::vector<DnsAnswer>& answers) {
  if (answers.empty())
    return "not asked";
  std::string text;
  for (const DnsAnswer& answer : answers) {
    if (!text.empty())
      text += " | ";
    text += to_string(answer.type) + " ";
    if (!answer.answered) {
      text += answer.error;
      continue;
    }
    std::vector<std::string> values;
    for (const DnsRecord& record : answer.records) {
      if (record.type == answer.type)
        values.push_back(record.value);
    }
    text += answer.rcode != 0 ? dns_detail::rcode_text(answer.rcode) : values.empty() ? "none" : joined(values);
    text += " (" + std::to_string(static_cast<long long>(answer.elapsed_ms)) + " ms)";
  }
  return text;
}

int command_network_name(const ParsedArguments& parsed, const CancellationToken& cancel) {
  const std::string name = parsed.positionals.size() >= 3U ? parsed.positionals[2] : option(parsed, "host").value_or("");
  if (trim(name).empty()) {
    std::cerr << "network name requires a name or address\n";
    return kExitUsage;
  }
  const NameCheckResult result = check_name(name, cancel);
  if (flag(parsed, "json")) {
    std::cout << tool_json::name_check(result) << '\n';
    return result.addresses.empty() ? kExitFindings : kExitSuccess;
  }
  std::cout << "Name: " << result.name;
  if (!result.completed_name.empty())
    std::cout << " (completed as " << result.completed_name << ")";
  std::cout << '\n';
  if (!result.is_address) {
    std::cout << "Resolves to: " << (result.addresses.empty() ? "nothing (" + result.resolver_error + ")"
                                                              : joined(result.addresses))
              << '\n';
    if (!result.source.empty())
      std::cout << "Came from: " << result.source << '\n';
    if (!result.aliases.empty())
      std::cout << "Aliases: " << joined(result.aliases) << '\n';
    std::cout << "Lookup order: " << result.settings.lookup_order << '\n';
    std::cout << "Hosts file: " << result.settings.hosts_file;
    for (const HostsEntry& entry : result.hosts_entries)
      std::cout << " | line " << entry.line_number << ": " << entry.address;
    if (result.hosts_entries.empty())
      std::cout << " | no entry";
    std::cout << '\n';
    if (!result.settings.search_suffixes.empty())
      std::cout << "Search suffixes: " << joined(result.settings.search_suffixes) << '\n';
    std::cout << "DNS servers:\n";
    for (const DnsServer& server : result.settings.servers) {
      std::vector<DnsAnswer> answers;
      for (const DnsAnswer& answer : result.per_server) {
        if (answer.server == server.address)
          answers.push_back(answer);
      }
      std::cout << "  " << server.address << (server.interface_name.empty() ? "" : " (" + server.interface_name + ")")
                << ": " << dns_answer_text(answers) << '\n';
    }
    if (result.settings.servers.empty())
      std::cout << "  none configured\n";
    if (!result.settings.note.empty())
      std::cout << "Note: " << result.settings.note << '\n';
  }
  for (const ReverseLookup& lookup : result.reverse) {
    std::cout << "Reverse " << lookup.address << ": "
              << (lookup.name.empty() ? lookup.error
                                      : lookup.name + (lookup.agrees ? " (resolves back to it)"
                                                                     : " (does not resolve back to it)"))
              << '\n';
  }
  for (const std::string& note : result.notes)
    std::cout << "Note: " << note << '\n';
  return result.addresses.empty() ? kExitFindings : kExitSuccess;
}

std::string clock_difference_text(const SntpResult& sntp) {
  const double seconds = std::abs(sntp.offset_ms) / 1000.0;
  std::ostringstream text;
  text.setf(std::ios::fixed);
  text.precision(3);
  text << "this clock is " << seconds << " s " << (sntp.offset_ms >= 0 ? "behind " : "ahead of ") << sntp.server;
  return text.str();
}

int command_time(const ParsedArguments& parsed, const CancellationToken& cancel) {
  if (parsed.positionals.size() < 2U || (parsed.positionals[1] != "check" && parsed.positionals[1] != "convert" &&
                                         parsed.positionals[1] != "zones" && parsed.positionals[1] != "log-clock")) {
    std::cerr << "time requires check, convert, log-clock or zones\n";
    return kExitUsage;
  }
  const bool json = flag(parsed, "json");
  if (parsed.positionals[1] == "zones") {
    // Each zone with its offset now, for --zone.
    const std::int64_t now = unix_millis_now();
    for (const NamedTimeZone& zone : named_time_zones()) {
      const ZoneOffset offset = zone_offset_at(zone, now);
      std::cout << zone.name << " | " << zone.iana << " | now " << format_utc_offset(offset.offset_minutes)
                << (offset.daylight ? ", " + zone.daylight_name : std::string()) << '\n';
    }
    return kExitSuccess;
  }
  if (parsed.positionals[1] == "log-clock") {
    // What a log records of its own clock: its headers' offsets and the zone it names.
    if (parsed.positionals.size() < 3U) {
      std::cerr << "time log-clock requires a log file\n";
      return kExitUsage;
    }
    const LogClock clock = read_log_clock(path_from_utf8(parsed.positionals[2]));
    if (json) {
      std::cout << tool_json::log_clock(clock) << '\n';
      return clock.error.empty() ? kExitSuccess : kExitFailure;
    }
    if (!clock.error.empty()) {
      std::cerr << clock.error << '\n';
      return kExitFailure;
    }
    const LogClockSummary summary = summarize_log_clock(clock);
    std::cout << clock.source << '\n' << summary.headline << '\n';
    for (const std::string& note : summary.notes)
      std::cout << note << '\n';
    for (const auto& [label, value] : summary.rows)
      std::cout << label << ": " << value << '\n';
    return kExitSuccess;
  }
  if (parsed.positionals[1] == "convert") {
    if (parsed.positionals.size() < 3U) {
      std::cerr << "time convert requires a timestamp or a log line, quoted when it holds spaces\n";
      return kExitUsage;
    }
    std::string text = parsed.positionals[2];
    for (std::size_t index = 3; index < parsed.positionals.size(); ++index)
      text += " " + parsed.positionals[index];
    // Written in: --zone, --offset, else the log's own clock with --log, else this machine's offset.
    ZoneChoice written_in;
    if (const auto zone_text = option(parsed, "zone")) {
      written_in = read_zone_choice(*zone_text);
      if (written_in.kind != ZoneChoice::Kind::zone) {
        std::cerr << "--zone takes a zone 'time zones' lists, by name, Windows id or IANA name, such as "
                     "\"Eastern Time\" or America/New_York\n";
        return kExitUsage;
      }
    } else if (const auto offset_text = option(parsed, "offset")) {
      const auto minutes = parse_utc_offset(*offset_text);
      if (!minutes) {
        std::cerr << "--offset takes a UTC offset such as -05:00, +0530, UTC or -300 (minutes)\n";
        return kExitUsage;
      }
      written_in.kind = ZoneChoice::Kind::offset;
      written_in.offset_minutes = *minutes;
    }
    std::optional<LogClock> log;
    if (const auto log_path = option(parsed, "log")) {
      log = read_log_clock(path_from_utf8(*log_path));
      if (!log->error.empty()) {
        std::cerr << log->error << '\n';
        return kExitFailure;
      }
      if (written_in.kind == ZoneChoice::Kind::none)
        written_in.kind = ZoneChoice::Kind::from_log;
    }
    ZoneChoice show_in;
    if (const auto show_text = option(parsed, "show-in")) {
      show_in = read_zone_choice(*show_text);
      if (show_in.kind != ZoneChoice::Kind::zone && show_in.kind != ZoneChoice::Kind::offset) {
        std::cerr << "--show-in takes a zone 'time zones' lists or a UTC offset such as -05:00\n";
        return kExitUsage;
      }
    }
    const ConvertedTime converted = convert_with_choices(text, written_in, log ? &*log : nullptr, show_in);
    if (json) {
      std::cout << tool_json::converted_time(converted) << '\n';
      return converted.ok ? kExitSuccess : kExitUsage;
    }
    if (!converted.ok) {
      std::cerr << converted.error << '\n';
      return kExitUsage;
    }
    for (const auto& [label, value] : converted_time_rows(converted))
      std::cout << label << ": " << value << '\n';
    return kExitSuccess;
  }

  const TimeCheckResult result = check_time(option(parsed, "server").value_or(""), cancel);
  if (json) {
    std::cout << tool_json::time_check(result) << '\n';
    return result.beyond_kerberos ? kExitFindings : kExitSuccess;
  }
  std::cout << "Time zone: " << result.zone.name << " (" << format_utc_offset(result.zone.utc_offset_minutes)
            << (result.zone.daylight_saving_now ? ", daylight saving time now" : "") << ")\n";
  std::cout << "Time service: " << (result.source.service.empty() ? "none running" : result.source.service);
  if (!result.source.mode.empty())
    std::cout << ", " << result.source.mode;
  if (!result.source.servers.empty())
    std::cout << ", servers " << joined(result.source.servers);
  if (!result.source.domain_controller.empty())
    std::cout << ", domain controller " << result.source.domain_controller;
  std::cout << '\n';
  if (!result.source.note.empty())
    std::cout << "Note: " << result.source.note << '\n';
  if (!result.sntp.server.empty()) {
    std::cout << "Asked " << result.sntp.server;
    if (!result.sntp.address.empty() && result.sntp.address != result.sntp.server)
      std::cout << " (" << result.sntp.address << ")";
    if (result.sntp.answered)
      std::cout << ": " << clock_difference_text(result.sntp) << ", round trip "
                << static_cast<long long>(result.sntp.round_trip_ms) << " ms, stratum " << result.sntp.stratum << '\n';
    else
      std::cout << ": " << result.sntp.error << '\n';
  }
  for (const std::string& note : result.notes)
    std::cout << "Note: " << note << '\n';
  return result.beyond_kerberos ? kExitFindings : kExitSuccess;
}

void print_holder(const FileHolder& holder) {
  std::cout << "  PID " << holder.pid << " | " << (holder.name.empty() ? "(name not readable)" : holder.name);
  if (!holder.services.empty())
    std::cout << " | services: " << holder.services;
  if (!holder.path.empty())
    std::cout << " | " << holder.path;
  if (holder.started_unix_millis > 0)
    std::cout << " | started " << readable_utc_from_unix_millis(holder.started_unix_millis);
  std::cout << '\n';
}

// A folder: the folder and every file and folder under it.
int command_files_lock_folder(const ParsedArguments& parsed, const std::string& path, const CancellationToken& cancel) {
  auto result = find_folder_holders(path, cancel);
  if (!result.ok())
    return fail(result.error(), kExitUsage);
  const FolderLockResult& locks = result.value();
  if (flag(parsed, "json")) {
    std::cout << tool_json::folder_lock(locks) << '\n';
    return kExitSuccess;
  }
  std::cout << "Folder: " << locks.folder << '\n'
            << "Checked " << locks.files_checked << " file(s) in " << locks.folders_checked << " folder(s)"
            << (locks.stopped_at_limit ? ", then stopped at the limit" : "") << ".\n";
  if (locks.held.empty())
    std::cout << "Nothing under it is held open.\n";
  for (const FileHolder& holder : locks.holders)
    print_holder(holder);
  for (const HeldFile& held : locks.held) {
    std::cout << "  " << held.path << " |";
    for (const std::uint32_t pid : held.pids)
      std::cout << " PID " << pid;
    std::cout << '\n';
  }
  if (!locks.note.empty())
    std::cout << "Note: " << locks.note << '\n';
  return kExitSuccess;
}

int command_files_lock(const ParsedArguments& parsed, const CancellationToken& cancel) {
  const auto path = option(parsed, "path");
  if (!path) {
    std::cerr << "files lock requires --path FILE|FOLDER\n";
    return kExitUsage;
  }
  std::error_code ignored;
  if (std::filesystem::is_directory(path_from_utf8(*path), ignored))
    return command_files_lock_folder(parsed, *path, cancel);
  auto result = find_file_holders(*path);
  if (!result.ok())
    return fail(result.error(), kExitUsage);
  const FileLockResult& locks = result.value();
  if (flag(parsed, "json")) {
    std::cout << tool_json::file_lock(locks) << '\n';
    return kExitSuccess;
  }
  std::cout << "File: " << locks.file << '\n';
  if (locks.holders.empty())
    std::cout << "No process holds it open.\n";
  for (const FileHolder& holder : locks.holders)
    print_holder(holder);
  if (!locks.note.empty())
    std::cout << "Note: " << locks.note << '\n';
  return kExitSuccess;
}

void print_volume(const VolumeInfo& volume) {
  const auto line = [](const char* label, const std::string& value) {
    if (!value.empty())
      std::cout << label << ": " << value << '\n';
  };
  if (!volume.path.empty())
    std::cout << "Path: " << volume.path << '\n';
  std::cout << "Volume: " << (volume.mount_point.empty() ? std::string("no mount point") : volume.mount_point);
  if (!volume.label.empty())
    std::cout << " (" << volume.label << ")";
  if (!volume.device.empty())
    std::cout << " on " << volume.device;
  std::cout << '\n';
  if (volume.mount_points.size() > 1)
    line("Mount points", joined(volume.mount_points));
  std::cout << "File system: " << (volume.file_system.empty() ? std::string("not read") : volume.file_system)
            << (volume.file_system_version.empty() ? "" : " " + volume.file_system_version);
  if (volume.cluster_size != 0)
    std::cout << ", cluster " << volume_detail::format_bytes(volume.cluster_size);
  std::cout << '\n';
  if (volume.total_bytes != 0)
    std::cout << "Space: " << volume_detail::format_bytes(volume.free_bytes) << " free of "
              << volume_detail::format_bytes(volume.total_bytes) << '\n';
  line("On", volume.kind);
  line("Bus", volume.bus);
  line("Disk", volume.disk);
  line("Controller", volume.controller);
  line("Driver", volume.driver);
  line("LUN", volume.lun);
  line(volume.network_share ? "Share" : "Target", volume.remote);
  line("Layers", joined(volume.layers, " > "));
  if (volume.volume_compressed)
    std::cout << "Volume compressed: yes\n";
  line("Encryption", volume.encryption.empty() ? volume.encryption_note : volume.encryption);
  if (!volume.path.empty() && volume.folder_attributes_read)
    std::cout << "Folder: " << (volume.folder_compressed ? "compressed" : "not compressed") << ", "
              << (volume.folder_encrypted ? "encrypted" : "not encrypted") << '\n';
  line("Fast Clone", volume.fast_clone_text);
  line("Mount options", volume.mount_options);
  for (const std::string& note : volume.notes)
    std::cout << "Note: " << note << '\n';
  if (!volume.guide_url.empty())
    std::cout << "Guide: " << volume.guide_title << ", " << volume.guide_url << '\n';
}

int command_volume(const ParsedArguments& parsed) {
  const std::string action = parsed.positionals.size() >= 2U ? parsed.positionals[1] : std::string();
  if (action == "list") {
    auto result = list_volumes();
    if (!result.ok())
      return fail(result.error(), kExitUsage);
    if (flag(parsed, "json")) {
      std::cout << tool_json::volumes(result.value()) << '\n';
      return kExitSuccess;
    }
    bool first = true;
    for (const VolumeInfo& volume : result.value()) {
      if (!first)
        std::cout << '\n';
      first = false;
      print_volume(volume);
    }
    return kExitSuccess;
  }
  if (action != "check") {
    std::cerr << "volume requires list, or check --path DIR\n";
    return kExitUsage;
  }
  const auto path = option(parsed, "path");
  if (!path) {
    std::cerr << "volume check requires --path DIR\n";
    return kExitUsage;
  }
  auto result = check_volume(*path);
  if (!result.ok())
    return fail(result.error(), kExitUsage);
  if (flag(parsed, "json")) {
    std::cout << tool_json::volume(result.value()) << '\n';
    return kExitSuccess;
  }
  print_volume(result.value());
  return kExitSuccess;
}

// storage tests | storage speed-test: the Disk Speed Test, KB2014's tests on DiskSpd or fio.
int command_storage(const ParsedArguments& parsed, const CancellationToken& cancel) {
  const std::string action = parsed.positionals.size() >= 2U ? parsed.positionals[1] : std::string();
  const StorageTestCatalog& catalog = storage_test_catalog();
  if (action == "tests") {
    std::cout << catalog.source_title << " (" << catalog.source_url << ", read " << catalog.reviewed << ")\n";
    for (const StorageTest& test : catalog.tests) {
      std::cout << "  " << test.id << " | " << test.name << " | " << test.simulates << " | "
                << (test.reads_existing_file ? "reads an existing file (--file)" : "writes a " + test.file_size + " test file (--folder)")
                << '\n';
    }
    return kExitSuccess;
  }
  if (action != "speed-test") {
    std::cerr << "storage requires tests, or speed-test --test ID | --custom, with --folder DIR | --file PATH\n";
    return kExitUsage;
  }
  // One of KB2014's tests, or --custom with the engineer's own mix.
  const bool custom = flag(parsed, "custom");
  const auto test_id = option(parsed, "test");
  const StorageTest* test = !custom && test_id ? find_storage_test(*test_id) : nullptr;
  if (!custom && test == nullptr) {
    std::cerr << "storage speed-test requires --custom, or --test with one of:";
    for (const StorageTest& known : catalog.tests)
      std::cerr << ' ' << known.id;
    std::cerr << '\n';
    return kExitUsage;
  }
  const auto target = custom ? (option(parsed, "folder") ? option(parsed, "folder") : option(parsed, "file"))
                             : option(parsed, test->reads_existing_file ? "file" : "folder");
  if (!target) {
    if (custom)
      std::cerr << "storage speed-test --custom requires --folder DIR (where SAT writes its test file) or --file PATH "
                   "(an existing file, read only)\n";
    else
      std::cerr << "storage speed-test --test " << test->id << " requires "
                << (test->reads_existing_file ? "--file PATH (an existing file to read)"
                                              : "--folder DIR (where SAT writes its test file)")
                << '\n';
    return kExitUsage;
  }
  std::filesystem::path tools_root = argument_path(option(parsed, "tools-root").value_or(""));
  if (tools_root.empty())
    tools_root = path_from_utf8(current_executable_path()).parent_path() / "Tools";
  auto engine = find_speed_test_engine(tools_root);
  if (!engine.ok())
    return fail(engine.error(), kExitUsage);
  DiskSpeedTestOptions speed_options;
  if (custom) {
    CustomSpeedTest mix;
    const auto number = [](const std::optional<std::string>& value, const char* label, int fallback) {
      return value ? parse_integer<int>(*value, label) : Result<int>::success(fallback);
    };
    const auto write = number(option(parsed, "write-percent"), "write-percent", 0);
    const auto threads = number(option(parsed, "threads"), "threads", 0);
    const auto outstanding = number(option(parsed, "outstanding"), "outstanding", 0);
    const auto warmup = number(option(parsed, "warmup"), "warmup", -1);
    for (const Result<int>* value : {&write, &threads, &outstanding, &warmup}) {
      if (!value->ok())
        return fail(value->error(), kExitUsage);
    }
    mix.write_percent = write.value();
    mix.threads = threads.value();
    mix.outstanding = outstanding.value();
    mix.warmup_seconds = warmup.value();
    mix.random = flag(parsed, "random");
    mix.caching = flag(parsed, "caching");
    speed_options.custom = mix;
  } else {
    speed_options.test_id = test->id;
  }
  if (const auto role = option(parsed, "role")) {
    const std::optional<StorageRole> named = parse_storage_role(*role);
    if (!named) {
      std::cerr << "--role takes repository, source or other\n";
      return kExitUsage;
    }
    speed_options.role = *named;
  }
  speed_options.target = argument_path(*target);
  speed_options.block_size = option(parsed, "block").value_or("");
  speed_options.file_size = option(parsed, "size").value_or("");
  if (const auto seconds = option(parsed, "seconds")) {
    auto value = parse_integer<int>(*seconds, "seconds");
    if (!value.ok())
      return fail(value.error(), kExitUsage);
    speed_options.seconds = value.value();
  }
  auto plan = plan_disk_speed_test(speed_options, engine.value().engine, engine.value().path);
  if (!plan.ok())
    return fail(plan.error(), kExitUsage);
  if (!flag(parsed, "json")) {
    const DiskSpeedTestPlan& planned = plan.value();
    std::cout << planned.test.name << (planned.test.simulates.empty() ? "" : ": " + planned.test.simulates) << '\n'
              << planned.settings << '\n'
              << (planned.creates_file ? "Writes SAT's own test file " : "Reads ") << path_to_utf8(planned.file)
              << " for " << planned.seconds << " seconds; it loads the storage, so run it outside the backup window.\n";
  }
  const auto elapsed = [](const ProgressEvent& event) {
    std::cerr << '\r' << event.phase << " | " << event.processed << " s elapsed | "
              << event.current_scope.substr(0, 110) << "    " << std::flush;
  };
  auto result = run_disk_speed_test(plan.value(), cancel, elapsed);
  finish_progress_line();
  if (!result.ok())
    return fail(result.error());
  const DiskSpeedTestResult& value = result.value();
  if (flag(parsed, "json")) {
    std::cout << tool_json::disk_speed_test(value) << '\n';
    return value.cancelled ? kExitCancelled : kExitSuccess;
  }
  std::cout << '\n' << speed_test_text(summarize_speed_test(value));
  return value.cancelled ? kExitCancelled : kExitSuccess;
}

#ifdef SUPPORT_ASSIST_OBJECT_STORAGE_CHECK
// objectstorage presets | objectstorage check: the Object Storage Check, experimental. The keys come
// from SAT_S3_ACCESS_KEY and SAT_S3_SECRET_KEY, never from the command line.
int command_object_storage(const ParsedArguments& parsed, const CancellationToken& cancel) {
  const std::string action = parsed.positionals.size() >= 2U ? parsed.positionals[1] : std::string();
  if (action == "presets") {
    std::cout << "Presets (--preset):\n";
    for (const ObjectStoragePreset& preset : object_storage_catalog().presets) {
      std::cout << "  " << preset.id << " | " << preset.name << " | "
                << (preset.later ? std::string("not checked yet")
                                 : preset.endpoint.empty() ? std::string("endpoint entered with --endpoint")
                                                           : preset.endpoint + ", " + preset.addressing)
                << '\n';
      if (!preset.later && preset.regions.size() > 1U) {
        std::string regions;
        for (const std::string& region : preset.regions)
          regions += (regions.empty() ? "" : ", ") + region;
        std::cout << "      regions (--region): " << regions << '\n';
      }
    }
    std::cout << "\nProducts the key's permissions are held against (--product):\n";
    for (const ObjectStoragePermissions& product : object_storage_catalog().permissions)
      std::cout << "  " << product.id << " | " << product.product << '\n';
    return kExitSuccess;
  }
  if (action != "check") {
    std::cerr << "objectstorage requires presets, or check --preset ID --bucket NAME\n";
    return kExitUsage;
  }
  ObjectStorageOptions options;
  options.target.preset = option(parsed, "preset").value_or("amazon-s3");
  options.target.endpoint = option(parsed, "endpoint").value_or("");
  options.target.region = option(parsed, "region").value_or("");
  options.target.bucket = option(parsed, "bucket").value_or("");
  options.target.addressing = option(parsed, "addressing").value_or("");
  options.target.pinned_sha256 = option(parsed, "expected-fingerprint").value_or("");
  options.target.certificate_file = option(parsed, "certificate-file").value_or("");
  options.accept_cost = flag(parsed, "accept-cost");
  options.product = option(parsed, "product").value_or("");
  if (!options.product.empty() && find_object_storage_permissions(options.product)->id != options.product) {
    std::cerr << "No product \"" << options.product << "\"; 'objectstorage presets' lists them.\n";
    return kExitUsage;
  }
  if (!flag(parsed, "no-signed"))
    options.credentials = object_storage_credentials_from_environment();
  const auto resolved = resolve_object_storage_endpoint(options.target);
  if (!resolved.ok())
    return fail(resolved.error(), kExitUsage);
  const ObjectStorageEstimate estimate = estimate_object_storage_check(options.target);
  const bool json = flag(parsed, "json");
  if (options.credentials && estimate.needs_agreement && !options.accept_cost && !json)
    std::cerr << estimate.text << "\nThe signed reads run with --accept-cost.\n";
  const auto step = [json](const ProgressEvent& event) {
    if (!json)
      std::cerr << '\r' << event.current_scope.substr(0, 100) << "                    " << std::flush;
  };
  auto result = check_object_storage(options, cancel, step);
  if (!json)
    finish_progress_line();
  if (!result.ok())
    return fail(result.error());
  const ObjectStorageResult& value = result.value();
  if (json) {
    std::cout << tool_json::object_storage(value) << '\n';
    return kExitSuccess;
  }
  std::cout << "Object Storage Check (experimental): " << value.preset << ", " << value.endpoint.request_host << '\n'
            << value.headline << '\n';
  std::string section;
  for (const ObjectCheckRow& row : value.rows) {
    if (row.section != section) {
      section = row.section;
      std::cout << '\n' << section << '\n';
    }
    const char* mark = row.state == ObjectCheckState::pass        ? "[ok]   "
                       : row.state == ObjectCheckState::attention ? "[look] "
                       : row.state == ObjectCheckState::fail      ? "[fail] "
                       : row.state == ObjectCheckState::not_checked ? "[--]   "
                                                                    : "       ";
    std::cout << "  " << mark << row.label << ": " << row.value << '\n';
  }
  return kExitSuccess;
}
#endif

void print_watch_item(const WatchItem& item) {
  std::cout << "  " << (item.kind == WatchKind::service ? "service" : "process") << " | " << item.name;
  if (item.kind == WatchKind::service && !item.display_name.empty() && item.display_name != item.name)
    std::cout << " (" << item.display_name << ")";
  std::cout << " | " << item.state;
  if (item.pid != 0)
    std::cout << " | PID " << item.pid;
  if (item.started_unix_millis > 0)
    std::cout << " | since " << readable_utc_from_unix_millis(item.started_unix_millis);
  if (!item.listening.empty())
    std::cout << " | listening " << item.listening;
  std::cout << '\n';
}

int command_watch(const ParsedArguments& parsed, const CancellationToken& cancel) {
  const std::string filter = option(parsed, "filter").value_or("veeam");
  std::uint64_t seconds = 0;
  if (const auto text = option(parsed, "seconds")) {
    auto value = parse_integer<std::uint64_t>(*text, "seconds");
    if (!value.ok())
      return fail(value.error(), kExitUsage);
    seconds = value.value();
  }
  std::uint64_t interval_ms = 2000;
  if (const auto text = option(parsed, "interval-ms")) {
    auto value = parse_integer<std::uint64_t>(*text, "interval-ms");
    if (!value.ok())
      return fail(value.error(), kExitUsage);
    if (value.value() < 250) {
      std::cerr << "--interval-ms is at least 250\n";
      return kExitUsage;
    }
    interval_ms = value.value();
  }
  WatchSnapshot snapshot = take_watch_snapshot(filter);
  std::cout << "Services and processes matching \"" << filter << "\" at "
            << readable_utc_from_unix_millis(snapshot.taken_unix_millis) << ":\n";
  for (const WatchItem& item : snapshot.items)
    print_watch_item(item);
  if (snapshot.items.empty())
    std::cout << "  none\n";
  if (!snapshot.note.empty())
    std::cout << "Note: " << snapshot.note << '\n';
  if (seconds == 0)
    return kExitSuccess;
  std::cout << "Watching for " << seconds << " s:\n" << std::flush;
  const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
  while (!cancel.is_cancelled() && std::chrono::steady_clock::now() < until) {
    const auto wake = std::chrono::steady_clock::now() + std::chrono::milliseconds(interval_ms);
    while (!cancel.is_cancelled() && std::chrono::steady_clock::now() < wake)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    WatchSnapshot next = take_watch_snapshot(filter);
    for (const WatchEvent& event : diff_watch(snapshot, next))
      std::cout << readable_utc_from_unix_millis(event.at_unix_millis) << "  " << event.text << '\n' << std::flush;
    snapshot = std::move(next);
  }
  return cancel.is_cancelled() ? kExitCancelled : kExitSuccess;
}

// Installer Cache Check: the installed products by UpgradeCode or name, the cached package Windows
// keeps for each and whether it is there, and an installer or folder checked against them.
int command_system_installer_cache(const ParsedArguments& parsed, const CancellationToken& cancel) {
  InstallerCacheOptions options;
  const auto upgrade_code = option(parsed, "upgrade-code");
  const auto name = option(parsed, "name");
  if (upgrade_code && name) {
    std::cerr << "system installer-cache takes --upgrade-code or --name, not both\n";
    return kExitUsage;
  }
  if (upgrade_code) {
    if (installer_cache_detail::normalize_guid(*upgrade_code).empty()) {
      std::cerr << "--upgrade-code takes a GUID, such as {12345678-90AB-CDEF-1234-567890ABCDEF}\n";
      return kExitUsage;
    }
    options.upgrade_code = *upgrade_code;
  }
  if (name) {
    if (*name == "true") {
      std::cerr << "--name takes the text to look for in product names, such as --name Veeam; "
                   "--name \"\" lists every product\n";
      return kExitUsage;
    }
    options.name_filter = *name;
  }
  if (const auto check = option_path(parsed, "check"))
    options.check_path = *check;
  const bool json = flag(parsed, "json");
  auto result = check_installer_cache(options, cancel, json ? ProgressCallback{} : ProgressCallback{progress_text});
  if (!json)
    finish_progress_line();
  if (!result.ok()) {
#ifdef _WIN32
    return fail(result.error(), cancel.is_cancelled() ? kExitCancelled : kExitFailure);
#else
    return fail(result.error(), kExitUnavailable);
#endif
  }
  const InstallerCacheResult& value = result.value();
  const int exit_code = installer_cache_has_missing(value) ? kExitFindings : kExitSuccess;
  if (json) {
    std::cout << tool_json::installer_cache(value) << '\n';
    return exit_code;
  }
  // The rows grouped under their product, each item's value with its state after it.
  std::string current;
  for (const InstallerCacheRow& row : installer_cache_rows(value)) {
    if (row.product != current) {
      std::cout << (current.empty() ? "" : "\n") << row.product << '\n';
      current = row.product;
    }
    std::string item = row.item;
    if (item.size() < 24U)
      item.resize(24U, ' ');
    std::cout << "  " << item << ' ' << row.value;
    if (!row.state.empty())
      std::cout << "  [" << row.state << ']';
    std::cout << '\n';
  }
  std::cout << '\n' << installer_cache_summary(value) << ".\n";
  return exit_code;
}

// Named Pipes: every pipe in \\.\pipe\ by name with its instance counts, the names SAT knows marked
// with their product and service. No pipe is opened.
int command_system_pipes(const ParsedArguments& parsed, const CancellationToken& cancel) {
  NamedPipesOptions options;
  options.veeam_only = flag(parsed, "veeam");
  const bool json = flag(parsed, "json");
  auto result = list_named_pipes(options, cancel, json ? ProgressCallback{} : ProgressCallback{progress_text});
  if (!json)
    finish_progress_line();
  if (!result.ok()) {
#ifdef _WIN32
    return fail(result.error(), cancel.is_cancelled() ? kExitCancelled : kExitFailure);
#else
    return fail(result.error(), kExitUnavailable);
#endif
  }
  const NamedPipesResult& value = result.value();
  if (json) {
    std::cout << tool_json::named_pipes(value) << '\n';
    return kExitSuccess;
  }
  for (const NamedPipeRow& row : named_pipe_rows(value)) {
    std::cout << row.pipe << "  [" << (row.instances.empty() ? std::string("?") : row.instances) << "]\n";
    if (!row.known_as.empty())
      std::cout << "    " << row.known_as << '\n';
    if (!row.owner.empty())
      std::cout << "    " << row.owner << '\n';
  }
  for (const std::string& note : value.notes)
    std::cout << '\n' << note;
  std::cout << '\n' << named_pipes_summary(value) << ".\n";
  return kExitSuccess;
}

int command_system_host_checks(const ParsedArguments& parsed, const CancellationToken& cancel) {
  HostChecksOptions options;
  if (const auto checks = option(parsed, "checks")) {
    for (const std::string& id : split(*checks, ','))
      if (!trim(id).empty())
        options.groups.push_back(trim(id));
  }
  if (const auto days = option(parsed, "days")) {
    auto value = parse_integer<int>(*days, "days");
    if (!value.ok() || value.value() < 1 || value.value() > 365) {
      std::cerr << "--days takes 1 to 365\n";
      return kExitUsage;
    }
    options.days = value.value();
  }
  const bool json = flag(parsed, "json");
  auto result = run_host_checks(options, cancel, json ? ProgressCallback{} : ProgressCallback{progress_text});
  if (!json)
    finish_progress_line();
  if (!result.ok())
    return fail(result.error(), kExitUsage);
  const HostChecksReport& report = result.value();
  const int exit_code = cancel.is_cancelled()               ? kExitCancelled
                        : host_checks_has_finding(report) ? kExitFindings
                                                          : kExitSuccess;
  if (json) {
    std::cout << tool_json::host_checks(report) << '\n';
    return exit_code;
  }
  std::string current;
  for (const HostCheckRow& row : report.rows) {
    if (row.group != current) {
      std::cout << (current.empty() ? "" : "\n") << row.group << '\n';
      current = row.group;
    }
    std::cout << "  " << row.check << "  [" << row.status << "]\n      " << row.detail << '\n';
    if (!row.source.empty())
      std::cout << "      " << row.source << '\n';
  }
  std::cout << '\n' << host_checks_summary(report) << '\n';
  return exit_code;
}

int command_system(const ParsedArguments& parsed, const CancellationToken& cancel) {
  if (parsed.positionals.size() >= 2U && parsed.positionals[1] == "installer-cache")
    return command_system_installer_cache(parsed, cancel);
  if (parsed.positionals.size() >= 2U && parsed.positionals[1] == "host-checks")
    return command_system_host_checks(parsed, cancel);
  if (parsed.positionals.size() >= 2U && parsed.positionals[1] == "pipes")
    return command_system_pipes(parsed, cancel);
  if (parsed.positionals.size() < 2U || parsed.positionals[1] != "pending-restart") {
    std::cerr << "system requires pending-restart, host-checks, installer-cache or pipes\n";
    return kExitUsage;
  }
  const PendingRestartResult result = check_pending_restart();
  if (flag(parsed, "json")) {
    std::cout << tool_json::pending_restart(result) << '\n';
    return result.restart_needed ? kExitFindings : kExitSuccess;
  }
  std::cout << "Restart needed: " << (result.restart_needed ? "yes" : "no") << " (last start "
            << readable_utc_from_unix_millis(result.boot_unix_millis) << ")\n";
  for (const RestartMarker& marker : result.markers) {
    std::cout << marker.name << ": " << marker.meaning;
    if (marker.set_unix_millis > 0)
      std::cout << " Set " << readable_utc_from_unix_millis(marker.set_unix_millis) << '.';
    std::cout << '\n';
    for (const std::string& detail : marker.details)
      std::cout << "    " << detail << '\n';
    for (const std::string& reason : marker.reasons)
      std::cout << "    " << reason << '\n';
  }
  if (result.markers.empty())
    std::cout << "No restart marker is set.\n";
  return result.restart_needed ? kExitFindings : kExitSuccess;
}

int command_network_adapters(const ParsedArguments& parsed) {
  auto adapters = list_network_adapters();
  if (!adapters.ok())
    return fail(adapters.error());
  if (flag(parsed, "json")) {
    std::cout << '[';
    for (std::size_t index = 0; index < adapters.value().size(); ++index) {
      const NetworkAdapter& adapter = adapters.value()[index];
      std::cout << (index == 0 ? "" : ",") << "{\"name\":" << tool_json::text(adapter.name)
                << ",\"description\":" << tool_json::text(adapter.description)
                << ",\"addresses\":" << tool_json::list(adapter.addresses)
                << ",\"link_bits_per_second\":" << adapter.link_bits_per_second << ",\"mtu\":" << adapter.mtu
                << ",\"up\":" << (adapter.up ? "true" : "false") << ",\"loopback\":" << (adapter.loopback ? "true" : "false")
                << ",\"virtual\":" << (adapter.virtual_adapter ? "true" : "false")
                << ",\"receive_errors\":" << adapter.receive_errors << ",\"send_errors\":" << adapter.send_errors
                << ",\"receive_discards\":" << adapter.receive_discards << ",\"send_discards\":" << adapter.send_discards
                << '}';
    }
    std::cout << "]\n";
    return kExitSuccess;
  }
  for (const NetworkAdapter& adapter : adapters.value()) {
    std::cout << network_adapter_label(adapter) << '\n';
    if (!adapter.description.empty())
      std::cout << "    " << adapter.description << '\n';
    std::cout << "    errors: " << adapter.receive_errors << " received, " << adapter.send_errors << " sent; discards: "
              << adapter.receive_discards << " received, " << adapter.send_discards << " sent\n";
  }
  return kExitSuccess;
}

int command_network_transfer_time(const ParsedArguments& parsed, const CancellationToken& cancel) {
  TransferInputs inputs;
  const auto size = option(parsed, "size");
  if (!size) {
    std::cerr << "network transfer-time requires --size, such as --size 20TB\n";
    return kExitUsage;
  }
  auto size_bytes = parse_data_size(*size);
  if (!size_bytes.ok())
    return fail(size_bytes.error(), kExitUsage);
  inputs.size_bytes = size_bytes.value();
  if (const auto adapter_name = option(parsed, "adapter")) {
    auto adapters = list_network_adapters();
    if (!adapters.ok())
      return fail(adapters.error());
    const auto found = std::find_if(adapters.value().begin(), adapters.value().end(),
                                    [&](const NetworkAdapter& adapter) { return adapter.name == *adapter_name; });
    if (found == adapters.value().end() || found->link_bits_per_second == 0U) {
      std::cerr << "No adapter named \"" << *adapter_name << "\" reports a link speed; see 'network adapters'.\n";
      return kExitUsage;
    }
    inputs.link_bits_per_second = static_cast<double>(found->link_bits_per_second);
    inputs.link_name = found->name;
    if (found->mtu >= 576U && found->mtu <= 9216U)
      inputs.mtu = static_cast<int>(found->mtu);
  }
  if (const auto link = option(parsed, "link")) {
    auto bits = parse_link_speed(*link);
    if (!bits.ok())
      return fail(bits.error(), kExitUsage);
    inputs.link_bits_per_second = bits.value();
  }
  if (!(inputs.link_bits_per_second > 0.0)) {
    std::cerr << "network transfer-time requires --link, such as --link 10G, or --adapter NAME\n";
    return kExitUsage;
  }
  if (const auto mtu = option(parsed, "mtu")) {
    auto value = parse_mtu(*mtu);
    if (!value.ok())
      return fail(value.error(), kExitUsage);
    inputs.mtu = value.value();
  }
  inputs.ip = flag(parsed, "ipv6") ? TransferIp::ipv6 : TransferIp::ipv4;
  inputs.tcp_timestamps = flag(parsed, "timestamps");
  if (const auto share = option(parsed, "share")) {
    auto value = parse_percent(*share, "--share");
    if (!value.ok())
      return fail(value.error(), kExitUsage);
    inputs.share_percent = value.value();
  }
  if (const auto reduced = option(parsed, "reduced-to")) {
    auto value = parse_percent(*reduced, "--reduced-to");
    if (!value.ok())
      return fail(value.error(), kExitUsage);
    inputs.reduced_to_percent = value.value();
  }
  // The network's and the storage's speed, typed in as the live test would measure them.
  if (const auto network = option(parsed, "network-speed")) {
    auto value = parse_byte_rate(*network);
    if (!value.ok())
      return fail(value.error(), kExitUsage);
    inputs.network_bytes_per_second = value.value();
  }
  if (const auto storage = option(parsed, "storage-speed")) {
    auto value = parse_byte_rate(*storage);
    if (!value.ok())
      return fail(value.error(), kExitUsage);
    inputs.storage_bytes_per_second = value.value();
  }
  if (const auto host = option(parsed, "host"); host && flag(parsed, "iperf3")) {
    IperfTransferOptions iperf;
    iperf.host = *host;
    if (const auto port_text = option(parsed, "port")) {
      auto port = parse_integer<std::uint16_t>(*port_text, "port");
      if (!port.ok())
        return fail(port.error(), kExitUsage);
      iperf.port = port.value();
    }
    if (const auto streams = option(parsed, "streams")) {
      auto count = parse_integer<std::uint16_t>(*streams, "streams");
      if (!count.ok())
        return fail(count.error(), kExitUsage);
      iperf.streams = count.value();
    }
    iperf.tools_folder = argument_path(option(parsed, "tools-root").value_or(""));
    auto speed = run_iperf3_transfer_test(iperf, cancel);
    if (!speed.ok())
      return fail(speed.error());
    inputs.measured.push_back(speed.value());
  } else if (host) {
    TransferTestOptions test;
    test.host = *host;
    if (const auto port_text = option(parsed, "port")) {
      auto port = parse_integer<std::uint16_t>(*port_text, "port");
      if (!port.ok())
        return fail(port.error(), kExitUsage);
      test.port = port.value();
    }
    auto bytes = parse_transfer_size(option(parsed, "bytes").value_or("1G"));
    if (!bytes.ok())
      return fail(bytes.error(), kExitUsage);
    test.bytes = bytes.value();
    auto measured = run_transfer_test(test, cancel, progress_text);
    finish_progress_line();
    if (!measured.ok())
      return fail(measured.error());
    if (measured.value().cancelled)
      return kExitCancelled;
    // The overhead follows the address family the test went over.
    if (measured.value().ipv6)
      inputs.ip = TransferIp::ipv6;
    inputs.measured.push_back({"Network test to " + test.host,
                               measured.value().answered_by + ", one connection, " +
                                   link_speed_text(measured.value().bytes_per_second * 8.0),
                               measured.value().bytes_per_second, "the network test to " + test.host});
  }
  if (const auto storage = option(parsed, "storage-result")) {
    std::ifstream input(path_from_utf8(*storage), std::ios::binary);
    if (!input) {
      std::cerr << "Cannot read " << *storage << '\n';
      return kExitUsage;
    }
    const std::string json_text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    auto speed = storage_speed_from_result(json_text);
    if (!speed.ok())
      return fail(speed.error(), kExitUsage);
    inputs.measured.push_back(speed.value());
  }
  auto estimate = estimate_transfer(inputs);
  if (!estimate.ok())
    return fail(estimate.error(), kExitUsage);
  if (flag(parsed, "json")) {
    std::cout << tool_json::file_transfer(estimate.value()) << '\n';
    return kExitSuccess;
  }
  if (flag(parsed, "email")) {
    const TransferEmail email = transfer_email(estimate.value());
    std::cout << email.subject << "\n\n" << email.body << '\n';
    return kExitSuccess;
  }
  std::cout << transfer_text(estimate.value());
  return kExitSuccess;
}

int command_network(const ParsedArguments& parsed, const CancellationToken& cancel) {
  if (parsed.positionals.size() < 2U) {
    std::cerr << "network requires test, listen, udp, tls, service-channel, throughput, transfer-time, adapters, local-ports, presets or "
                 "name\n";
    return kExitUsage;
  }
  if (parsed.positionals[1] == "service-channel") {
    ServiceChannelOptions channel;
    channel.product = option(parsed, "product").value_or("agent");
    if (const auto folder = option(parsed, "folder"))
      channel.log_folder = argument_path(*folder);
    if (const auto hours = option(parsed, "hours")) {
      auto parsed_hours = parse_integer<int>(*hours, "hours");
      if (!parsed_hours.ok())
        return fail(parsed_hours.error(), kExitUsage);
      channel.hours = parsed_hours.value();
    }
    channel.live = !flag(parsed, "logs-only");
    const ServiceChannelReport report = run_service_channel_test(channel, cancel);
    bool failed = false;
    for (const ServiceChannelRow& row : report.rows) {
      std::cout << row.status << " | " << row.layer << " | " << row.check << " | " << row.detail << '\n';
      failed = failed || row.status == "Fail";
    }
    std::cout << report.summary << '\n';
    return failed ? kExitFindings : kExitSuccess;
  }
  if (parsed.positionals[1] == "local-ports")
    return command_network_local_ports(parsed);
  if (parsed.positionals[1] == "transfer-time")
    return command_network_transfer_time(parsed, cancel);
  if (parsed.positionals[1] == "adapters")
    return command_network_adapters(parsed);
  if (parsed.positionals[1] == "presets")
    return command_network_presets();
  if (parsed.positionals[1] == "name")
    return command_network_name(parsed, cancel);
  if (parsed.positionals[1] == "interfaces") {
    auto interfaces = enumerate_network_interfaces();
    if (!interfaces.ok())
      return fail(interfaces.error());
    for (const auto& item : interfaces.value()) {
      std::cout << item.name << " | " << item.address_family << " | " << item.address
                << "/" << item.prefix_length
                << " | up=" << (item.up ? "yes" : "no")
                << " | default=" << (item.diagnostic_default ? "yes" : "no")
                << " | loopback=" << (item.loopback ? "yes" : "no")
                << " | virtual=" << (item.virtual_interface ? "yes" : "no")
                << " | vlan=" << (item.vlan_interface ? "yes" : "no")
                << " | team_bond=" << (item.team_or_bond ? "yes" : "no");
      if (!item.gateway.empty())
        std::cout << " | gateway=" << item.gateway;
      if (!item.members.empty()) {
        std::cout << " | members=";
        for (std::size_t index = 0; index < item.members.size(); ++index) {
          if (index != 0) std::cout << ',';
          std::cout << item.members[index];
        }
      }
      if (!item.description.empty() && item.description != item.name)
        std::cout << " | " << item.description;
      std::cout << '\n';
    }
    return kExitSuccess;
  }
  if (parsed.positionals[1] == "test") {
    const auto host = option(parsed, "host");
    const auto port_text = option(parsed, "port");
    if (!host || !port_text) {
      std::cerr << "network test requires --host and --port\n";
      return kExitUsage;
    }
    auto port = parse_integer<std::uint16_t>(*port_text, "port");
    if (!port.ok())
      return fail(port.error(), kExitUsage);
    std::uint64_t timeout_ms = 5000;
    if (const auto text = option(parsed, "timeout-ms")) {
      auto parsed_timeout = parse_integer<std::uint64_t>(*text, "timeout-ms");
      if (!parsed_timeout.ok())
        return fail(parsed_timeout.error(), kExitUsage);
      timeout_ms = parsed_timeout.value();
    }
    TcpPortTestOptions test_options;
    test_options.host = *host;
    test_options.port = port.value();
    test_options.timeout = std::chrono::milliseconds(timeout_ms);
    test_options.source_address = option(parsed, "source").value_or("");
    test_options.source_interface = option(parsed, "interface").value_or("");
    test_options.detect_sat_listener = !flag(parsed, "no-sat-handshake");
    if (flag(parsed, "no-sat-payload")) {
      test_options.sat_payload_bytes = 0;
    } else if (const auto payload_text = option(parsed, "sat-payload")) {
      auto payload = parse_transfer_size(*payload_text);
      if (!payload.ok())
        return fail(payload.error(), kExitUsage);
      test_options.sat_payload_bytes = payload.value();
    }
    if (flag(parsed, "all-interfaces")) {
      auto matrix = test_tcp_across_interfaces(test_options, cancel, progress_text,
                                               flag(parsed, "include-virtual"));
      finish_progress_line();
      if (!matrix.ok())
        return fail(matrix.error());
      bool any_connected = false;
      bool payload_finding = false;
      for (const auto& entry : matrix.value()) {
        std::cout << "INTERFACE " << entry.interface.name
                  << " source=" << entry.interface.address
                  << " family=" << entry.interface.address_family
                  << " gateway=" << (entry.interface.gateway.empty() ? "(none/unknown)" : entry.interface.gateway)
                  << " vlan=" << (entry.interface.vlan_interface ? "yes" : "no")
                  << " team_bond=" << (entry.interface.team_or_bond ? "yes" : "no") << '\n';
        for (const auto& attempt : entry.test.attempts) {
          any_connected = any_connected || attempt.connected;
          if (attempt.sat_listener_detected && attempt.sat_payload_bytes > 0 &&
              !attempt.sat_payload_validated)
            payload_finding = true;
          std::cout << "  " << attempt.address << " | "
                    << (attempt.connected ? "connected" : "failed")
                    << " | local=" << attempt.local_address
                    << " | " << attempt.elapsed_ms << " ms";
          if (attempt.sat_listener_detected)
            std::cout << " | sat_test_id=" << attempt.sat_test_id
                      << " | payload=" << (attempt.sat_payload_validated ? "verified" : "not-verified");
          std::cout << " | " << attempt.message << '\n';
        }
      }
      return any_connected && !payload_finding ? kExitSuccess : kExitFindings;
    }

    auto result = test_tcp_port(test_options, cancel, progress_text);
    finish_progress_line();
    if (!result.ok())
      return fail(result.error());
    std::cout << (result.value().connected ? "CONNECTED" : "FAILED")
              << " host=" << result.value().host << " port=" << result.value().port
              << " address=" << result.value().connected_address
              << " elapsed_ms=" << result.value().elapsed_ms << '\n';
    if (result.value().dns_lookup_required)
      std::cout << "  resolved=" << joined(result.value().resolved_addresses, ",")
                << (result.value().name_source.empty() ? std::string() : " source=" + result.value().name_source)
                << '\n';
    for (const auto& attempt : result.value().attempts) {
      std::cout << "  " << attempt.address << " | " << (attempt.connected ? "connected" : "failed")
                << " | source=" << (attempt.source_address.empty() ? "automatic" : attempt.source_address)
                << " | local=" << attempt.local_address
                << " | native=" << attempt.native_code << " | " << attempt.elapsed_ms << " ms";
      if (attempt.sat_listener_detected) {
        std::cout << " | sat_listener=yes | test_id=" << attempt.sat_test_id
                  << " | handshake=" << (attempt.sat_handshake_completed ? "ok" : "failed");
        if (attempt.sat_payload_bytes > 0) {
          std::cout << " | payload_bytes=" << attempt.sat_payload_bytes
                    << " | payload=" << (attempt.sat_payload_validated ? "verified" : "failed")
                    << " | sha256=" << attempt.sat_payload_sha256
                    << " | rate=" << format_transfer_rate(attempt.sat_payload_bits_per_second);
        }
      }
      std::cout << " | " << attempt.message << '\n';
    }
    bool payload_finding = false;
    for (const auto& attempt : result.value().attempts) {
      if (attempt.sat_listener_detected && attempt.sat_payload_bytes > 0 &&
          !attempt.sat_payload_validated)
        payload_finding = true;
    }
    return result.value().connected && !payload_finding ? kExitSuccess : kExitFindings;
  }
  if (parsed.positionals[1] == "listen") {
    const auto port_text = option(parsed, "port");
    if (!port_text) {
      std::cerr << "network listen requires --port\n";
      return kExitUsage;
    }
    auto port = parse_integer<std::uint16_t>(*port_text, "port");
    if (!port.ok())
      return fail(port.error(), kExitUsage);
    std::uint64_t seconds = 30;
    if (const auto text = option(parsed, "seconds")) {
      auto parsed_seconds = parse_integer<std::uint64_t>(*text, "seconds");
      if (!parsed_seconds.ok())
        return fail(parsed_seconds.error(), kExitUsage);
      seconds = parsed_seconds.value();
    }
    TcpListenerOptions listener_options;
    listener_options.port = port.value();
    listener_options.duration = std::chrono::seconds(seconds);
    listener_options.banner = option(parsed, "banner").value_or(std::string(kDefaultListenerBanner));
    listener_options.accept_multiple = flag(parsed, "multiple");
    auto result = listen_tcp(listener_options, cancel, progress_text);
    finish_progress_line();
    if (!result.ok())
      return fail(result.error());
    std::cout << "Accepted connections: " << result.value().connections.size() << '\n';
    for (const auto& connection : result.value().connections) {
      std::cout << connection.accepted_utc
                << " local=" << connection.local_address << ':' << connection.local_port
                << " remote=" << connection.remote_address << ':' << connection.remote_port;
      if (connection.sat_throughput) {
        std::cout << " throughput_test=yes bytes=" << connection.sat_payload_bytes
                  << " received=" << (connection.sat_payload_validated ? "all" : "partial")
                  << " seconds=" << connection.sat_payload_seconds;
      } else if (connection.sat_probe) {
        std::cout << " sat_probe=yes test_id=" << connection.sat_test_id
                  << " payload_bytes=" << connection.sat_payload_bytes
                  << " payload=" << (connection.sat_payload_validated ? "verified" : "not-verified")
                  << " sha256=" << connection.sat_payload_sha256;
      }
      std::cout << '\n';
    }
    if (result.value().cancelled)
      return kExitCancelled;
    return result.value().connections.empty() ? kExitFindings : kExitSuccess;
  }
  if (parsed.positionals[1] == "udp") {
    if (parsed.positionals.size() < 3U ||
        (parsed.positionals[2] != "test" && parsed.positionals[2] != "listen")) {
      std::cerr << "network udp requires test or listen\n";
      return kExitUsage;
    }
    const auto port_text = option(parsed, "port");
    if (!port_text) {
      std::cerr << "network udp requires --port\n";
      return kExitUsage;
    }
    auto port = parse_integer<std::uint16_t>(*port_text, "port");
    if (!port.ok())
      return fail(port.error(), kExitUsage);
    if (parsed.positionals[2] == "listen") {
      std::uint64_t seconds = 30;
      if (const auto text = option(parsed, "seconds")) {
        auto parsed_seconds = parse_integer<std::uint64_t>(*text, "seconds");
        if (!parsed_seconds.ok()) return fail(parsed_seconds.error(), kExitUsage);
        seconds = parsed_seconds.value();
      }
      UdpListenerOptions udp;
      udp.port = port.value();
      udp.duration = std::chrono::seconds(seconds);
      udp.accept_multiple = !flag(parsed, "single");
      auto result = listen_udp(udp, cancel, progress_text);
      finish_progress_line();
      if (!result.ok()) return fail(result.error());
      for (const auto& datagram : result.value().datagrams) {
        std::cout << datagram.received_utc << " local=" << datagram.local_address << ':' << datagram.local_port
                  << " remote=" << datagram.remote_address << ':' << datagram.remote_port
                  << " bytes=" << datagram.bytes;
        if (datagram.sat_probe)
          std::cout << " sat_probe=yes test_id=" << datagram.sat_test_id
                    << " ack=" << (datagram.sat_ack_sent ? "sent" : "failed");
        std::cout << '\n';
      }
      if (result.value().cancelled) return kExitCancelled;
      return result.value().datagrams.empty() ? kExitFindings : kExitSuccess;
    }

    const auto host = option(parsed, "host");
    if (!host) {
      std::cerr << "network udp test requires --host\n";
      return kExitUsage;
    }
    std::uint64_t timeout_ms = 2000;
    if (const auto text = option(parsed, "timeout-ms")) {
      auto parsed_timeout = parse_integer<std::uint64_t>(*text, "timeout-ms");
      if (!parsed_timeout.ok()) return fail(parsed_timeout.error(), kExitUsage);
      timeout_ms = parsed_timeout.value();
    }
    UdpPortTestOptions udp;
    udp.host = *host;
    udp.port = port.value();
    udp.timeout = std::chrono::milliseconds(timeout_ms);
    udp.source_address = option(parsed, "source").value_or("");
    udp.source_interface = option(parsed, "interface").value_or("");
    udp.mode = flag(parsed, "sat-listener") ? UdpProbeMode::sat_listener
                                            : UdpProbeMode::generic_datagram;
    if (flag(parsed, "all-interfaces")) {
      auto matrix = test_udp_across_interfaces(udp, cancel, progress_text,
                                               flag(parsed, "include-virtual"));
      finish_progress_line();
      if (!matrix.ok()) return fail(matrix.error());
      bool verified = false;
      bool sent = false;
      bool response = false;
      for (const auto& entry : matrix.value()) {
        std::cout << "INTERFACE " << entry.interface.name << " source=" << entry.interface.address
                  << " gateway=" << (entry.interface.gateway.empty() ? "(none/unknown)" : entry.interface.gateway)
                  << '\n';
        for (const auto& attempt : entry.test.attempts) {
          sent = sent || attempt.datagram_sent;
          response = response || attempt.response_received;
          verified = verified || attempt.sat_acknowledged;
          std::cout << "  " << attempt.address << " | sent=" << (attempt.datagram_sent ? "yes" : "no")
                    << " | ack=" << (attempt.sat_acknowledged ? "yes" : "no")
                    << " | " << attempt.message << '\n';
        }
      }
      if (udp.mode == UdpProbeMode::sat_listener)
        return verified ? kExitSuccess : kExitFindings;
      // A successful send only proves the local UDP stack accepted the datagram.
      // Without an application response, report a diagnostic finding/indeterminate state.
      return response ? kExitSuccess : kExitFindings;
    }
    auto result = test_udp_port(udp, cancel, progress_text);
    finish_progress_line();
    if (!result.ok()) return fail(result.error());
    if (result.value().dns_lookup_required)
      std::cout << "resolved=" << joined(result.value().resolved_addresses, ",")
                << (result.value().name_source.empty() ? std::string() : " source=" + result.value().name_source)
                << '\n';
    bool verified = false;
    bool sent = false;
    bool response = false;
    for (const auto& attempt : result.value().attempts) {
      sent = sent || attempt.datagram_sent;
      response = response || attempt.response_received;
      verified = verified || attempt.sat_acknowledged;
      std::cout << attempt.address << " | source="
                << (attempt.source_address.empty() ? "automatic" : attempt.source_address)
                << " | local=" << attempt.local_address
                << " | sent=" << (attempt.datagram_sent ? "yes" : "no")
                << " | response=" << (attempt.response_received ? "yes" : "no")
                << " | sat_ack=" << (attempt.sat_acknowledged ? "yes" : "no")
                << " | " << attempt.message << '\n';
    }
    if (udp.mode == UdpProbeMode::sat_listener)
      return verified ? kExitSuccess : kExitFindings;
    // Generic UDP never reports PASS solely because sendto() succeeded. A reply
    // is required for success; otherwise the result is explicitly indeterminate.
    (void)sent;
    return response ? kExitSuccess : kExitFindings;
  }
  if (parsed.positionals[1] == "tls") {
    const auto host = option(parsed, "host");
    const auto port_text = option(parsed, "port");
    if (!host || !port_text) {
      std::cerr << "network tls requires --host and --port\n";
      return kExitUsage;
    }
    auto port = parse_integer<std::uint16_t>(*port_text, "port");
    if (!port.ok())
      return fail(port.error(), kExitUsage);
    std::uint64_t timeout_ms = 10000;
    if (const auto text = option(parsed, "timeout-ms")) {
      auto parsed_timeout = parse_integer<std::uint64_t>(*text, "timeout-ms");
      if (!parsed_timeout.ok())
        return fail(parsed_timeout.error(), kExitUsage);
      timeout_ms = parsed_timeout.value();
    }

    const auto print_tls_result = [&](const TlsProbeResult& value,
                                      std::string_view label,
                                      std::string_view interface_label) -> int {
      std::cout << "TLS PROBE " << label;
      if (!interface_label.empty())
        std::cout << " | interface=" << interface_label;
      std::cout << '\n'
                << "  tcp=" << (value.tcp_connected ? "connected" : "failed")
                << " address=" << value.connected_address
                << " source=" << (value.source_address.empty() ? "automatic" : value.source_address)
                << " local=" << value.local_address
                << " tcp_ms=" << value.tcp_elapsed_ms << '\n'
                << "  ClientHello=" << (value.client_hello_observed ? "observed" : "not-observed")
                << " bytes=" << value.client_hello_bytes
                << " sni=" << value.requested_server_name << '\n'
                << "  ServerHello=" << (value.server_hello_observed ? "observed" : "not-observed")
                << " bytes=" << value.server_hello_bytes
                << " version=" << value.negotiated_version
                << " cipher=" << value.negotiated_cipher_suite
                << " cipher_match=" << (value.negotiated_cipher_was_offered ? "yes" : "no") << '\n'
                << "  client_certificate_requested="
                << (value.server_requested_client_certificate ? "yes" : "no") << '\n'
                << "  handshake=" << (value.handshake_completed ? "complete" : "incomplete")
                << " tls_ms=" << value.tls_elapsed_ms;
      if (!value.failure_stage.empty() || !value.failure_reason.empty())
        std::cout << " stage=" << value.failure_stage << " reason=" << value.failure_reason;
      std::cout << '\n';
      if (!value.certificate.subject.empty()) {
        std::cout << "  certificate_subject=" << value.certificate.subject << '\n'
                  << "  certificate_issuer=" << value.certificate.issuer << '\n'
                  << "  certificate_valid_from=" << value.certificate.valid_from << '\n'
                  << "  certificate_valid_until=" << value.certificate.valid_until << '\n'
                  << "  certificate_sha1=" << value.certificate.sha1_thumbprint << '\n'
                  << "  certificate_sha256=" << value.certificate.sha256_fingerprint << '\n'
                  << "  hostname_match="
                  << (value.certificate.hostname_checked
                          ? (value.certificate.hostname_matches ? "yes" : "no")
                          : "not-checked") << '\n'
                  << "  system_trust="
                  << (value.certificate.system_trust_checked
                          ? (value.certificate.system_trusted ? "trusted" : "not-trusted")
                          : "not-checked")
                  << " detail=" << value.certificate.system_trust_detail << '\n';
        if (value.certificate.expected_fingerprint_provided) {
          std::cout << "  expected_fingerprint_match="
                    << (value.certificate.expected_fingerprint_matches ? "yes" : "no") << '\n';
        } else {
          std::cout << "  expected_fingerprint_match=not-checked (provide --expected-fingerprint for pinning)\n";
        }
        for (const auto& san : value.certificate.subject_alt_names)
          std::cout << "  SAN=" << san << '\n';
      }
      std::cout << "  offered_ciphers=" << value.offered_cipher_suites.size() << '\n';
      for (const auto& cipher : value.offered_cipher_suites)
        std::cout << "    " << cipher << '\n';
      return value.handshake_completed ? kExitSuccess : kExitFindings;
    };

    const auto run_one = [&](TlsProbeVersion version, std::string_view label) -> int {
      TlsProbeOptions tls;
      tls.host = *host;
      tls.port = port.value();
      tls.server_name = option(parsed, "sni").value_or(*host);
      tls.source_address = option(parsed, "source").value_or("");
      tls.source_interface = option(parsed, "interface").value_or("");
      tls.expected_fingerprint = option(parsed, "expected-fingerprint").value_or("");
      tls.timeout = std::chrono::milliseconds(timeout_ms);
      tls.version = version;
      tls.check_system_trust = !flag(parsed, "no-system-trust");
      if (flag(parsed, "all-interfaces")) {
        auto matrix = test_tls_across_interfaces(tls, cancel, progress_text, flag(parsed, "include-virtual"));
        finish_progress_line();
        if (!matrix.ok())
          return fail(matrix.error());
        bool completed = false;
        for (const auto& item : matrix.value()) {
          const std::string interface_label = item.interface.name + " [" + item.interface.address + "]";
          std::cout << "INTERFACE " << interface_label;
          if (!item.interface.gateway.empty())
            std::cout << " gateway=" << item.interface.gateway;
          std::cout << '\n';
          completed = print_tls_result(item.test, label, interface_label) == kExitSuccess || completed;
        }
        return completed ? kExitSuccess : kExitFindings;
      }
      auto result = test_tls_handshake(tls, cancel, progress_text);
      finish_progress_line();
      if (!result.ok())
        return fail(result.error());
      return print_tls_result(result.value(), label, {});
    };

    if (flag(parsed, "compare-versions")) {
      const int tls12 = run_one(TlsProbeVersion::tls12_only, "TLS 1.2 only");
      const int tls13 = run_one(TlsProbeVersion::tls13_only, "TLS 1.3 only");
      if (tls12 == kExitSuccess || tls13 == kExitSuccess)
        return kExitSuccess;
      return kExitFindings;
    }

    TlsProbeVersion version = TlsProbeVersion::automatic;
    if (const auto version_text = option(parsed, "version")) {
      if (*version_text == "1.2" || *version_text == "tls1.2")
        version = TlsProbeVersion::tls12_only;
      else if (*version_text == "1.3" || *version_text == "tls1.3")
        version = TlsProbeVersion::tls13_only;
      else if (*version_text != "auto") {
        std::cerr << "--version must be auto, 1.2, or 1.3\n";
        return kExitUsage;
      }
    }
    return run_one(version, "requested mode");
  }
  if (parsed.positionals[1] == "throughput") {
    if (parsed.positionals.size() < 3U ||
        (parsed.positionals[2] != "client" && parsed.positionals[2] != "server")) {
      std::cerr << "network throughput requires client or server\n";
      return kExitUsage;
    }
    TcpThroughputOptions throughput_options;
    throughput_options.server = parsed.positionals[2] == "server";
    throughput_options.host = option(parsed, "host").value_or("");
    if (!throughput_options.server && throughput_options.host.empty()) {
      std::cerr << "network throughput client requires --host\n";
      return kExitUsage;
    }
    if (const auto port_text = option(parsed, "port")) {
      auto port = parse_integer<std::uint16_t>(*port_text, "port");
      if (!port.ok())
        return fail(port.error(), kExitUsage);
      throughput_options.port = port.value();
    }
    if (throughput_options.server) {
      throughput_options.transfer_bytes = 0;
    } else {
      const std::string transfer_text = option(parsed, "bytes").value_or("1G");
      auto transfer = parse_transfer_size(transfer_text);
      if (!transfer.ok())
        return fail(transfer.error(), kExitUsage);
      throughput_options.transfer_bytes = transfer.value();
    }
    if (const auto timeout_text = option(parsed, "connect-timeout-ms")) {
      auto timeout = parse_integer<std::uint64_t>(*timeout_text, "connect-timeout-ms");
      if (!timeout.ok())
        return fail(timeout.error(), kExitUsage);
      throughput_options.connect_timeout = std::chrono::milliseconds(timeout.value());
    }
    if (const auto timeout_text = option(parsed, "idle-timeout-ms")) {
      auto timeout = parse_integer<std::uint64_t>(*timeout_text, "idle-timeout-ms");
      if (!timeout.ok())
        return fail(timeout.error(), kExitUsage);
      throughput_options.idle_timeout = std::chrono::milliseconds(timeout.value());
    }
    auto result = run_tcp_throughput(throughput_options, cancel, progress_text);
    finish_progress_line();
    if (!result.ok())
      return fail(result.error());
    std::cout << (result.value().server ? "SERVER" : "CLIENT")
              << " peer=" << result.value().peer_address
              << " port=" << result.value().port
              << " bytes=" << result.value().transferred_bytes
              << " seconds=" << result.value().elapsed_seconds
              << " rate=" << format_transfer_rate(result.value().bits_per_second) << '\n';
    return result.value().cancelled ? kExitCancelled : kExitSuccess;
  }
  return kExitUsage;
}

// Reviews Customer/Lab tool output that Log Collection already packages into the bundle, so
// results recorded in structured tool artifacts do not need to be retyped into the case note by
// hand.
int command_tools_review(const ParsedArguments& parsed) {
  const auto source = option(parsed, "source");
  if (!source.has_value() || source->empty()) {
    std::cerr << "tools review requires --source DIR (a bundle Tools directory, a Log-Collections "
                 "tree, or any parent of them)\n";
    return 64;
  }
  auto loaded = load_tool_evidence(argument_path(*source));
  if (!loaded.ok()) {
    std::cerr << "tools review failed: " << loaded.error().message << '\n';
    return 74;
  }
  const auto evidence = std::move(loaded).value();
  const std::string machine = option(parsed, "machine").value_or("");

  if (flag(parsed, "note")) {
    std::cout << render_tool_timeline_note(evidence, machine);
    return 0;
  }

  if (flag(parsed, "json")) {
    const auto timeline = build_tool_timeline(evidence);
    std::cout << "[";
    bool first = true;
    for (const auto& entry : timeline) {
      if (!machine.empty() && ascii_lower(entry.host) != ascii_lower(machine)) continue;
      if (!first) std::cout << ',';
      first = false;
      std::cout << "{\"utc\":\"" << json_escape(entry.utc_text) << "\",\"host\":\""
                << json_escape(entry.host) << "\",\"tool\":\"" << json_escape(entry.tool)
                << "\",\"execution_status\":\"" << json_escape(entry.status)
                << "\",\"diagnostic_status\":\"" << json_escape(entry.diagnostic)
                << "\",\"findings\":" << entry.finding_count << ",\"summary\":\""
                << json_escape(entry.summary) << "\",\"source\":\""
                << json_escape(path_to_utf8(entry.source)) << "\"}";
    }
    std::cout << "]\n";
    return 0;
  }

  const auto machines = group_tool_evidence_by_machine(evidence);
  if (machines.empty()) {
    std::cout << "No SAT tool evidence found under " << *source << '\n';
    return 0;
  }
  for (const auto& host : machines) {
    if (!machine.empty() && ascii_lower(host.host) != ascii_lower(machine)) continue;
    std::cout << host.host << " | " << host.evidence.size() << " tool run(s)";
    if (host.finding_count > 0) std::cout << " | " << host.finding_count << " with findings";
    std::cout << '\n';
    for (const auto& item : host.evidence) {
      std::cout << "  " << item.manifest.started_utc << " | " << item.tool() << " | "
                << to_string(item.manifest.execution_status) << " | "
                << to_string(item.manifest.diagnostic_status);
      const auto findings = item.finding_rows();
      if (!findings.empty()) std::cout << " | " << findings.size() << " finding row(s)";
      std::cout << '\n';
      if (!item.manifest.summary.empty())
        std::cout << "      " << item.manifest.summary << '\n';
    }
  }
  return 0;
}

// Command-line entry point for the guided diagnostics catalogue (`tools` handles collected
// artifacts; `diagnostics` reports the host environment).
//
//   guided scenarios                 - the scenarios for this host
//   guided run --scenario <id> [--input NAME=VALUE ...] [--continue]
int command_guided(const ParsedArguments& parsed, const CancellationToken& cancel) {
  if (parsed.positionals.size() < 2U || parsed.positionals[1] == "list" || parsed.positionals[1] == "scenarios") {
    for (const ScenarioDefinition& scenario : available_scenarios(native_product_discovery_context())) {
      std::cout << scenario.id << '\t' << scenario.title << '\n';
      for (const ScenarioInput& input : scenario.inputs) {
        std::cout << "    --input " << input.id << "=VALUE\t" << input.label;
        if (!input.default_value.empty())
          std::cout << " (default " << input.default_value << ')';
        else if (input.optional)
          std::cout << " (optional)";
        std::cout << '\n';
      }
      for (const std::string& line : scenario.setup)
        std::cout << "    setup: " << line << '\n';
    }
    return kExitSuccess;
  }
  if (parsed.positionals[1] != "run") {
    std::cerr << "guided requires scenarios or run\n";
    return kExitUsage;
  }
  // --id takes an old guided diagnostic id; it runs the scenario that replaced it.
  const std::string id = option(parsed, "scenario").value_or(option(parsed, "id").value_or(""));
  const ScenarioDefinition* scenario = id.empty() ? nullptr : find_scenario(id);
  if (scenario == nullptr) {
    std::cerr << "guided run requires --scenario ID (see: guided scenarios)\n";
    return kExitUsage;
  }
  std::map<std::string, std::string> inputs;
  for (const std::string& pair : options(parsed, "input")) {
    const std::size_t equals = pair.find('=');
    if (equals == std::string::npos) {
      std::cerr << "guided run --input takes NAME=VALUE\n";
      return kExitUsage;
    }
    inputs[pair.substr(0, equals)] = pair.substr(equals + 1U);
  }
  if (const auto machine = option(parsed, "machine"))
    inputs["target"] = *machine;
  for (const ScenarioInput& input : scenario->inputs) {
    const auto given = inputs.find(input.id);
    if (!input.optional && input.default_value.empty() && (given == inputs.end() || trim(given->second).empty())) {
      std::cerr << "guided run --scenario " << scenario->id << " requires --input " << input.id << "=VALUE ("
                << input.label << ")\n";
      return kExitUsage;
    }
  }
  const ScenarioResult result = run_scenario(scenario->id, inputs, flag(parsed, "continue"), cancel, progress_text);
  finish_progress_line();
  for (const ScenarioStepResult& step : result.steps) {
    std::cout << step.status << " | Step " << step.number << " | " << step.title;
    if (!step.found.empty())
      std::cout << " | " << step.found;
    std::cout << '\n';
  }
  std::cout << '\n' << result.case_note;
  return result.overall == "Fail" ? kExitFindings : kExitSuccess;
}

// tools run --id ID [--FIELD VALUE ...]: an Integrations guided run from the command line, with the
// same form and argument mapping as the Run window. The storage test runs through storage
// speed-test --custom, and Packet Monitor's elevated capture from the Integrations page.
int command_tools_run(const ParsedArguments& parsed, const CancellationToken& cancel) {
  const auto id = option(parsed, "id");
  const ToolRunProfile* profile = id ? find_tool_run_profile(*id) : nullptr;
  if (profile == nullptr || tool_run_is_storage_test(*id) || *id == "pktmon") {
    std::cerr << "tools run requires --id iperf3, etl2pcapng or tcpdump (storage speed-test --custom runs DiskSpd "
                 "and fio)\n";
    return kExitUsage;
  }
  // Each field's option, read by name so the registry sees it; a field left out takes its default.
  const std::map<std::string, std::optional<std::string>> given{
      {"mode", option(parsed, "mode")},           {"host", option(parsed, "host")},
      {"direction", option(parsed, "direction")}, {"streams", option(parsed, "streams")},
      {"stream_count", option(parsed, "stream-count")}, {"duration", option(parsed, "duration")},
      {"port", option(parsed, "port")},           {"protocol", option(parsed, "protocol")},
      {"interface", option(parsed, "interface")}, {"count", option(parsed, "count")},
      {"input", option(parsed, "input")},         {"output", option(parsed, "output")}};
  std::map<std::string, std::string> values;
  for (const ToolRunField& field : profile->fields) {
    const auto found = given.find(field.key);
    std::string value = found != given.end() && found->second ? *found->second : field.default_value;
    if (field.kind == ToolRunField::Kind::choice) {
      const auto choice = std::find_if(field.choices.begin(), field.choices.end(),
                                       [&](const std::string& item) { return ascii_lower(item) == ascii_lower(value); });
      if (choice == field.choices.end()) {
        std::cerr << tool_run_option(field.key) << " takes one of:";
        for (const std::string& item : field.choices)
          std::cerr << ' ' << item;
        std::cerr << '\n';
        return kExitUsage;
      }
      value = *choice;
    }
    values[field.key] = value;
  }
  std::filesystem::path root = argument_path(option(parsed, "root").value_or(""));
  if (root.empty())
    root = path_from_utf8(current_executable_path()).parent_path() / "Tools";
  std::filesystem::path executable;
  for (const ExternalToolStatus& status : inspect_external_tools(root)) {
    if (status.definition.id == *id && status.availability == ToolAvailability::available)
      executable = status.resolved_path;
  }
  if (executable.empty()) {
    std::cerr << *id << " is not in " << path_to_utf8(root) << " or on this machine: tools source --id " << *id
              << " opens where it comes from, and the Integrations page acquires it.\n";
    return kExitFailure;
  }
  const auto value_of = [&](const std::string& key) {
    const auto found = values.find(key);
    return found == values.end() ? std::string() : found->second;
  };
  ProcessOptions run;
  run.executable = executable;
  run.arguments = build_tool_run_arguments(*id, value_of);
  run.working_directory = executable.parent_path();
  // A server or a capture runs until it ends or Ctrl+C stops it.
  run.timeout = std::chrono::hours(24);
  run.merge_standard_error = true;
  std::cerr << "> " << command_line_text(path_to_utf8(executable), run.arguments) << '\n';
  auto result = run_process_capture(run, cancel);
  if (!result.ok())
    return fail(result.error());
  std::cout << result.value().output;
  if (result.value().cancelled)
    return kExitCancelled;
  return result.value().exit_code == 0 ? kExitSuccess : kExitFailure;
}

int command_tools(const ParsedArguments& parsed, const CancellationToken& cancel) {
  if (parsed.positionals.size() > 1U && parsed.positionals[1] == "review")
    return command_tools_review(parsed);
  if (parsed.positionals.size() > 1U && parsed.positionals[1] == "run")
    return command_tools_run(parsed, cancel);
  const std::filesystem::path root = argument_path(option(parsed, "root").value_or(""));
  if (parsed.positionals.size() < 2U || parsed.positionals[1] == "status") {
    auto statuses = inspect_external_tools(root);
    statuses.erase(std::remove_if(statuses.begin(), statuses.end(), [](const auto& status) {
      return status.availability == ToolAvailability::unsupported;
    }), statuses.end());
    if (flag(parsed, "json")) {
      std::cout << "[";
      for (std::size_t index = 0; index < statuses.size(); ++index) {
        const auto& status = statuses[index];
        if (index != 0U)
          std::cout << ',';
        std::cout << "{\"id\":\"" << json_escape(status.definition.id) << "\",\"name\":\""
                  << json_escape(status.definition.name) << "\",\"status\":\""
                  << to_string(status.availability) << "\",\"path\":\""
                  << json_escape(path_to_utf8(status.resolved_path)) << "\",\"optional\":"
                  << (status.definition.optional_integration ? "true" : "false")
                  << ",\"native_alternative\":\""
                  << json_escape(status.definition.native_alternative) << "\"}";
      }
      std::cout << "]\n";
    } else {
      for (const auto& status : statuses) {
        std::cout << status.definition.id << " | " << status.definition.name << " | "
                  << to_string(status.availability) << " | " << status.detail;
        if (!status.definition.native_alternative.empty())
          std::cout << " | native: " << status.definition.native_alternative;
        std::cout << '\n';
      }
    }
    return kExitSuccess;
  }
  if (parsed.positionals[1] == "source") {
    const auto id = option(parsed, "id");
    if (!id) {
      std::cerr << "tools source requires --id\n";
      return kExitUsage;
    }
    const Status status = open_external_tool_source(*id);
    return status.ok() ? kExitSuccess : fail(status.error());
  }
  return kExitUsage;
}


int command_products_detect(const ParsedArguments& parsed) {
  const auto context = native_product_discovery_context();
  const auto products = detect_products(context);
  if (flag(parsed, "json")) {
    std::cout << "{\"platform\":\"" << json_escape(to_string(context.platform))
              << "\",\"products\":[";
    for (std::size_t index = 0; index < products.size(); ++index) {
      if (index != 0U) std::cout << ',';
      const auto& product = products[index];
      std::cout << "{\"id\":\"" << json_escape(product.definition.id)
                << "\",\"name\":\"" << json_escape(product.definition.display_name)
                << "\",\"role\":\"" << json_escape(product.definition.role)
                << "\",\"evidence\":[";
      for (std::size_t evidence = 0; evidence < product.evidence_paths.size(); ++evidence) {
        if (evidence != 0U) std::cout << ',';
        std::cout << '"' << json_escape(path_to_utf8(product.evidence_paths[evidence])) << '"';
      }
      std::cout << "]}";
    }
    std::cout << "]}\n";
  } else {
    std::cout << format_detected_products_report(products);
  }
  return kExitSuccess;
}

int command_logs_gather_universal(const ParsedArguments& parsed, const CancellationToken& cancel) {
  const auto output = option(parsed, "output");
  if (!output) {
    std::cerr << "logs gather requires --output DIR\n";
    return kExitUsage;
  }
  UniversalCollectionOptions options;
  options.output_root = argument_path(*output);
  options.create_archive = !flag(parsed, "no-archive");
  // The kept tool output, as the window's Log Collection takes it: Log-Collections\Tools beside the
  // program, archived with the logs and removed after a finished archive.
  options.tool_output_directory = path_from_utf8(current_executable_path()).parent_path() / "Log-Collections" / "Tools";
  options.include_tool_output_logs = true;
  options.cleanup_tool_output_after_archive = options.create_archive;
  options.include_third_party_error_logs = !flag(parsed, "no-third-party-errors");
  options.include_platform_context = !flag(parsed, "no-platform-context");
  options.include_official_product_exporters = flag(parsed, "official-exporters");
  // --products and --days carry the engineer's product selection and age window into a CLI
  // collection run, including an elevated re-run the GUI itself starts, so the elevated run
  // matches the original request instead of collecting every detected product and every log.
  if (const auto products = option(parsed, "products"); products && !products->empty()) {
    std::string_view remaining(*products);
    while (!remaining.empty()) {
      const std::size_t comma = remaining.find(',');
      std::string id(trim(remaining.substr(0, comma)));
      if (!id.empty())
        options.selected_product_ids.push_back(std::move(id));
      if (comma == std::string_view::npos)
        break;
      remaining.remove_prefix(comma + 1U);
    }
    options.product_selection_explicit = !options.selected_product_ids.empty();
  }
  if (const auto days = option(parsed, "days"); days && !days->empty()) {
    const auto parsed_days = parse_integer<unsigned int>(*days, "days");
    if (!parsed_days.ok() || parsed_days.value() == 0U || parsed_days.value() > 3650U) {
      std::cerr << "logs gather --days expects a whole number from 1 to 3650\n";
      return kExitUsage;
    }
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    options.from_utc_ms =
        now_ms - static_cast<std::int64_t>(parsed_days.value()) * 24LL * 60LL * 60LL * 1000LL;
    options.to_utc_ms = now_ms;
  }
  auto result = collect_universal_support_bundle(options, cancel, progress_text);
  finish_progress_line();
  if (!result.ok()) return fail(result.error());
  std::cout << "Platform: " << to_string(result.value().platform) << '\n'
            << "Detected products/roles: " << result.value().detected_products.size() << '\n'
            << "Collection: " << path_to_utf8(result.value().logs.collection_directory) << '\n'
            << "Primary collected files: " << result.value().logs.copied_files << '\n'
            << "Official exporter runs: " << result.value().official_exporter_runs.size() << '\n'
            << "Sanitized third-party error logs: " << result.value().third_party_files.size() << '\n';
  if (result.value().time_base) {
    const auto clock = time_base_summary(*result.value().time_base);
    std::cout << "Clock: " << clock.zone << ", " << clock.difference << '\n';
  }
  if (!result.value().logs.archive_path.empty())
    std::cout << "Archive: " << path_to_utf8(result.value().logs.archive_path) << '\n';
  for (const auto& warning : result.value().warnings) std::cout << "Warning: " << warning << '\n';
  return cancel.is_cancelled() ? kExitCancelled : kExitSuccess;
}

int command_logs_collect(const ParsedArguments& parsed, const CancellationToken& cancel) {
  const auto profile_text = option(parsed, "profile");
  const auto output = option(parsed, "output");
  if (!profile_text || !output) {
    std::cerr << "logs collect requires --profile and --output\n";
    return kExitUsage;
  }
  auto profile = parse_log_collection_profile(*profile_text);
  if (!profile.ok())
    return fail(profile.error(), kExitUsage);
  LogCollectionOptions collection_options;
  collection_options.profile = profile.value();
  collection_options.output_root = argument_path(*output);
  for (const auto& source : options(parsed, "source")) {
    collection_options.sources.emplace_back(argument_path(source));
  }
  collection_options.create_archive = !flag(parsed, "no-archive");
  collection_options.include_windows_support_context = !flag(parsed, "no-windows-context");
  if (const auto from = option(parsed, "from")) {
    const auto parsed_time = parse_timestamp(*from, DateOrder::automatic);
    if (!parsed_time) {
      std::cerr << "Could not parse --from timestamp\n";
      return kExitUsage;
    }
    collection_options.from_utc_ms = parsed_time->unix_millis;
  }
  if (const auto to = option(parsed, "to")) {
    const auto parsed_time = parse_timestamp(*to, DateOrder::automatic);
    if (!parsed_time) {
      std::cerr << "Could not parse --to timestamp\n";
      return kExitUsage;
    }
    collection_options.to_utc_ms = parsed_time->unix_millis;
  }
  auto result = collect_logs(collection_options, cancel, progress_text);
  finish_progress_line();
  if (!result.ok())
    return fail(result.error());
  std::cout << "Collection: " << path_to_utf8(result.value().collection_directory) << '\n'
            << "Files: " << result.value().copied_files << '\n'
            << "Bytes: " << result.value().copied_bytes << '\n'
            << "Errors: " << result.value().error_count << '\n';
  if (result.value().windows_support_files != 0U) {
    std::cout << "Windows support context: " << result.value().windows_support_files
              << " raw evidence file(s) under " << path_to_utf8(result.value().windows_support_directory) << '\n';
  }
  if (!result.value().archive_path.empty()) {
    std::cout << "Archive: " << path_to_utf8(result.value().archive_path) << '\n';
  }
  return result.value().error_count == 0 ? kExitSuccess : kExitFindings;
}

std::string secret_from_environment(const char* name);

// WMI health: the Winmgmt service, the repository, a timed probe of each namespace and the recent
// WMI faults, grouped by stage, each row with its status after it.
int command_wmi_health(const ParsedArguments& parsed, const CancellationToken& cancel) {
  if (option(parsed, "user")) {
    std::cerr << "wmi health signs in as the account SAT runs as; --user is for wmi query\n";
    return kExitUsage;
  }
  WmiHealthOptions options;
  options.machine = option(parsed, "machine").value_or(".");
  const bool json = flag(parsed, "json");
  auto result = run_wmi_health(options, cancel, json ? ProgressCallback{} : ProgressCallback{progress_text});
  if (!json)
    finish_progress_line();
  if (!result.ok()) {
#ifdef _WIN32
    return fail(result.error(), cancel.is_cancelled() ? kExitCancelled : kExitFailure);
#else
    return fail(result.error(), kExitUnavailable);
#endif
  }
  const WmiHealthReport& report = result.value();
  const int exit_code = report.cancelled             ? kExitCancelled
                        : wmi_health_has_finding(report) ? kExitFindings
                                                         : kExitSuccess;
  if (json) {
    std::cout << tool_json::wmi_health(report) << '\n';
    return exit_code;
  }
  std::string current;
  for (const WmiHealthRow& row : report.rows) {
    if (row.stage != current) {
      std::cout << (current.empty() ? "" : "\n") << row.stage << '\n';
      current = row.stage;
    }
    std::cout << "  " << row.finding << "  [" << row.status << "]\n";
    if (!row.detail.empty())
      std::cout << "      " << row.detail << '\n';
  }
  std::cout << '\n' << wmi_health_summary(report) << '\n';
  return exit_code;
}

int command_wmi(const ParsedArguments& parsed, const CancellationToken& cancel) {
  if (parsed.positionals.size() >= 2U && parsed.positionals[1] == "health")
    return command_wmi_health(parsed, cancel);
#ifndef _WIN32
  static_cast<void>(parsed);
  static_cast<void>(cancel);
  Error error;
  error.component = "WMI";
  error.operation = "query";
  error.message = "WMI diagnostics require the Windows build.";
  return fail(error, kExitUnavailable);
#else
  if (parsed.positionals.size() < 2U || parsed.positionals[1] != "query") {
    std::cerr << "wmi requires query or health\n";
    return kExitUsage;
  }
  const std::string machine = option(parsed, "machine").value_or(".");
  WmiQueryOptions query_options;
  const std::string preset = ascii_lower(option(parsed, "preset").value_or("custom"));
  if (preset == "host")
    query_options = make_host_wmi_preset(machine);
  else if (preset == "cluster")
    query_options = make_cluster_wmi_preset(machine);
  else if (preset == "process" || preset == "processes")
    query_options = make_process_wmi_preset(machine);
  else {
    query_options.machine = machine;
    query_options.name_space = option(parsed, "namespace").value_or("root\\cimv2");
    const auto query = option(parsed, "query");
    if (!query) {
      std::cerr << "wmi query requires --query or --preset host|cluster|process\n";
      return kExitUsage;
    }
    query_options.query = *query;
  }
  // Another account, for another machine only. The password comes from SAT_WMI_PASSWORD, never from
  // the command line.
  if (const auto user = option(parsed, "user")) {
    if (is_this_computer(query_options.machine)) {
      std::cerr << "wmi query --user signs in to another machine: name it with --machine. On this machine WMI "
                   "signs in as the account SAT runs as.\n";
      return kExitUsage;
    }
    query_options.sign_in.user = *user;
    query_options.sign_in.password = secret_from_environment("SAT_WMI_PASSWORD");
    if (query_options.sign_in.password.empty()) {
      std::cerr << "wmi query --user reads the password from SAT_WMI_PASSWORD; set it first\n";
      return kExitUsage;
    }
  }
  auto rows = query_wmi(query_options, cancel, progress_text);
  forget_wmi_password(query_options.sign_in);
  finish_progress_line();
  // A namespace the machine does not have is an answer: its role is not installed.
  if (!rows.ok() && wmi_namespace_absent(rows.error())) {
    std::cout << "The namespace " << query_options.name_space << " is not on "
              << (is_this_computer(query_options.machine) ? std::string("this machine") : query_options.machine)
              << (query_options.name_space == "root\\MSCluster" ? ": no failover cluster role is installed." : ".")
              << '\n';
    return kExitSuccess;
  }
  if (!rows.ok()) {
    // The code's meaning from the WMI error list, after the failure as WMI reported it.
    const Error& error = rows.error();
    if (const std::string meaning = wmi_error_meaning(error.hresult); !meaning.empty()) {
      std::cerr << describe_error(error) << ". " << meaning << '\n';
      return kExitFailure;
    }
    return fail(error);
  }
  // Each object's properties in the order WMI gave them.
  for (const auto& row : rows.value()) {
    if (row.order.empty()) {
      for (const auto& [key, value] : row.values)
        std::cout << key << '=' << value << '\n';
    } else {
      for (const std::string& key : row.order) {
        const auto found = row.values.find(key);
        std::cout << key << '=' << (found == row.values.end() ? std::string() : found->second) << '\n';
      }
    }
    std::cout << "---\n";
  }
  return kExitSuccess;
#endif
}

int command_packet(const ParsedArguments& parsed, const CancellationToken& cancel) {
  if (parsed.positionals.size() < 2U)
    return kExitUsage;
  const std::string& action = parsed.positionals[1];
  if (action == "events") {
    const auto input = option(parsed, "input");
    if (!input) {
      std::cerr << "packet events requires --input capture.pcapng\n";
      return kExitUsage;
    }
    auto report = analyze_packet_capture(argument_path(*input), cancel);
    if (!report.ok())
      return fail(report.error());
    for (const auto& [label, value] : packet_event_summary(report.value()))
      std::cout << label << ": " << value << '\n';
    for (const PacketEvent& event : report.value().events)
      std::cout << packet_event_time(event.time_micros) << "  " << packet_event_name(event.kind) << "  "
                << event.connection << "  " << event.detail << '\n';
    return kExitSuccess;
  }
#ifndef _WIN32
  if (action != "convert") {
    static_cast<void>(cancel);
    Error error;
    error.component = "PacketCapture";
    error.operation = action;
    error.message = "Packet capture start/status/stop require the Windows build.";
    return fail(error, kExitUnavailable);
  }
#endif
  if (action == "start") {
    const auto output = option(parsed, "output");
    if (!output) {
      std::cerr << "packet start requires --output capture.etl\n";
      return kExitUsage;
    }
    PacketCaptureOptions packet_options;
    packet_options.output_etl = argument_path(*output);
    packet_options.ip_filter = option(parsed, "ip");
    if (const auto port_text = option(parsed, "port")) {
      auto port = parse_integer<std::uint16_t>(*port_text, "port");
      if (!port.ok())
        return fail(port.error(), kExitUsage);
      packet_options.port_filter = port.value();
    }
    packet_options.custom_start_arguments = options(parsed, "arg");
    auto backend = parse_packet_capture_backend(option(parsed, "backend").value_or("auto"));
    if (!backend.ok())
      return fail(backend.error(), kExitUsage);
    packet_options.backend = backend.value();
    const std::filesystem::path state_directory = option_path(parsed, "state-dir")
                                                      .value_or(packet_options.output_etl.parent_path() / "capture-state");
    auto result = packet_capture_start_owned(packet_options, state_directory, cancel, progress_text);
    finish_progress_line();
    if (!result.ok())
      return fail(result.error());
    std::cout << "session_id=" << result.value().session_id << '\n'
              << "backend=" << to_string(result.value().backend) << '\n'
              << "state=" << path_to_utf8(result.value().state_path) << '\n'
              << "output=" << path_to_utf8(result.value().output_etl) << '\n';
    return kExitSuccess;
  }
  if (action == "stop" || action == "status") {
    const auto state = option(parsed, "state");
    if (!state) {
      std::cerr << "packet " << action << " requires --state <SAT capture state file>\n";
      return kExitUsage;
    }
    auto session = load_packet_capture_session(*state);
    if (!session.ok())
      return fail(session.error(), kExitUsage);
    auto result = action == "stop" ? packet_capture_stop_owned(session.value(), cancel, progress_text)
                                   : packet_capture_status_owned(session.value(), cancel, progress_text);
    finish_progress_line();
    if (!result.ok())
      return fail(result.error());
    std::cout << result.value().output;
    if (action == "stop")
      std::cout << "\nstate=" << path_to_utf8(session.value().state_path) << '\n';
    return result.value().exit_code == 0 ? kExitSuccess : kExitFailure;
  }
  if (action == "convert") {
    const auto input = option(parsed, "input");
    const auto output = option(parsed, "output");
    if (!input || !output) {
      std::cerr << "packet convert requires --input and --output\n";
      return kExitUsage;
    }
    auto result = convert_packet_capture(
        argument_path(*input), argument_path(*output),
        argument_path(option(parsed, "tools-root").value_or("")), cancel, progress_text);
    finish_progress_line();
    if (!result.ok())
      return fail(result.error());
    std::cout << result.value().output;
    return result.value().exit_code == 0 ? kExitSuccess : kExitFailure;
  }
  return kExitUsage;
}

int command_procmon(const ParsedArguments& parsed, const CancellationToken& cancel) {
#ifndef _WIN32
  static_cast<void>(parsed);
  static_cast<void>(cancel);
  Error error;
  error.component = "Procmon";
  error.operation = "capture";
  error.message = "Process Monitor capture requires the Windows build.";
  return fail(error, kExitUnavailable);
#else
  if (parsed.positionals.size() < 2U)
    return kExitUsage;
  const std::filesystem::path tools_root = argument_path(option(parsed, "tools-root").value_or(""));
  if (parsed.positionals[1] == "start") {
    const auto output = option(parsed, "output");
    if (!output) {
      std::cerr << "procmon start requires --output capture.pml\n";
      return kExitUsage;
    }
    ProcmonOptions procmon_options;
    procmon_options.output_pml = argument_path(*output);
    procmon_options.filter_file = option(parsed, "filter").value_or("");
    procmon_options.custom_arguments = options(parsed, "arg");
    procmon_options.third_party_directory = tools_root;
    const std::filesystem::path state_directory = option_path(parsed, "state-dir")
                                                      .value_or(procmon_options.output_pml.parent_path() / "capture-state");
    auto session = procmon_start_owned(procmon_options, state_directory);
    if (!session.ok())
      return fail(session.error());
    std::cout << "session_id=" << session.value().session_id << '\n'
              << "process_id=" << session.value().process_id << '\n'
              << "state=" << path_to_utf8(session.value().state_path) << '\n'
              << "output=" << path_to_utf8(session.value().output_pml) << '\n';
    return kExitSuccess;
  }
  if (parsed.positionals[1] == "stop" || parsed.positionals[1] == "status") {
    const auto state = option(parsed, "state");
    if (!state) {
      std::cerr << "procmon " << parsed.positionals[1] << " requires --state <SAT Procmon state file>\n";
      return kExitUsage;
    }
    auto session = load_procmon_session(*state);
    if (!session.ok())
      return fail(session.error(), kExitUsage);
    auto result = parsed.positionals[1] == "stop"
                      ? procmon_stop_owned(session.value(), cancel, progress_text)
                      : procmon_status_owned(session.value());
    finish_progress_line();
    if (!result.ok())
      return fail(result.error());
    std::cout << result.value().output;
    if (parsed.positionals[1] == "stop")
      std::cout << "\nstate=" << path_to_utf8(session.value().state_path) << '\n';
    return result.value().exit_code == 0 ? kExitSuccess : kExitFailure;
  }
  return kExitUsage;
#endif
}

int command_iperf(const ParsedArguments& parsed, const CancellationToken& cancel) {
  if (parsed.positionals.size() < 2U)
    return kExitUsage;
  IperfOptions iperf_options;
  iperf_options.server = parsed.positionals[1] == "server";
  if (!iperf_options.server && parsed.positionals[1] != "client")
    return kExitUsage;
  iperf_options.host = option(parsed, "host").value_or("");
  if (const auto port_text = option(parsed, "port")) {
    auto port = parse_integer<std::uint16_t>(*port_text, "port");
    if (!port.ok())
      return fail(port.error(), kExitUsage);
    iperf_options.port = port.value();
  }
  iperf_options.payload = option(parsed, "payload").value_or("");
  iperf_options.custom_arguments = options(parsed, "arg");
  iperf_options.third_party_directory = argument_path(option(parsed, "tools-root").value_or(""));
  auto result = run_iperf(iperf_options, cancel, progress_text);
  finish_progress_line();
  if (!result.ok())
    return fail(result.error());
  std::cout << result.value().output;
  return result.value().exit_code == 0 ? kExitSuccess : kExitFailure;
}

// The secret in an environment variable, empty when it is not set. A password is never an option.
std::string secret_from_environment(const char* name) {
  std::string secret;
#ifdef _WIN32
  char* value = nullptr;
  std::size_t length = 0;
  if (_dupenv_s(&value, &length, name) == 0 && value != nullptr) {
    secret = value;
    std::fill(value, value + length, '\0');
  }
  std::free(value);
#else
  if (const char* value = std::getenv(name); value != nullptr)
    secret = value;
#endif
  return secret;
}

// One line per row, a section as its heading between dashes; 3 when a check failed.
int print_sql_report(const SqlCheckReport& report) {
  bool failed = false;
  for (const SqlCheckRow& row : report.rows) {
    if (row.status == SqlCheckStatus::section) {
      std::cout << "-- " << row.area << " --\n";
      continue;
    }
    std::cout << to_string(row.status) << " | " << row.area << " | " << row.check << " | " << row.detail;
    if (!row.source.empty())
      std::cout << " | " << row.source;
    std::cout << '\n';
    failed = failed || row.status == SqlCheckStatus::fail;
  }
  return failed ? kExitFindings : kExitSuccess;
}

// The statement --query names: a named query of the engine by its name, else the text as given.
std::string resolved_sql_query(const std::string& given, SqlEngine engine) {
  const auto& named = engine == SqlEngine::postgresql ? postgres_named_queries() : sql_named_queries();
  for (const SqlNamedQuery& query : named) {
    if (query.name == given)
      return query.text;
  }
  return given;
}

// A read-only query's rows as the result sets they came from: a text table when a set fits (8 columns
// or fewer, the row's name counted), a block per row when it is wider, or tab-separated text.
int print_sql_query(const SqlCheckReport& report, const ParsedArguments& parsed) {
  const std::string format = ascii_lower(option(parsed, "format").value_or("auto"));
  if (format != "auto" && format != "table" && format != "records" && format != "tsv") {
    std::cerr << "sql query --format takes table, records or tsv\n";
    return kExitUsage;
  }
  std::vector<std::array<std::string, 3>> rows;
  bool failed = false;
  for (const SqlCheckRow& row : report.rows) {
    rows.push_back({row.area, row.check, row.detail});
    failed = failed || row.status == SqlCheckStatus::fail;
  }
  const auto grids = sql_query_grids(rows);
  for (std::size_t index = 0; index < grids.size(); ++index) {
    const SqlQueryGrid& grid = grids[index];
    if (grids.size() > 1U)
      std::cout << (index == 0U ? "" : "\n") << "-- Result set " << index + 1U << " --\n";
    const auto shown = sql_query_shown_columns(grid, sql_query_main_columns(grid));
    if (!grid.labels.empty()) {
      if (format == "tsv")
        std::cout << sql_query_tsv(grid);
      else if (format == "records" || (format == "auto" && shown.size() < grid.columns.size()))
        std::cout << sql_query_text_records(grid);
      else
        std::cout << sql_query_text_table(grid, shown);
    }
    for (const std::string& note : grid.notes)
      std::cout << note << '\n';
  }
  return failed ? kExitFindings : kExitSuccess;
}

int command_sql_instances(bool engine_given, SqlEngine engine) {
  std::size_t shown = 0;
  for (const SqlInstanceChoice& choice : local_database_instances()) {
    if (engine_given && choice.engine != engine)
      continue;
    std::cout << sql_engine_name(choice.engine) << " | " << choice.name;
    if (!choice.detail.empty())
      std::cout << " | " << choice.detail;
    std::cout << '\n';
    ++shown;
  }
  if (shown == 0U)
    std::cout << "No database server was found on this machine.\n";
  return kExitSuccess;
}

int command_sql_databases(const ParsedArguments& parsed, SqlEngine engine, const std::string& server,
                          const CancellationToken& cancel) {
  const auto login = option(parsed, "login");
  std::string secret;
  if (login) {
    const char* variable = engine == SqlEngine::postgresql ? "PGPASSWORD" : "SQLCMDPASSWORD";
    secret = secret_from_environment(variable);
    if (secret.empty()) {
      std::cerr << "sql --login reads the password from " << variable << "; set it first\n";
      return kExitUsage;
    }
  }
  auto names = list_databases(engine, server, !login.has_value(), login.value_or(""), secret, cancel,
                              flag(parsed, "trust-certificate"), argument_path(option(parsed, "tools-root").value_or("")));
  std::fill(secret.begin(), secret.end(), '\0');
  if (!names.ok())
    return fail(names.error());
  for (const std::string& name : names.value())
    std::cout << name << '\n';
  return kExitSuccess;
}

// --show-sql: the SQL a check runs, in order, as it is sent, between comment lines both engines read,
// so it can be pasted into SSMS, sqlcmd or psql.
void print_sql_statements(const std::string& action, SqlEngine engine, const std::vector<std::string>& statements) {
  std::cout << "-- sql " << action << ", " << sql_engine_name(engine) << ": " << statements.size()
            << (statements.size() == 1U ? " statement" : " statements") << ", run in this order, read only\n";
  for (std::size_t index = 0; index < statements.size(); ++index)
    std::cout << "-- " << (index + 1U) << '\n' << statements[index] << "\n\n";
}

int command_sql_postgres(const ParsedArguments& parsed, const std::string& action, const std::string& server,
                         const CancellationToken& cancel) {
  for (const char* sql_server_only : {"against", "days", "trust-certificate"}) {
    if (option(parsed, sql_server_only)) {
      std::cerr << "sql --engine postgres does not take --" << sql_server_only << "\n";
      return kExitUsage;
    }
  }
  std::vector<std::string> statements;
  PostgresPermissionOptions permissions;
  if (action == "check") {
    permissions.configuration_database = option(parsed, "config-database").value_or("");
    permissions.another_account = option(parsed, "account").value_or("");
    statements = postgres_permission_statements(permissions);
  } else if (action == "shape") {
    statements = postgres_shape_statements();
  } else if (action == "backups") {
    statements = postgres_backup_statements();
  } else if (action == "files") {
    statements = postgres_files_statements();
  } else {
    const auto query = option(parsed, "query");
    if (!query) {
      std::cerr << "sql query requires --query \"SELECT ...\"\n";
      return kExitUsage;
    }
    const std::string text = resolved_sql_query(*query, SqlEngine::postgresql);
    if (const auto refusal = postgres_query_refusal(text)) {
      std::cerr << *refusal << '\n';
      return kExitUsage;
    }
    statements = {text};
  }
  // A read-only query prints its statement first, for whoever reads the output to check or run it
  // elsewhere; tab-separated output stays a plain table unless --show-sql asks for it.
  const bool show_sql = flag(parsed, "show-sql");
  if (show_sql || (action == "query" && ascii_lower(option(parsed, "format").value_or("")) != "tsv")) {
    print_sql_statements(action, SqlEngine::postgresql, statements);
    if (show_sql && server.empty())
      return kExitSuccess;
  }

  const auto login = option(parsed, "login");
  std::string secret;
  if (login) {
    // The password never goes on the command line.
    secret = secret_from_environment("PGPASSWORD");
    if (secret.empty()) {
      std::cerr << "sql --login reads the password from PGPASSWORD; set it first\n";
      return kExitUsage;
    }
  }
  auto made = make_postgres_connection(server, !login.has_value(), login.value_or(""), secret,
                                       action == "query" ? option(parsed, "database").value_or("") : std::string(),
                                       argument_path(option(parsed, "tools-root").value_or("")));
  std::fill(secret.begin(), secret.end(), '\0');
  if (!made.ok()) {
    std::cerr << made.error().message << '\n';
    return kExitUsage;
  }
  PostgresConnection connection = std::move(made.value());
  auto batch = run_postgres_statements(connection, statements, cancel, progress_text);
  std::fill(connection.password.begin(), connection.password.end(), '\0');
  finish_progress_line();
  if (!batch.ok())
    return fail(batch.error());
  const SqlCheckReport report =
      action == "check"     ? evaluate_postgres_permissions(batch.value(), connection, permissions)
      : action == "shape"   ? evaluate_postgres_shape(batch.value())
      : action == "backups" ? evaluate_postgres_backups(batch.value())
      : action == "files"   ? evaluate_postgres_files(batch.value(), sql_server_is_this_host(connection.host))
                            : sql_query_rows(batch.value());
  return action == "query" ? print_sql_query(report, parsed) : print_sql_report(report);
}

int command_sql(const ParsedArguments& parsed, const CancellationToken& cancel) {
  if (parsed.positionals.size() < 2U)
    return kExitUsage;
  const std::string& action = parsed.positionals[1];
  if (action != "check" && action != "shape" && action != "backups" && action != "files" && action != "query" &&
      action != "instances" && action != "databases") {
    std::cerr << "sql takes check, shape, backups, files, query, instances or databases\n";
    return kExitUsage;
  }
  const auto engine_option = option(parsed, "engine");
  const std::string engine_text = ascii_lower(engine_option.value_or("sqlserver"));
  SqlEngine engine = SqlEngine::sql_server;
  if (engine_text == "postgres" || engine_text == "postgresql") {
    engine = SqlEngine::postgresql;
  } else if (engine_text != "sqlserver" && engine_text != "mssql") {
    std::cerr << "sql --engine takes sqlserver or postgres\n";
    return kExitUsage;
  }
  if (action == "instances")
    return command_sql_instances(engine_option.has_value(), engine);
  const auto server = option(parsed, "server");
  const bool show_sql = flag(parsed, "show-sql");
  if (!server && !(show_sql && action != "databases")) {
    std::cerr << "sql " << action << " requires --server INSTANCE\n";
    return kExitUsage;
  }
  if (action == "databases")
    return command_sql_databases(parsed, engine, *server, cancel);
  if (engine == SqlEngine::postgresql)
    return command_sql_postgres(parsed, action, server.value_or(""), cancel);
  SqlConnection connection;
  connection.server = server.value_or("");
  connection.trust_server_certificate = flag(parsed, "trust-certificate");
  if (const auto login = option(parsed, "login"); login && server) {
    // The password never goes on the command line.
    std::string secret = secret_from_environment("SQLCMDPASSWORD");
    if (secret.empty()) {
      std::cerr << "sql --login reads the password from SQLCMDPASSWORD; set it first\n";
      return kExitUsage;
    }
    connection.integrated = false;
    connection.login = *login;
    connection.password = std::move(secret);
  }
  std::vector<std::string> statements;
  SqlPermissionCheckOptions permissions;
  SqlBackupOptions backups;
  if (action == "check") {
    const std::string against = option(parsed, "against").value_or("guest");
    if (against != "guest" && against != "config") {
      std::cerr << "sql check --against takes guest or config\n";
      return kExitUsage;
    }
    permissions.target = against == "config" ? SqlPermissionTarget::configuration_database : SqlPermissionTarget::guest_processing;
    permissions.configuration_database = option(parsed, "config-database").value_or("");
    permissions.another_account = option(parsed, "account").value_or("");
    statements = sql_permission_statements(permissions);
  } else if (action == "shape") {
    statements = sql_shape_statements();
  } else if (action == "backups") {
    backups.database = option(parsed, "database").value_or("");
    if (const auto days = option(parsed, "days")) {
      auto parsed_days = parse_integer<int>(*days, "days");
      if (!parsed_days.ok())
        return fail(parsed_days.error(), kExitUsage);
      backups.days = parsed_days.value();
    }
    backups.veeam_on_sql_host = !connection.server.empty() && veeam_installed_on_sql_host(connection.server);
    connection.database = "msdb";
    statements = sql_backup_statements(backups);
  } else if (action == "files") {
    statements = sql_files_statements();
  } else {
    const auto query = option(parsed, "query");
    if (!query) {
      std::cerr << "sql query requires --query \"SELECT ...\"\n";
      return kExitUsage;
    }
    const std::string text = resolved_sql_query(*query, SqlEngine::sql_server);
    if (const auto refusal = sql_query_refusal(text)) {
      std::cerr << *refusal << '\n';
      return kExitUsage;
    }
    connection.database = option(parsed, "database").value_or("master");
    statements = {text};
  }
  // A read-only query prints its statement first, for whoever reads the output to check or run it
  // elsewhere; tab-separated output stays a plain table unless --show-sql asks for it.
  if (show_sql || (action == "query" && ascii_lower(option(parsed, "format").value_or("")) != "tsv")) {
    print_sql_statements(action, SqlEngine::sql_server, statements);
    if (show_sql && !server)
      return kExitSuccess;
  }
  auto batch = run_sql_statements(connection, statements, cancel, progress_text);
  std::fill(connection.password.begin(), connection.password.end(), '\0');
  finish_progress_line();
  if (!batch.ok())
    return fail(batch.error());
  const SqlCheckReport report =
      action == "check"     ? evaluate_sql_permissions(batch.value(), connection, permissions)
      : action == "shape"   ? evaluate_sql_shape(batch.value())
      : action == "backups" ? evaluate_sql_backups(batch.value(), backups)
      : action == "files"   ? evaluate_sql_files(batch.value(), sql_server_is_this_host(connection.server))
                            : sql_query_rows(batch.value());
  return action == "query" ? print_sql_query(report, parsed) : print_sql_report(report);
}

int command_diagnostics(const ParsedArguments& parsed) {
  const auto security = current_security_context();
  if (!security.ok())
    return fail(security.error());

  std::error_code current_error;
  const auto current_directory = std::filesystem::current_path(current_error);
  std::error_code temporary_error;
  const auto temporary_directory = std::filesystem::temp_directory_path(temporary_error);

#ifdef _WIN32
  constexpr std::string_view platform = "Windows";
#elif defined(__APPLE__)
  constexpr std::string_view platform = "macOS";
#else
  constexpr std::string_view platform = "Linux";
#endif

  const std::vector<ToolRequirement> requirements = read_tool_requirements();

  if (flag(parsed, "json")) {
    std::cout << "{\"application\":\"" << json_escape(std::string(kProductName))
              << "\",\"version\":\"" << json_escape(std::string(kVersion)) << "\",\"platform\":\""
              << json_escape(platform)
              << "\",\"elevated\":" << (security.value().elevated ? "true" : "false")
              << ",\"session_id\":" << security.value().session_id << ",\"current_directory\":\""
              << json_escape(current_error ? std::string{} : path_to_utf8(current_directory))
              << "\",\"temporary_directory\":\""
              << json_escape(temporary_error ? std::string{} : path_to_utf8(temporary_directory))
              << "\",\"enabled_privileges\":[";
    for (std::size_t index = 0; index < security.value().enabled_privileges.size(); ++index) {
      if (index != 0)
        std::cout << ',';
      std::cout << "\"" << json_escape(security.value().enabled_privileges[index]) << "\"";
    }
    std::cout << "]";
    if (flag(parsed, "include-user")) {
      std::cout << ",\"user\":\"" << json_escape(security.value().user) << "\"";
    }
    std::cout << ",\"requirements\":[";
    for (std::size_t index = 0; index < requirements.size(); ++index) {
      const ToolRequirement& requirement = requirements[index];
      if (index != 0)
        std::cout << ',';
      std::cout << "{\"name\":\"" << json_escape(requirement.name) << "\",\"found\":\""
                << json_escape(requirement.found) << "\",\"status\":\"" << json_escape(requirement.status)
                << "\",\"used_by\":\"" << json_escape(requirement.used_by) << "\"}";
    }
    std::cout << "]}\n";
    return kExitSuccess;
  }

  std::cout << "Application: " << kProductName << ' ' << kVersion << '\n'
            << "Platform: " << platform << '\n'
            << "Elevation: " << (security.value().elevated ? "elevated" : "standard user") << '\n'
            << "Session: " << security.value().session_id << '\n';
  if (flag(parsed, "include-user"))
    std::cout << "User: " << security.value().user << '\n';
  std::cout << "Current directory: "
            << (current_error ? "unavailable: " + current_error.message()
                              : path_to_utf8(current_directory))
            << '\n'
            << "Temporary directory: "
            << (temporary_error ? "unavailable: " + temporary_error.message()
                                : path_to_utf8(temporary_directory))
            << '\n'
            << "Enabled privileges: ";
  if (security.value().enabled_privileges.empty()) {
    std::cout << "none reported\n";
  } else {
    for (std::size_t index = 0; index < security.value().enabled_privileges.size(); ++index) {
      if (index != 0)
        std::cout << ", ";
      std::cout << security.value().enabled_privileges[index];
    }
    std::cout << '\n';
  }
  std::cout << "\nREQUIREMENTS\n";
  if (requirements.empty()) {
    std::cout << "  None read on this platform.\n";
  } else {
    for (const ToolRequirement& requirement : requirements)
      std::cout << "  " << requirement.status << " | " << requirement.name << " | " << requirement.found
                << " | Used by: " << requirement.used_by << '\n';
  }
  return kExitSuccess;
}

int command_health(const ParsedArguments& parsed) {
  SystemHealthSampler sampler;
  // Seed rate-based counters, then take the reportable sample.
  static_cast<void>(sampler.sample());
  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  auto sampled = sampler.sample();
  if (!sampled.ok())
    return fail(sampled.error());
  const std::string report = format_system_health_report(sampled.value());
  if (const auto output = option(parsed, "output")) {
    const std::filesystem::path target = argument_path(*output);
    std::ofstream stream(target, std::ios::binary | std::ios::trunc);
    if (!stream) {
      std::cerr << "health sample could not create " << path_to_utf8(target) << "\n";
      return kExitFailure;
    }
    stream << report;
    if (!stream) {
      std::cerr << "health sample could not write " << path_to_utf8(target) << "\n";
      return kExitFailure;
    }
    // The file holds the report; the console says where it went and what it found, which is what
    // the exit code (3 for findings) also says.
    const std::size_t findings = sampled.value().findings.size();
    std::cout << "Health sample written to " << path_to_utf8(target) << ": "
              << (findings == 0 ? std::string("no findings")
                                : std::to_string(findings) + (findings == 1 ? " finding" : " findings"))
              << ".\n";
  } else {
    std::cout << report;
  }
  return sampled.value().findings.empty() ? kExitSuccess : kExitFindings;
}

// Read a health report written by any SAT edition.
//
// The report format is shared core, so a file written on Windows must load on Linux and the other
// way round. This prints only deterministic fields so the same file read by two editions produces
// identical output and can be compared directly.
int command_health_load(const ParsedArguments& parsed) {
  const auto input = option(parsed, "input");
  if (!input) {
    std::cerr << "health load requires --input FILE\n";
    return kExitUsage;
  }
  // A directory is a log collection, not a saved report. Rebuild the snapshot from its raw
  // evidence instead of refusing: a customer collection frequently arrives with the WindowsSupport
  // tree and no <MACHINE>-SystemHealth.txt, and that tree carries most of what the snapshot needs.
  SystemHealthSnapshot snapshot;
  std::vector<std::string> reconstruction_gaps;
  std::error_code directory_error;
  if (std::filesystem::is_directory(argument_path(*input), directory_error)) {
    const auto existing = existing_health_report(argument_path(*input));
    if (!existing.empty()) {
      std::ifstream saved(existing, std::ios::binary);
      std::string saved_text((std::istreambuf_iterator<char>(saved)),
                             std::istreambuf_iterator<char>());
      auto parsed_saved = parse_system_health_report(saved_text);
      if (!parsed_saved.ok())
        return fail(parsed_saved.error());
      snapshot = std::move(parsed_saved.value());
      std::cout << "Loaded the collection's own snapshot: " << path_to_utf8(existing) << "\n\n";
    } else {
      auto rebuilt = reconstruct_collected_evidence(argument_path(*input));
      if (!rebuilt.ok())
        return fail(rebuilt.error());
      snapshot = std::move(rebuilt.value().health);
      reconstruction_gaps = rebuilt.value().unavailable;
      std::cout << "Reconstructed from collected evidence in "
                << path_to_utf8(rebuilt.value().collection_root) << "\n";
      for (const auto& item : rebuilt.value().recovered)
        std::cout << "  rebuilt:      " << item << "\n";
      std::cout << "\n";
    }
  } else {
    std::ifstream stream(argument_path(*input), std::ios::binary);
    if (!stream) {
      std::cerr << "health load could not open " << *input << "\n";
      return kExitFailure;
    }
    std::string text((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    stream.close();

    auto parsed_report = parse_system_health_report(text);
    if (!parsed_report.ok())
      return fail(parsed_report.error());
    snapshot = std::move(parsed_report.value());
  }

  // Build the summary once, then send it to a file when asked.
  //
  // --output is not a convenience here. On Windows SAT is a single GUI-subsystem binary that
  // attaches to the parent console, so a calling process CANNOT capture its stdout - which makes
  // stdout-only output unusable from a script on the platform where most casework happens.
  std::ostringstream summary;
  summary << "Machine:           " << snapshot.machine_name << '\n'
          << "Captured UTC:      " << snapshot.captured_utc << '\n'
          << "Volumes:           " << snapshot.volumes.size() << '\n'
          << "Storage devices:   " << snapshot.storage_devices.size() << '\n'
          << "Network adapters:  " << snapshot.network_adapters.size() << '\n'
          << "Top processes:     " << snapshot.top_processes.size() << '\n'
          << "Findings:          " << snapshot.findings.size() << '\n'
          << "Warnings:          " << snapshot.warnings.size() << '\n';
  for (const auto& finding : snapshot.findings)
    summary << "  FINDING  " << finding.component << " / " << finding.metric << ": "
            << finding.summary << '\n';

  // What could not be rebuilt is part of the answer, not a footnote. A reconstructed snapshot that
  // silently reports zero volumes reads as a machine with no disks.
  for (const auto& gap : reconstruction_gaps)
    summary << "  NOT REBUILT  " << gap << '\n';

  if (const auto out = option(parsed, "output")) {
    std::ofstream out_stream(argument_path(*out), std::ios::binary | std::ios::trunc);
    if (!out_stream) {
      std::cerr << "health load could not create --output file\n";
      return kExitFailure;
    }
    out_stream << summary.str();
    if (!out_stream)
      return kExitFailure;
  } else {
    std::cout << summary.str();
  }
  return snapshot.findings.empty() ? kExitSuccess : kExitFindings;
}

// Turn a raw log collection into the two documents SAT can already load and render.
//
// A customer collection carries the WindowsSupport tree but not environment.log or
// <MACHINE>-SystemHealth.txt. This reconstructs both from that raw evidence, in the shipped
// formats, so the Environment and Health pages can load them like any other case.
int command_logs_reconstruct(const ParsedArguments& parsed) {
  const auto input = option(parsed, "path");
  if (!input) {
    std::cerr << "logs reconstruct requires --path COLLECTION_DIR\n";
    return kExitUsage;
  }
  auto rebuilt = reconstruct_collected_evidence(argument_path(*input));
  if (!rebuilt.ok())
    return fail(rebuilt.error());
  auto& value = rebuilt.value();

  const std::filesystem::path destination =
      option(parsed, "output") ? argument_path(*option(parsed, "output"))
                               : value.collection_root;
  std::error_code error;
  std::filesystem::create_directories(destination, error);

  std::cout << "Collection:  " << path_to_utf8(value.collection_root) << "\n"
            << "Machine:     "
            << (value.health.machine_name.empty() ? "Unknown" : value.health.machine_name) << "\n"
            << "Captured:    "
            << (value.health.captured_utc.empty() ? "Unknown" : value.health.captured_utc) << "\n\n";

  for (const auto& item : value.recovered)
    std::cout << "  rebuilt:      " << item << "\n";
  for (const auto& item : value.unavailable)
    std::cout << "  not rebuilt:  " << item << "\n";
  std::cout << "\n";

  int written = 0;
  if (value.environment_reconstructed) {
    const auto path = destination / "environment.log";
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
      std::cerr << "Could not write " << path_to_utf8(path) << "\n";
      return kExitFailure;
    }
    output << value.environment_text;
    output.flush();
    if (!output) {
      std::cerr << "Could not completely write " << path_to_utf8(path) << "\n";
      return kExitFailure;
    }
    std::cout << "Environment: " << path_to_utf8(path) << "\n";
    ++written;
  }
  if (value.health_reconstructed) {
    const std::string machine =
        value.health.machine_name.empty() ? "Unknown" : value.health.machine_name;
    const auto path = destination / (machine + "-SystemHealth.txt");
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
      std::cerr << "Could not write " << path_to_utf8(path) << "\n";
      return kExitFailure;
    }
    output << format_system_health_report(value.health);
    output.flush();
    if (!output) {
      std::cerr << "Could not completely write " << path_to_utf8(path) << "\n";
      return kExitFailure;
    }
    std::cout << "Health:      " << path_to_utf8(path) << "\n";
    ++written;
  }
  if (written == 0) {
    std::cerr << "Nothing could be reconstructed from that collection.\n";
    return kExitUnavailable;
  }
  return value.unavailable.empty() ? kExitSuccess : kExitFindings;
}

int command_capabilities(const ParsedArguments& parsed) {
#ifdef _WIN32
  constexpr bool registry_available = true;
  constexpr bool vss_available = true;
  constexpr bool usn_available = true;
  constexpr bool event_log_available = true;
#else
  constexpr bool registry_available = false;
  constexpr bool vss_available = false;
  constexpr bool usn_available = false;
  constexpr bool event_log_available = false;
#endif
#ifdef SUPPORT_ASSIST_HAS_RE2
  constexpr bool re2_available = true;
#else
  constexpr bool re2_available = false;
#endif
#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
  constexpr bool archive_available = true;
#else
  constexpr bool archive_available = false;
#endif

  if (flag(parsed, "json")) {
    std::cout << "{\"registry\":" << (registry_available ? "true" : "false")
              << ",\"filesystem\":true"
              << ",\"network_tools\":true"
              << ",\"log_collection\":true"
              << ",\"case_workspace\":true"
              << ",\"vss\":" << (vss_available ? "true" : "false")
              << ",\"usn\":" << (usn_available ? "true" : "false")
              << ",\"windows_event_log\":" << (event_log_available ? "true" : "false")
              << ",\"re2\":" << (re2_available ? "true" : "false")
              << ",\"archives\":" << (archive_available ? "true" : "false") << "}\n";
  } else {
    std::cout << "Registry: " << (registry_available ? "available" : "Windows build required")
              << '\n'
              << "Filesystem change analysis: available\n"
              << "Case workspace: available\n"
              << "TCP tools: available\n"
              << "Log collection: available\n"
              << "VSS diagnostic lab: " << (vss_available ? "available" : "Windows build required")
              << '\n'
              << "USN query: " << (usn_available ? "available" : "Windows build required") << '\n'
              << "Windows Event Log: "
              << (event_log_available ? "available" : "Windows build required") << '\n'
              << "RE2 regex: " << (re2_available ? "enabled" : "disabled") << '\n'
              << "Archive search: " << (archive_available ? "enabled" : "disabled") << '\n';
  }
  return kExitSuccess;
}

// The version line `version` prints and the help starts with: the full version, version +
// "." + build number, and the build date, as About shows them. The release
// channel and build revision stay support detail in About.
std::string full_version_line() {
  std::string line = std::string(kProductName) + " " + std::string(kVersion) + "." +
                     std::to_string(kBuildNumber);
  if (!kBuildDate.empty())
    line += " (built " + std::string(kBuildDate) + ")";
  return line;
}

} // namespace

void print_help() {
  std::string help = R"HELP( - command line for Veeam support casework

Usage:
  {exe} version
  {exe} capabilities [--json]
  {exe} diagnostics [--json] [--include-user]
      # also lists what the tools need on this machine
  {exe} health sample [--output system-health.txt]
  {exe} health load --input system-health.txt|COLLECTION_DIR [--output summary.txt]
      # a directory is read as a log collection: its own saved snapshot if it has one,
      # otherwise a snapshot rebuilt from the raw evidence it carries.
      # opens a health report captured on any platform, including one from the GUI.
  {exe} products detect [--json]

Case workspace:
  {exe} case create --parent DIR --id CASE-ID
      [--title TEXT] [--engineer NAME] [--notes TEXT]

Tools:
  {exe} tools review --source DIR [--machine NAME] [--json] [--note]
      # reviews Customer/Lab tool output, grouped by machine and ordered in UTC.
      # --note formats the result for pasting into a case note.
  {exe} network interfaces
  {exe} network test --host HOST --port PORT [--timeout-ms 5000]
      [--source IP] [--interface NAME] [--all-interfaces] [--include-virtual]
      [--sat-payload 50M | --no-sat-payload] [--no-sat-handshake]
  {exe} network listen --port PORT [--seconds 30] [--multiple] [--banner TEXT]
      # the banner defaults to "SAT - listening on %port%", with the port filled in;
      # --banner "" sends none.
  {exe} network udp test --host HOST --port PORT [--timeout-ms 2000]
      [--sat-listener] [--source IP] [--all-interfaces] [--include-virtual]
  {exe} network udp listen --port PORT [--seconds 30] [--single]
  {exe} network service-channel [--product agent|vbr] [--folder LOGS] [--hours 24] [--logs-only]
      # The channel Veeam's processes use to reach their service: the service, its named pipe and
      # an HTTP/2 handshake on it as this account (Windows), then the gRPC lines the product
      # logged. --logs-only reads a log folder, such as a collected bundle's, on any machine.
  {exe} network tls --host HOST --port PORT [--sni NAME] [--source IP]
      [--interface NAME] [--all-interfaces] [--include-virtual]
      [--expected-fingerprint HEX] [--version auto|1.2|1.3]
      [--compare-versions] [--timeout-ms 10000] [--no-system-trust]
  {exe} network throughput client --host HOST [--port 2500] [--bytes 1G]
      [--connect-timeout-ms 10000] [--idle-timeout-ms 30000]
  {exe} network throughput server [--port 2500]
      [--connect-timeout-ms 60000] [--idle-timeout-ms 30000]
  {exe} wmi query [--machine HOST [--user ACCOUNT]] --preset host|cluster|process
  {exe} wmi query [--machine HOST [--user ACCOUNT]] [--namespace root\cimv2] --query WQL
      # Without --user, another machine is signed in to as the account SAT runs as. --user signs in
      # to it as ACCOUNT (DOMAIN\name, name@domain, or an account of that machine) and reads the
      # password from SAT_WMI_PASSWORD. The connection is then encrypted (packet privacy).
  {exe} wmi health [--machine HOST] [--json]
      # Windows: the Winmgmt service and the services it depends on, the repository's consistency
      # (winmgmt /verifyrepository, as administrator) and size, a timed probe of each namespace
      # Veeam reads, and the WMI faults logged in the last 7 days. For another machine the service
      # and namespaces are checked there; the repository and event logs on this machine only.
      # Exits 3 when a row is a finding.
  {exe} packet start --output capture.etl [--ip ADDRESS] [--port PORT]
      [--backend auto|pktmon|netsh] [--state-dir PATH]
  {exe} packet status --state <SAT capture state file>
  {exe} packet stop --state <SAT capture state file>
  {exe} packet convert --input capture.etl --output capture.pcapng
      [--tools-root DIR]
  {exe} packet events --input capture.pcapng
      # The notable events in a .pcapng or .pcap, with their times: TCP retransmissions, duplicate
      # ACKs, keep-alives, resets, zero windows and missing segments, and TLS handshake messages and
      # alerts. Copies of one packet logged at several pktmon components count once.
  {exe} procmon start --output capture.pml [--filter file.pmc]
      [--tools-root DIR] [--state-dir PATH] [--arg VALUE]
  {exe} procmon status --state <SAT Procmon state file>
  {exe} procmon stop --state <SAT Procmon state file>
  {exe} iperf client --host HOST [--port 2500] [--payload 1G]
      [--tools-root DIR] [--arg VALUE]    # needs iperf3; see 'tools source --id iperf3'
  {exe} iperf server [--port 2500] [--tools-root DIR] [--arg VALUE]

Quick checks (the tools of the F2, F6, F7, F8, F9, F10 and F12 windows):
  {exe} network transfer-time --size 20TB --link 10G | --adapter NAME [--mtu 9000] [--ipv6]
                    [--timestamps] [--share 100] [--reduced-to 100] [--network-speed 6Gb/s]
                    [--storage-speed 520MB/s]
                    [--host HOST [--port 2500] [--bytes 1G]]
                    [--host HOST --iperf3 [--port 5201] [--streams 4] [--tools-root DIR]]
                    [--storage-result result.json] [--email] [--json]
      # how long a transfer takes, worked out step by step: the link in bytes, less the Ethernet and
      # TCP/IP overhead, per hour, then the size. Sizes are as Windows counts them (1 TB = 1,024 GB).
      # --host measures the network to SAT's listener (or the throughput server) on that port, or with
      # --iperf3 to an iPerf3 server started there; --storage-result takes the speed a Disk Speed Test
      # kept. The lowest speed sets the time.
      # --share is the link throttle: the % of the link this transfer can use as a Veeam network
      # traffic rule throttles it or other traffic shares it. --reduced-to is the % of the data sent after Veeam's
      # compression and deduplication: a job session's Transferred / Read x 100.
      # --email prints the email text only.
  {exe} network adapters [--json]
      # this machine's network adapters: link speed, MTU, addresses, errors and discards.
  {exe} network local-ports PORTS [--udp] [--tcp] [--json]
  {exe} network local-ports --preset ROLE | --process NAME|PID [--json]
      # PORTS is a list such as 999,123,22-23. Reads this machine's sockets and firewall, and
      # gives each port a verdict: Open, Blocked here, Local only, Closed, Closed and blocked.
  {exe} network presets
      # the Veeam roles --preset takes, with their ports from the Veeam Backup & Replication guide.
  {exe} network name NAME [--json]
      # the addresses a name resolves to, where the answer came from first, each DNS server's
      # answer and the reverse lookup of each address.
  {exe} time check [--server HOST] [--json]
  {exe} time convert TIMESTAMP [--log FILE] [--zone "Eastern Time" | --offset -05:00]
                    [--show-in "Mountain Time"] [--json]
      # TIMESTAMP is a time or a whole line from a log. --log reads the offset from that log's own
      # headers (its UTC time, its UTC offset or the zone it names). Otherwise --zone or --offset
      # names the zone the log was written in, and this machine's offset is used when neither is
      # given. A --zone applies that zone's daylight saving on the date read. --show-in gives the
      # same moment in another zone, such as another machine's.
  {exe} time log-clock FILE [--json]
      # what a log records of its own clock: each header's UTC offset and daylight saving state,
      # the zone it names, and the listed zones on that offset.
  {exe} time zones
      # the zones --zone takes, with their offset now.
  {exe} files lock --path FILE|FOLDER [--json]
      # the processes holding a file open; for a folder, every file and folder under it.
  {exe} volume list [--json]
      # every volume: what it sits on (bus, disk, controller and driver, LUN or share), its file
      # system, space, compression, encryption, and Fast Clone on ReFS and XFS.
  {exe} volume check --path DIR [--json]
      # the volume a folder is on, with the folder's own compression and encryption.
  {exe} storage tests
  {exe} storage speed-test --custom --folder DIR | --file PATH [--write-percent 0-100] [--random]
                    [--threads N] [--outstanding N] [--warmup SECONDS] [--caching] [--block 64K]
                    [--size 4G] [--seconds 60] [--role repository|source|other] [--tools-root DIR] [--json]
      # the DiskSpd wizard's own mix. A test that writes needs --folder, where SAT writes its own test
      # file and removes it; --file reads an existing file only (--write-percent 0).
  {exe} storage speed-test --test ID --folder DIR | --file PATH [--size 25G] [--block 512K]
      [--seconds 600] [--role repository|source|other] [--tools-root DIR] [--json]
      # Veeam's KB2014 tests on DiskSpd (Windows) or fio (Linux). A write test writes only SAT's
      # own new file in the folder and removes it; a read test opens the file for reading only.
      # --role says what the storage is, for what the result means: a backup repository (the
      # default for --test), the source a backup reads, or other.
  {exe} objectstorage presets
  {exe} objectstorage check --preset ID --bucket NAME [--endpoint HOST[:PORT]] [--region REGION]
                    [--addressing virtual-hosted|path] [--expected-fingerprint SHA256 | --certificate-file FILE]
                    [--accept-cost] [--product vbr-13|vbr-12|vaw-13|val-13|vb365-8] [--no-signed] [--json]
      # experimental: an S3-compatible bucket as Veeam reaches it. The keys come from
      # SAT_S3_ACCESS_KEY and SAT_S3_SECRET_KEY; without them only the checks that send no request
      # run. It writes nothing; on an endpoint that bills requests the signed requests need --accept-cost.
      # The key's permissions are held against --product's list (Veeam Backup & Replication 13 when
      # none is given) and every other product's; on Amazon S3, AWS STS and IAM, which bill nothing,
      # say who the key is and what its policies allow. 'objectstorage presets' lists the products.
      # The certificate is checked with this machine's certificate store; --certificate-file also trusts
      # the server's own certificate or a CA that issued it, --expected-fingerprint a SHA-256 fingerprint.
  {exe} watch [--filter veeam] [--seconds 0] [--interval-ms 2000]
      # lists the matching services and processes; with --seconds, prints what starts,
      # ends or changes until then.
  {exe} system pending-restart [--json]
      # which restart marker is set, when, and the events that name the cause. Exits 3 when
      # the system needs a restart.
  {exe} system host-checks [--checks events,drivers,shadow-storage,dotnet-tls,kernel-log] [--days N] [--json]
      # read-only checks of what most often explains a failed snapshot or backup. Windows: backup
      # events (volsnap, VSS, disk, NTFS) in the last --days (7 by default), the Veeam drivers, VSS
      # shadow storage, and the .NET and TLS registry values. Linux: the Veeam snapshot module and
      # the kernel log. Without --checks every check for this system runs. Exits 3 on a finding.
  {exe} system installer-cache [--upgrade-code GUID | --name TEXT] [--check FILE.msi|FILE.exe|DIR] [--json]
      # Windows: the installed products with that UpgradeCode, or whose name or publisher holds TEXT
      # (Veeam when neither is given), each with its version, install date, original package,
      # PackageCode, last used source, the cached package Windows keeps in C:\Windows\Installer and
      # whether it is there, its patches and its main program's version. --check reads an installer's
      # identity and SHA-256 and says whether it is the package a product was installed from; a
      # folder, such as a mounted ISO, is searched four levels down for .msi files. Exits 3 when a
      # cached package is missing.
  {exe} system pipes [--veeam] [--json]
      # Windows: every named pipe in \\.\pipe\ by name, with its current and maximum instances. The
      # Veeam, SQL Server and PostgreSQL pipes SAT knows show their product, purpose and service, and
      # a pipe whose name carries a process ID shows that process. Linux: every Unix domain socket
      # with a path, its type, whether it listens and the process that holds it. --veeam lists the
      # Veeam and database ones only. No pipe or socket is opened or connected to.

Log collection and analysis:
  {exe} logs gather --output DIR [--no-third-party-errors] [--no-platform-context] [--no-archive]
      [--official-exporters]
      # detects the installed Veeam products and collects their support logs.
      # The vendor's own exporters are not run unless --official-exporters is given.
  {exe} logs collect --profile universal|vaw|vbr|sql-plugin|rman-plugin|custom [--no-windows-context]
      --output DIR [--source DIR] [--from DATE] [--to DATE] [--no-archive]
  {exe} logs review --path DIR|FILE|ARCHIVE [--path DIR|FILE|ARCHIVE ...]
      [--profile auto|vaw|vbr|sql-plugin|rman-plugin|generic]
      [--output report.txt|DIR] [--case CASE_ROOT] [--full-scan] [--multi-machine-source]
      [--cache-dir DIR] [--no-cache] [--json]
      [--from DATE --to DATE --date-order mdy|dmy|iso|system|auto]
      [--assumed-offset-minutes N] [--context 4] [--max-incidents N]
      [--find TEXT] [--case-sensitive] [--discover-veeam]
      [--workers N | --single-thread] [--no-warnings] [--no-archives]
      # without --output or --case, the report goes to Log-Collections/Log-Review beside SAT.
  {exe} logs reconstruct --path COLLECTION_DIR [--output DIR]
      # rebuilds environment.log and <MACHINE>-SystemHealth.txt from a collection that carries
      # only raw evidence, so the Environment and Health pages can load it. Reports what it
      # could not rebuild and why.
  {exe} logs search [--path DIR ... | --discover-veeam] [--text TEXT | --regex REGEX]
      [--pattern GLOB] [--severity VALUE] [--case-sensitive] [--max-results N]
      [--from DATE --to DATE --date-order mdy|dmy|iso|system|auto]
      [--assumed-offset-minutes N] [--context 4] [--no-archives]
      [--output FILE] [--format text|html|json|csv]
  {exe} logs eventlog [--channel "Veeam Agent"] [--event-id N]
      [--text TEXT] [--severity VALUE] [--case-sensitive] [--max-results N]
      [--from DATE --to DATE --date-order mdy|dmy|iso|system|auto]
      [--assumed-offset-minutes N] [--output FILE] [--format text|html|json|csv]
)HELP" R"HELP(
SQL tools:
  {exe} sql check --server INSTANCE [--against guest|config] [--config-database NAME]
      [--account LOGIN] [--login LOGIN] [--trust-certificate]
      # An account's rights against Veeam's Permissions page: guest processing (sysadmin, or the
      # minimal list) or the configuration database. Without --account, the account connecting.
  {exe} sql shape --server INSTANCE
      # Failover cluster instance, availability groups, replicas, listeners, backup preference.
  {exe} sql backups --server INSTANCE [--database NAME] [--days 14]
      # msdb's backup history: whose backups they are, log chain gaps, restarts and forks.
  {exe} sql files --server INSTANCE
      # Every database file, and on the SQL host the volume it is on.
  {exe} sql query --server INSTANCE [--database master] --query "SELECT ..." [--format table|records|tsv]
      # One query that reads data, or a named query by its name. The statement prints first, then the result:
      # 8 columns or fewer as a table, wider as a block per row; --format chooses (tsv prints the result
      # only). Every sql command connects as the account running SAT; with
      # --login it uses that SQL login and reads the password from SQLCMDPASSWORD. Exits 3 when
      # a check fails.
  {exe} sql check|shape|backups|files|query [--engine sqlserver|postgres] --show-sql [--server ...]
      # Prints the SQL the check runs, in order, before its results; without --server it prints
      # the SQL only and connects to nothing.
  {exe} sql instances [--engine sqlserver|postgres]
      # The SQL Server and PostgreSQL instances on this machine.
  {exe} sql databases --server INSTANCE [--engine sqlserver|postgres] [--login LOGIN]
      [--trust-certificate] [--tools-root DIR]
      # The databases of one server, one per line.
  {exe} sql check --engine postgres --server HOST[:PORT] [--config-database NAME]
      [--account ROLE] [--login ROLE] [--tools-root DIR]
  {exe} sql shape|backups|files --engine postgres --server HOST[:PORT] [--login ROLE]
  {exe} sql query --engine postgres --server HOST[:PORT] [--database postgres] --query "SELECT ..."
      # The same five checks for PostgreSQL, run through psql: the Tools folder (--tools-root), the
      # PATH or the PostgreSQL install folders. Without --login the account running SAT connects (on
      # Windows as the postgres role that Veeam's installer maps its Windows accounts to); with
      # --login the password is read from PGPASSWORD. The session is read only.

Third-party integrations:
  {exe} tools status [--root DIR] [--json]
  {exe} tools source --id procmon|iperf3|etl2pcapng|wireshark|vsstrace|sqlcmd|psql|diskspd
  {exe} tools run --id iperf3 [--mode Client|Server] [--host HOST] [--direction Upload|Download]
                  [--streams Single|Multiple] [--stream-count 5] [--duration 20] [--port 5201]
                  [--protocol TCP|UDP] [--root DIR]
  {exe} tools run --id etl2pcapng --input FILE.etl [--output FILE.pcapng] [--root DIR]
      # the Integrations Run window's guided run: the same fields, the same command line. The Run
      # window's CLI button prints it.

Change analysis (compares file and registry metadata between two points in time):
  {exe} registry baseline --root HKLM\Software\Vendor
      [--root HKCU\Software\Vendor] [--view native|32|64|both]
      [--security] [--batch-size N] --output before.satsnap
  {exe} registry compare --baseline before.satsnap [--baseline-id ID]
      (--other after.satsnap [--other-id ID] | --live)
      [--keep] [--output FILE --format text|html|json|csv]
  {exe} files baseline --path C:\ProgramData\Vendor --output before.satsnap
      [--hash none|all|below-size|extensions] [--hash-max-bytes N]
      [--hash-extension .log] [--exclude pattern] [--maximum-depth N]
      [--maximum-objects N] [--batch-size N] [--follow-reparse]
      [--streams] [--no-file-id] [--hydrate-cloud-files]
  {exe} files compare --baseline before.satsnap [--baseline-id ID]
      (--other after.satsnap [--other-id ID] | --live)
      [--timestamp-tolerance-100ns N] [--no-move-detection] [--no-hash-inference]
      [--no-journal] [--keep] [--output FILE --format text|html|json|csv]
      # --keep stores the result in the baseline file; baseline inspect lists the stored comparisons.

Guided Diagnostics:
  {exe} guided scenarios
      # The scenarios for this machine, each with its inputs.
  {exe} guided run --scenario ID [--input NAME=VALUE ...] [--machine HOST] [--continue]
      # Runs the scenario's read-only checks in order and stops at the first decisive failure;
      # --continue runs every step. --machine HOST is --input target=HOST. Prints each step, then
      # the block for the case note. Exits 3 when a step fails.

VSS diagnostics:
  {exe} vss writers
  {exe} vss test --volume C:\ [--volume D:\ ...] [--writer GUID]
      [--backup-type copy|full] [--component-mode] [--select-all-components]
      [--bootable-system-state] [--partial-file-support]
      [--hold-seconds N] [--direct]

Other diagnostics:
  {exe} usn query --volume C:\
  {exe} baseline inspect --file baseline.satsnap [--baseline-id ID]
  {exe} snapshot inspect --file baseline.satsnap [--baseline-id ID]
  {exe} baselines list [--folder PATH]
  {exe} snapshots list [--folder PATH]

File checksums:
  {exe} files hash --path FILE [--path FILE ...] [--expect SHA256] [--json]
  {exe} files hash --check SHA256SUMS [--check LIST ...] [--json]
      # the SHA-256 of each file, read in place. --expect compares each result with a published
      # value; --check reads a SHA256SUMS list and checks every file it names, found beside the
      # list. Exits 3 when a file does not match or is missing.

Exit codes:
  0  success, or completed with no findings
  2  not available on this host, or not applicable
  3  completed and found something (comparison and diagnostic commands only)
  64 the command line was wrong
  70 the operation failed
  74 tools review only: the source could not be read
  130 cancelled
)HELP";
#ifndef _WIN32
  const auto erase_help_range = [&](std::string_view first, std::string_view last_exclusive) {
    const auto begin = help.find(first);
    if (begin == std::string::npos) return;
    const auto end = help.find(last_exclusive, begin);
    if (end != std::string::npos) help.erase(begin, end - begin);
  };
  // Keep defensive command handlers compiled, but do not advertise tools that
  // cannot run on this platform. The native GUI applies the same policy.
  // packet events reads a capture file, so it stays; the other packet and procmon commands go.
  erase_help_range("  {exe} wmi query", "  {exe} packet events");
  erase_help_range("  {exe} procmon start", "  {exe} iperf client");
  erase_help_range("  {exe} logs eventlog", "\nSQL tools:");
  erase_help_range("  {exe} registry baseline", "  {exe} files baseline");
  erase_help_range("VSS diagnostics:", "Other diagnostics:");
  erase_help_range("  {exe} usn query", "  {exe} baseline inspect");
  erase_help_range("  {exe} system installer-cache", "  {exe} system pipes");
  const std::string windows_sources =
      "  {exe} tools source --id procmon|iperf3|etl2pcapng|wireshark|vsstrace|sqlcmd|psql|diskspd";
  const auto sources_position = help.find(windows_sources);
  if (sources_position != std::string::npos) {
    help.replace(sources_position,
                 windows_sources.size(),
                 "  {exe} tools source --id iperf3|wireshark|sqlcmd|psql|tcpdump|fio");
  }
  const std::string windows_run = "  {exe} tools run --id etl2pcapng --input FILE.etl [--output FILE.pcapng] [--root DIR]";
  const auto run_position = help.find(windows_run);
  if (run_position != std::string::npos) {
    help.replace(run_position, windows_run.size(),
                 "  {exe} tools run --id tcpdump [--interface any] [--host HOST] [--port PORT] [--count 500] [--root DIR]");
  }
  const std::string windows_path = "--path C:\\ProgramData\\Vendor";
  const auto path_position = help.find(windows_path);
  if (path_position != std::string::npos)
    help.replace(path_position, windows_path.size(), "--path /path/to/vendor");
  for (const std::string& windows_only : {std::string(" [--streams]"),
                                         std::string(" [--no-file-id]"),
                                         std::string(" [--hydrate-cloud-files]")}) {
    std::size_t found = 0;
    while ((found = help.find(windows_only, found)) != std::string::npos)
      help.erase(found, windows_only.size());
  }
  // Those options were the only thing on their line, so removing them leaves the indent behind as
  // a whitespace-only line. Drop any line that now holds nothing but spaces.
  for (std::size_t line_start = 0; line_start < help.size();) {
    const std::size_t line_end = help.find('\n', line_start);
    if (line_end == std::string::npos) break;
    if (line_end > line_start &&
        help.find_first_not_of(' ', line_start) >= line_end) {
      help.erase(line_start, line_end - line_start + 1U);
      continue;
    }
    line_start = line_end + 1U;
  }
#endif
  std::string executable(kExecutableName);
#ifdef _WIN32
  executable += ".exe";
#endif
#ifndef SUPPORT_ASSIST_OBJECT_STORAGE_CHECK
  // The Object Storage Check is in test builds only.
  if (const auto begin = help.find("  {exe} objectstorage presets"); begin != std::string::npos) {
    if (const auto end = help.find("  {exe} watch", begin); end != std::string::npos)
      help.erase(begin, end - begin);
  }
#endif
  std::size_t position = 0;
  while ((position = help.find("{exe}", position)) != std::string::npos) {
    help.replace(position, 5, executable);
    position += executable.size();
  }
  std::cout << full_version_line() << help;
}

int dispatch(const std::vector<std::string>& arguments, const CancellationToken& cancel) {
  if (arguments.empty() || arguments[0] == "help" || arguments[0] == "--help") {
    print_help();
    return kExitSuccess;
  }
  const ParsedArguments parsed = parse_arguments(arguments);
  if (const auto unknown = unknown_option(parsed)) {
    // An unrecognised option is rejected rather than accepted silently: a constraining flag fails
    // open when it goes unread, so a typo is a correctness risk, not merely a usability one.
    // `--output-dir` for `--output` would still run a full review and write the report to the
    // default location - inside the customer's log bundle - and a mistyped `--no-archives` would
    // still let SAT extract archives on a customer machine after the engineer explicitly asked it
    // not to.
    std::cerr << "Unknown option --" << *unknown << "\n";
    if (const auto suggestion = closest_option(*unknown))
      std::cerr << "Did you mean --" << *suggestion << "?\n";
    std::cerr << "Run \"" << arguments[0] << " help\" for the options this command accepts.\n";
    return kExitUsage;
  }
  if (arguments[0] == "version" || arguments[0] == "--version") {
    std::cout << full_version_line() << '\n';
    return kExitSuccess;
  }
  if (arguments[0] == "capabilities")
    return command_capabilities(parsed);
  if (arguments[0] == "diagnostics")
    return command_diagnostics(parsed);
  if (arguments[0] == "health" && arguments.size() > 1 && arguments[1] == "sample")
    return command_health(parsed);
  if (arguments[0] == "health" && arguments.size() > 1 && arguments[1] == "load")
    return command_health_load(parsed);
  if (arguments[0] == "products" && arguments.size() > 1 && arguments[1] == "detect")
    return command_products_detect(parsed);
  if (arguments[0] == "case")
    return command_case(parsed);
  if (arguments[0] == "network")
    return command_network(parsed, cancel);
  if (arguments[0] == "guided")
    return command_guided(parsed, cancel);
  if (arguments[0] == "tools")
    return command_tools(parsed, cancel);
  if (arguments[0] == "wmi")
    return command_wmi(parsed, cancel);
  if (arguments[0] == "packet")
    return command_packet(parsed, cancel);
  if (arguments[0] == "procmon")
    return command_procmon(parsed, cancel);
  if (arguments[0] == "iperf")
    return command_iperf(parsed, cancel);
  if (arguments[0] == "sql")
    return command_sql(parsed, cancel);
  if (arguments[0] == "time")
    return command_time(parsed, cancel);
  if (arguments[0] == "volume")
    return command_volume(parsed);
  if (arguments[0] == "storage")
    return command_storage(parsed, cancel);
#ifdef SUPPORT_ASSIST_OBJECT_STORAGE_CHECK
  if (arguments[0] == "objectstorage")
    return command_object_storage(parsed, cancel);
#endif
  if (arguments[0] == "watch")
    return command_watch(parsed, cancel);
  if (arguments[0] == "system")
    return command_system(parsed, cancel);

  if (arguments[0] == "registry" && arguments.size() > 1) {
    if (arguments[1] == "baseline" || arguments[1] == "snapshot")
      return command_registry_baseline(parsed, cancel);
    if (arguments[1] == "compare")
      return command_registry_compare(parsed, cancel);
  }
  if (arguments[0] == "files" && arguments.size() > 1) {
    if (arguments[1] == "baseline" || arguments[1] == "snapshot")
      return command_files_baseline(parsed, cancel);
    if (arguments[1] == "compare")
      return command_files_compare(parsed, cancel);
    if (arguments[1] == "hash")
      return command_files_hash(parsed, cancel);
    if (arguments[1] == "lock")
      return command_files_lock(parsed, cancel);
  }
  if (arguments[0] == "logs" && arguments.size() > 1) {
    if (arguments[1] == "gather" || arguments[1] == "universal")
      return command_logs_gather_universal(parsed, cancel);
    if (arguments[1] == "collect")
      return command_logs_collect(parsed, cancel);
    if (arguments[1] == "review")
      return command_logs_review(parsed, cancel);
    if (arguments[1] == "search")
      return command_logs_search(parsed, cancel);
    if (arguments[1] == "reconstruct")
      return command_logs_reconstruct(parsed);
    if (arguments[1] == "eventlog")
      return command_event_log_search(parsed, cancel);
  }
  if (arguments[0] == "vss")
    return command_vss(parsed, cancel);
  if (arguments[0] == "usn" && arguments.size() > 1 && arguments[1] == "query") {
    const auto volume = option(parsed, "volume");
    if (!volume) {
      std::cerr << "usn query requires --volume\n";
      return kExitUsage;
    }
    auto result = query_usn_journal(*volume);
    if (!result.ok())
      return fail(result.error());
    std::cout << (result.value().eligible ? "eligible" : "not eligible") << ": "
              << result.value().reason << '\n';
    return result.value().eligible ? kExitSuccess : kExitUnavailable;
  }
  if ((arguments[0] == "baseline" || arguments[0] == "snapshot") && arguments.size() > 1 &&
      arguments[1] == "inspect") {
    return command_snapshot_inspect(parsed);
  }
  if ((arguments[0] == "baselines" || arguments[0] == "snapshots") && arguments.size() > 1 &&
      arguments[1] == "list") {
    return command_snapshots_list(parsed);
  }

  // The command line names nothing SAT runs: say which words, on stderr, and where the list is.
  std::string executable(kExecutableName);
#ifdef _WIN32
  executable += ".exe";
#endif
  std::string typed = arguments[0];
  if (arguments.size() > 1 && arguments[1].rfind("--", 0) != 0)
    typed += " " + arguments[1];
  std::cerr << "Unknown command: " << typed << "\n"
            << "Run \"" << executable << " help\" for the commands and their options.\n";
  return kExitUsage;
}

} // namespace support_assist::cli
