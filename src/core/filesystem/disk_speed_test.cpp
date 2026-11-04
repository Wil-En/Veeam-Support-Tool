#include "support_assist/disk_speed_test.hpp"

#include "support_assist/data_files.hpp"
#include "support_assist/json.hpp"
#include "support_assist/process.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/tool_catalog.hpp"
#include "support_assist/tool_download.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <limits>
#include <mutex>
#include <system_error>
#include <thread>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace support_assist {
namespace {

Error speed_error(std::string operation, std::string source, std::string message) {
  Error error;
  error.component = "DiskSpeedTest";
  error.operation = std::move(operation);
  error.source = std::move(source);
  error.message = std::move(message);
  return error;
}

StorageTestCatalog load_catalog() {
  StorageTestCatalog catalog;
  const JsonValue& data = data_file("storage-tests.json");
  const JsonValue& defaults = data["defaults"];
  catalog.default_block_size = defaults["block_size"].as_string("512K");
  catalog.default_seconds = static_cast<int>(defaults["duration_seconds"].as_number(600.0));
  catalog.block_sizes = defaults["block_sizes"].string_items();
  catalog.block_size_note = defaults["block_size_note"].as_string();
  catalog.min_free_percent_after = static_cast<int>(defaults["min_free_percent_after"].as_number(10.0));
  const JsonValue& custom = data["custom"];
  CustomSpeedTestSettings& settings = catalog.custom;
  settings.block_sizes = custom["block_sizes"].string_items();
  settings.block_size = custom["block_size"].as_string("64K");
  settings.seconds = static_cast<int>(custom["duration_seconds"].as_number(60.0));
  settings.file_size = custom["file_size"].as_string("4G");
  settings.threads = static_cast<int>(custom["threads"].as_number(1.0));
  settings.outstanding = static_cast<int>(custom["outstanding"].as_number(4.0));
  settings.warmup_seconds = static_cast<int>(custom["warmup_seconds"].as_number(5.0));
  settings.max_threads = static_cast<int>(custom["max_threads"].as_number(64.0));
  settings.max_outstanding = static_cast<int>(custom["max_outstanding"].as_number(256.0));
  settings.max_warmup_seconds = static_cast<int>(custom["max_warmup_seconds"].as_number(300.0));
  settings.diskspd = custom["diskspd"].as_string();
  settings.diskspd_create = custom["diskspd_create"].as_string();
  settings.diskspd_random = custom["diskspd_random"].as_string();
  settings.diskspd_no_cache = custom["diskspd_no_cache"].as_string();
  settings.fio = custom["fio"].as_string();
  settings.fio_no_cache = custom["fio_no_cache"].as_string();
  for (const JsonValue& item : custom["presets"].items()) {
    StoragePreset preset;
    preset.name = item["name"].as_string();
    preset.description = item["description"].as_string();
    for (const auto& [key, value] : item["values"].members())
      preset.values.emplace_back(key, value.as_string());
    if (!preset.name.empty())
      settings.presets.push_back(std::move(preset));
  }
  catalog.source_title = data["source"]["title"].as_string();
  catalog.source_url = data["source"]["url"].as_string();
  catalog.reviewed = data["source"]["reviewed"].as_string();
  for (const JsonValue& item : data["tests"].items()) {
    StorageTest test;
    test.id = item["id"].as_string();
    test.name = item["name"].as_string();
    test.preset = item["preset"].as_string(test.name);
    test.simulates = item["simulates"].as_string();
    test.write_percent = static_cast<int>(item["write_percent"].as_number());
    test.random = item["random"].as_bool();
    test.reads_existing_file = item["reads_backup_file"].as_bool();
    test.file_size = item["file_size"].as_string();
    test.divide_by = std::max(1, static_cast<int>(item["divide_by"].as_number(1.0)));
    test.diskspd = item["diskspd"].as_string();
    test.fio = item["fio"].as_string();
    if (!test.id.empty())
      catalog.tests.push_back(std::move(test));
  }
  return catalog;
}

void replace_all(std::string& text, std::string_view from, std::string_view to) {
  for (std::size_t at = text.find(from); at != std::string::npos; at = text.find(from, at + to.size()))
    text.replace(at, from.size(), to);
}

// A size as DiskSpd and fio read it, from bytes: "25G", "512K".
std::string size_text(std::uint64_t bytes) {
  constexpr std::uint64_t kilo = 1024ULL;
  constexpr std::uint64_t mega = kilo * 1024ULL;
  constexpr std::uint64_t giga = mega * 1024ULL;
  if (bytes % giga == 0U)
    return std::to_string(bytes / giga) + "G";
  if (bytes % mega == 0U)
    return std::to_string(bytes / mega) + "M";
  if (bytes % kilo == 0U)
    return std::to_string(bytes / kilo) + "K";
  return std::to_string(bytes);
}

std::string readable_bytes(std::uint64_t bytes) {
  const double gib = static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0);
  if (gib >= 1.0)
    return std::to_string(static_cast<std::uint64_t>(gib + 0.5)) + " GB";
  return std::to_string(bytes / (1024ULL * 1024ULL)) + " MB";
}

// "412.6", one decimal.
std::string one_decimal(double value) {
  char text[48] = {};
  std::snprintf(text, sizeof(text), "%.1f", value);
  return text;
}

std::string two_decimals(double value) {
  char text[48] = {};
  std::snprintf(text, sizeof(text), "%.2f", value);
  return text;
}

// "1.42 TiB" or "605.3 GiB": what a rate in MiB/s moves in an hour.
std::string per_hour(double mib_per_second) {
  const double gib = mib_per_second * 3600.0 / 1024.0;
  return gib >= 1024.0 ? two_decimals(gib / 1024.0) + " TiB" : one_decimal(gib) + " GiB";
}

// "all writes", "all reads", "30% writes".
std::string mix_text(int write_percent) {
  if (write_percent >= 100)
    return "all writes";
  if (write_percent <= 0)
    return "all reads";
  return std::to_string(write_percent) + "% writes";
}

// A test file's name: SAT-speed-test-20260930T154856102Z.dat.
std::string test_file_name() {
  std::string stamp;
  for (const char character : utc_now_iso8601()) {
    if (std::isalnum(static_cast<unsigned char>(character)) != 0)
      stamp.push_back(character);
  }
  return std::string(kSpeedTestFilePrefix) + stamp + ".dat";
}

// fio reads ':' in --filename as a separator between files.
std::string fio_file_argument(const std::filesystem::path& file) {
  std::string text = path_to_utf8(file);
  replace_all(text, ":", "\\:");
  return "--filename=" + text;
}

std::optional<double> number_of(std::string_view text) {
  const std::string value = trim(text);
  if (value.empty() || value == "N/A")
    return std::nullopt;
  double number = 0.0;
  const auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
  if (parsed.ec != std::errc())
    return std::nullopt;
  return number;
}

// SAT's own test file, removed after the run. The engine may hold it for a moment after it exits.
bool remove_test_file(const std::filesystem::path& file) {
  for (int attempt = 0; attempt < 20; ++attempt) {
    std::error_code error;
    std::filesystem::remove(file, error);
    std::error_code exists_error;
    if (!std::filesystem::exists(file, exists_error))
      return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }
  return false;
}

#ifdef _WIN32
// DiskSpd's release carries a build per processor; this machine's own, when SAT runs emulated.
bool native_arm64() {
  USHORT process_machine = 0;
  USHORT native_machine = 0;
  if (IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine) == FALSE)
    return false;
  return native_machine == IMAGE_FILE_MACHINE_ARM64;
}
#endif

} // namespace

namespace speed_test_detail {

std::optional<std::uint64_t> parse_size(std::string_view text) {
  const std::string value = trim(text);
  if (value.empty())
    return std::nullopt;
  std::uint64_t number = 0;
  const auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
  if (parsed.ec != std::errc() || number == 0U)
    return std::nullopt;
  const std::string unit = ascii_upper(std::string_view(
      parsed.ptr, static_cast<std::size_t>(value.data() + value.size() - parsed.ptr)));
  std::uint64_t scale = 0;
  if (unit.empty() || unit == "B")
    scale = 1ULL;
  else if (unit == "K" || unit == "KB" || unit == "KIB")
    scale = 1024ULL;
  else if (unit == "M" || unit == "MB" || unit == "MIB")
    scale = 1024ULL * 1024ULL;
  else if (unit == "G" || unit == "GB" || unit == "GIB")
    scale = 1024ULL * 1024ULL * 1024ULL;
  else if (unit == "T" || unit == "TB" || unit == "TIB")
    scale = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
  else
    return std::nullopt;
  if (number > std::numeric_limits<std::uint64_t>::max() / scale)
    return std::nullopt;
  return number * scale;
}

std::vector<std::string> expand_arguments(std::string_view pattern, std::string_view size, std::string_view block,
                                          int seconds) {
  return expand_arguments(pattern, {{"size", std::string(size)}, {"block", std::string(block)},
                                    {"seconds", std::to_string(seconds)}});
}

std::vector<std::string> expand_arguments(std::string_view pattern,
                                          const std::vector<std::pair<std::string, std::string>>& values) {
  std::vector<std::string> arguments;
  for (const std::string& part : split(pattern, ' ')) {
    std::string word = trim(part);
    if (word.empty())
      continue;
    for (const auto& [name, value] : values)
      replace_all(word, "{" + name + "}", value);
    arguments.push_back(std::move(word));
  }
  return arguments;
}

Result<DiskSpeedTestResult> parse_diskspd_report(std::string_view text) {
  DiskSpeedTestResult result;
  enum class Section { none, total, read, write, latency };
  Section section = Section::none;
  bool found = false;
  for (const std::string& raw : split(text, '\n')) {
    const std::string line = trim(raw);
    if (line.rfind("actual test time:", 0) == 0) {
      std::string seconds = trim(line.substr(17));
      if (!seconds.empty() && seconds.back() == 's')
        seconds.pop_back();
      result.seconds_run = number_of(seconds).value_or(0.0);
      continue;
    }
    if (line == "Total IO") {
      section = Section::total;
      continue;
    }
    if (line == "Read IO") {
      section = Section::read;
      continue;
    }
    if (line == "Write IO") {
      section = Section::write;
      continue;
    }
    if (line.rfind("%-ile", 0) == 0) {
      section = Section::latency;
      continue;
    }
    if (section == Section::latency) {
      const auto fields = split(line, '|');
      if (fields.size() >= 4U && trim(fields[0]) == "99th") {
        result.read.p99_latency_ms = number_of(fields[1]);
        result.write.p99_latency_ms = number_of(fields[2]);
        result.total.p99_latency_ms = number_of(fields[3]);
      }
      continue;
    }
    if (section == Section::none || line.rfind("total:", 0) != 0)
      continue;
    // total: bytes | I/Os | MiB/s | I/O per s | AvgLat | LatStdDev
    const auto fields = split(line.substr(6), '|');
    if (fields.size() < 4U)
      continue;
    SpeedFigures& figures =
        section == Section::read ? result.read : section == Section::write ? result.write : result.total;
    figures.bytes = static_cast<std::uint64_t>(number_of(fields[0]).value_or(0.0));
    figures.mib_per_second = number_of(fields[2]).value_or(0.0);
    figures.iops = number_of(fields[3]).value_or(0.0);
    if (fields.size() >= 5U && figures.bytes != 0U)
      figures.average_latency_ms = number_of(fields[4]);
    found = found || section == Section::total;
  }
  if (!found)
    return Result<DiskSpeedTestResult>::failure(
        speed_error("read DiskSpd's report", "DiskSpd", "The report has no Total IO figures."));
  return Result<DiskSpeedTestResult>::success(std::move(result));
}

Result<DiskSpeedTestResult> parse_fio_report(std::string_view text) {
  const std::size_t brace = text.find('{');
  if (brace == std::string_view::npos)
    return Result<DiskSpeedTestResult>::failure(
        speed_error("read fio's report", "fio", "fio printed no JSON report."));
  auto parsed = parse_json(text.substr(brace));
  if (!parsed.ok())
    return Result<DiskSpeedTestResult>::failure(
        speed_error("read fio's report", "fio", "fio's report could not be read: " + parsed.error().message));
  const JsonValue& report = parsed.value();
  const auto& jobs = report["jobs"].items();
  if (jobs.empty())
    return Result<DiskSpeedTestResult>::failure(
        speed_error("read fio's report", "fio", "fio's report holds no job."));
  const JsonValue& job = jobs.front();
  DiskSpeedTestResult result;
  result.engine_version = report["fio version"].as_string();
  const auto side = [](const JsonValue& value) {
    SpeedFigures figures;
    figures.bytes = static_cast<std::uint64_t>(value["io_bytes"].as_number());
    figures.mib_per_second = value["bw_bytes"].as_number() / (1024.0 * 1024.0);
    figures.iops = value["iops"].as_number();
    if (figures.bytes != 0U) {
      if (value["lat_ns"].has("mean"))
        figures.average_latency_ms = value["lat_ns"]["mean"].as_number() / 1.0e6;
      const JsonValue& percentiles = value["clat_ns"]["percentile"];
      if (percentiles.has("99.000000"))
        figures.p99_latency_ms = percentiles["99.000000"].as_number() / 1.0e6;
    }
    return figures;
  };
  result.read = side(job["read"]);
  result.write = side(job["write"]);
  result.total.bytes = result.read.bytes + result.write.bytes;
  result.total.mib_per_second = result.read.mib_per_second + result.write.mib_per_second;
  result.total.iops = result.read.iops + result.write.iops;
  // The average over both directions, weighted by the I/Os each made; the 99th percentile only
  // where one direction made them all, since two percentiles do not add.
  if (result.total.iops > 0.0) {
    double weighted = 0.0;
    double counted = 0.0;
    for (const SpeedFigures* figures : {&result.read, &result.write}) {
      if (figures->average_latency_ms) {
        weighted += *figures->average_latency_ms * figures->iops;
        counted += figures->iops;
      }
    }
    if (counted > 0.0)
      result.total.average_latency_ms = weighted / counted;
  }
  if (result.write.bytes == 0U)
    result.total.p99_latency_ms = result.read.p99_latency_ms;
  else if (result.read.bytes == 0U)
    result.total.p99_latency_ms = result.write.p99_latency_ms;
  result.seconds_run = job["elapsed"].as_number(job["job_runtime"].as_number() / 1000.0);
  return Result<DiskSpeedTestResult>::success(std::move(result));
}

} // namespace speed_test_detail

std::optional<StorageRole> parse_storage_role(std::string_view text) {
  const std::string value = ascii_lower(trim(text));
  if (value == "repository" || value == "backup repository" || value == "repo")
    return StorageRole::repository;
  if (value == "source" || value == "backup source")
    return StorageRole::source;
  if (value == "other" || value == "not sure" || value.empty())
    return StorageRole::not_sure;
  return std::nullopt;
}

std::string storage_role_name(StorageRole role) {
  switch (role) {
  case StorageRole::repository: return "Backup repository";
  case StorageRole::source: return "Backup source";
  case StorageRole::not_sure: break;
  }
  return "Not sure";
}

const StorageTestCatalog& storage_test_catalog() {
  static const StorageTestCatalog catalog = load_catalog();
  return catalog;
}

const StorageTest* find_storage_test(std::string_view id) {
  const auto& tests = storage_test_catalog().tests;
  const auto found = std::find_if(tests.begin(), tests.end(), [&](const StorageTest& test) { return test.id == id; });
  return found == tests.end() ? nullptr : &*found;
}

Result<DiskSpeedTestPlan> plan_disk_speed_test(const DiskSpeedTestOptions& options, SpeedTestEngine engine,
                                               const std::filesystem::path& engine_path) {
  const StorageTestCatalog& catalog = storage_test_catalog();
  const CustomSpeedTestSettings& custom_settings = catalog.custom;
  std::error_code error;
  const std::filesystem::path target = options.preview && options.target.empty()
                                           ? std::filesystem::path("FOLDER")
                                           : std::filesystem::absolute(options.target, error);
  if (error || (options.target.empty() && !options.preview))
    return Result<DiskSpeedTestPlan>::failure(
        speed_error("plan the test", path_to_utf8(options.target), "Choose a folder or a file to test."));

  DiskSpeedTestPlan plan;
  plan.engine = engine;
  plan.engine_path = engine_path;
  std::optional<CustomSpeedTest> custom = options.custom;
  if (custom) {
    // The engineer's own mix. A folder gets SAT's own new file; an existing file is only read.
    if (custom->threads <= 0)
      custom->threads = custom_settings.threads;
    if (custom->outstanding <= 0)
      custom->outstanding = custom_settings.outstanding;
    if (custom->warmup_seconds < 0)
      custom->warmup_seconds = custom_settings.warmup_seconds;
    if (custom->write_percent < 0 || custom->write_percent > 100)
      return Result<DiskSpeedTestPlan>::failure(speed_error(
          "plan the test", std::to_string(custom->write_percent), "The share of writes is 0 to 100 percent."));
    if (custom->threads > custom_settings.max_threads)
      return Result<DiskSpeedTestPlan>::failure(speed_error(
          "plan the test", std::to_string(custom->threads),
          "Threads run from 1 to " + std::to_string(custom_settings.max_threads) + "."));
    if (custom->outstanding > custom_settings.max_outstanding)
      return Result<DiskSpeedTestPlan>::failure(speed_error(
          "plan the test", std::to_string(custom->outstanding),
          "Outstanding I/Os per thread run from 1 to " + std::to_string(custom_settings.max_outstanding) + "."));
    if (custom->warmup_seconds > custom_settings.max_warmup_seconds)
      return Result<DiskSpeedTestPlan>::failure(speed_error(
          "plan the test", std::to_string(custom->warmup_seconds),
          "The warm-up runs from 0 to " + std::to_string(custom_settings.max_warmup_seconds) + " seconds."));
    StorageTest test;
    test.id = "custom";
    test.name = std::string("Custom: ") + (custom->random ? "random" : "sequential") + ", " +
                mix_text(custom->write_percent);
    test.write_percent = custom->write_percent;
    test.random = custom->random;
    test.file_size = custom_settings.file_size;
    test.divide_by = 1;
    if (std::filesystem::is_regular_file(target, error)) {
      if (custom->write_percent > 0)
        return Result<DiskSpeedTestPlan>::failure(speed_error(
            "plan the test", path_to_utf8(target),
            "A test that writes needs a folder, where SAT creates its own test file. An existing file is "
            "only read: set the share of writes to 0."));
      test.reads_existing_file = true;
    }
    plan.test = std::move(test);
  } else {
    const StorageTest* test = find_storage_test(options.test_id);
    if (test == nullptr)
      return Result<DiskSpeedTestPlan>::failure(speed_error(
          "plan the test", options.test_id, "There is no speed test named \"" + options.test_id + "\"."));
    plan.test = *test;
  }
  const StorageTest* test = &plan.test;

  const std::vector<std::string>& block_sizes = custom ? custom_settings.block_sizes : catalog.block_sizes;
  const std::string& default_block = custom ? custom_settings.block_size : catalog.default_block_size;
  plan.block_size = ascii_upper(trim(options.block_size.empty() ? default_block : options.block_size));
  if (std::find(block_sizes.begin(), block_sizes.end(), plan.block_size) == block_sizes.end()) {
    std::string listed;
    for (const auto& size : block_sizes)
      listed += (listed.empty() ? "" : ", ") + size;
    return Result<DiskSpeedTestPlan>::failure(speed_error(
        "plan the test", plan.block_size,
        "The block size must be one of " + listed + (custom ? std::string(".") : std::string(", as KB2014 gives them."))));
  }
  plan.block_bytes = speed_test_detail::parse_size(plan.block_size).value_or(0);
  plan.seconds = options.seconds != 0 ? options.seconds : custom ? custom_settings.seconds : catalog.default_seconds;
  if (plan.seconds < kSpeedTestMinimumSeconds || plan.seconds > kSpeedTestMaximumSeconds)
    return Result<DiskSpeedTestPlan>::failure(speed_error(
        "plan the test", std::to_string(plan.seconds),
        "The test runs for " + std::to_string(kSpeedTestMinimumSeconds) + " seconds to " +
            std::to_string(kSpeedTestMaximumSeconds / 60) + " minutes" +
            (custom ? std::string(".") : std::string("; KB2014 asks for at least 10 minutes."))));
  // DiskSpd warms up for 5 seconds unless told otherwise; fio does not unless asked.
  plan.warmup_seconds = custom ? custom->warmup_seconds : engine == SpeedTestEngine::diskspd ? 5 : 0;
  // KB2014's tests are a repository's; a custom test is whatever the engineer says it is.
  plan.role = !custom && options.role == StorageRole::not_sure ? StorageRole::repository : options.role;
  if (custom) {
    plan.threads = custom->threads;
    plan.outstanding = custom->outstanding;
    plan.caching = custom->caching;
  }
  plan.settings = plan.block_size + " blocks, " + (test->random ? "random" : "sequential") + ", " +
                  mix_text(test->write_percent);
  if (custom)
    plan.settings += ", " + std::to_string(custom->threads) + (custom->threads == 1 ? " thread" : " threads") +
                     " with " + std::to_string(custom->outstanding) + " outstanding I/O" +
                     (custom->outstanding == 1 ? "" : "s") + " each, " + std::to_string(plan.warmup_seconds) +
                     " s warm-up, caching " + (custom->caching ? "on" : "off");
  else
    plan.settings += ", caching off";

  if (!test->reads_existing_file) {
    if (!options.preview && !std::filesystem::is_directory(target, error))
      return Result<DiskSpeedTestPlan>::failure(speed_error(
          "plan the test", path_to_utf8(target),
          "No folder at this path. SAT makes its test file in an existing folder on the storage to test."));
    const auto bytes = speed_test_detail::parse_size(options.file_size.empty() ? test->file_size : options.file_size);
    constexpr std::uint64_t gib = 1024ULL * 1024ULL * 1024ULL;
    if (!bytes || *bytes < gib || *bytes > 4096ULL * gib)
      return Result<DiskSpeedTestPlan>::failure(speed_error(
          "plan the test", options.file_size, "The test file is 1 GB to 4 TB, such as 25G or 100G."));
    plan.file_bytes = *bytes;
    plan.file_size = size_text(*bytes);
    // A failed read reports every figure as the largest value, rather than trusting the error code.
    const auto space = std::filesystem::space(target, error);
    if (space.capacity == static_cast<std::uintmax_t>(-1) || space.capacity == 0U)
      return Result<DiskSpeedTestPlan>::failure(speed_error(
          "read the free space", path_to_utf8(target), "The free space could not be read: " + error.message()));
    plan.volume_capacity_bytes = space.capacity;
    plan.volume_free_bytes = space.available;
    const std::uint64_t keep = space.capacity / 100U * static_cast<std::uint64_t>(catalog.min_free_percent_after);
    if (space.available < plan.file_bytes || space.available - plan.file_bytes < keep)
      return Result<DiskSpeedTestPlan>::failure(speed_error(
          "plan the test", path_to_utf8(target),
          "A " + readable_bytes(plan.file_bytes) + " test file would leave less than " +
              std::to_string(catalog.min_free_percent_after) + "% of the volume free (" +
              readable_bytes(space.available) + " free of " + readable_bytes(space.capacity) + ")."));
    plan.file = target / test_file_name();
    if (std::filesystem::exists(plan.file, error))
      return Result<DiskSpeedTestPlan>::failure(
          speed_error("plan the test", path_to_utf8(plan.file), "A file of that name is already there."));
    plan.creates_file = true;
  } else {
    if (!std::filesystem::is_regular_file(target, error))
      return Result<DiskSpeedTestPlan>::failure(speed_error(
          "plan the test", path_to_utf8(target),
          "A read test needs an existing file on the storage to test, such as a backup file (.vbk)."));
    const std::uintmax_t bytes = std::filesystem::file_size(target, error);
    if (bytes == static_cast<std::uintmax_t>(-1) || bytes == 0U)
      return Result<DiskSpeedTestPlan>::failure(
          speed_error("plan the test", path_to_utf8(target), "The file to read is empty or its size could not be read."));
    plan.file = target;
    plan.file_bytes = static_cast<std::uint64_t>(bytes);
    plan.file_size = readable_bytes(plan.file_bytes);
    const auto space = std::filesystem::space(target.parent_path(), error);
    if (space.capacity != static_cast<std::uintmax_t>(-1)) {
      plan.volume_capacity_bytes = space.capacity;
      plan.volume_free_bytes = space.available;
    }
  }

  // The arguments come from the data file and the checked values above; only the file's path is
  // the engineer's, and it is passed as its own argument.
  std::vector<std::pair<std::string, std::string>> values{
      {"size", plan.file_size}, {"block", plan.block_size}, {"seconds", std::to_string(plan.seconds)}};
  if (custom) {
    const int write = custom->write_percent;
    values.emplace_back("write", std::to_string(write));
    values.emplace_back("threads", std::to_string(custom->threads));
    values.emplace_back("outstanding", std::to_string(custom->outstanding));
    values.emplace_back("warmup", std::to_string(plan.warmup_seconds));
    values.emplace_back("fio_rw", write <= 0    ? (custom->random ? "randread" : "read")
                                  : write >= 100 ? (custom->random ? "randwrite" : "write")
                                                 : (custom->random ? "randrw" : "rw"));
  }
  const auto add = [&](const std::string& pattern) {
    for (std::string& argument : speed_test_detail::expand_arguments(pattern, values))
      plan.arguments.push_back(std::move(argument));
  };
  if (engine == SpeedTestEngine::diskspd) {
    if (custom) {
      // -c only for SAT's own new file: DiskSpd would size an existing file to it.
      if (plan.creates_file)
        add(custom_settings.diskspd_create);
      add(custom_settings.diskspd);
      if (custom->random)
        add(custom_settings.diskspd_random);
      if (!custom->caching)
        add(custom_settings.diskspd_no_cache);
    } else {
      add(test->diskspd);
    }
    plan.arguments.push_back("-L");
    plan.arguments.push_back(path_to_utf8(plan.file));
  } else {
    if (custom) {
      add(custom_settings.fio);
      if (!custom->caching)
        add(custom_settings.fio_no_cache);
    } else {
      add(test->fio);
    }
    plan.arguments.push_back("--name=sat-speed-test");
    plan.arguments.push_back(fio_file_argument(plan.file));
    plan.arguments.push_back("--bs=" + ascii_lower(plan.block_size));
    plan.arguments.push_back("--runtime=" + std::to_string(plan.seconds));
    plan.arguments.push_back("--time_based");
    plan.arguments.push_back("--output-format=json");
    if (plan.creates_file)
      plan.arguments.push_back("--size=" + plan.file_size);
    else
      plan.arguments.push_back("--readonly");
  }
  return Result<DiskSpeedTestPlan>::success(std::move(plan));
}

Result<DiskSpeedTestResult> run_disk_speed_test(const DiskSpeedTestPlan& plan, const CancellationToken& cancel,
                                                ProgressCallback progress) {
  const std::string engine_name = plan.engine == SpeedTestEngine::diskspd ? "DiskSpd" : "fio";
#ifdef _WIN32
  if (plan.engine == SpeedTestEngine::diskspd) {
    // Microsoft signs DiskSpd's releases as Microsoft Windows (2.3) or Microsoft Corporation.
    DownloadPublisherCheck signature;
    for (const char* publisher : {"Microsoft Windows", "Microsoft Corporation"}) {
      signature = verify_installer_publisher(plan.engine_path, publisher);
      if (signature.trusted)
        break;
    }
    if (!signature.trusted)
      return Result<DiskSpeedTestResult>::failure(
          speed_error("check DiskSpd's signature", path_to_utf8(plan.engine_path),
                      "DiskSpd runs only while Microsoft's signature on it checks out: " + signature.failure));
  }
#endif
  ProcessOptions options;
  options.executable = plan.engine_path;
  options.arguments = plan.arguments;
  // Creating a large file comes before the timed part, so the limit leaves an hour for it.
  options.timeout = std::chrono::seconds(plan.seconds + plan.warmup_seconds + 3600);
  options.merge_standard_error = false;
  options.maximum_output_bytes = 4U * 1024U * 1024U;

  const std::int64_t started = unix_millis_now();
  // The engine reports only at the end, so the elapsed time is reported here once a second.
  std::mutex mutex;
  std::condition_variable wake;
  bool finished = false;
  std::thread ticker([&]() {
    if (!progress)
      return;
    const auto begun = std::chrono::steady_clock::now();
    std::unique_lock<std::mutex> lock(mutex);
    while (!wake.wait_for(lock, std::chrono::seconds(1), [&]() { return finished; })) {
      ProgressEvent event;
      event.phase = plan.test.name;
      // A write test creates its file first, and the engine warms up before the timed part.
      std::string steps;
      if (plan.creates_file)
        steps = "creates the " + readable_bytes(plan.file_bytes) + " test file";
      if (plan.warmup_seconds > 0)
        steps += std::string(steps.empty() ? "" : ", ") + "warms up for " + std::to_string(plan.warmup_seconds) +
                 " seconds";
      event.current_scope = engine_name + " " + (steps.empty() ? "" : steps + ", then ") +
                            (plan.creates_file ? "tests for " : "reads for ") + std::to_string(plan.seconds) +
                            " seconds";
      event.elapsed_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - begun).count();
      event.total = static_cast<std::uint64_t>(plan.seconds);
      event.processed = static_cast<std::uint64_t>(event.elapsed_seconds);
      progress(event);
    }
  });
  auto ran = run_process_capture(options, cancel);
  {
    std::lock_guard<std::mutex> lock(mutex);
    finished = true;
  }
  wake.notify_all();
  ticker.join();
  const std::int64_t ended = unix_millis_now();

  // SAT's own file goes whatever happened to the run.
  const bool removed = plan.creates_file ? remove_test_file(plan.file) : false;
  if (!ran.ok())
    return Result<DiskSpeedTestResult>::failure(ran.error());
  const ProcessResult& process = ran.value();

  DiskSpeedTestResult result;
  if (process.cancelled) {
    result.cancelled = true;
  } else {
    auto parsed = plan.engine == SpeedTestEngine::diskspd ? speed_test_detail::parse_diskspd_report(process.output)
                                                          : speed_test_detail::parse_fio_report(process.output);
    if (!parsed.ok()) {
      std::string said = trim(process.standard_error.empty() ? process.output : process.standard_error);
      if (said.size() > 600U)
        said = said.substr(said.size() - 600U);
      return Result<DiskSpeedTestResult>::failure(speed_error(
          "run " + engine_name, path_to_utf8(plan.engine_path),
          engine_name + " ended with code " + std::to_string(process.exit_code) + (said.empty() ? "" : ": " + said)));
    }
    result = std::move(parsed.value());
  }
  result.test_id = plan.test.id;
  result.test_name = plan.test.name;
  result.simulates = plan.test.simulates;
  result.engine = engine_name;
  result.command_line = process.command_display;
  result.file = path_to_utf8(plan.file);
  result.created_file = plan.creates_file;
  result.file_removed = removed;
  result.file_bytes = plan.file_bytes;
  result.block_bytes = plan.block_bytes;
  result.seconds_requested = plan.seconds;
  result.divide_by = plan.test.divide_by;
  result.write_percent = plan.test.write_percent;
  result.random = plan.test.random;
  result.threads = plan.threads;
  result.outstanding = plan.outstanding;
  result.caching = plan.caching;
  result.role = plan.role;
  result.settings = plan.settings;
  // The engine's own report, as it printed it: the full output keeps it.
  result.engine_report = process.output.size() > 64U * 1024U ? process.output.substr(0, 64U * 1024U) : process.output;
  result.started_unix_millis = started;
  result.ended_unix_millis = ended;
  return Result<DiskSpeedTestResult>::success(std::move(result));
}

std::string plain_rate(double mib_per_second) {
  // Whole megabytes from 100 up, with thousands separators: "2,514 MB/s".
  if (mib_per_second < 100.0)
    return one_decimal(mib_per_second) + " MB/s";
  std::string digits = std::to_string(std::llround(mib_per_second));
  for (std::size_t at = digits.size(); at > 3U; at -= 3U)
    digits.insert(at - 3U, ",");
  return digits + " MB/s";
}

namespace {

// "742 MB/s (0.72 GB/s), 2.5 TB per hour"
std::string plain_rate_line(double mib_per_second) {
  const double gib_per_hour = mib_per_second * 3600.0 / 1024.0;
  return plain_rate(mib_per_second) + " (" + two_decimals(mib_per_second / 1024.0) + " GB/s), " +
         (gib_per_hour >= 1024.0 ? one_decimal(gib_per_hour / 1024.0) + " TB"
                                 : std::to_string(std::llround(gib_per_hour)) + " GB") +
         " per hour";
}

// "about 24 minutes" for a terabyte at this rate.
std::string terabyte_time(double mib_per_second) {
  const double minutes = 1024.0 * 1024.0 / mib_per_second / 60.0;
  if (minutes < 1.0)
    return "under a minute";
  if (minutes < 90.0) {
    const long long whole = std::llround(minutes);
    return "about " + std::to_string(whole) + (whole == 1 ? " minute" : " minutes");
  }
  return "about " + one_decimal(minutes / 60.0) + " hours";
}

// "512 KB" for 512K, "1 MB" for 1M.
std::string plain_block(std::uint64_t bytes) {
  constexpr std::uint64_t mib = 1024ULL * 1024ULL;
  if (bytes >= mib && bytes % mib == 0U)
    return std::to_string(bytes / mib) + " MB";
  if (bytes >= 1024U && bytes % 1024U == 0U)
    return std::to_string(bytes / 1024U) + " KB";
  return std::to_string(bytes) + " bytes";
}

// "10 seconds", "1 minute", "10 minutes".
std::string plain_duration(double seconds) {
  const long long whole = std::llround(seconds);
  if (whole == 60)
    return "1 minute";
  if (whole >= 120 && whole % 60 == 0)
    return std::to_string(whole / 60) + " minutes";
  return std::to_string(whole) + " seconds";
}

// What SAT did, in a sentence: the direction, the file, the pattern, the block, the time and the
// parallel work.
std::string what_was_done(const DiskSpeedTestResult& result) {
  const bool reads = result.write_percent < 100;
  const bool writes = result.write_percent > 0;
  std::string sentence = std::string("SAT ") + (reads && writes ? "read and wrote " : writes ? "wrote " : "read ");
  const std::filesystem::path file = path_from_utf8(result.file);
  if (result.created_file)
    sentence += "its own " + readable_bytes(result.file_bytes) + " test file" +
                (file.has_parent_path() ? " in " + path_to_utf8(file.parent_path()) : std::string());
  else
    sentence += result.file + " (" + readable_bytes(result.file_bytes) + ")";
  if (reads && writes)
    sentence += " (" + std::to_string(result.write_percent) + "% writes)";
  sentence += result.random ? ", scattered across the file" : ", in order";
  sentence += ", " + plain_block(result.block_bytes) + " at a time, for " +
              plain_duration(result.seconds_run > 0.0 ? result.seconds_run : result.seconds_requested);
  if (result.threads > 1 || result.outstanding > 1) {
    const int workers = std::max(1, result.threads);
    sentence += ", with " + std::to_string(workers) + (workers == 1 ? " worker" : " workers") + " keeping " +
                std::to_string(std::max(1, result.outstanding)) +
                (result.outstanding > 1 ? " requests" : " request") + " waiting" + (workers > 1 ? " each" : "");
  }
  sentence += result.created_file ? ", then deleted it." : ", and changed nothing.";
  return sentence;
}

// What the result means for this storage, by what it is and what the test did.
std::string what_it_means(const DiskSpeedTestResult& result, double read_rate, double write_rate) {
  const bool reads = result.write_percent < 100;
  const bool writes = result.write_percent > 0;
  const std::string read = plain_rate(read_rate);
  const std::string write = plain_rate(write_rate);
  switch (result.role) {
  case StorageRole::repository:
    if (writes && !reads)
      return result.random ? "Backups mostly write to a repository in order; this test wrote scattered across the "
                             "file, and this repository took those writes at about " + write + "."
                           : "Backups write to a repository like this (an active full, an incremental), so a backup "
                             "writing here goes no faster than about " + write + ".";
    if (reads && !writes)
      return result.random ? "Restores from a fragmented backup file, health checks, SureBackup and Instant Recovery "
                             "read a repository like this: about " + read + " here, the slow end of restore speed."
                           : "Restoring a whole backup, and copying backups elsewhere, read a repository like this, "
                             "so they go no faster than about " + read + ".";
    return result.random ? "Merges, synthetic fulls and reverse incrementals read and write a repository at once like "
                           "this: about " + read + " of reads and " + write + " of writes here."
                         : "This repository read and wrote at once, in order: jobs that read and write it at the same "
                           "time share about " + read + " of reads and " + write + " of writes.";
  case StorageRole::source:
    if (writes && !reads)
      return "A restore writes back to its source like this, so restoring to this storage goes no faster than "
             "about " + write + ".";
    if (reads && !writes)
      return result.random ? "An incremental backup reads the changed blocks scattered across its source like this: "
                             "about " + read + " here."
                           : "A full backup reads its source in order like this, so a backup of this storage reads no "
                             "faster than about " + read + ".";
    return "This source read and wrote at once, as busy applications on it do; a backup reading it at the same time "
           "shares about " + read + " of reads with them.";
  case StorageRole::not_sure:
    break;
  }
  if (writes && !reads)
    return "Anything writing to this storage this way goes no faster than about " + write + ".";
  if (reads && !writes)
    return "Anything reading this storage this way goes no faster than about " + read + ".";
  return "Reading and writing at once this way, this storage managed about " + read + " of reads and " + write +
         " of writes.";
}

} // namespace

SpeedTestSummary summarize_speed_test(const DiskSpeedTestResult& result) {
  SpeedTestSummary summary;
  const std::string block = size_text(result.block_bytes);
  const auto latency = [](const SpeedFigures& figures) {
    std::string text;
    if (figures.average_latency_ms)
      text = "average " + two_decimals(*figures.average_latency_ms) + " ms";
    if (figures.p99_latency_ms)
      text += (text.empty() ? "" : ", ") + std::string("99th percentile ") + two_decimals(*figures.p99_latency_ms) + " ms";
    return text;
  };
  const auto figures_text = [&](const SpeedFigures& figures) {
    std::string text = one_decimal(figures.mib_per_second) + " MiB/s, " +
                       std::to_string(std::llround(figures.iops)) + " IOPS";
    const std::string wait = latency(figures);
    return wait.empty() ? text : text + ", " + wait;
  };
  const bool reads = result.write_percent < 100;
  const bool writes = result.write_percent > 0;

  if (result.cancelled) {
    summary.stopped = true;
    summary.headline = "Stopped before it finished";
    summary.plain_explanation.push_back(result.engine + " reports only when a run ends, so a stopped run has no figures. "
                                        "Run it again and let it finish.");
  } else {
    // The simple view: each direction on its own, a terabyte's time, and the response time.
    const double read_rate = writes ? result.read.mib_per_second : result.total.mib_per_second;
    const double write_rate = reads ? result.write.mib_per_second : result.total.mib_per_second;
    if (reads && writes)
      summary.headline = "Reads " + plain_rate(read_rate) + ", writes " + plain_rate(write_rate);
    else
      summary.headline = (writes ? "Writes " : "Reads ") + plain_rate(result.total.mib_per_second);
    if (reads)
      summary.plain.emplace_back("Reading", plain_rate_line(read_rate));
    if (writes)
      summary.plain.emplace_back("Writing", plain_rate_line(write_rate));
    std::string terabyte;
    if (reads && read_rate > 0.0)
      terabyte = terabyte_time(read_rate) + " to read";
    if (writes && write_rate > 0.0)
      terabyte += (terabyte.empty() ? "" : ", ") + terabyte_time(write_rate) + " to write";
    if (!terabyte.empty())
      summary.plain.emplace_back("1 TB takes", terabyte);
    if (result.total.average_latency_ms) {
      std::string response = two_decimals(*result.total.average_latency_ms) + " ms on average";
      if (result.total.p99_latency_ms)
        response += "; the slowest 1 in 100 took " + two_decimals(*result.total.p99_latency_ms) + " ms";
      summary.plain.emplace_back("Response time", response);
    }
    if (result.role != StorageRole::not_sure)
      summary.plain.emplace_back("Used as", storage_role_name(result.role));

    // What was done, what it means for this storage, and what the figures themselves show.
    summary.plain_explanation.push_back(what_was_done(result));
    summary.plain_explanation.push_back(what_it_means(result, read_rate, write_rate));
    if (result.total.average_latency_ms && result.total.p99_latency_ms && *result.total.average_latency_ms > 0.0 &&
        *result.total.p99_latency_ms >= 4.0 * *result.total.average_latency_ms)
      summary.plain_explanation.push_back(
          "The wait was uneven: the slowest 1 in 100 took " +
          std::to_string(std::llround(*result.total.p99_latency_ms / *result.total.average_latency_ms)) +
          " times the average.");
    constexpr std::uint64_t ten_gib = 10ULL * 1024ULL * 1024ULL * 1024ULL;
    const bool short_test = result.seconds_requested > 0 && result.seconds_requested < 300;
    const bool small_file = result.file_bytes > 0U && result.file_bytes < ten_gib;
    if (short_test && small_file)
      summary.plain_explanation.push_back("This was a short test on a small file, which a storage cache can hold, so "
                                          "the storage on its own may be slower. KB2014 runs 10 minutes on a 25 GB to "
                                          "100 GB file.");
    else if (short_test)
      summary.plain_explanation.push_back("This was a short test; KB2014 runs 10 minutes so the storage's cache fills "
                                          "and the result settles.");
    else if (small_file)
      summary.plain_explanation.push_back("The file was small enough for a storage cache to hold, so the storage on its "
                                          "own may be slower. KB2014 uses a 25 GB to 100 GB file.");
    if (result.caching)
      summary.plain_explanation.push_back("Caching was on, so these figures include the caches; the storage on its own "
                                          "is slower.");
    summary.plain_explanation.push_back(
        result.role == StorageRole::repository
            ? "This is the repository on its own: a backup also waits on the source, the proxy and the network."
        : result.role == StorageRole::source
            ? "This is the source on its own: a backup also waits on the proxy, the network and the repository."
            : "This is the storage on its own: a real job also waits on the network and the other machines involved.");

    // The full results, for whoever wants the engine's figures.
    summary.rows.emplace_back(reads && writes ? "Throughput, reads and writes together" : "Throughput",
                              one_decimal(result.total.mib_per_second) + " MiB/s, " +
                                  per_hour(result.total.mib_per_second) + " per hour");
    summary.rows.emplace_back("I/O rate", std::to_string(std::llround(result.total.iops)) + " IOPS of " + block);
    const std::string wait = latency(result.total);
    if (!wait.empty())
      summary.rows.emplace_back("Latency", wait);
    if (reads && writes) {
      summary.rows.emplace_back("Reads", figures_text(result.read));
      summary.rows.emplace_back("Writes", figures_text(result.write));
    }
    if (result.divide_by > 1)
      summary.rows.emplace_back("KB2014 reading", one_decimal(result.total.mib_per_second / result.divide_by) +
                                                      " MiB/s, the result divided by " +
                                                      std::to_string(result.divide_by));
    summary.explanation.push_back("MiB/s is the data moved each second in mebibytes (1,048,576 bytes), the unit "
                                  "Windows and Veeam call MB.");
    summary.explanation.push_back("IOPS is the reads and writes finished each second, each of " + block +
                                  ". Throughput is IOPS times the block size.");
    summary.explanation.push_back("Latency is how long each read or write took. The 99th percentile is the slow end, "
                                  "where 1 in 100 took longer.");
    if (result.divide_by > 1)
      summary.explanation.push_back("KB2014 counts " + std::to_string(result.divide_by) +
                                    " I/Os for each Veeam block in this test, so it divides the result by " +
                                    std::to_string(result.divide_by) + ".");
  }
  summary.rows.emplace_back("Test", result.test_name + (result.simulates.empty() ? "" : ": " + result.simulates));
  summary.rows.emplace_back("Settings", result.settings);
  summary.rows.emplace_back("Storage", result.file + (result.created_file
                                                          ? ", SAT's own " + readable_bytes(result.file_bytes) + " test file"
                                                          : ", an existing file, read only"));
  if (!result.cancelled)
    summary.rows.emplace_back("Ran", result.engine + (result.engine_version.empty() ? "" : " " + result.engine_version) +
                                         " for " + one_decimal(result.seconds_run) + " s");
  if (result.created_file)
    summary.rows.emplace_back("Test file", result.file_removed ? "removed" : "could not be removed: " + result.file);
  return summary;
}

std::string speed_test_text(const SpeedTestSummary& summary) {
  const auto rows_text = [](const std::vector<std::pair<std::string, std::string>>& rows) {
    std::size_t width = 0;
    for (const auto& row : rows)
      width = std::max(width, row.first.size());
    std::string text;
    for (const auto& [label, value] : rows)
      text += "  " + label + ": " + std::string(width - label.size(), ' ') + value + "\n";
    return text;
  };
  std::string text = summary.headline + "\n\nSimple\n";
  text += rows_text(summary.plain);
  for (const std::string& line : summary.plain_explanation)
    text += "- " + line + "\n";
  text += "\nFull results\n" + rows_text(summary.rows);
  if (!summary.explanation.empty()) {
    text += "\nWhat the full results mean\n";
    for (const std::string& line : summary.explanation)
      text += "- " + line + "\n";
  }
  return text;
}

Result<SpeedTestEngineLocation> find_speed_test_engine(const std::filesystem::path& tools_folder) {
#ifdef _WIN32
  auto resolved = resolve_external_tool("diskspd", tools_folder);
  if (!resolved.ok())
    return Result<SpeedTestEngineLocation>::failure(speed_error(
        "find DiskSpd", path_to_utf8(tools_folder),
        "DiskSpd is not in SAT's tools folder. Get it on the Integrations page: it is Microsoft's, and SAT "
        "runs it only while Microsoft's signature on it checks out."));
  SpeedTestEngineLocation location;
  location.engine = SpeedTestEngine::diskspd;
  location.path = resolved.value();
  const std::filesystem::path preferred =
      location.path.parent_path().parent_path() / (native_arm64() ? "arm64" : "amd64") / location.path.filename();
  std::error_code error;
  if (std::filesystem::is_regular_file(preferred, error))
    location.path = preferred;
  return Result<SpeedTestEngineLocation>::success(std::move(location));
#else
  static_cast<void>(tools_folder);
  // The system's own directories only: an fio earlier on PATH is not what SAT runs.
  for (const char* candidate : {"/usr/bin/fio", "/usr/local/bin/fio", "/bin/fio"}) {
    std::error_code error;
    if (std::filesystem::is_regular_file(candidate, error) && ::access(candidate, X_OK) == 0) {
      SpeedTestEngineLocation location;
      location.engine = SpeedTestEngine::fio;
      location.path = candidate;
      return Result<SpeedTestEngineLocation>::success(std::move(location));
    }
  }
  return Result<SpeedTestEngineLocation>::failure(speed_error(
      "find fio", "fio",
      "fio is not installed. Install it from the distribution's packages (apt install fio, dnf install fio or "
      "zypper install fio), as KB2014 does."));
#endif
}

std::vector<std::filesystem::path> speed_test_leftovers(const std::filesystem::path& folder) {
  std::vector<std::filesystem::path> found;
  std::error_code error;
  for (std::filesystem::directory_iterator entry(folder, std::filesystem::directory_options::skip_permission_denied, error),
       end;
       !error && entry != end; entry.increment(error)) {
    const std::string name = path_to_utf8(entry->path().filename());
    if (name.rfind(kSpeedTestFilePrefix, 0) != 0 || name.size() < 4U || name.substr(name.size() - 4U) != ".dat")
      continue;
    std::error_code kind_error;
    if (entry->is_regular_file(kind_error))
      found.push_back(entry->path());
  }
  return found;
}

std::uint64_t speed_test_leftover_bytes(const std::vector<std::filesystem::path>& files) {
  std::uint64_t total = 0;
  for (const std::filesystem::path& file : files) {
    std::error_code error;
    const std::uintmax_t size = std::filesystem::file_size(file, error);
    if (!error)
      total += static_cast<std::uint64_t>(size);
  }
  return total;
}

std::size_t remove_speed_test_leftovers(const std::vector<std::filesystem::path>& files) {
  std::size_t removed = 0;
  for (const std::filesystem::path& file : files) {
    const std::string name = path_to_utf8(file.filename());
    if (name.rfind(kSpeedTestFilePrefix, 0) != 0 || name.size() < 4U || name.substr(name.size() - 4U) != ".dat")
      continue;
    if (remove_test_file(file))
      ++removed;
  }
  return removed;
}

} // namespace support_assist
