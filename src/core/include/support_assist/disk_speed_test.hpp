#pragma once

// The Disk Speed Test (docs/PROPOSAL_5.x_CHECKS.md section 10): Veeam's own KB2014 tests of the
// storage behind a folder, run by DiskSpd on Windows and fio on Linux. The command lines are built
// from config/checks/storage-tests.json, never typed. A write test only ever creates SAT's own new
// file and deletes it afterwards; a read test opens an existing file for reading only.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

// One of KB2014's tests.
struct StorageTest {
  std::string id;
  std::string name;
  std::string preset;               // its name in the storage test wizard's Preset list
  std::string simulates;
  int write_percent = 0;
  bool random = false;
  bool reads_existing_file = false; // reads an existing file, opened for reading only
  std::string file_size;            // "25G"; empty for a read test
  int divide_by = 1;                // the I/Os each block costs, as the KB reads a random test
  std::string diskspd;              // the argument template: {size}, {block}, {seconds}
  std::string fio;
};

// An example the storage test wizard offers: the wizard's field values by key.
struct StoragePreset {
  std::string name;
  std::string description;
  std::vector<std::pair<std::string, std::string>> values;
};

// The custom test's limits, defaults and argument templates ("custom" in storage-tests.json).
struct CustomSpeedTestSettings {
  std::vector<StoragePreset> presets;
  std::vector<std::string> block_sizes;
  std::string block_size = "64K";
  int seconds = 60;
  std::string file_size = "4G";
  int threads = 1;
  int outstanding = 4;
  int warmup_seconds = 5;
  int max_threads = 64;
  int max_outstanding = 256;
  int max_warmup_seconds = 300;
  std::string diskspd;          // {block} {write} {threads} {outstanding} {warmup} {seconds}
  std::string diskspd_create;   // only when SAT creates its own file: {size}
  std::string diskspd_random;
  std::string diskspd_no_cache;
  std::string fio;              // also {fio_rw}
  std::string fio_no_cache;
};

struct StorageTestCatalog {
  CustomSpeedTestSettings custom;
  std::vector<StorageTest> tests;
  std::string default_block_size = "512K";
  int default_seconds = 600;
  std::vector<std::string> block_sizes;
  std::string block_size_note;
  int min_free_percent_after = 10;
  std::string source_title;
  std::string source_url;
  std::string reviewed;
};

// The tests and settings from storage-tests.json.
const StorageTestCatalog& storage_test_catalog();
const StorageTest* find_storage_test(std::string_view id);

enum class SpeedTestEngine { diskspd, fio };

// What the storage is, as the engineer says: a backup repository, a source (the data a backup reads),
// or not said. It decides what the result means; KB2014's tests are a repository's.
enum class StorageRole { not_sure, repository, source };
// "repository", "source", "other" and the wizard's names for them; nothing for anything else.
std::optional<StorageRole> parse_storage_role(std::string_view text);
// "Backup repository", "Backup source", "Not sure": the wizard's names.
std::string storage_role_name(StorageRole role);

// A test of the engineer's own mix, in place of one of KB2014's: any share of writes, sequential or
// random, with the threads, outstanding I/Os, warm-up and caching chosen. A test that writes still
// needs a folder, where SAT creates its own file; an existing file is only read.
struct CustomSpeedTest {
  int write_percent = 0;
  bool random = false;
  int threads = 0;          // 0: the data file's default
  int outstanding = 0;      // 0: the data file's default
  int warmup_seconds = -1;  // below 0: the data file's default
  bool caching = false;     // false bypasses the system and drive caches (-Sh, --direct=1), as KB2014 runs
};

struct DiskSpeedTestOptions {
  std::string test_id;          // one of KB2014's tests; ignored when custom is set
  std::optional<CustomSpeedTest> custom;
  StorageRole role = StorageRole::not_sure;  // a KB2014 test without one tests a repository
  std::filesystem::path target; // the folder for a write test; the existing file for a read test
  std::string block_size;       // empty: the catalog's default
  std::string file_size;        // empty: the test's own
  int seconds = 0;              // 0: the catalog's default
  // A plan to show the command line only: the folder need not exist yet, and an empty target reads
  // FOLDER. A preview plan is never run.
  bool preview = false;
};

// The shortest and longest run SAT starts, in seconds. KB2014 asks for at least ten minutes; a
// shorter run is for trying the setup.
inline constexpr int kSpeedTestMinimumSeconds = 10;
inline constexpr int kSpeedTestMaximumSeconds = 3600;

struct DiskSpeedTestPlan {
  StorageTest test;
  SpeedTestEngine engine = SpeedTestEngine::diskspd;
  std::filesystem::path engine_path;
  std::filesystem::path file; // what the engine reads or writes
  bool creates_file = false;  // SAT's own new file, deleted when the run ends
  std::uint64_t file_bytes = 0;
  std::uint64_t block_bytes = 0;
  std::string block_size;     // as the test reads it: "512K"
  std::string file_size;      // "25G"; the file's own size for a read test
  int seconds = 0;
  int warmup_seconds = 0;     // before the timed part: DiskSpd's own 5 for KB2014's tests
  std::string settings;       // "512K blocks, sequential, all writes, caching off"
  StorageRole role = StorageRole::not_sure;
  int threads = 0;            // 0: the engine's own default (KB2014's tests)
  int outstanding = 0;
  bool caching = false;
  std::vector<std::string> arguments;
  std::uint64_t volume_capacity_bytes = 0;
  std::uint64_t volume_free_bytes = 0;
};

// Checks the options and builds the command line. Refuses a test it does not know, a block size
// the data file does not list, a time out of range, a write test whose folder does not exist or
// whose file would leave less than the minimum free, and a read test whose file is not an
// existing regular file.
Result<DiskSpeedTestPlan> plan_disk_speed_test(const DiskSpeedTestOptions& options, SpeedTestEngine engine,
                                               const std::filesystem::path& engine_path);

struct SpeedFigures {
  double mib_per_second = 0.0;
  double iops = 0.0;
  std::uint64_t bytes = 0;
  std::optional<double> average_latency_ms;
  std::optional<double> p99_latency_ms;
};

struct DiskSpeedTestResult {
  std::string test_id;
  std::string test_name;
  std::string simulates;
  std::string engine;         // "DiskSpd" or "fio"
  std::string engine_version; // fio reports its own
  std::string command_line;
  std::string file;
  bool created_file = false;
  bool file_removed = false;
  std::uint64_t file_bytes = 0;
  std::uint64_t block_bytes = 0;
  int seconds_requested = 0;
  double seconds_run = 0.0;
  SpeedFigures total;
  SpeedFigures read;
  SpeedFigures write;
  int divide_by = 1;
  int write_percent = 0;
  bool random = false;
  int threads = 0;            // 0: the engine's own default
  int outstanding = 0;
  bool caching = false;
  StorageRole role = StorageRole::not_sure;
  std::string settings;
  std::string engine_report;  // the engine's own report as it printed it, for the full output
  bool cancelled = false;
  std::int64_t started_unix_millis = 0;
  std::int64_t ended_unix_millis = 0;
};

// A result two ways. The simple view is for anyone: reads and writes in MB/s and GB/s, as Windows and
// Veeam's job statistics count them, what that comes to in an hour and for a terabyte, the response
// time, and what was done and what it means for this storage (a repository, a source, or neither
// said), with what the figures themselves show (an uneven wait, a short test, caching on). The full
// results add IOPS, percentiles, the settings and the engine, with what those terms mean.
struct SpeedTestSummary {
  std::string headline;  // "Writes 2,514 MB/s"
  bool stopped = false;
  std::vector<std::pair<std::string, std::string>> plain;
  std::vector<std::string> plain_explanation;
  std::vector<std::pair<std::string, std::string>> rows;
  std::vector<std::string> explanation;
};
SpeedTestSummary summarize_speed_test(const DiskSpeedTestResult& result);
// The summary as text: the plain view, then "Full results" and what they mean.
std::string speed_test_text(const SpeedTestSummary& summary);
// "2,514 MB/s" for a rate in MiB/s, as Windows counts a megabyte.
std::string plain_rate(double mib_per_second);

// Runs the plan. On Windows DiskSpd runs only when Microsoft's signature on it checks out. The
// file SAT created is deleted when the run ends, is stopped or fails.
Result<DiskSpeedTestResult> run_disk_speed_test(const DiskSpeedTestPlan& plan, const CancellationToken& cancel,
                                                ProgressCallback progress = {});

// The engine on this machine: DiskSpd from SAT's tools folder on Windows, fio from the system's
// own directories on Linux. The error says how to get it.
struct SpeedTestEngineLocation {
  SpeedTestEngine engine = SpeedTestEngine::diskspd;
  std::filesystem::path path;
};
Result<SpeedTestEngineLocation> find_speed_test_engine(const std::filesystem::path& tools_folder);

// The name SAT gives its test files, and the files a run that did not finish left in a folder.
inline constexpr std::string_view kSpeedTestFilePrefix = "SAT-speed-test-";
std::vector<std::filesystem::path> speed_test_leftovers(const std::filesystem::path& folder);
// The size of the files speed_test_leftovers found.
std::uint64_t speed_test_leftover_bytes(const std::vector<std::filesystem::path>& files);
// Deletes the files speed_test_leftovers found, each only when its name is SAT's test file's;
// returns how many went.
std::size_t remove_speed_test_leftovers(const std::vector<std::filesystem::path>& files);

namespace speed_test_detail {
// "512K", "25G", "4M" in bytes, binary units as DiskSpd and fio read them; nothing for other text.
std::optional<std::uint64_t> parse_size(std::string_view text);
// The arguments from a template, with {size}, {block} and {seconds} replaced.
std::vector<std::string> expand_arguments(std::string_view pattern, std::string_view size, std::string_view block,
                                          int seconds);
// The same, for any set of {name} values.
std::vector<std::string> expand_arguments(std::string_view pattern,
                                          const std::vector<std::pair<std::string, std::string>>& values);
// DiskSpd's text report (run with -L) and fio's JSON report.
Result<DiskSpeedTestResult> parse_diskspd_report(std::string_view text);
Result<DiskSpeedTestResult> parse_fio_report(std::string_view text);
} // namespace speed_test_detail

} // namespace support_assist
