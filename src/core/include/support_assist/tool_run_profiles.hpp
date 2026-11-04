#pragma once

// Guided-run profiles for the command-line integrations: iPerf3, ETL2PCAPNG, tcpdump, Packet Monitor,
// and the storage test on DiskSpd (Windows) or fio (Linux). Each profile is a small parameter form
// and a fixed mapping from the entered values to the tool's arguments, so both editions show the
// same form and build the same command line, and SAT's command line runs the same mapping (tools
// run). The storage test runs through the Disk Speed Test engine (disk_speed_test.hpp), which
// writes only SAT's own test file. Nothing here launches anything.

#include "support_assist/disk_speed_test.hpp"
#include "support_assist/error.hpp"
#include "support_assist/strings.hpp"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace support_assist {

struct ToolRunField {
  enum class Kind { text, number, choice, path, multiline };
  std::string key;                    // internal identifier, passed back to the value lookup
  std::string label;                  // shown beside the field
  Kind kind = Kind::text;
  std::vector<std::string> choices;   // choice fields
  std::string default_value;
  std::string hint;                   // a short example, shown inside the empty field
  std::string help;                   // what the field means and how to choose it
};

// A worked example: the values it gives the fields, by key. A field it does not name keeps its value.
struct ToolRunPreset {
  std::string name;
  std::string description;
  std::vector<std::pair<std::string, std::string>> values;
};

struct ToolRunProfile {
  std::string tool_id;
  std::string title;
  std::string summary;                // one line describing what Run will do
  std::vector<ToolRunField> fields;
  std::vector<ToolRunPreset> presets;
  bool long_running = false;          // Run flips to Stop (a server, a trace, a timed test)
};

// The storage test's form, the same for DiskSpd and fio. Its limits and defaults are the custom
// test's in storage-tests.json.
inline std::vector<ToolRunField> storage_test_fields() {
  const CustomSpeedTestSettings& settings = storage_test_catalog().custom;
  using Kind = ToolRunField::Kind;
#ifdef _WIN32
  const std::string where = "D:\\Backups, or a .vbk to read";
  const std::string folder_example = "D:\\Backups";
#else
  const std::string where = "/mnt/backups, or a backup file to read";
  const std::string folder_example = "/mnt/backups";
#endif
  return {
      {"target", "Folder or file", Kind::path, {}, "", where,
       "Where to test. A folder: SAT creates its own test file there, runs the test and deletes the file. "
       "A file: SAT only reads it, such as a backup file (.vbk) for a restore, or a large file on a source "
       "for a backup's read. Example: " + folder_example},
      {"role", "Used as", Kind::choice, {"Not sure", "Backup repository", "Backup source"}, "Not sure", {},
       "What this storage is to Veeam. A backup repository holds the backups. A backup source holds the data "
       "a backup reads: a VM's datastore, a file server's disks, a database's volume. The result says what "
       "the figures mean for it."},
      {"write_percent", "Share of writes (%)", Kind::number, {}, "0", "100",
       "How much of the work is writing. 100 writes only, as a backup writes to a repository and a restore "
       "to a source; 0 reads only, as a restore reads a repository and a backup its source; 50 is half "
       "each, as a merge or a synthetic full on a repository."},
      {"pattern", "Access pattern", Kind::choice, {"Sequential", "Random"}, "Sequential", {},
       "Sequential works through the file in order, as an active full backup writes and a full backup "
       "reads its source. Random jumps around the file, as a merge or a synthetic full does on a "
       "repository, and as an incremental backup reads its source's changed blocks."},
      {"block", "Block size", Kind::choice, settings.block_sizes, settings.block_size, {},
       "The size of each read or write. Veeam's default storage optimization reads the source 1 MB at a "
       "time and writes blocks of about 512 KB (1 MB, compressed to about half). Smaller blocks show how "
       "many operations the storage manages; larger ones how much data it moves."},
      {"size", "Test file size", Kind::text, {}, settings.file_size, "4G",
       "The size of the file SAT creates in a folder. A file larger than the storage's cache shows the "
       "storage itself: KB2014 uses 25G for its sequential test and 100G for the random ones. At least "
       "10% of the volume always stays free."},
      {"seconds", "Duration (seconds)", Kind::number, {}, std::to_string(settings.seconds), "60",
       "How long the timed part runs, from " + std::to_string(kSpeedTestMinimumSeconds) + " to " +
           std::to_string(kSpeedTestMaximumSeconds) + ". 60 is a quick look; KB2014 runs 600 (10 minutes) so "
           "the storage's cache fills and the result is steady."},
      {"threads", "Threads", Kind::number, {}, std::to_string(settings.threads), "1",
       "How many workers send reads and writes at once. 1 is like one backup task; 4 is like four "
       "tasks writing to the same storage."},
      {"outstanding", "Queue depth (per thread)", Kind::number, {}, std::to_string(settings.outstanding), "2",
       "How many reads or writes each thread keeps waiting at once. A deeper queue shows what the "
       "storage can do when it is kept busy. 2 to 8 is usual."},
      {"warmup", "Warm-up (seconds)", Kind::number, {}, std::to_string(settings.warmup_seconds), "5",
       "Seconds of reading or writing before the timed part, so the result leaves out the storage "
       "getting up to speed."},
      {"caching", "Caching", Kind::choice, {"Off", "On"}, "Off", {},
       "Off measures the storage itself: it bypasses the operating system's and the drive's caches, as "
       "KB2014's tests do. On lets the caches help, which reads faster and says less about the storage."}};
}

// The storage test's presets: the data file's quick looks, KB2014's tests as the wizard runs them (a
// repository's), then the data file's tests for a storage it names, such as a backup source.
inline std::vector<ToolRunPreset> storage_test_presets() {
  const StorageTestCatalog& catalog = storage_test_catalog();
  const auto names_role = [](const StoragePreset& preset) {
    return std::any_of(preset.values.begin(), preset.values.end(),
                       [](const std::pair<std::string, std::string>& entry) { return entry.first == "role"; });
  };
  std::vector<ToolRunPreset> presets;
  for (const StoragePreset& extra : catalog.custom.presets) {
    if (!names_role(extra))
      presets.push_back({extra.name, extra.description, extra.values});
  }
  for (const StorageTest& test : catalog.tests) {
    ToolRunPreset preset;
    preset.name = test.preset;
    const std::string like = test.simulates.empty() ? test.name : test.simulates;
    preset.description = "Like " + ascii_lower(like.substr(0, 1)) + like.substr(1) +
                         ", as KB2014 tests it: " +
                         (test.reads_existing_file ? std::string("choose a backup file (.vbk) in Folder or file; SAT only reads it")
                                                   : "SAT's own " + test.file_size + " test file") +
                         ", " + catalog.default_block_size + " blocks, " + std::to_string(catalog.default_seconds / 60) +
                         " minutes.";
    preset.values = {{"role", "Backup repository"},
                     {"write_percent", std::to_string(test.write_percent)},
                     {"pattern", test.random ? "Random" : "Sequential"},
                     {"block", catalog.default_block_size},
                     {"seconds", std::to_string(catalog.default_seconds)},
                     {"threads", "1"},
                     {"outstanding", "2"},
                     {"warmup", "5"},
                     {"caching", "Off"}};
    if (!test.file_size.empty())
      preset.values.emplace_back("size", test.file_size);
    presets.push_back(std::move(preset));
  }
  for (const StoragePreset& extra : catalog.custom.presets) {
    if (names_role(extra))
      presets.push_back({extra.name, extra.description, extra.values});
  }
  return presets;
}

// The catalogue of guided-run profiles. A tool without a profile is either launch-only (Wireshark)
// or has its own run on Integrations (VSS Trace's elevated trace, Process Monitor's capture).
inline const std::vector<ToolRunProfile>& tool_run_profiles() {
  static const std::vector<ToolRunProfile> profiles = [] {
    std::vector<ToolRunProfile> list;
    using Kind = ToolRunField::Kind;

    // iPerf3, shaped for Veeam network checks (proxy <-> repository throughput). Direction covers
    // upload (client -> server) and download (-R reverse); streams cover single vs the parallel data
    // movers Veeam uses; -O 2 omits TCP slow-start per ESnet's fasterdata guidance.
    ToolRunProfile iperf3;
    iperf3.tool_id = "iperf3";
    iperf3.title = "iPerf3 throughput";
    iperf3.summary =
        "Measure how fast the network carries data between two machines, such as a proxy and a "
        "repository. Start the server on one, then run the client on the other.";
    iperf3.fields = {
        {"mode", "Mode", Kind::choice, {"Client", "Server"}, "Client", {},
         "Client sends to the other machine's iPerf3 server and measures. Server waits for a client: "
         "start it first, on the other machine."},
        {"host", "Server", Kind::text, {}, "", "repo01 or 10.0.4.21",
         "The machine running the iPerf3 server, by name or address, such as the repository."},
        {"direction", "Direction", Kind::choice, {"Upload", "Download"}, "Upload", {},
         "Upload: this machine sends to the server, as a proxy writes to a repository. Download: the "
         "server sends to this machine, as a restore does."},
        {"streams", "Streams", Kind::choice, {"Single", "Multiple"}, "Single", {},
         "Single uses one connection. Multiple uses several at once, as Veeam's data movers do; much "
         "more with several streams points at a limit on each connection."},
        {"stream_count", "Number of streams", Kind::number, {}, "5", "5",
         "How many connections at once when Streams is Multiple. Veeam sends a job's data over 5 by default."},
        {"duration", "Duration (seconds)", Kind::number, {}, "20", "20",
         "How long the client sends. 20 is a quick check; 60 gives a steadier figure."},
        {"port", "Port", Kind::number, {}, "5201", "5201",
         "The server's port. iPerf3 uses 5201; both machines must use the same, and a firewall between "
         "them must let it through."},
        {"protocol", "Protocol", Kind::choice, {"TCP", "UDP"}, "TCP", {},
         "TCP measures what a connection achieves, as Veeam's traffic does. UDP sends at a set rate to "
         "show lost packets and jitter."}};
    iperf3.presets = {
        {"Quick check: one stream for 20 seconds",
         "One connection to the server for 20 seconds. Start the Server preset on the other machine first.",
         {{"mode", "Client"}, {"direction", "Upload"}, {"streams", "Single"}, {"duration", "20"}, {"port", "5201"},
          {"protocol", "TCP"}}},
        {"Veeam default: five streams for a minute",
         "Five connections at once for a minute, the number of upload streams Veeam uses for a job by default "
         "(Help Center, Managing Upload Streams). Compare it with one stream: much more with five points at a "
         "limit on each connection.",
         {{"mode", "Client"}, {"direction", "Upload"}, {"streams", "Multiple"}, {"stream_count", "5"},
          {"duration", "60"}, {"port", "5201"}, {"protocol", "TCP"}}},
        {"Like a restore: five streams back to this machine",
         "The server sends to this machine for a minute on five connections, Veeam's default, as data flows in "
         "a restore.",
         {{"mode", "Client"}, {"direction", "Download"}, {"streams", "Multiple"}, {"stream_count", "5"},
          {"duration", "60"}, {"port", "5201"}, {"protocol", "TCP"}}},
        {"Server: wait for the other machine",
         "This machine waits on port 5201 for the client to connect. Run it first, then the client on the "
         "other machine, and press Stop when done.",
         {{"mode", "Server"}, {"port", "5201"}}}};
    iperf3.long_running = true;  // a server waits until stopped
    list.push_back(std::move(iperf3));

    // Packet Monitor (pktmon), the in-box Windows capture. Run starts an elevated capture, filtered
    // to the failing host/port; Stop ends it and converts the .etl to .pcapng.
    ToolRunProfile pktmon;
    pktmon.tool_id = "pktmon";
    pktmon.title = "Packet Monitor capture";
    pktmon.summary =
        "Capture network traffic with Windows' own Packet Monitor, then convert it to .pcapng for "
        "Wireshark. Runs as administrator: Run, reproduce the problem, then Stop.";
    pktmon.fields = {
        {"host", "Host", Kind::text, {}, "", "repo01 or 10.0.4.21",
         "Only traffic to or from this machine: the agent, the repository or the gateway. Leave it "
         "empty for every host."},
        {"port", "Port", Kind::text, {}, "", "445",
         "Only traffic on this port. 445 for SMB (agent deployment, file shares), 443 for HTTPS (object "
         "storage). Leave it empty for every port."},
        {"size", "Capture", Kind::choice, {"Headers", "Full packets"}, "Headers", {},
         "Headers keeps the start of each packet, enough to follow connections. Full packets keeps "
         "everything for a closer look in Wireshark, and the capture grows faster."}};
    pktmon.presets = {
        {"SMB: agent deployment and file shares (port 445)",
         "Traffic on port 445, where Windows agents are deployed and file shares are reached. Put the "
         "target machine in Host to keep the capture small.",
         {{"port", "445"}, {"size", "Headers"}}},
        {"HTTPS: object storage (port 443)",
         "Traffic on port 443, as object storage and other HTTPS services use.",
         {{"port", "443"}, {"size", "Headers"}}},
        {"Everything to and from one host",
         "Every port, for the machine named in Host.", {{"port", ""}, {"size", "Headers"}}}};
    pktmon.long_running = true;  // Run -> Stop
    list.push_back(std::move(pktmon));

    // tcpdump - the Linux packet capture, the counterpart of pktmon. Filtered to the failing host and
    // port (headers only), limited to a packet count so Run finishes. Requires root.
    ToolRunProfile tcpdump;
    tcpdump.tool_id = "tcpdump";
    tcpdump.title = "tcpdump capture";
    tcpdump.summary =
        "Capture network traffic on Linux, filtered to the machine and port that is failing (headers "
        "only). Needs root. Run captures up to the packet limit and prints a line per packet.";
    tcpdump.fields = {
        {"interface", "Interface", Kind::text, {}, "any", "eth0",
         "The network interface to capture on; any captures them all."},
        {"host", "Host", Kind::text, {}, "", "repo01 or 10.0.4.21",
         "Only traffic to or from this machine. Leave it empty for every host."},
        {"port", "Port", Kind::text, {}, "", "22",
         "Only traffic on this port. 22 for SSH (Linux agent deployment), 443 for HTTPS (object "
         "storage). Leave it empty for every port."},
        {"count", "Packet limit", Kind::number, {}, "500", "500",
         "tcpdump stops after this many packets."}};
    tcpdump.presets = {
        {"SSH: Linux agent deployment (port 22)", "Traffic on port 22, where Linux agents are deployed.",
         {{"port", "22"}, {"count", "500"}}},
        {"HTTPS: object storage (port 443)", "Traffic on port 443, as object storage uses.",
         {{"port", "443"}, {"count", "500"}}},
        {"Everything to and from one host", "Every port, for the machine named in Host.",
         {{"port", ""}, {"count", "1000"}}}};
    tcpdump.long_running = true;  // Run -> Stop
    list.push_back(std::move(tcpdump));

    // ETL2PCAPNG: an input .etl and an auto-named .pcapng under the active case's log directory (or
    // Log-Collections when there is no case). Output may be left blank to auto-name from the input.
    ToolRunProfile etl2pcapng;
    etl2pcapng.tool_id = "etl2pcapng";
    etl2pcapng.title = "ETL to PCAPNG";
    etl2pcapng.summary =
        "Convert an .etl network capture into a .pcapng that Wireshark can open. Output goes to the "
        "active case's log directory, or Log-Collections when there is no case.";
    etl2pcapng.fields = {
        {"input", "Capture (.etl)", Kind::path, {}, "", "PktMon.etl",
         "The capture to convert: PktMon.etl from Packet Monitor, or another .etl network capture."},
        {"output", "Save as (.pcapng)", Kind::path, {}, "", "capture.pcapng",
         "Where to write the converted capture. Leave it empty to write it beside the case's logs."}};
    list.push_back(std::move(etl2pcapng));

    // The storage test: any mix of reads and writes on the storage behind a folder, through the Disk
    // Speed Test engine. DiskSpd on Windows, fio on Linux; the window carries the test's name.
    for (const auto& [tool_id, measured_with] :
         {std::pair<const char*, const char*>{"diskspd", "measured with DiskSpd from Integrations"},
          std::pair<const char*, const char*>{"fio", "measured with fio from the distribution's packages"}}) {
      ToolRunProfile storage;
      storage.tool_id = tool_id;
      storage.title = "Disk Speed Test";
      storage.summary = std::string("How fast the storage behind a folder reads and writes, ") + measured_with +
                        ". Pick a preset or set your own. A test that writes uses SAT's own test file and "
                        "deletes it; a file you choose is only read.";
      storage.fields = storage_test_fields();
      storage.presets = storage_test_presets();
      storage.long_running = true;  // Run -> Stop
      list.push_back(std::move(storage));
    }

    return list;
  }();
  return profiles;
}

inline const ToolRunProfile* find_tool_run_profile(const std::string& tool_id) {
  for (const auto& profile : tool_run_profiles())
    if (profile.tool_id == tool_id)
      return &profile;
  return nullptr;
}

// The storage test profiles run through the Disk Speed Test engine, not the tool directly.
inline bool tool_run_is_storage_test(const std::string& tool_id) {
  return tool_id == "diskspd" || tool_id == "fio";
}

// Build the argument list for a guided run from the entered field values. `value(key)` returns the
// current value of a field. The mapping is fixed per tool so the command line can never be steered
// by anything other than the declared fields - no free-form argument passthrough.
inline std::vector<std::string> build_tool_run_arguments(
    const std::string& tool_id, const std::function<std::string(const std::string&)>& value) {
  std::vector<std::string> args;
  if (tool_id == "iperf3") {
    const std::string port = value("port").empty() ? std::string("5201") : value("port");
    if (value("mode") == "Server") {
      args = {"-s", "-p", port};
    } else {
      args = {"-c", value("host"), "-p", port, "-O", "2"};  // omit TCP slow-start (ESnet)
      if (value("direction") == "Download")
        args.push_back("-R");  // reverse: server sends, client receives
      if (value("streams") == "Multiple") {
        const std::string count = value("stream_count").empty() ? std::string("5")
                                                                 : value("stream_count");
        args.push_back("-P");
        args.push_back(count);
      }
      if (!value("duration").empty()) {
        args.push_back("-t");
        args.push_back(value("duration"));
      }
      if (value("protocol") == "UDP")
        args.push_back("-u");
    }
  } else if (tool_id == "etl2pcapng") {
    args.push_back(value("input"));
    if (!value("output").empty())
      args.push_back(value("output"));  // blank lets etl2pcapng auto-name from the input
  } else if (tool_id == "tcpdump") {
    args = {"-i", value("interface").empty() ? std::string("any") : value("interface"), "-n", "-s",
            "96"};  // headers only
    if (!value("count").empty()) {
      args.push_back("-c");
      args.push_back(value("count"));
    }
    std::string filter;
    if (!value("host").empty())
      filter = "host " + value("host");
    if (!value("port").empty()) {
      if (!filter.empty())
        filter += " and ";
      filter += "port " + value("port");
    }
    if (!filter.empty())
      args.push_back(filter);  // tcpdump takes the BPF expression as trailing arguments
  }
  return args;
}

// The storage test's values as the Disk Speed Test engine takes them.
inline Result<DiskSpeedTestOptions> storage_test_options(const std::function<std::string(const std::string&)>& value) {
  const auto whole = [&](const char* key, const char* label, int fallback) -> Result<int> {
    const std::string text = trim(value(key));
    if (text.empty())
      return Result<int>::success(fallback);
    int number = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), number);
    if (parsed.ec != std::errc() || parsed.ptr != text.data() + text.size()) {
      Error error;
      error.component = "DiskSpeedTest";
      error.operation = "read the test's settings";
      error.source = text;
      error.message = std::string(label) + " takes a whole number.";
      return Result<int>::failure(error);
    }
    return Result<int>::success(number);
  };
  const auto write = whole("write_percent", "Writes (%)", 0);
  const auto seconds = whole("seconds", "Duration (s)", 0);
  const auto threads = whole("threads", "Threads", 0);
  const auto outstanding = whole("outstanding", "Outstanding I/Os", 0);
  const auto warmup = whole("warmup", "Warm-up (s)", -1);
  for (const Result<int>* number : {&write, &seconds, &threads, &outstanding, &warmup}) {
    if (!number->ok())
      return Result<DiskSpeedTestOptions>::failure(number->error());
  }
  const std::optional<StorageRole> role = parse_storage_role(value("role"));
  if (!role) {
    Error error;
    error.component = "DiskSpeedTest";
    error.operation = "read the test's settings";
    error.source = value("role");
    error.message = "Used as is a backup repository, a backup source or not sure.";
    return Result<DiskSpeedTestOptions>::failure(error);
  }
  DiskSpeedTestOptions options;
  options.role = *role;
  CustomSpeedTest mix;
  mix.write_percent = write.value();
  mix.random = value("pattern") == "Random";
  mix.threads = threads.value();
  mix.outstanding = outstanding.value();
  mix.warmup_seconds = warmup.value();
  mix.caching = value("caching") == "On";
  options.custom = mix;
  options.target = path_from_utf8(trim(value("target")));
  options.block_size = trim(value("block"));
  options.file_size = trim(value("size"));
  options.seconds = seconds.value();
  return Result<DiskSpeedTestOptions>::success(std::move(options));
}

// The folder a storage test's Folder or file names: the folder itself, or the file's folder.
inline std::filesystem::path storage_test_folder(const std::string& target) {
  const std::filesystem::path chosen = path_from_utf8(trim(target));
  std::error_code error;
  return std::filesystem::is_directory(chosen, error) ? chosen : chosen.parent_path();
}

// The question before deleting the test files an earlier run left in a folder.
inline std::string speed_test_leftover_question(const std::vector<std::filesystem::path>& files,
                                                const std::filesystem::path& folder) {
  char size[32] = {};
  std::snprintf(size, sizeof(size), "%.1f GB",
                static_cast<double>(speed_test_leftover_bytes(files)) / (1024.0 * 1024.0 * 1024.0));
  const bool one = files.size() == 1U;
  return std::to_string(files.size()) + (one ? " test file" : " test files") + " from an earlier run " +
         (one ? "is" : "are") + " in\n" + path_to_utf8(folder) + "\n(" + size + "). Delete " +
         (one ? "it" : "them") + " before the test?";
}

// "--stream-count" for the field "stream_count".
inline std::string tool_run_option(const std::string& key) {
  std::string option = "--" + key;
  for (char& character : option) {
    if (character == '_')
      character = '-';
  }
  return option;
}

// A command line as an engineer types it: only an argument with a space, a quote or nothing in it is
// quoted, the Windows way on Windows and the shell's way elsewhere.
inline std::string command_line_text(const std::string& program, const std::vector<std::string>& arguments) {
  const auto quoted = [](const std::string& text) {
    if (!text.empty() && text.find_first_of(" \t\"'&|<>;$`") == std::string::npos)
      return text;
#ifdef _WIN32
    std::string escaped;
    for (const char character : text) {
      if (character == '"')
        escaped += '\\';
      escaped += character;
    }
    return "\"" + escaped + "\"";
#else
    std::string escaped;
    for (const char character : text)
      escaped += character == '\'' ? std::string("'\\''") : std::string(1, character);
    return "'" + escaped + "'";
#endif
  };
  std::string line = quoted(program);
  for (const std::string& argument : arguments)
    line += " " + quoted(argument);
  return line;
}

// SAT's program as a command line names it: by name on Windows, from its folder elsewhere.
inline std::string sat_program_name() {
#ifdef _WIN32
  return "SupportAssistTool.exe";
#else
  return "./SupportAssistTool";
#endif
}

// SAT's own command for a guided run: storage speed-test --custom for the storage test, tools run for
// the others. Empty for Packet Monitor, whose capture runs from the Integrations page only.
inline std::string tool_run_sat_command(const std::string& tool_id,
                                        const std::function<std::string(const std::string&)>& value) {
  const ToolRunProfile* profile = find_tool_run_profile(tool_id);
  if (profile == nullptr || tool_id == "pktmon")
    return {};
  std::vector<std::string> arguments;
  if (tool_run_is_storage_test(tool_id)) {
    const std::string target = trim(value("target"));
    std::error_code error;
    const bool file = !target.empty() && std::filesystem::is_regular_file(path_from_utf8(target), error);
    arguments = {"storage", "speed-test", "--custom", file ? "--file" : "--folder", target.empty() ? "FOLDER" : target};
    const std::optional<StorageRole> role = parse_storage_role(value("role"));
    if (role && *role != StorageRole::not_sure) {
      arguments.push_back("--role");
      arguments.push_back(*role == StorageRole::repository ? "repository" : "source");
    }
    const auto add = [&](const char* flag_name, const std::string& text) {
      if (!trim(text).empty()) {
        arguments.push_back(flag_name);
        arguments.push_back(trim(text));
      }
    };
    add("--write-percent", value("write_percent"));
    if (value("pattern") == "Random")
      arguments.push_back("--random");
    add("--threads", value("threads"));
    add("--outstanding", value("outstanding"));
    add("--warmup", value("warmup"));
    if (value("caching") == "On")
      arguments.push_back("--caching");
    add("--block", value("block"));
    if (!file)
      add("--size", value("size"));
    add("--seconds", value("seconds"));
  } else {
    arguments = {"tools", "run", "--id", tool_id};
    for (const ToolRunField& field : profile->fields) {
      const std::string text = trim(value(field.key));
      if (text.empty())
        continue;
      arguments.push_back(tool_run_option(field.key));
      arguments.push_back(text);
    }
  }
  return command_line_text(sat_program_name(), arguments);
}

// What the CLI button shows: SAT's own command when it has one, then the tool's own command line.
inline std::string tool_run_cli_text(const std::string& sat_command, const std::string& tool_name,
                                     const std::string& tool_command) {
  std::string text;
  if (!sat_command.empty())
    text += "SAT:\n  " + sat_command + "\n";
  text += tool_name + ":\n  " + tool_command + "\n";
  return text;
}

} // namespace support_assist
