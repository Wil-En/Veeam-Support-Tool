// The Linux environment collector.
//
// Deliberately a separate implementation from the Windows edition's collector rather than a shared
// abstraction over both. See environment_report.hpp for why. The categories match so an engineer
// reading either report recognises the other; the collection does not.
//
// Everything here is read-only: files under /proc, /sys and /etc, plus a small set of bounded
// read-only commands. Nothing is installed, started, stopped or reconfigured, and a command that
// is absent produces a stated coverage note rather than a gap.

#include "support_assist/environment_report.hpp"

// glibc-only, and this translation unit is compiled on every platform. The guard has to sit
// AFTER a standard header: __GLIBC__ is defined by <features.h>, which nothing has pulled in
// yet at the top of the file - so guarding there skipped the include while the use site below
// still compiled, and the build failed with "gnu_get_libc_version was not declared".
#if defined(__linux__) && defined(__GLIBC__)
#include <gnu/libc-version.h>
#endif

#include "support_assist/network.hpp"
#include "support_assist/process.hpp"
#include "support_assist/product_discovery.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/system_info.hpp"
#include "support_assist/time.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <sstream>
#include <system_error>
#ifndef _WIN32
#include <unistd.h>
#endif

namespace support_assist {
namespace {

constexpr const char* kSystem = "System";
constexpr const char* kProducts = "Veeam Products";
constexpr const char* kMaintenance = "Maintenance";
constexpr const char* kServices = "Services";
constexpr const char* kSoftware = "Installed Software";
constexpr const char* kNetwork = "Network";
constexpr const char* kSecurity = "TLS / Security";
constexpr const char* kVeeamConfig = "Veeam Certificates / Configuration";

// List sections are not capped. A cap keeps environment.log small but silently drops content - a
// 400-line cap dropped 313 packages on an ordinary host. A larger file is the lesser problem: the
// report is read in a scrolling window or searched, not printed.

std::string read_text_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    return {};
  }
  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

std::string first_line(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  std::string line;
  if (input && std::getline(input, line)) {
    return std::string(trim(line));
  }
  return {};
}

// Pulls KEY=value or KEY: value out of a text blob, tolerating both because /etc/os-release and
// /proc/cpuinfo disagree about which they use.
std::string value_for(const std::string& text, std::string_view key, char separator) {
  std::istringstream input(text);
  std::string line;
  while (std::getline(input, line)) {
    const auto position = line.find(separator);
    if (position == std::string::npos) {
      continue;
    }
    if (std::string(trim(std::string_view(line).substr(0, position))) != key) {
      continue;
    }
    std::string value(trim(std::string_view(line).substr(position + 1)));
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
      value = value.substr(1, value.size() - 2);
    }
    return value;
  }
  return {};
}

void add_line(EnvironmentSection& section, std::string_view key, std::string value) {
  if (value.empty()) {
    return;
  }
  section.lines.push_back(std::string(key) + "=" + std::move(value));
}

// Runs one bounded read-only command. A missing command is a coverage note, never a failure: a
// minimal container image legitimately has no systemctl, and the rest of the report is still worth
// having.
bool run_tool(EnvironmentSection& section,
              const std::string& executable,
              std::vector<std::string> arguments,
              const CancellationToken& cancel,
              std::string* output) {
  ProcessOptions options;
  options.executable = executable;
  options.arguments = std::move(arguments);
  options.timeout = std::chrono::milliseconds(15000);
  options.merge_standard_error = false;
  options.maximum_output_bytes = 2U * 1024U * 1024U;
  auto result = run_process_capture(options, cancel, {});
  if (!result.ok() || !result.value().launched) {
    section.unavailable_reason = executable + " is not present on this host";
    return false;
  }
  if (result.value().exit_code != 0 && result.value().output.empty()) {
    section.unavailable_reason = executable + " returned exit code " +
                                 std::to_string(result.value().exit_code);
    return false;
  }
  *output = result.value().output;
  return true;
}

// maximum == 0 means no cap.
//
// The inventories pass 0. Capping them hid data an engineer came to read - a 713-package host
// showed 400 rows and "[TRUNCATED BY SAT] 313 further entries were not included", which is the
// tool refusing to answer the question it was opened to answer. The detail window scrolls; there
// is no reason to decide on the engineer's behalf that they have seen enough.
void add_capped_lines(EnvironmentSection& section, const std::string& text, std::size_t maximum) {
  std::istringstream input(text);
  std::string line;
  std::size_t emitted = 0;
  std::size_t total = 0;
  while (std::getline(input, line)) {
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
      line.pop_back();
    }
    if (line.empty()) {
      continue;
    }
    ++total;
    if (maximum == 0U || emitted < maximum) {
      section.lines.push_back(std::move(line));
      ++emitted;
    }
  }
  if (total > emitted) {
    section.lines.push_back("[TRUNCATED BY SAT] " + std::to_string(total - emitted) +
                            " further entries were not included");
  }
}

// systemctl --plain prints whitespace-ALIGNED columns: UNIT LOAD ACTIVE SUB DESCRIPTION.
// Emitted raw, the whole line lands in one cell and the alignment is lost, leaving the service list
// unreadable and every unit looking "dead" (that word sits nearest the unit name). Splitting here
// produces tab-separated fields, the same convention the Windows collector uses, so the frontend
// can build real columns.
//
// The state is deliberately the SECOND field, next to the unit name, because that adjacency is
// what an engineer scans. A line that does not parse is kept verbatim rather than dropped.
// `openssl version -a` prints "Key: value" lines, plus a bare version banner on the first line.
// Splitting those on '=' - which the generic renderer does when it sees no tabs - lands inside a
// compiler flag such as -fzero-call-used-regs=used-gpr and produces a row that is worse than
// useless. Split on the first COLON, and label the banner rather than leaving Item empty.
void add_colon_fields(EnvironmentSection& section, const std::string& text,
                      const std::string& banner_label) {
  std::istringstream input(text);
  std::string line;
  bool first = true;
  while (std::getline(input, line)) {
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
      line.pop_back();
    }
    if (line.empty()) {
      continue;
    }
    const auto colon = line.find(": ");
    if (colon == std::string::npos) {
      section.lines.push_back((first ? banner_label : std::string("Detail")) + "\t" + line);
      first = false;
      continue;
    }
    first = false;
    std::string key(trim(std::string_view(line).substr(0, colon)));
    std::string value(trim(std::string_view(line).substr(colon + 1)));
    section.lines.push_back(key + "\t" + value);
  }
}

// `ip route show` writes "<destination> [via GW] dev IF <attributes>". Left whole it produced a
// row with an empty Item and the entire line in Value - unsortable, and the destination (the one
// field a reader scans for) buried mid-string. Split it into the three fields that matter.
void add_route_lines(EnvironmentSection& section, const std::string& text) {
  std::istringstream input(text);
  std::string line;
  while (std::getline(input, line)) {
    const std::string cleaned(trim(line));
    if (cleaned.empty()) {
      continue;
    }
    std::istringstream fields(cleaned);
    std::string destination;
    fields >> destination;
    std::string token;
    std::string gateway;
    std::string device;
    std::vector<std::string> rest;
    while (fields >> token) {
      if (token == "via" && gateway.empty()) {
        fields >> gateway;
      } else if (token == "dev" && device.empty()) {
        fields >> device;
      } else {
        rest.push_back(token);
      }
    }
    // A route with no gateway is not missing one - it is on-link, reached directly on the wire.
    // Saying so beats an empty cell the reader has to interpret.
    std::string detail = device.empty() ? std::string("(no interface)") : ("dev " + device);
    for (const auto& extra : rest) {
      detail += " " + extra;
    }
    section.lines.push_back(destination + "\t" + (gateway.empty() ? "on-link" : gateway) +
                            "\t" + detail);
  }
}

// Returns the units whose ACTIVE state is "failed". Reading that from the parsed field matters:
// the previous test searched the whole systemctl blob for the word "failed", which a unit
// DESCRIPTION can contain without anything being wrong.
std::vector<std::string> add_systemd_units(EnvironmentSection& section, const std::string& text) {
  std::vector<std::string> failed;
  std::istringstream input(text);
  std::string line;
  while (std::getline(input, line)) {
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
      line.pop_back();
    }
    if (line.empty()) {
      continue;
    }
    std::istringstream fields(line);
    std::string unit;
    std::string load;
    std::string active;
    std::string sub;
    if (!(fields >> unit >> load >> active >> sub)) {
      section.lines.push_back(line);
      continue;
    }
    if (active == "failed") {
      failed.push_back(unit);
    }
    std::string description;
    std::getline(fields, description);
    while (!description.empty() && description.front() == ' ') {
      description.erase(description.begin());
    }
    // "active (running)" reads as one state; "loaded" is carried too because a not-found unit is a
    // different problem from a stopped one.
    std::string state = active + " (" + sub + ")";
    if (load != "loaded") {
      state += "  [" + load + "]";
    }
    // systemd repeats the unit name as the description when it has no unit file to read one
    // from. Echoing it back as if it were a description tells the reader nothing; saying why the
    // column is empty tells them the unit is not installed on this host at all.
    if (description == unit) {
      if (load == "not-found") {
        description = "(no unit file on this host)";
      } else if (load == "masked") {
        // Masked is deliberate: an administrator linked the unit to /dev/null so it cannot be
        // started, by hand or as a dependency. Worth saying, because "inactive" alone reads like
        // an ordinary stopped service that a restart would fix.
        description = "(masked - cannot be started until unmasked)";
      }
    }
    section.lines.push_back(unit + "\t" + state + "\t" + description);
  }
  return failed;
}

std::string format_duration(std::uint64_t seconds) {
  const std::uint64_t days = seconds / 86400U;
  const std::uint64_t hours = (seconds % 86400U) / 3600U;
  const std::uint64_t minutes = (seconds % 3600U) / 60U;
  std::ostringstream output;
  if (days != 0U) {
    output << days << "d ";
  }
  output << hours << "h " << minutes << "m";
  return output.str();
}

} // namespace

const std::vector<std::string>& environment_report_categories() {
  static const std::vector<std::string> categories{kSystem,   kProducts, kMaintenance,
                                                   kServices, kSoftware, kNetwork,
                                                   kSecurity, kVeeamConfig};
  return categories;
}

Result<EnvironmentReport> collect_linux_environment(const CancellationToken& cancel,
                                                    ProgressCallback progress) {
#ifdef _WIN32
  static_cast<void>(cancel);
  static_cast<void>(progress);
  Error error;
  error.component = "Environment";
  error.operation = "collect Linux environment";
  error.message = "The Linux environment collector does not run on Windows; the Windows edition "
                  "collects its own environment report";
  return Result<EnvironmentReport>::failure(std::move(error));
#else
  const auto report_progress = [&progress](std::string_view phase) {
    if (progress) {
      ProgressEvent event;
      event.phase = std::string(phase);
      progress(event);
    }
  };

  EnvironmentReport report;
  report.captured_utc = utc_now_iso8601();
  const auto host = make_snapshot_metadata(SnapshotKind::combined, "environment-review");
  report.machine_name = host.machine_name;

  report.coverage_notes.push_back(
      "Collected read-only from /proc, /sys, /etc and a small set of bounded read-only commands. "
      "Nothing on this host was installed, started, stopped or reconfigured.");
  report.coverage_notes.push_back(
      "Sections that need a command this host does not ship are still listed, with the reason. A "
      "missing section means SAT looked and could not read it, not that nothing is there.");

  // ---------------------------------------------------------------- System
  report_progress("System: host identity and hardware");
  {
    EnvironmentSection section;
    section.name = "[Computer]";
    section.category = kSystem;
    section.purpose = "Which machine this report is about, and how long it has been up.";
    section.windows_equivalent = "The Computer / Operating System page of msinfo32.";
    add_line(section, "Hostname", host.machine_name);
    const std::string uptime_text = first_line("/proc/uptime");
    if (!uptime_text.empty()) {
      const auto space = uptime_text.find(' ');
      const double seconds = std::strtod(uptime_text.substr(0, space).c_str(), nullptr);
      add_line(section, "Uptime", format_duration(static_cast<std::uint64_t>(seconds)));
      if (seconds < 900.0) {
        section.notes.push_back(
            "This host rebooted less than 15 minutes ago. If the case is about a job that failed "
            "before then, the evidence you need may predate the current boot.");
      }
    }
    add_line(section, "Timezone", first_line("/etc/timezone"));
    report.sections.push_back(std::move(section));
  }
  {
    EnvironmentSection section;
    section.name = "[Operating System]";
    section.category = kSystem;
    section.purpose = "The distribution and kernel, which decide what Veeam supports here.";
    section.windows_equivalent = "The Windows edition and build number.";
    const std::string release = read_text_file("/etc/os-release");
    add_line(section, "Product", host.os_distribution.empty()
                                     ? value_for(release, "PRETTY_NAME", '=')
                                     : host.os_distribution);
    add_line(section, "Distribution ID", value_for(release, "ID", '='));
    add_line(section, "Version", value_for(release, "VERSION_ID", '='));
    add_line(section, "Kernel", host.os_version);
    add_line(section, "Architecture", host.architecture);
    // The C library version, which is the single fact that decides whether a given Linux binary
    // will even start on this machine. A binary built against a newer glibc fails at load time
    // with a version-symbol error that says nothing useful to the person holding it, so an
    // engineer asking "why will this not run here" is usually asking this question.
#if defined(__linux__) && defined(__GLIBC__)
    add_line(section, "C library", std::string("glibc ") + gnu_get_libc_version());
#endif
    section.notes.push_back(
        "The kernel line is the equivalent of a Windows build number: Veeam support policy is "
        "stated against the DISTRIBUTION version above, not the kernel.");
    section.notes.push_back(
        "The C library line is the closest Linux equivalent to the Visual C++ redistributable "
        "version on Windows. It is what decides whether a binary built elsewhere can run here at "
        "all, and it cannot be upgraded independently of the distribution.");
    report.sections.push_back(std::move(section));
  }
  {
    EnvironmentSection section;
    section.name = "[Processor]";
    section.category = kSystem;
    section.purpose = "Processor model and core count.";
    section.windows_equivalent = "The Processor line in msinfo32.";
    const std::string cpuinfo = read_text_file("/proc/cpuinfo");
    add_line(section, "Model", value_for(cpuinfo, "model name", ':'));
    const std::size_t cores =
        static_cast<std::size_t>(std::count(cpuinfo.begin(), cpuinfo.end(), '\n') == 0
                                     ? 0
                                     : std::string(cpuinfo).find("processor") == std::string::npos
                                           ? 0
                                           : 0);
    static_cast<void>(cores);
    std::size_t logical = 0;
    std::istringstream cpu_input(cpuinfo);
    std::string cpu_line;
    while (std::getline(cpu_input, cpu_line)) {
      if (cpu_line.rfind("processor", 0) == 0) {
        ++logical;
      }
    }
    if (logical != 0U) {
      add_line(section, "Logical processors", std::to_string(logical));
    }
    report.sections.push_back(std::move(section));
  }
  {
    EnvironmentSection section;
    section.name = "[System Product]";
    section.category = kSystem;
    section.purpose = "Chassis identity - physical server, or which hypervisor this is a guest of.";
    section.windows_equivalent = "System Manufacturer / System Model in msinfo32.";
    const std::string vendor = first_line("/sys/class/dmi/id/sys_vendor");
    const std::string product = first_line("/sys/class/dmi/id/product_name");
    add_line(section, "Manufacturer", vendor);
    add_line(section, "Product", product);
    if (!vendor.empty() || !product.empty()) {
      add_line(section, "Serial", "[REDACTED BY SAT]");
    }
    const std::string folded = ascii_lower(vendor + " " + product);
    if (folded.find("vmware") != std::string::npos || folded.find("virtualbox") != std::string::npos ||
        folded.find("kvm") != std::string::npos || folded.find("qemu") != std::string::npos ||
        folded.find("microsoft") != std::string::npos || folded.find("xen") != std::string::npos) {
      section.notes.push_back(
          "This is a virtual machine. For a backup case that matters: a guest is protected very "
          "differently from a physical host, and application-aware processing depends on the "
          "hypervisor's guest tools being present.");
    }
    report.sections.push_back(std::move(section));
  }
  {
    EnvironmentSection section;
    section.name = "[BIOS]";
    section.category = kSystem;
    section.purpose = "Firmware identity.";
    section.windows_equivalent = "BIOS Version/Date in msinfo32.";
    add_line(section, "Vendor", first_line("/sys/class/dmi/id/bios_vendor"));
    add_line(section, "Version", first_line("/sys/class/dmi/id/bios_version"));
    add_line(section, "Date", first_line("/sys/class/dmi/id/bios_date"));
    report.sections.push_back(std::move(section));
  }
  {
    EnvironmentSection section;
    section.name = "[SAT Process]";
    section.category = kSystem;
    section.purpose = "How SAT itself is running, which decides what it was able to read.";
    section.windows_equivalent = "Whether the tool is elevated, and under which account.";
    add_line(section, "Process ID", std::to_string(static_cast<long long>(::getpid())));
    add_line(section, "User ID", std::to_string(static_cast<long long>(::getuid())));
    add_line(section, "Effective user ID", std::to_string(static_cast<long long>(::geteuid())));
    if (::geteuid() != 0) {
      section.notes.push_back(
          "SAT is not running as root. Sections below that need privileged reads will say so. "
          "This is the Linux equivalent of running the Windows edition without Administrator - "
          "usually the right choice on a customer machine.");
    }
    report.sections.push_back(std::move(section));
  }

  // ---------------------------------------------------------------- Veeam products
  report_progress("Veeam products");
  {
    EnvironmentSection section;
    section.name = "[Detected Veeam Products]";
    section.category = kProducts;
    section.purpose = "The Veeam roles this host actually carries evidence for.";
    section.windows_equivalent = "The installed Veeam products listed under Programs and Features.";
    const auto context = native_product_discovery_context();
    const auto detected = detect_products(context);
    std::size_t signatures = 0;
    for (const auto& product : detected) {
      if (!product.signature_detected) {
        continue;
      }
      ++signatures;
      // A detected product carries its evidence paths rather than a version string; the version
      // lives in the product's own logs, which Log Review reads.
      section.lines.push_back(product.definition.display_name + "=" +
                              std::to_string(product.evidence_paths.size()) +
                              " evidence path(s)");
      for (const auto& path : product.evidence_paths) {
        section.lines.push_back("  evidence=" + path_to_utf8(path));
      }
    }
    if (signatures == 0U) {
      section.lines.push_back("No Veeam installation signature was found on this host");
      section.notes.push_back(
          "No Veeam product is installed here. That is normal for a host that is only a backup "
          "TARGET (a repository or an NFS/SMB share) or a protected workload - neither runs Veeam "
          "software locally.");
    }
    report.sections.push_back(std::move(section));
  }

  // ---------------------------------------------------------------- Maintenance
  report_progress("Maintenance: patch state");
  {
    EnvironmentSection section;
    section.name = "[Patch and Reboot State]";
    section.category = kMaintenance;
    section.purpose = "Whether this host is mid-patch or waiting on a reboot.";
    section.windows_equivalent = "Installed updates and the 'restart required' flag.";
    std::error_code error;
    const bool reboot_required = std::filesystem::exists("/var/run/reboot-required", error);
    add_line(section, "Reboot required", reboot_required ? "yes" : "no");
    if (reboot_required) {
      section.notes.push_back(
          "A reboot is pending. A kernel or library updated but not yet loaded is a common cause "
          "of a service behaving differently from its installed version.");
    }
    const std::string dpkg_log = first_line("/var/log/dpkg.log");
    if (!dpkg_log.empty()) {
      add_line(section, "Oldest retained package log entry", dpkg_log);
    }
    report.sections.push_back(std::move(section));
  }

  // ---------------------------------------------------------------- Services
  report_progress("Services");
  {
    EnvironmentSection section;
    section.name = "[Services - running]";
    section.category = kServices;
    section.purpose = "Which services are running, and which have failed.";
    section.windows_equivalent = "services.msc. A systemd 'unit' is a Windows 'service'.";
    section.column_headers = {"Unit", "State", "Description"};
    std::string output;
    if (run_tool(section, "systemctl",
                 {"list-units", "--type=service", "--all", "--no-pager", "--no-legend",
                  "--plain"},
                 cancel, &output)) {
      const std::vector<std::string> failed = add_systemd_units(section, output);
      if (!failed.empty()) {
        // Name them. SAT has just read the state of every unit on the host; sending the engineer
        // back through the list to find the failures by eye wastes what it already knows.
        std::string listed;
        for (std::size_t index = 0; index < failed.size() && index < 8U; ++index) {
          listed += (listed.empty() ? "" : ", ") + failed[index];
        }
        if (failed.size() > 8U) {
          listed += ", and " + std::to_string(failed.size() - 8U) + " more";
        }
        section.notes.push_back(
            "Failed unit(s): " + listed +
            ". 'systemctl status <name>' is the equivalent of opening a service's properties.");
      }
    } else {
      section.notes.push_back(
          "Without systemd there is no single service list. On a container or a minimal image "
          "this is expected.");
    }
    report.sections.push_back(std::move(section));
  }

  // ---------------------------------------------------------------- Installed software
  report_progress("Installed software");
  {
    EnvironmentSection section;
    section.name = "[Installed Software - alphabetical]";
    section.column_headers = {"Package", "Version"};
    section.category = kSoftware;
    section.purpose = "The installed package inventory.";
    section.windows_equivalent = "Programs and Features / Get-Package.";
    std::string output;
    if (run_tool(section, "dpkg-query", {"-W", "-f=${Package}=${Version}\\n"}, cancel, &output)) {
      add_capped_lines(section, output, 0U);
    } else {
      EnvironmentSection retry;
      if (run_tool(retry, "rpm", {"-qa", "--qf", "%{NAME}=%{VERSION}-%{RELEASE}\\n"}, cancel,
                   &output)) {
        section.unavailable_reason.clear();
        add_capped_lines(section, output, 0U);
      } else {
        section.unavailable_reason =
            "Neither dpkg-query nor rpm is present; this host uses a package manager SAT does not "
            "yet read";
      }
    }
    report.sections.push_back(std::move(section));
  }

  // ---------------------------------------------------------------- Network
  report_progress("Network: interfaces and routes");
  {
    EnvironmentSection section;
    section.name = "[Adapters]";
    section.category = kNetwork;
    section.purpose = "Every local interface SAT can originate a test from.";
    section.windows_equivalent = "ipconfig /all, and the adapter list in ncpa.cpl.";
    section.column_headers = {"Interface", "Address", "Family, state, gateway"};
    auto interfaces = enumerate_network_interfaces();
    if (interfaces.ok()) {
      for (const auto& item : interfaces.value()) {
        // Tab-separated so the table renderer gets Interface / Address / Detail as real,
        // sortable columns. As one '=' separated string the whole record collapsed into a
        // single cell that could not be sorted by state or by gateway.
        std::ostringstream detail;
        detail << item.address_family << "; " << (item.up ? "up" : "DOWN");
        if (!item.gateway.empty()) {
          detail << "; gateway " << item.gateway;
        }
        if (item.team_or_bond) {
          detail << "; bond";
        }
        if (item.vlan_interface) {
          detail << "; vlan";
        }
        section.lines.push_back(item.name + "\t" + item.address + "/" +
                                std::to_string(item.prefix_length) + "\t" + detail.str());
      }
      section.notes.push_back(
          "A Veeam host often has a management NIC and a separate backup NIC. If a job fails but "
          "a ping works, test the specific interface - Network Tools can originate a test from "
          "each address listed here.");
    } else {
      section.unavailable_reason = describe_error(interfaces.error());
    }
    report.sections.push_back(std::move(section));
  }
  {
    EnvironmentSection section;
    section.name = "[Routes]";
    section.category = kNetwork;
    section.purpose = "Which interface traffic to a given network actually leaves by.";
    section.windows_equivalent = "route print.";
    std::string output;
    section.column_headers = {"Destination", "Gateway", "Interface and attributes"};
    if (run_tool(section, "ip", {"route", "show"}, cancel, &output)) {
      add_route_lines(section, output);
      section.notes.push_back(
          "The 'default via' line is the default gateway. Traffic to a network without a route of "
          "its own leaves through it, backup traffic for a separate backup network included.");
    }
    report.sections.push_back(std::move(section));
  }
  {
    EnvironmentSection section;
    section.name = "[Firewall]";
    section.category = kNetwork;
    section.purpose = "Whether a local firewall could be filtering Veeam traffic.";
    section.windows_equivalent = "Windows Defender Firewall profiles.";
    std::string output;
    if (run_tool(section, "systemctl", {"is-active", "firewalld"}, cancel, &output)) {
      add_line(section, "firewalld", std::string(trim(output)));
    }
    std::string ufw_output;
    EnvironmentSection ufw_probe;
    if (run_tool(ufw_probe, "systemctl", {"is-active", "ufw"}, cancel, &ufw_output)) {
      add_line(section, "ufw", std::string(trim(ufw_output)));
    }
    if (section.lines.empty()) {
      section.lines.push_back("No firewalld or ufw service was found");
      section.notes.push_back(
          "No managed firewall service is running. Note that nftables/iptables rules can still "
          "exist without one, and a hypervisor or physical firewall between hosts is far more "
          "common than a local one.");
    } else {
      section.notes.push_back(
          "If a firewall is active, confirm the Veeam ports for this role are permitted. Network "
          "Tools on this host can prove reachability rather than assuming it.");
    }
    report.sections.push_back(std::move(section));
  }

  // ---------------------------------------------------------------- TLS / security
  report_progress("TLS and security posture");
  {
    EnvironmentSection section;
    section.name = "[TLS]";
    section.category = kSecurity;
    section.purpose = "The TLS library this host presents to Veeam components.";
    section.windows_equivalent = "SCHANNEL protocol settings and the cipher suite order.";
    std::string output;
    section.column_headers = {"Setting", "Value"};
    if (run_tool(section, "openssl", {"version", "-a"}, cancel, &output)) {
      add_colon_fields(section, output, "OpenSSL version");
    }
    report.sections.push_back(std::move(section));
  }
  {
    EnvironmentSection section;
    section.name = "[Mandatory Access Control]";
    section.category = kSecurity;
    section.purpose = "SELinux or AppArmor, either of which can deny an operation that file "
                      "permissions appear to allow.";
    section.windows_equivalent =
        "There is no close Windows equivalent. The nearest idea is a policy that overrides an "
        "ACL: the account has permission and the access is still refused.";
    const std::string selinux = first_line("/sys/fs/selinux/enforce");
    if (!selinux.empty()) {
      add_line(section, "SELinux", selinux == "1" ? "enforcing" : "permissive");
      if (selinux == "1") {
        section.notes.push_back(
            "SELinux is ENFORCING. This is a leading cause of a Veeam repository or agent failing "
            "with a permission error while ls and the file mode both look correct. Check "
            "/var/log/audit/audit.log for AVC denials before concluding it is a Veeam fault.");
      }
    }
    std::error_code error;
    if (std::filesystem::exists("/sys/kernel/security/apparmor", error)) {
      add_line(section, "AppArmor", "present");
      section.notes.push_back(
          "AppArmor is present. Like SELinux it can deny an access that file permissions allow; "
          "denials appear in the system journal.");
    }
    if (section.lines.empty()) {
      section.lines.push_back("Neither SELinux nor AppArmor was detected");
    }
    report.sections.push_back(std::move(section));
  }

  // ---------------------------------------------------------------- Veeam configuration
  report_progress("Veeam configuration and kernel modules");
  {
    EnvironmentSection section;
    section.name = "[Veeam Configuration Paths]";
    section.category = kVeeamConfig;
    section.purpose = "Veeam's own configuration and certificate locations on this host.";
    section.windows_equivalent = "The Veeam registry hive and the certificate store.";
    static constexpr std::array<const char*, 6> kPaths{
        "/etc/veeam", "/var/lib/veeam", "/var/log/veeam", "/opt/veeam",
        "/etc/ssl/certs", "/usr/share/veeam"};
    for (const char* path : kPaths) {
      std::error_code error;
      add_line(section, path,
               std::filesystem::exists(path, error) ? "present" : "not present");
    }
    section.notes.push_back(
        "Linux has no registry. Veeam configuration lives in the files under the paths above, so "
        "read those where you would read HKLM\\SOFTWARE\\Veeam on Windows.");
    report.sections.push_back(std::move(section));
  }
  {
    EnvironmentSection section;
    section.name = "[Kernel Modules]";
    section.category = kVeeamConfig;
    section.purpose = "Loaded kernel modules, including Veeam's own snapshot module.";
    section.windows_equivalent =
        "Filesystem minifilter drivers (fltmc). A module here plays the same role a filter driver "
        "plays on Windows.";
    const std::string modules = read_text_file("/proc/modules");
    std::istringstream input(modules);
    std::string line;
    bool veeam_module = false;
    while (std::getline(input, line)) {
      const auto space = line.find(' ');
      const std::string name = space == std::string::npos ? line : line.substr(0, space);
      if (name.find("veeam") != std::string::npos || name.find("blksnap") != std::string::npos) {
        section.lines.push_back(name + "=loaded");
        veeam_module = true;
      }
    }
    if (!veeam_module) {
      section.lines.push_back("No Veeam snapshot kernel module is loaded");
      section.notes.push_back(
          "Veeam Agent for Linux uses a kernel module (veeamsnap or blksnap) to take a consistent "
          "snapshot. If the agent is installed here and no module is loaded, that is the first "
          "thing to check for a failing or inconsistent backup.");
    }
    report.sections.push_back(std::move(section));
  }

  // A section that collected nothing states why rather than appearing as an empty heading. DMI is
  // the common case: containers, WSL and some cloud images expose none of it.
  for (auto& section : report.sections) {
    if (section.lines.empty() && section.unavailable_reason.empty()) {
      section.unavailable_reason =
          "This host exposes no values for this section. Virtual machines, containers and WSL "
          "commonly omit hardware and firmware identity entirely.";
    }
  }

  report_progress("Environment collection complete");
  return Result<EnvironmentReport>::success(std::move(report));
#endif
}

std::string format_environment_report(const EnvironmentReport& report) {
  std::ostringstream output;
  output << report.format << "\n";
  output << "Machine=" << report.machine_name << "\n";
  output << "CapturedUtc=" << report.captured_utc << "\n\n";
  for (const auto& note : report.coverage_notes) {
    output << "[Coverage Note] " << note << "\n";
  }
  output << "\n";
  for (const auto& section : report.sections) {
    output << section.name << "\n";
    if (!section.purpose.empty()) {
      output << "  Purpose: " << section.purpose << "\n";
    }
    if (!section.windows_equivalent.empty()) {
      output << "  On Windows: " << section.windows_equivalent << "\n";
    }
    if (!section.unavailable_reason.empty()) {
      output << "  Unavailable: " << section.unavailable_reason << "\n";
    }
    // The collector's own names for its tab-separated fields. Written into the report so the
    // naming survives a trip to the other edition: a Linux capture opened on Windows showed a
    // correctly aligned grid of columns called "Field 1", "Field 2", "Field 3".
    if (!section.column_headers.empty()) {
      output << "  Columns:";
      for (const auto& header : section.column_headers) {
        output << "\t" << header;
      }
      output << "\n";
    }
    for (const auto& line : section.lines) {
      output << "  " << line << "\n";
    }
    for (const auto& note : section.notes) {
      output << "  Note: " << note << "\n";
    }
    output << "\n";
  }
  return output.str();
}

} // namespace support_assist
