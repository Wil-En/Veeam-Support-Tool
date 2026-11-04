// Linux firewall, read-only: firewalld when it is running (one firewall-cmd --list-all-zones call,
// and the service definitions read from their XML files), else ufw (ufw status verbose as root, its
// configuration files otherwise). Each tool is started from its system path, never through PATH,
// and only with options that report.
#include "support_assist/firewall.hpp"

#include "support_assist/cancellation.hpp"
#include "support_assist/process.hpp"
#include "support_assist/strings.hpp"

#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>

namespace support_assist {
namespace {

std::optional<std::filesystem::path> system_tool(std::initializer_list<const char*> candidates) {
  for (const char* candidate : candidates) {
    std::error_code error;
    const std::filesystem::path path(candidate);
    const bool found = std::filesystem::is_regular_file(path, error);
    if (!error && found)
      return path;
  }
  return std::nullopt;
}

std::string read_text(const std::filesystem::path& path, std::size_t max_bytes = 256U * 1024U) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    return {};
  std::string text(max_bytes, '\0');
  input.read(text.data(), static_cast<std::streamsize>(max_bytes));
  text.resize(static_cast<std::size_t>(input.gcount()));
  return text;
}

Result<ProcessResult> run_tool(const std::filesystem::path& tool, std::vector<std::string> arguments) {
  ProcessOptions options;
  options.executable = tool;
  options.arguments = std::move(arguments);
  options.timeout = std::chrono::milliseconds(20000);
  options.merge_standard_error = true;
  options.maximum_output_bytes = 2U * 1024U * 1024U;
  CancellationSource cancel;
  return run_process_capture(options, cancel.token());
}

std::string first_line(std::string_view text) {
  const std::string value = trim(text);
  return value.substr(0, value.find('\n'));
}

// The ports of each service the zones name, from /etc/firewalld/services (the administrator's own
// definitions) before /usr/lib/firewalld/services (the packaged ones).
std::vector<std::pair<std::string, std::vector<std::pair<std::string, int>>>> firewalld_service_ports(
    const std::vector<firewall_detail::FirewalldZone>& zones) {
  std::vector<std::pair<std::string, std::vector<std::pair<std::string, int>>>> result;
  auto wanted = [&](const std::string& name) {
    if (name.empty() || name.find_first_of("/\\") != std::string::npos)
      return;
    for (const auto& entry : result) {
      if (entry.first == name)
        return;
    }
    for (const char* folder : {"/etc/firewalld/services/", "/usr/lib/firewalld/services/"}) {
      const std::string xml = read_text(std::filesystem::path(std::string(folder) + name + ".xml"));
      if (!xml.empty()) {
        result.emplace_back(name, firewall_detail::parse_firewalld_service_ports(xml));
        return;
      }
    }
  };
  for (const auto& zone : zones) {
    for (const std::string& service : zone.services)
      wanted(service);
    for (const std::string& rule : zone.rich_rules) {
      const std::size_t at = rule.find("service name=");
      if (at == std::string::npos)
        continue;
      std::string name = rule.substr(at + 13);
      if (!name.empty() && (name.front() == '"' || name.front() == '\'')) {
        const char quote = name.front();
        name = name.substr(1, name.find(quote, 1) == std::string::npos ? std::string::npos : name.find(quote, 1) - 1);
      }
      wanted(name);
    }
  }
  return result;
}

std::vector<std::pair<std::string, std::string>> ufw_application_ports() {
  std::vector<std::pair<std::string, std::string>> ports;
  std::error_code error;
  for (std::filesystem::directory_iterator it("/etc/ufw/applications.d", error), end; !error && it != end;
       it.increment(error)) {
    std::error_code file_error;
    if (!it->is_regular_file(file_error) || file_error)
      continue;
    for (auto& entry : firewall_detail::parse_ufw_app_profiles(read_text(it->path())))
      ports.push_back(std::move(entry));
  }
  return ports;
}

// KEY=value from a shell-style configuration file, without quotes.
std::string config_value(const std::string& text, std::string_view key) {
  std::istringstream lines(text);
  std::string line;
  const std::string wanted = std::string(key) + "=";
  while (std::getline(lines, line)) {
    const std::string item = trim(line);
    if (item.rfind(wanted, 0) != 0)
      continue;
    std::string value = trim(item.substr(wanted.size()));
    if (value.size() >= 2 && (value.front() == '"' || value.front() == '\'') && value.back() == value.front())
      value = value.substr(1, value.size() - 2);
    return value;
  }
  return {};
}

} // namespace

Result<FirewallSnapshot> read_firewall() {
  FirewallSnapshot snapshot;
  std::string firewalld_note;
  if (const auto tool = system_tool({"/usr/bin/firewall-cmd", "/bin/firewall-cmd", "/usr/sbin/firewall-cmd"})) {
    auto run = run_tool(*tool, {"--list-all-zones"});
    if (run.ok() && run.value().launched && !run.value().timed_out && run.value().exit_code == 0) {
      const auto zones = firewall_detail::parse_firewalld_zones(run.value().output);
      firewall_detail::add_firewalld_zones(zones, firewalld_service_ports(zones), snapshot);
      snapshot.product = "firewalld";
      snapshot.readable = !snapshot.profiles.empty();
      if (!snapshot.readable)
        snapshot.note = "firewalld is running and reported no active zone.";
      return Result<FirewallSnapshot>::success(std::move(snapshot));
    }
    // 252 is firewalld's NOT_RUNNING; any other code (polkit refusing the query) goes in the note.
    if (run.ok() && run.value().exit_code != 252) {
      firewalld_note = "firewall-cmd did not list the zones (exit code " + std::to_string(run.value().exit_code) +
                       "): " + first_line(run.value().output);
    }
  }

  if (system_tool({"/usr/sbin/ufw", "/sbin/ufw", "/usr/bin/ufw"})) {
    snapshot.product = "ufw";
    if (geteuid() == 0) {
      const auto tool = system_tool({"/usr/sbin/ufw", "/sbin/ufw", "/usr/bin/ufw"});
      auto run = run_tool(*tool, {"status", "verbose"});
      if (run.ok() && run.value().launched && !run.value().timed_out && run.value().exit_code == 0 &&
          firewall_detail::parse_ufw_status(run.value().output, ufw_application_ports(), snapshot)) {
        snapshot.readable = true;
        return Result<FirewallSnapshot>::success(std::move(snapshot));
      }
    }
    // Without root, ufw refuses to report; its configuration files say whether it is on.
    const std::string enabled = ascii_lower(config_value(read_text("/etc/ufw/ufw.conf"), "ENABLED"));
    if (enabled == "no") {
      FirewallProfileState profile;
      profile.name = "ufw";
      profile.active = true;
      profile.enabled = false;
      snapshot.profiles.push_back(std::move(profile));
      snapshot.readable = true;
      return Result<FirewallSnapshot>::success(std::move(snapshot));
    }
    snapshot.note = enabled == "yes" ? "ufw is on. Its rules can be read as root."
                                     : "ufw is installed. Its state can be read as root.";
    return Result<FirewallSnapshot>::success(std::move(snapshot));
  }

  snapshot.note = !firewalld_note.empty()
                      ? firewalld_note
                      : "Neither firewalld nor ufw is running. Rules set directly in nftables or iptables are not read.";
  return Result<FirewallSnapshot>::success(std::move(snapshot));
}

} // namespace support_assist
