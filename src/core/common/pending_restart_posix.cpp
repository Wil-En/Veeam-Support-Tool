// Pending restart on Linux: Debian and Ubuntu's /run/reboot-required with its package list, a
// newer kernel installed than the one running, and a newer Veeam snapshot module installed than the
// one loaded. Files only; nothing is run.
#include "support_assist/pending_restart.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"

#include <sys/stat.h>
#include <sys/utsname.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace support_assist {
namespace {

std::int64_t modified_unix_millis(const std::string& path) {
  struct stat info {};
  if (stat(path.c_str(), &info) != 0)
    return 0;
  return static_cast<std::int64_t>(info.st_mtime) * 1000;
}

std::vector<std::string> lines_of(const std::string& path) {
  std::vector<std::string> lines;
  std::ifstream input(path);
  std::string line;
  while (std::getline(input, line)) {
    if (!trim(line).empty())
      lines.push_back(trim(line));
  }
  return lines;
}

std::int64_t boot_unix_millis() {
  std::ifstream input("/proc/stat");
  std::string line;
  while (std::getline(input, line)) {
    if (line.rfind("btime ", 0) == 0)
      return std::strtoll(line.c_str() + 6, nullptr, 10) * 1000;
  }
  return 0;
}

// Versions from folder names that start with prefix ("vmlinuz-", "veeamsnap-").
std::vector<std::string> versions_in(const std::string& folder, const std::string& prefix) {
  std::vector<std::string> versions;
  std::error_code error;
  for (std::filesystem::directory_iterator it(folder, error), end; !error && it != end; it.increment(error)) {
    const std::string name = it->path().filename().string();
    if (name.rfind(prefix, 0) != 0 || name.size() == prefix.size())
      continue;
    const std::string version = name.substr(prefix.size());
    if (version.find("rescue") != std::string::npos || version.size() > 64)
      continue;
    versions.push_back(version);
  }
  return versions;
}

} // namespace

PendingRestartResult check_pending_restart() {
  PendingRestartResult result;
  result.boot_unix_millis = boot_unix_millis();

  for (const char* flag : {"/run/reboot-required", "/var/run/reboot-required"}) {
    std::error_code error;
    if (!std::filesystem::exists(flag, error))
      continue;
    RestartMarker marker;
    marker.id = "reboot-required";
    marker.name = flag;
    marker.meaning = "A package asked for a restart (Debian and Ubuntu).";
    marker.restart_needed = true;
    marker.set_unix_millis = modified_unix_millis(flag);
    marker.details = lines_of(std::string(flag) + ".pkgs");
    if (!marker.details.empty())
      marker.reasons.push_back("Packages that asked: " + std::to_string(marker.details.size()) + ".");
    result.markers.push_back(std::move(marker));
    break;
  }

  utsname system{};
  if (uname(&system) == 0) {
    const std::string running = system.release;
    const std::string newest = restart_detail::newest_version(versions_in("/boot", "vmlinuz-"));
    if (!newest.empty() && restart_detail::compare_versions(newest, running) > 0) {
      RestartMarker marker;
      marker.id = "kernel";
      marker.name = "Kernel";
      marker.meaning = "A newer kernel is installed than the one running; it loads at the next start.";
      marker.restart_needed = true;
      marker.set_unix_millis = modified_unix_millis("/boot/vmlinuz-" + newest);
      marker.details = {"running " + running, "newest installed " + newest};
      result.markers.push_back(std::move(marker));
    }
  }

  for (const char* module : {"veeamsnap", "veeamblksnap", "blksnap"}) {
    const auto version_lines = lines_of(std::string("/sys/module/") + module + "/version");
    const std::string loaded = version_lines.empty() ? std::string() : version_lines.front();
    if (loaded.empty())
      continue;
    const std::string installed = restart_detail::newest_version(versions_in("/usr/src", std::string(module) + "-"));
    if (!installed.empty() && restart_detail::compare_versions(installed, loaded) > 0) {
      RestartMarker marker;
      marker.id = "veeam-module";
      marker.name = std::string("Veeam snapshot module (") + module + ")";
      marker.meaning = "A newer Veeam snapshot module is installed than the one loaded; it loads after a restart "
                       "or a module reload.";
      marker.set_unix_millis = modified_unix_millis("/usr/src/" + std::string(module) + "-" + installed);
      marker.details = {"loaded " + loaded, "installed " + installed};
      result.markers.push_back(std::move(marker));
    }
  }

  for (const RestartMarker& marker : result.markers)
    result.restart_needed = result.restart_needed || marker.restart_needed;
  return result;
}

} // namespace support_assist
