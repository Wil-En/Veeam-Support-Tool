// Linux side of Time Check: the zone (TZ, /etc/timezone or the /etc/localtime link) and the time
// service that is running, chrony, systemd-timesyncd or ntpd, with the servers its configuration
// names. Files and /proc only; chronyc and timedatectl are not run.
#include "support_assist/time_check.hpp"

#include "support_assist/process_identity.hpp"
#include "support_assist/strings.hpp"

#include <unistd.h>

#include <algorithm>
#include <climits>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace support_assist {
namespace {

std::string read_text(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    return {};
  std::ostringstream text;
  text << input.rdbuf();
  return text.str();
}

// The main file, then each file of the drop-in folders, in name order as the services read them.
std::string read_with_drop_ins(const std::vector<std::string>& files, const std::vector<std::string>& folders,
                               const std::string& extension) {
  std::string text;
  for (const std::string& file : files)
    text += read_text(file) + "\n";
  for (const std::string& folder : folders) {
    std::vector<std::filesystem::path> entries;
    std::error_code error;
    for (std::filesystem::directory_iterator it(folder, error), end; !error && it != end; it.increment(error)) {
      if (it->path().extension() == extension)
        entries.push_back(it->path());
    }
    std::sort(entries.begin(), entries.end());
    for (const auto& entry : entries)
      text += read_text(entry) + "\n";
  }
  return text;
}

bool process_running(const ProcessDirectory& processes, const char* name) {
  for (const auto& process : processes.all()) {
    if (process.name == name)
      return true;
  }
  return false;
}

} // namespace

TimeZoneInfo read_time_zone() {
  TimeZoneInfo zone;
  if (const char* tz = std::getenv("TZ"); tz != nullptr && *tz != '\0')
    zone.name = tz[0] == ':' ? tz + 1 : tz;
  if (zone.name.empty())
    zone.name = trim(read_text("/etc/timezone"));
  if (zone.name.empty()) {
    char target[PATH_MAX] = {};
    const ssize_t length = readlink("/etc/localtime", target, sizeof(target) - 1);
    if (length > 0) {
      const std::string link(target, static_cast<std::size_t>(length));
      const std::size_t at = link.find("zoneinfo/");
      zone.name = at != std::string::npos ? link.substr(at + 9) : link;
    }
  }
  const std::time_t now = std::time(nullptr);
  std::tm local{};
  if (localtime_r(&now, &local) != nullptr) {
    zone.utc_offset_minutes = static_cast<int>(local.tm_gmtoff / 60);
    zone.daylight_saving_now = local.tm_isdst > 0;
    if (zone.name.empty() && local.tm_zone != nullptr)
      zone.name = local.tm_zone;
  }
  return zone;
}

TimeSourceSettings read_time_source() {
  TimeSourceSettings source;
  const ProcessDirectory processes = ProcessDirectory::capture();
  if (process_running(processes, "chronyd")) {
    source.service = "chrony";
    source.mode = "NTP";
    source.servers = time_check_detail::parse_ntp_conf_servers(
        read_with_drop_ins({"/etc/chrony.conf", "/etc/chrony/chrony.conf"},
                           {"/etc/chrony/conf.d", "/etc/chrony/sources.d", "/run/chrony-dhcp"}, ".conf") +
        read_with_drop_ins({}, {"/etc/chrony/sources.d", "/run/chrony-dhcp"}, ".sources"));
  } else if (process_running(processes, "systemd-timesyn")) { // comm holds 15 characters
    source.service = "systemd-timesyncd";
    source.mode = "SNTP";
    source.servers = time_check_detail::parse_timesyncd_servers(
        read_with_drop_ins({"/etc/systemd/timesyncd.conf"},
                           {"/etc/systemd/timesyncd.conf.d", "/run/systemd/timesyncd.conf.d"}, ".conf"));
    if (source.servers.empty())
      source.note = "No NTP= server is set; systemd-timesyncd uses the servers DHCP gives, or its built-in ones.";
  } else if (process_running(processes, "ntpd")) {
    source.service = "ntpd";
    source.mode = "NTP";
    source.servers =
        time_check_detail::parse_ntp_conf_servers(read_with_drop_ins({"/etc/ntp.conf", "/etc/ntpsec/ntp.conf"}, {}, ""));
  } else {
    source.note = "No time service (chrony, systemd-timesyncd or ntpd) is running.";
  }
  return source;
}

namespace time_check_detail {

int local_offset_minutes_at(std::int64_t unix_millis) {
  const auto seconds = static_cast<std::time_t>(unix_millis / 1000);
  std::tm local{};
  if (localtime_r(&seconds, &local) == nullptr)
    return 0;
  return static_cast<int>(local.tm_gmtoff / 60);
}

} // namespace time_check_detail

} // namespace support_assist
