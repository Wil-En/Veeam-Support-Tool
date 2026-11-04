#pragma once

// The quick tools' results as raw data: the JSON the command line prints with --json. The GUI
// keeps the same JSON as result.json in a quick tool run's output on a Customer / Lab machine, so
// a later import can bring that machine's checks into a case.

#include "support_assist/disk_speed_test.hpp"
#include "support_assist/file_lock.hpp"
#include "support_assist/file_transfer.hpp"
#include "support_assist/host_checks.hpp"
#include "support_assist/installer_cache.hpp"
#include "support_assist/named_pipes.hpp"
#include "support_assist/name_check.hpp"
#include "support_assist/object_storage.hpp"
#include "support_assist/pending_restart.hpp"
#include "support_assist/port_check.hpp"
#include "support_assist/quick_scan.hpp"
#include "support_assist/time_check.hpp"
#include "support_assist/veeam_watch.hpp"
#include "support_assist/volume_check.hpp"
#include "support_assist/wmi_health.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

// One run of the Local Port Checker's listener: what arrived, and Quick scan's count when it ran.
struct ListenerRunRecord {
  std::uint16_t port = 0;
  PortProtocol protocol = PortProtocol::tcp;
  int minutes = 0;
  std::int64_t started_unix_millis = 0;
  std::int64_t ended_unix_millis = 0;
  struct Arrival {
    std::string time_utc; // ISO 8601
    std::string peer;     // address:port
    std::string what;     // "Connection", "Datagram", "SAT probe, test 3"
  };
  std::vector<Arrival> arrivals;
  bool scanned = false;
  QuickScanCounts scan;
  std::string error; // why the listener did not start
};

namespace tool_json {
std::string text(std::string_view value); // a JSON string, quoted and escaped
std::string list(const std::vector<std::string>& values);
std::string port_check(const PortCheckResult& result);
std::string name_check(const NameCheckResult& result);
std::string time_check(const TimeCheckResult& result);
std::string converted_time(const ConvertedTime& converted);
// What a log records of its own clock (time log-clock).
std::string log_clock(const LogClock& clock);
std::string file_lock(const FileLockResult& result);
std::string folder_lock(const FolderLockResult& result);
std::string volume(const VolumeInfo& volume);
std::string volumes(const std::vector<VolumeInfo>& volumes);
std::string pending_restart(const PendingRestartResult& result);
// Installer Cache Check (system installer-cache).
std::string installer_cache(const InstallerCacheResult& result);
// Named Pipes (system pipes).
std::string named_pipes(const NamedPipesResult& result);
// WMI health (wmi health).
std::string wmi_health(const WmiHealthReport& report);
std::string host_checks(const HostChecksReport& report);
std::string watch(const std::string& filter, const WatchSnapshot& snapshot, const std::vector<WatchEvent>& events);
std::string quick_scan(const QuickScanCounts& counts);
std::string listener_run(const ListenerRunRecord& run);
std::string disk_speed_test(const DiskSpeedTestResult& result);
std::string object_storage(const ObjectStorageResult& result);
std::string file_transfer(const TransferEstimate& estimate);
} // namespace tool_json

} // namespace support_assist
