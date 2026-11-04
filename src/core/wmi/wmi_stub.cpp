#include "support_assist/wmi.hpp"

namespace support_assist {

Result<std::vector<WmiRow>>
query_wmi(const WmiQueryOptions&, const CancellationToken&, ProgressCallback) {
  Error error;
  error.component = "WMI";
  error.operation = "query";
  error.message = "WMI queries require the Windows build";
  return Result<std::vector<WmiRow>>::failure(std::move(error));
}

WmiQueryOptions make_host_wmi_preset(std::string machine) {
  WmiQueryOptions options;
  options.machine = std::move(machine);
  options.query = "SELECT CSName, Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime "
                  "FROM Win32_OperatingSystem";
  return options;
}

WmiQueryOptions make_cluster_wmi_preset(std::string machine) {
  WmiQueryOptions options;
  options.machine = std::move(machine);
  options.name_space = "root\\MSCluster";
  options.query = "SELECT Name, State FROM MSCluster_Node";
  return options;
}

WmiQueryOptions make_process_wmi_preset(std::string machine) {
  WmiQueryOptions options;
  options.machine = std::move(machine);
  options.query = "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, "
                  "CreationDate, ThreadCount, WorkingSetSize FROM Win32_Process";
  options.maximum_rows = 10000;
  return options;
}

} // namespace support_assist
