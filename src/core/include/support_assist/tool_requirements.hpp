#pragma once

// What SAT's tools need on this machine, as rows of name, what was found, a status and the tools
// that use it. Windows: the Windows build, .NET Framework, Windows PowerShell and PowerShell 7, the
// machine's PowerShell execution policy, the Service Control Manager, the WMI service, the account's
// rights, the ODBC drivers for SQL Server and psql. Linux: glibc, the kernel, unixODBC, the ODBC
// drivers for SQL Server, psql and the account's rights. Other platforms have no rows. The registry,
// the file system and the loader are read; no program is started, nothing is asked of the network
// and nothing is written.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

inline constexpr const char* kRequirementPresent = "Present";
inline constexpr const char* kRequirementMissing = "Missing";
inline constexpr const char* kRequirementAttention = "Attention";
inline constexpr const char* kRequirementNotApplicable = "Not applicable";

struct ToolRequirement {
  std::string name;
  std::string found;   // what was read, in a sentence or a version
  std::string status;  // one of the four kRequirement values above
  std::string used_by; // the SAT tools that need it, in a few words
};

// tools_folder is where SAT keeps downloaded tools; psql is looked for there as well as on the PATH
// and in the PostgreSQL install folders.
std::vector<ToolRequirement> read_tool_requirements(const std::filesystem::path& tools_folder = {});

namespace tool_requirements_detail {

// "4.8" for a .NET Framework 4.x Release value, "4.8.1", "4.5"; empty when the value is below 4.5.
std::string dotnet_release_name(std::uint32_t release);

// The policy Windows applies when none is set: Restricted on a client edition, RemoteSigned on a
// server.
std::string execution_policy_default(bool server);

// How the machine's execution policy reads, from the Group Policy values (EnableScripts and
// ExecutionPolicy under Policies) and the value PowerShell keeps for the machine. Empty text is a
// value that is not set.
struct PolicyReading {
  std::string found;
  std::string status;
};
PolicyReading execution_policy_reading(std::optional<std::uint32_t> group_policy_enable_scripts,
                                       const std::string& group_policy, const std::string& local_policy,
                                       bool server);

// Section names of an odbcinst.ini, in the order they appear: the text between [ and ] on a line of
// its own, without comments.
std::vector<std::string> odbcinst_sections(std::string_view text);

// The ODBC driver names SAT puts in a connection string for SQL Server, newest first, and the order
// it tries them in.
const std::vector<std::string>& sql_server_driver_names();

// The row for the ODBC drivers for SQL Server given every driver name the system lists and where
// the list came from. Names that SAT does not ask for are shown only when none that it does is
// installed.
ToolRequirement sql_server_driver_requirement(const std::vector<std::string>& installed, const std::string& source);

} // namespace tool_requirements_detail

} // namespace support_assist
