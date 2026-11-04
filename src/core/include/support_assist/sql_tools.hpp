#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/process.hpp"

#include <filesystem>
#include <string>

namespace support_assist {

struct SqlPermissionOptions {
  std::string server;
  std::string database = "master";
  std::string principal;
  bool trusted_connection = true;
  bool prefer_native_odbc = true;
  bool trust_server_certificate = false;
  bool include_database_permissions = true;
  std::string connection_string;
  std::filesystem::path sqlcmd_path;
  std::filesystem::path output_file;
  std::filesystem::path third_party_directory;
};

std::string make_sql_permission_diagnostic_script(std::string_view principal,
                                                  bool include_database_permissions = true);

Result<std::filesystem::path> write_sql_permission_script(const SqlPermissionOptions& options);

Result<ProcessResult> run_sql_permission_diagnostic(const SqlPermissionOptions& options,
                                                    const CancellationToken& cancel,
                                                    ProgressCallback progress = {});

} // namespace support_assist
