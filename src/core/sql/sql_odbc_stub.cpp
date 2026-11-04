#include "sql_odbc.hpp"

namespace support_assist {

Result<ProcessResult> run_sql_permission_diagnostic_odbc(const SqlPermissionOptions&,
                                                         const CancellationToken&,
                                                         ProgressCallback) {
  Error error;
  error.component = "SQL ODBC";
  error.operation = "run permission diagnostic";
  error.message = "Native SQL Server ODBC diagnostics require the Windows build";
  return Result<ProcessResult>::failure(std::move(error));
}

Result<SqlBatchResult> run_sql_statements(const SqlConnection&, const std::vector<std::string>&,
                                          const CancellationToken&, ProgressCallback) {
  Error error;
  error.component = "SQL ODBC";
  error.operation = "connect";
  error.message = "This build of SAT has no ODBC support; SQL Tools needs a build with the ODBC headers present.";
  return Result<SqlBatchResult>::failure(std::move(error));
}

} // namespace support_assist
