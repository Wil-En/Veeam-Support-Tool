#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/process.hpp"
#include "support_assist/progress.hpp"
#include "support_assist/sql_check.hpp"
#include "support_assist/sql_tools.hpp"

namespace support_assist {

Result<ProcessResult> run_sql_permission_diagnostic_odbc(const SqlPermissionOptions& options,
                                                         const CancellationToken& cancel,
                                                         ProgressCallback progress = {});

} // namespace support_assist
