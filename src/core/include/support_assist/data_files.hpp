#pragma once

// SAT's data files: what follows Veeam's releases (ports per role, guide and KB links, the storage
// tests from KB2014, object storage prices), kept as JSON under config/checks and embedded in the
// executable at build time, so a package is still one file and nothing beside it can be edited on a
// customer machine (docs/PROPOSAL_5.x_CHECKS.md section 2).

#include "support_assist/json.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

// The embedded text of a data file by its file name ("ports.json"); empty when there is none.
std::string_view embedded_data_file(std::string_view name);
std::vector<std::string> embedded_data_file_names();

// The parsed data file; a null value when it is missing or does not parse.
const JsonValue& data_file(std::string_view name);

} // namespace support_assist
