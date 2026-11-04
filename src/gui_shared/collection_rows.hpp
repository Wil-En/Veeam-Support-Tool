#pragma once

// The rows a Universal Log Collection's result reads as. The Windows and Linux windows build them
// here, and so does the elevated helper for a collection run with administrator rights, which sends
// them back as text (elevated_protocol::encode_rows).

#include "support_assist/log_collection.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time_check.hpp"
#include "support_assist/universal_collection.hpp"

#include <array>
#include <filesystem>
#include <string>
#include <vector>

namespace support_assist::gui {

using CollectionRow = std::array<std::string, 4>;

inline std::vector<CollectionRow> universal_collection_rows(const UniversalCollectionResult& result) {
  const LogCollectionResult& logs = result.logs;
  std::string products;
  for (const auto& product : result.detected_products) {
    if (!products.empty())
      products += "; ";
    products += product.definition.display_name;
    if (!product.signature_detected)
      products += " [engineer-selected]";
  }
  if (products.empty())
    products = "No Veeam product roots selected";
  std::vector<CollectionRow> rows{
      {"Collection", "Universal / selected products", path_to_utf8(logs.collection_directory), "Complete"},
      {"Products", products, std::to_string(result.detected_products.size()) + " selected product role(s)",
       "Collected"},
      {"Files", std::to_string(logs.copied_files), std::to_string(logs.copied_bytes) + " bytes",
       std::to_string(logs.error_count) + " errors"},
      {"Manifest", "Universal collection manifest", path_to_utf8(result.universal_manifest_path), "Written"}};
  if (logs.additional_files != 0U)
    rows.push_back({"Additional", std::to_string(logs.additional_files) + " marked Explorer file(s)",
                    "Stored under " + path_to_utf8(std::filesystem::path("Additional") / "Local") +
                        " in the collection",
                    "Included"});
  if (!logs.health_report_path.empty())
    rows.push_back({"System Health", "Point-in-time snapshot", path_to_utf8(logs.health_report_path), "Included"});
  if (!result.platform_context_directory.empty())
    rows.push_back({"Platform Context", to_string(result.platform), path_to_utf8(result.platform_context_directory),
                    "Included"});
  if (!result.environment_log_path.empty())
    rows.push_back({"Environment", "Portable environment.log",
                    "Included at the bundle root and loadable by Engineer Environment Review", "Included"});
  if (result.time_base) {
    const TimeBaseSummary clock = time_base_summary(*result.time_base);
    rows.push_back({"Clock", clock.zone, clock.difference, clock.state});
  }
  if (!result.third_party_files.empty())
    rows.push_back({"Third-Party Diagnostics",
                    std::to_string(result.third_party_files.size()) + " bounded operational/error source(s)",
                    "Sanitized where applicable; no database payload collection", "Included"});
  if (logs.tool_output_files != 0U) {
    const bool cleaned = logs.tool_output_files_cleaned == logs.tool_output_files;
    rows.push_back({"Customer / Lab Tool Output",
                    std::to_string(logs.tool_output_files) + " SAT-owned transient tool log(s)",
                    cleaned ? "Archived under Tools and removed from " +
                                  path_to_utf8(std::filesystem::path("Log-Collections") / "Tools")
                            : std::string("Archived; local cleanup incomplete"),
                    cleaned ? "Collected + cleaned" : "Collected"});
  }
  if (!logs.archive_path.empty())
    rows.push_back({"Archive", "ZIP", path_to_utf8(logs.archive_path), "Written"});
  for (const auto& note : result.privacy_notes)
    rows.push_back({"Privacy", "Collection boundary", note, "Applied"});
  // What the file copy reported (a file it could not read or place), then the collection's own.
  for (const auto& warning : logs.warnings)
    rows.push_back({"Warning", "Collection", warning, "Review"});
  for (const auto& warning : result.warnings)
    rows.push_back({"Warning", "Universal collection", warning, "Review"});
  return rows;
}

// Where a finished collection is: its ZIP when one was written, otherwise its folder.
inline std::filesystem::path collection_result_path(const LogCollectionResult& logs) {
  return logs.archive_path.empty() ? logs.collection_directory : logs.archive_path;
}

} // namespace support_assist::gui
