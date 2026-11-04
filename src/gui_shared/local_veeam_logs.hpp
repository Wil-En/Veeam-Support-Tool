#pragma once

// The log folders of the Veeam products detected on this machine. Log Review's Auto Detect fills
// them in and starts a fast index when it opens on a Customer / Lab host with no case, on both
// editions. The locations come from the product catalogue, so a new product or path is added there
// once rather than in each frontend.

#include "support_assist/product_discovery.hpp"

#include <filesystem>
#include <set>
#include <system_error>
#include <vector>

namespace support_assist::gui {

inline std::vector<std::filesystem::path> detected_local_veeam_log_folders() {
  const auto context = support_assist::native_product_discovery_context();
  const auto detected = support_assist::detect_products(context);
  std::set<std::filesystem::path> folders;
  for (const auto& product : detected) {
    for (const auto& rule : product.definition.log_paths) {
      // Third-party locations and ones sensitive by nature are for collection by choice, not for
      // a review that starts on its own.
      if (rule.third_party || rule.sensitive_by_nature)
        continue;
      const auto candidate = support_assist::resolve_catalog_path(context, rule.path);
      std::error_code error;
      if (std::filesystem::exists(candidate, error))
        folders.insert(candidate);
    }
  }
  return {folders.begin(), folders.end()};
}

}  // namespace support_assist::gui
