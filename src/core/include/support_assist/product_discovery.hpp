#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

enum class HostPlatform { windows, linux, macos, unknown };

std::string to_string(HostPlatform platform);
HostPlatform native_host_platform();

struct DiagnosticPathRule {
  std::filesystem::path path;
  std::string label;
  bool recursive = true;
  bool third_party = false;
  bool sensitive_by_nature = false;
};

struct ProductDefinition {
  std::string id;
  std::string display_name;
  std::string role;
  std::vector<HostPlatform> platforms;
  std::string architecture_note;
  std::string documentation_reference;
  // Installation signatures only. Do not put shared/common log roots here.
  std::vector<std::filesystem::path> detection_paths;
  // Windows installations can also be identified by binaries under Program Files
  // and uninstall-product display names. These stay separate from log_paths so
  // product identity is never inferred merely because a shared Veeam log root exists.
  std::vector<std::filesystem::path> program_files_detection_paths;
  std::vector<std::string> installed_product_name_tokens;
  std::vector<std::string> installed_product_name_exclusion_tokens;
  std::vector<DiagnosticPathRule> log_paths;
  std::string preferred_exporter;
  std::vector<std::string> preferred_exporter_arguments;
  bool exporter_requires_elevation = false;
  bool exporter_may_include_configuration = false;
};

struct ProductDiscoveryContext {
  HostPlatform platform = HostPlatform::unknown;
  std::filesystem::path filesystem_root;
  std::filesystem::path program_data;
  std::filesystem::path program_files;
  std::filesystem::path local_app_data;
  std::filesystem::path home_directory;
  // Native Windows discovery populates this from uninstall registration. Tests
  // may inject names to validate product identity without touching the host registry.
  std::vector<std::string> installed_product_names;
};

struct DetectedProduct {
  ProductDefinition definition;
  std::vector<std::filesystem::path> evidence_paths;
  // True when SAT found an installation signature. Universal GUI collection
  // may also include an engineer-selected catalog product whose normal
  // signature is absent but whose known log paths are still present.
  bool signature_detected = true;
};

ProductDiscoveryContext native_product_discovery_context();
std::vector<ProductDefinition> product_catalog(HostPlatform platform);
std::vector<DetectedProduct> detect_products(const ProductDiscoveryContext& context);
std::string format_detected_products_report(const std::vector<DetectedProduct>& products);

// Resolve a catalog path against an injected test root. Native absolute paths
// remain absolute when filesystem_root is empty or "/". Tests can set a root
// to emulate Windows/Linux/macOS layouts without touching the host system.
std::filesystem::path resolve_catalog_path(const ProductDiscoveryContext& context,
                                           const std::filesystem::path& path);

} // namespace support_assist
