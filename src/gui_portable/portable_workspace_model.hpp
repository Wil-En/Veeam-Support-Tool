#pragma once

// SAT portable engineer parity model: shared case selection, categorized tools and explicit OS capability states.

#include "support_assist/case_workspace.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist::gui {

enum class PortablePlatform { linux, macos };

enum class PortableCapabilityState {
  available,
  requires_dependency,
  not_applicable,
  unavailable
};

struct PortableCapability {
  std::string id;
  std::string name;
  std::string category;
  PortableCapabilityState state = PortableCapabilityState::unavailable;
  std::string detail;
};

inline std::string platform_name(PortablePlatform platform) {
  return platform == PortablePlatform::macos ? "macOS" : "Linux";
}

inline std::string capability_state_label(PortableCapabilityState state,
                                          PortablePlatform platform) {
  switch (state) {
  case PortableCapabilityState::available: return "Available";
  case PortableCapabilityState::requires_dependency: return "Requires dependency";
  case PortableCapabilityState::not_applicable: return "Not applicable on " + platform_name(platform);
  case PortableCapabilityState::unavailable: return "Unavailable in this build";
  }
  return "Unavailable";
}

inline std::vector<PortableCapability> portable_tool_catalog(PortablePlatform platform,
                                                              bool ssh_available,
                                                              bool native_odbc_available) {
  using State = PortableCapabilityState;
  const std::string os = platform_name(platform);
  const std::string host_name = platform == PortablePlatform::macos
                                    ? "macOS Host Diagnostics"
                                    : "Linux Host Diagnostics";
  return {
      {"collection", "Log Collection", "Log Collection", State::available,
       "Product-aware universal support bundle collection using native " + os + " product/log locations."},
      {"guided", "Guided Diagnostics", "Guided Diagnostics", State::available,
       "Product-aware read-only guided checks for detected Veeam roles on " + os + "."},
      {"network", "Network Tools", "Network Tools", State::available,
       "TCP/UDP connectivity and listeners, TLS handshake inspection, interface-bound testing, payload validation and throughput."},
      {"sql", "SQL Tools", "SQL Tools",
       native_odbc_available ? State::available : State::requires_dependency,
       native_odbc_available
           ? "Permission-script generation and native ODBC/SQLCMD diagnostic workflow. Installed SQL Server ODBC driver requirements still apply."
           : "Permission-script generation is available, but native ODBC execution requires unixODBC/iODBC development support in this build."},
      {"filesystem", "Filesystem Change", "Filesystem Change", State::available,
       "Capture and compare filesystem baselines with exclusions and SHA-256 hashing."},
      {"host", host_name, "Host Diagnostics", State::available,
       "Read-only operating-system, process, storage, service, package, network and security context."},
      {"ssh", "SSH / SFTP", "Explorer", ssh_available ? State::available : State::requires_dependency,
       ssh_available ? "Secure remote browsing, transfer and console with explicit host-key trust."
                     : "libssh2 support was not compiled into this build."}
  };
}


// Windows technologies that have no equivalent on this platform.
//
// Deliberately NOT in portable_tool_catalog(). A tool category that can never execute is not a
// category: presenting one trains an engineer to click things that do nothing, and it makes the
// portable editions look like a degraded Windows rather than a product that fits the machine it is
// running on.
//
// They are still listed ONCE, in the Capability reference, because a Windows engineer moving to
// Linux or macOS will reasonably ask where VSS Tools went and deserves an answer.
inline std::vector<PortableCapability> portable_unavailable_technologies(PortablePlatform platform) {
  using State = PortableCapabilityState;
  const std::string os = platform_name(platform);
  const std::string host_name = platform == PortablePlatform::macos
                                    ? "macOS Host Diagnostics"
                                    : "Linux Host Diagnostics";
  return {
      {"vss", "VSS Tools", "Windows-only", State::not_applicable,
       "Microsoft Volume Shadow Copy Service is a Windows technology and has no literal " + os +
           " equivalent."},
      {"registry", "Registry Tools", "Windows-only", State::not_applicable,
       "The Windows Registry does not exist on " + os +
           "; use Filesystem Change and native service/configuration diagnostics instead."},
      {"wmi", "WMI Diagnostics", "Windows-only", State::not_applicable,
       "WMI is Windows-specific; " + host_name + " uses native operating-system interfaces."},
      {"vbr", "VBR Diagnostics", "Windows-only", State::not_applicable,
       "Local Veeam Backup & Replication server diagnostics require a Windows VBR server role."}};
}

struct PortableToolAction {
  std::string id;
  std::string name;
  PortableCapabilityState state = PortableCapabilityState::unavailable;
  std::string detail;
};

inline std::vector<PortableToolAction> portable_network_tool_actions(PortablePlatform platform) {
  using State = PortableCapabilityState;
  const std::string os = platform_name(platform);
  return {
      {"tcp-connect", "TCP Connectivity Test", State::available,
       "TCP reachability, DNS/source path, interface binding and optional SAT payload validation."},
      {"udp-connect", "UDP Connectivity Test", State::available,
       "UDP probe with explicit Indeterminate / No Response semantics unless a cooperating SAT listener acknowledges the test."},
      {"tcp-listener", "TCP Listener", State::available,
       "Temporary SAT listener with source/destination, Test ID and cooperating payload verification."},
      {"udp-listener", "UDP Listener", State::available,
       "Temporary SAT UDP listener with Test ID and acknowledgement behavior."},
      {"tls", "TLS Handshake Test", State::available,
       "TLS negotiation and public certificate inspection without installing a SAT certificate."},
      {"throughput-client", "Network Throughput Client", State::available,
       "Sustained SAT-to-SAT TCP throughput client."},
      {"throughput-server", "Network Throughput Server", State::available,
       "Sustained SAT-to-SAT TCP throughput server."},
      {"loopback", "Local Loopback Self-Test", State::not_applicable,
       "The current documented loopback self-test workflow is Windows-only; use localhost TCP/listener verification on " + os + "."},
      {"rpc", "Windows RPC Connectivity", State::not_applicable, "DCE/RPC Endpoint Mapper validation is Windows-specific."},
      {"grpc", "gRPC Connectivity / Listener", State::unavailable, "The controlled SAT gRPC transport backend has not yet been ported to " + os + "."},
      {"smb", "SMB Connectivity Test", State::not_applicable, "The bounded Windows SMB/UNC workflow uses Windows identity/credential semantics."},
      {"vbr-jobs", "Running VBR Jobs", State::not_applicable, "Requires a local Windows Veeam Backup & Replication server role."}
  };
}

struct PortableCaseCatalog {
  std::vector<CaseWorkspace> cases;
  int active_index = -1;

  const CaseWorkspace* active() const noexcept {
    if (active_index < 0 || static_cast<std::size_t>(active_index) >= cases.size()) return nullptr;
    return &cases[static_cast<std::size_t>(active_index)];
  }

  std::string active_label() const {
    const auto* workspace = active();
    if (workspace == nullptr) return "(No active case)";
    std::string label = workspace->case_id;
    if (!workspace->title.empty()) label += ": " + workspace->title;
    return label;
  }
};

inline std::filesystem::path portable_case_catalog_path(const std::filesystem::path& state_directory) {
  return state_directory / "case-catalog.txt";
}

inline std::filesystem::path portable_active_case_path(const std::filesystem::path& state_directory) {
  return state_directory / "active-case.txt";
}

inline void save_portable_case_catalog(const PortableCaseCatalog& catalog,
                                       const std::filesystem::path& state_directory) {
  std::error_code error;
  std::filesystem::create_directories(state_directory, error);
  if (error) return;
  std::ofstream list(portable_case_catalog_path(state_directory), std::ios::binary | std::ios::trunc);
  if (list) {
    for (const auto& workspace : catalog.cases) list << workspace.root.string() << '\n';
  }
  std::ofstream active(portable_active_case_path(state_directory), std::ios::binary | std::ios::trunc);
  if (active && catalog.active() != nullptr) active << catalog.active()->root.string() << '\n';
}

inline PortableCaseCatalog load_portable_case_catalog(const std::filesystem::path& state_directory,
                                                       const std::vector<std::filesystem::path>& seed_roots = {}) {
  PortableCaseCatalog catalog;
  std::vector<std::filesystem::path> roots = seed_roots;
  {
    std::ifstream input(portable_case_catalog_path(state_directory), std::ios::binary);
    std::string line;
    while (std::getline(input, line)) {
      if (!line.empty() && line.back() == '\r') line.pop_back();
      if (!line.empty()) roots.emplace_back(line);
    }
  }

  std::set<std::string> seen;
  auto add = [&](CaseWorkspace workspace) {
    std::error_code error;
    auto normalized = std::filesystem::weakly_canonical(workspace.root, error);
    const auto key = (error ? workspace.root.lexically_normal() : normalized).string();
    if (seen.insert(key).second) catalog.cases.push_back(std::move(workspace));
  };

  for (const auto& root : roots) {
    auto direct = open_case_workspace(root);
    if (direct.ok()) {
      add(std::move(direct.value()));
      continue;
    }
    auto discovered = discover_case_workspaces(root);
    if (!discovered.ok()) continue;
    for (auto& workspace : discovered.value()) add(std::move(workspace));
  }

  std::stable_sort(catalog.cases.begin(), catalog.cases.end(), [](const auto& left, const auto& right) {
    if (left.created_utc != right.created_utc) return left.created_utc > right.created_utc;
    return left.case_id < right.case_id;
  });

  std::string active_path;
  {
    std::ifstream input(portable_active_case_path(state_directory), std::ios::binary);
    std::getline(input, active_path);
    if (!active_path.empty() && active_path.back() == '\r') active_path.pop_back();
  }
  if (!active_path.empty()) {
    for (std::size_t index = 0; index < catalog.cases.size(); ++index) {
      if (catalog.cases[index].root.lexically_normal() == std::filesystem::path(active_path).lexically_normal()) {
        catalog.active_index = static_cast<int>(index);
        break;
      }
    }
  }
  return catalog;
}

inline void register_portable_case(PortableCaseCatalog& catalog,
                                   CaseWorkspace workspace,
                                   const std::filesystem::path& state_directory) {
  for (std::size_t index = 0; index < catalog.cases.size(); ++index) {
    if (catalog.cases[index].root.lexically_normal() == workspace.root.lexically_normal()) {
      catalog.cases[index] = std::move(workspace);
      catalog.active_index = static_cast<int>(index);
      save_portable_case_catalog(catalog, state_directory);
      return;
    }
  }
  catalog.cases.insert(catalog.cases.begin(), std::move(workspace));
  catalog.active_index = 0;
  save_portable_case_catalog(catalog, state_directory);
}

inline void set_portable_active_case(PortableCaseCatalog& catalog,
                                     int index,
                                     const std::filesystem::path& state_directory) {
  catalog.active_index = (index >= 0 && static_cast<std::size_t>(index) < catalog.cases.size()) ? index : -1;
  save_portable_case_catalog(catalog, state_directory);
}

} // namespace support_assist::gui
