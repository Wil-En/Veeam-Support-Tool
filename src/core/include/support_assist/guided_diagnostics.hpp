#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/product_discovery.hpp"
#include "support_assist/progress.hpp"
#include "support_assist/vss.hpp"

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace support_assist {

enum class GuidedDiagnosticSafety { read_only, controlled_test };

struct GuidedDiagnosticDefinition {
  std::string id;
  std::string display_name;
  std::string description;
  std::vector<HostPlatform> platforms;
  std::vector<std::string> required_product_ids;
  std::string kb_id;
  std::string reference_url;
  GuidedDiagnosticSafety safety = GuidedDiagnosticSafety::read_only;
};

std::vector<GuidedDiagnosticDefinition> guided_diagnostic_catalog();
std::vector<GuidedDiagnosticDefinition> available_guided_diagnostics(
    const ProductDiscoveryContext& context);

struct WmiConnectivityDiagnosticOptions {
  std::string machine = ".";
  std::string name_space = "root\\cimv2";
};

struct WmiConnectivityDiagnosticResult {
  std::string machine;
  std::string name_space;
  bool query_succeeded = false;
  std::size_t rows_returned = 0;
  std::string os_caption;
  std::string os_version;
  std::string computer_name;
};

Result<WmiConnectivityDiagnosticResult> run_wmi_connectivity_diagnostic(
    const WmiConnectivityDiagnosticOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress = {});

struct VssWriterHealthResult {
  std::vector<VssWriterInfo> writers;
  std::size_t healthy = 0;
  std::size_t warning_or_failed = 0;
};

Result<VssWriterHealthResult> inspect_vss_writer_health();

struct ConfigurationDatabaseInfo {
  bool found = false;
  std::string product;
  std::string engine;
  std::string server;
  std::string instance;
  std::string database;
  std::string port;
  std::string windows_auth_account;
  std::string source;
};

Result<std::vector<ConfigurationDatabaseInfo>> identify_configuration_databases();

struct PostgreSqlSspiMapping {
  std::filesystem::path pg_ident_path;
  std::string postgres_version;
  std::vector<std::string> mapped_windows_accounts;
  std::filesystem::path latest_log_path;
  std::vector<std::string> recent_sspi_errors;
};

Result<std::vector<PostgreSqlSspiMapping>> inspect_postgresql_sspi_mappings(
    std::size_t maximum_error_lines = 20);

struct VeeamCertificateReference {
  bool available = false;
  std::string source;
  std::string subject;
  std::string issuer;
  std::string valid_from;
  std::string valid_until;
  std::string sha1_thumbprint;
  std::string detail;
};

Result<VeeamCertificateReference> read_local_vbr_configured_certificate(
    const CancellationToken& cancel,
    ProgressCallback progress = {});

struct StoreCertificate {
  std::string subject;
  std::string friendly_name;
  std::string issuer;
  std::string valid_from;
  std::string valid_until;
  std::string sha1_thumbprint;
  bool has_private_key = false;
  bool currently_valid = false;
};

// Read-only listing of the LocalMachine Personal (My) certificate store. Windows only.
Result<std::vector<StoreCertificate>> read_local_machine_certificates();

namespace guided_diagnostics_detail {
// The backup server certificate VBR generates carries "Veeam Backup Server Certificate" as its
// subject and friendly name. Returns the single valid one with a private key, or nothing when the
// store holds none or more than one.
std::optional<std::size_t> pick_vbr_store_certificate(const std::vector<StoreCertificate>& certificates);
// The certificate whose SHA-1 thumbprint is the one given, ignoring case, spaces and colons.
std::optional<std::size_t> pick_store_certificate_by_thumbprint(const std::vector<StoreCertificate>& certificates,
                                                                std::string_view thumbprint);
} // namespace guided_diagnostics_detail

} // namespace support_assist
