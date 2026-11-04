#include "support_assist/guided_diagnostics.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/process.hpp"
#include "support_assist/wmi.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <system_error>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#endif

namespace support_assist {
namespace {

bool supports_platform(const GuidedDiagnosticDefinition& definition, HostPlatform platform) {
  return std::find(definition.platforms.begin(), definition.platforms.end(), platform) !=
         definition.platforms.end();
}

bool has_any_required_product(const GuidedDiagnosticDefinition& definition,
                              const std::set<std::string>& detected_ids) {
  if (definition.required_product_ids.empty())
    return true;
  return std::any_of(definition.required_product_ids.begin(), definition.required_product_ids.end(),
                     [&](const std::string& id) { return detected_ids.contains(id); });
}

Error unsupported(std::string operation) {
  Error error;
  error.component = "Guided Diagnostics";
  error.operation = std::move(operation);
  error.message = "This diagnostic is not available on the current platform";
  error.recoverable = true;
  error.skipped = true;
  return error;
}

#ifdef _WIN32
std::string read_registry_string(HKEY root, const std::wstring& path, const wchar_t* value_name) {
  DWORD type = 0;
  DWORD bytes = 0;
  const LONG size_status = RegGetValueW(root, path.c_str(), value_name,
                                        RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                                        &type, nullptr, &bytes);
  if (size_status != ERROR_SUCCESS || bytes < sizeof(wchar_t))
    return {};
  std::vector<wchar_t> buffer((bytes / sizeof(wchar_t)) + 1U, L'\0');
  const LONG read_status = RegGetValueW(root, path.c_str(), value_name,
                                        RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                                        &type, buffer.data(), &bytes);
  if (read_status != ERROR_SUCCESS)
    return {};
  return utf8_from_wide(std::wstring(buffer.data()));
}

ConfigurationDatabaseInfo read_vbr_database_config() {
  ConfigurationDatabaseInfo info;
  info.product = "Veeam Backup & Replication";
  constexpr wchar_t kBase[] =
      L"SOFTWARE\\Veeam\\Veeam Backup and Replication\\DatabaseConfigurations";
  const std::string active = read_registry_string(HKEY_LOCAL_MACHINE, kBase, L"SqlActiveConfiguration");
  if (active.empty())
    return info;

  info.found = true;
  info.source = "HKLM\\SOFTWARE\\Veeam\\Veeam Backup and Replication\\DatabaseConfigurations";
  const std::string lowered = ascii_lower(active);
  if (lowered.find("postgres") != std::string::npos) {
    info.engine = "PostgreSQL";
    const std::wstring path = std::wstring(kBase) + L"\\PostgreSql";
    info.server = read_registry_string(HKEY_LOCAL_MACHINE, path, L"SqlHostName");
    info.port = read_registry_string(HKEY_LOCAL_MACHINE, path, L"SqlHostPort");
    info.database = read_registry_string(HKEY_LOCAL_MACHINE, path, L"SqlDatabaseName");
    info.windows_auth_account =
        read_registry_string(HKEY_LOCAL_MACHINE, path, L"PostgresUserForWindowsAuth");
  } else {
    info.engine = "Microsoft SQL Server";
    const std::wstring path = std::wstring(kBase) + L"\\MsSql";
    info.server = read_registry_string(HKEY_LOCAL_MACHINE, path, L"SqlServerName");
    info.instance = read_registry_string(HKEY_LOCAL_MACHINE, path, L"SqlInstanceName");
    info.database = read_registry_string(HKEY_LOCAL_MACHINE, path, L"SqlDatabaseName");
  }
  return info;
}
#endif

#ifdef _WIN32
std::vector<std::filesystem::path> postgres_roots() {
  std::vector<std::filesystem::path> roots;
#ifdef _WIN32
  wchar_t* value = nullptr;
  std::size_t length = 0;
  if (_wdupenv_s(&value, &length, L"ProgramFiles") == 0 && value != nullptr) {
    roots.emplace_back(std::filesystem::path(value) / L"PostgreSQL");
  }
  std::free(value);
#else
  roots.emplace_back("/var/lib/postgresql");
  roots.emplace_back("/var/lib/pgsql");
#endif
  return roots;
}

std::vector<std::string> read_sspi_errors(const std::filesystem::path& file,
                                          std::size_t maximum_lines) {
  std::ifstream input(file);
  if (!input)
    return {};
  std::vector<std::string> matches;
  std::string line;
  while (std::getline(input, line)) {
    const std::string lower = ascii_lower(line);
    if (lower.find("sspi authentication failed") != std::string::npos ||
        lower.find("no match in usermap") != std::string::npos) {
      matches.push_back(line.substr(0, 4096));
      if (matches.size() > maximum_lines)
        matches.erase(matches.begin());
    }
  }
  return matches;
}
#endif


#ifdef _WIN32
std::string certificate_name_text(const CERT_NAME_BLOB& name) {
  auto* blob = const_cast<CERT_NAME_BLOB*>(&name);
  const DWORD length = CertNameToStrW(X509_ASN_ENCODING, blob, CERT_X500_NAME_STR, nullptr, 0);
  if (length <= 1)
    return {};
  std::wstring text(length, L'\0');
  CertNameToStrW(X509_ASN_ENCODING, blob, CERT_X500_NAME_STR, text.data(), length);
  text.resize(length - 1);
  return utf8_from_wide(text);
}

std::string filetime_utc_text(const FILETIME& value) {
  SYSTEMTIME time{};
  if (!FileTimeToSystemTime(&value, &time))
    return {};
  char buffer[32]{};
  std::snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02uZ", time.wYear, time.wMonth,
                time.wDay, time.wHour, time.wMinute, time.wSecond);
  return buffer;
}

std::string certificate_thumbprint(PCCERT_CONTEXT certificate) {
  BYTE hash[20]{};
  DWORD size = sizeof(hash);
  if (!CertGetCertificateContextProperty(certificate, CERT_SHA1_HASH_PROP_ID, hash, &size))
    return {};
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string output;
  for (DWORD index = 0; index < size; ++index) {
    output.push_back(kHex[hash[index] >> 4]);
    output.push_back(kHex[hash[index] & 0x0F]);
  }
  return output;
}

std::string certificate_friendly_name(PCCERT_CONTEXT certificate) {
  DWORD size = 0;
  if (!CertGetCertificateContextProperty(certificate, CERT_FRIENDLY_NAME_PROP_ID, nullptr, &size) ||
      size < sizeof(wchar_t))
    return {};
  std::vector<wchar_t> buffer((size / sizeof(wchar_t)) + 1U, L'\0');
  if (!CertGetCertificateContextProperty(certificate, CERT_FRIENDLY_NAME_PROP_ID, buffer.data(), &size))
    return {};
  return utf8_from_wide(std::wstring(buffer.data()));
}
#endif

bool names_vbr_certificate(const std::string& text) {
  return ascii_lower(text).find("veeam backup server certificate") != std::string::npos;
}

} // namespace

namespace guided_diagnostics_detail {
std::optional<std::size_t> pick_vbr_store_certificate(const std::vector<StoreCertificate>& certificates) {
  std::optional<std::size_t> picked;
  for (std::size_t index = 0; index < certificates.size(); ++index) {
    const auto& certificate = certificates[index];
    if (!certificate.has_private_key || !certificate.currently_valid)
      continue;
    if (!names_vbr_certificate(certificate.subject) && !names_vbr_certificate(certificate.friendly_name))
      continue;
    if (picked.has_value())
      return std::nullopt;
    picked = index;
  }
  return picked;
}

std::optional<std::size_t> pick_store_certificate_by_thumbprint(const std::vector<StoreCertificate>& certificates,
                                                                std::string_view thumbprint) {
  const auto hex = [](std::string_view text) {
    std::string out;
    for (const char c : text) {
      if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
        out.push_back(static_cast<char>(c >= 'a' ? c - 'a' + 'A' : c));
    }
    return out;
  };
  const std::string wanted = hex(thumbprint);
  if (wanted.size() != 40U)
    return std::nullopt;
  for (std::size_t index = 0; index < certificates.size(); ++index) {
    if (hex(certificates[index].sha1_thumbprint) == wanted)
      return index;
  }
  return std::nullopt;
}
} // namespace guided_diagnostics_detail

Result<std::vector<StoreCertificate>> read_local_machine_certificates() {
#ifndef _WIN32
  return Result<std::vector<StoreCertificate>>::failure(unsupported("LocalMachine certificate store"));
#else
  HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                   CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG |
                                       CERT_STORE_OPEN_EXISTING_FLAG,
                                   L"MY");
  if (store == nullptr) {
    Error error;
    error.component = "Guided Diagnostics";
    error.operation = "Open the LocalMachine Personal certificate store";
    error.native_code = static_cast<std::int64_t>(GetLastError());
    error.message = "The LocalMachine Personal certificate store could not be opened";
    error.recoverable = true;
    return Result<std::vector<StoreCertificate>>::failure(std::move(error));
  }
  std::vector<StoreCertificate> output;
  PCCERT_CONTEXT certificate = nullptr;
  while ((certificate = CertEnumCertificatesInStore(store, certificate)) != nullptr) {
    StoreCertificate item;
    item.subject = certificate_name_text(certificate->pCertInfo->Subject);
    item.issuer = certificate_name_text(certificate->pCertInfo->Issuer);
    item.friendly_name = certificate_friendly_name(certificate);
    item.valid_from = filetime_utc_text(certificate->pCertInfo->NotBefore);
    item.valid_until = filetime_utc_text(certificate->pCertInfo->NotAfter);
    item.sha1_thumbprint = certificate_thumbprint(certificate);
    DWORD key_size = 0;
    item.has_private_key =
        CertGetCertificateContextProperty(certificate, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &key_size) != FALSE;
    item.currently_valid = CertVerifyTimeValidity(nullptr, certificate->pCertInfo) == 0;
    output.push_back(std::move(item));
  }
  CertCloseStore(store, 0);
  return Result<std::vector<StoreCertificate>>::success(std::move(output));
#endif
}

namespace {

} // namespace

std::vector<GuidedDiagnosticDefinition> guided_diagnostic_catalog() {
  using P = HostPlatform;
  return {
      {"wmi-connectivity", "WMI Connectivity Test",
       "Tests a read-only WMI namespace/query path without repairing or changing WMI.",
       {P::windows}, {"vbr", "vaw", "vspc", "veeam-one", "vro", "mssql-plugin"},
       "KB1926", "https://www.veeam.com/kb1926", GuidedDiagnosticSafety::read_only},
      {"vss-writer-health", "VSS Writer Health Check",
       "Enumerates VSS writer state and failure information for Windows snapshot troubleshooting.",
       {P::windows}, {"vbr", "vaw", "mssql-plugin"},
       "KB2041", "https://www.veeam.com/kb2041", GuidedDiagnosticSafety::read_only},
      {"managed-server-connectivity", "Managed Server Connectivity",
       "Guides DNS, route, TCP and Veeam service connectivity checks between managed roles.",
       {P::windows, P::linux, P::macos},
       {"vbr", "vbr-linux", "vaw", "val", "vam", "vspc-agent"},
       "KB2065 / KB4444", "https://www.veeam.com/kb2065", GuidedDiagnosticSafety::read_only},
      {"configuration-database", "Configuration Database Identification",
       "Reads documented local Veeam configuration metadata to identify the database connection without changing it.",
       {P::windows}, {"vbr", "vspc"},
       "KB1471", "https://www.veeam.com/kb1471", GuidedDiagnosticSafety::read_only},
      {"postgresql-sspi", "PostgreSQL SSPI Authentication Check",
       "Reads PostgreSQL Windows user mappings and recent SSPI authentication errors without modifying PostgreSQL configuration.",
       {P::windows}, {"vbr", "veeam-one"},
       "KB4542", "https://www.veeam.com/kb4542", GuidedDiagnosticSafety::read_only},
      {"veeam-secure-channel", "Veeam Secure Channel Test",
       "Runs DNS/TCP/TLS and public-certificate identity checks for an applicable Veeam secure channel.",
       {P::windows, P::linux, P::macos},
       {"vbr", "vbr-linux", "vaw", "val", "vam"},
       "Veeam secure communications reference", "https://helpcenter.veeam.com/docs/vbr/userguide/cipher_suites_protocols.html?ver=13",
       GuidedDiagnosticSafety::read_only},
  };
}

std::vector<GuidedDiagnosticDefinition> available_guided_diagnostics(
    const ProductDiscoveryContext& context) {
  const auto detected = detect_products(context);
  std::set<std::string> ids;
  for (const auto& product : detected)
    ids.insert(product.definition.id);

  std::vector<GuidedDiagnosticDefinition> available;
  for (const auto& definition : guided_diagnostic_catalog()) {
    if (supports_platform(definition, context.platform) && has_any_required_product(definition, ids))
      available.push_back(definition);
  }
  return available;
}

Result<WmiConnectivityDiagnosticResult> run_wmi_connectivity_diagnostic(
    const WmiConnectivityDiagnosticOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress) {
#ifndef _WIN32
  (void)options;
  (void)cancel;
  (void)progress;
  return Result<WmiConnectivityDiagnosticResult>::failure(unsupported("WMI connectivity"));
#else
  WmiQueryOptions query;
  query.machine = options.machine.empty() ? "." : options.machine;
  query.name_space = options.name_space.empty() ? "root\\cimv2" : options.name_space;
  query.query = "SELECT Caption,Version,CSName FROM Win32_OperatingSystem";
  query.maximum_rows = 4;
  query.maximum_properties = 16;
  auto rows = query_wmi(query, cancel, std::move(progress));
  if (!rows.ok())
    return Result<WmiConnectivityDiagnosticResult>::failure(rows.error());

  WmiConnectivityDiagnosticResult result;
  result.machine = query.machine;
  result.name_space = query.name_space;
  result.query_succeeded = true;
  result.rows_returned = rows.value().size();
  if (!rows.value().empty()) {
    const auto& values = rows.value().front().values;
    if (const auto it = values.find("Caption"); it != values.end()) result.os_caption = it->second;
    if (const auto it = values.find("Version"); it != values.end()) result.os_version = it->second;
    if (const auto it = values.find("CSName"); it != values.end()) result.computer_name = it->second;
  }
  return Result<WmiConnectivityDiagnosticResult>::success(std::move(result));
#endif
}

Result<VssWriterHealthResult> inspect_vss_writer_health() {
#ifndef _WIN32
  return Result<VssWriterHealthResult>::failure(unsupported("VSS writer health"));
#else
  auto writers = enumerate_vss_writers();
  if (!writers.ok())
    return Result<VssWriterHealthResult>::failure(writers.error());
  VssWriterHealthResult result;
  result.writers = std::move(writers.value());
  for (const auto& writer : result.writers) {
    const std::string state = ascii_lower(writer.state_name);
    if (writer.failure_hresult == 0 && (state.find("stable") != std::string::npos || writer.state == 1))
      ++result.healthy;
    else
      ++result.warning_or_failed;
  }
  return Result<VssWriterHealthResult>::success(std::move(result));
#endif
}

Result<std::vector<ConfigurationDatabaseInfo>> identify_configuration_databases() {
#ifndef _WIN32
  return Result<std::vector<ConfigurationDatabaseInfo>>::failure(
      unsupported("configuration database identification"));
#else
  std::vector<ConfigurationDatabaseInfo> output;
  auto vbr = read_vbr_database_config();
  if (vbr.found)
    output.push_back(std::move(vbr));
  return Result<std::vector<ConfigurationDatabaseInfo>>::success(std::move(output));
#endif
}

Result<std::vector<PostgreSqlSspiMapping>> inspect_postgresql_sspi_mappings(
    std::size_t maximum_error_lines) {
#ifndef _WIN32
  (void)maximum_error_lines;
  return Result<std::vector<PostgreSqlSspiMapping>>::failure(
      unsupported("PostgreSQL SSPI authentication"));
#else
  std::vector<PostgreSqlSspiMapping> output;
  for (const auto& root : postgres_roots()) {
    std::error_code error;
    if (!std::filesystem::is_directory(root, error) || error)
      continue;
    for (const auto& version_entry : std::filesystem::directory_iterator(root, error)) {
      if (error) break;
      if (!version_entry.is_directory(error) || error) continue;
      const auto data = version_entry.path() / L"data";
      const auto ident = data / L"pg_ident.conf";
      if (!std::filesystem::is_regular_file(ident, error) || error) continue;

      PostgreSqlSspiMapping mapping;
      mapping.pg_ident_path = ident;
      mapping.postgres_version = path_to_utf8(version_entry.path().filename());
      std::ifstream input(ident);
      std::string line;
      while (std::getline(input, line)) {
        const auto first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos || line[first] == '#') continue;
        std::istringstream parser(line);
        std::string map_name;
        std::string windows_account;
        std::string postgres_account;
        if (parser >> map_name >> windows_account >> postgres_account) {
          if (ascii_lower(map_name) == "veeam")
            mapping.mapped_windows_accounts.push_back(windows_account + " -> " + postgres_account);
        }
      }

      const auto log_dir = data / L"log";
      std::filesystem::path newest_log;
      std::filesystem::file_time_type newest_time{};
      if (std::filesystem::is_directory(log_dir, error) && !error) {
        for (const auto& log_entry : std::filesystem::directory_iterator(log_dir, error)) {
          if (error) break;
          if (!log_entry.is_regular_file(error) || error) continue;
          const auto time = log_entry.last_write_time(error);
          if (error) { error.clear(); continue; }
          if (newest_log.empty() || time > newest_time) {
            newest_log = log_entry.path();
            newest_time = time;
          }
        }
      }
      if (!newest_log.empty()) {
        mapping.latest_log_path = newest_log;
        mapping.recent_sspi_errors = read_sspi_errors(newest_log, maximum_error_lines);
      }
      output.push_back(std::move(mapping));
    }
  }
  return Result<std::vector<PostgreSqlSspiMapping>>::success(std::move(output));
#endif
}

Result<VeeamCertificateReference> read_local_vbr_configured_certificate(
    const CancellationToken& cancel,
    ProgressCallback progress) {
#ifndef _WIN32
  (void)cancel;
  (void)progress;
  return Result<VeeamCertificateReference>::failure(
      unsupported("VBR configured certificate identification"));
#else
  // VBR records the certificate it uses as BackupServerCertificateThumbprint (SHA-1), so a replaced
  // or CA-issued certificate is found in LocalMachine\My by that value; without the value, the one
  // default-named Veeam Backup Server Certificate in the store is taken.
  static_cast<void>(cancel);
  static_cast<void>(progress);
  const std::string recorded = read_registry_string(
      HKEY_LOCAL_MACHINE, L"SOFTWARE\\Veeam\\Veeam Backup and Replication", L"BackupServerCertificateThumbprint");
  auto store = read_local_machine_certificates();
  const auto from_store = [](const StoreCertificate& certificate, std::string source, std::string detail) {
    VeeamCertificateReference reference;
    reference.available = !certificate.sha1_thumbprint.empty();
    reference.source = std::move(source);
    reference.subject = certificate.subject;
    reference.issuer = certificate.issuer;
    reference.valid_from = certificate.valid_from;
    reference.valid_until = certificate.valid_until;
    reference.sha1_thumbprint = certificate.sha1_thumbprint;
    reference.detail = std::move(detail);
    return reference;
  };
  if (!trim(recorded).empty()) {
    if (store.ok()) {
      if (const auto found =
              guided_diagnostics_detail::pick_store_certificate_by_thumbprint(store.value(), recorded)) {
        return Result<VeeamCertificateReference>::success(from_store(
            store.value()[*found],
            "LocalMachine\\My certificate store (Veeam Backup Server Certificate, the thumbprint VBR records)",
            "The certificate VBR is configured with, found in the certificate store by its recorded thumbprint"));
      }
    }
    // The recorded thumbprint alone still identifies the certificate to compare with.
    VeeamCertificateReference reference;
    reference.available = true;
    reference.source = "BackupServerCertificateThumbprint in HKLM\\SOFTWARE\\Veeam\\Veeam Backup and Replication";
    reference.sha1_thumbprint = trim(recorded);
    reference.detail = "VBR records this certificate, and LocalMachine\\My does not hold it";
    return Result<VeeamCertificateReference>::success(std::move(reference));
  }
  if (store.ok()) {
    if (const auto picked = guided_diagnostics_detail::pick_vbr_store_certificate(store.value())) {
      return Result<VeeamCertificateReference>::success(
          from_store(store.value()[*picked], "LocalMachine\\My certificate store (Veeam Backup Server Certificate)",
                     "Configured VBR public certificate identity resolved from the certificate store"));
    }
  }
  VeeamCertificateReference reference;
  reference.source = "LocalMachine\\My certificate store";
  reference.detail = store.ok() ? "VBR records no certificate thumbprint here, and the store holds no single Veeam Backup "
                                  "Server Certificate; type the expected fingerprint to compare one"
                                : "The certificate store could not be read; type the expected fingerprint to compare one";
  return Result<VeeamCertificateReference>::success(std::move(reference));
#endif
}

} // namespace support_assist
