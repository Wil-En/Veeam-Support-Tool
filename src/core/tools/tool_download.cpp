#include "support_assist/tool_download.hpp"

#include "support_assist/debug_log.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/tool_catalog.hpp"
#include "support_assist/uuid.hpp"
#include "support_assist/version.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <winver.h>
// Authenticode publisher verification for anything SAT is about to execute. WinVerifyTrust proves
// the file carries a valid, unrevoked signature chaining to a trusted root; crypt32 then extracts
// the signer subject so it can be matched against the publisher named in the editable config.
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#endif

#include <optional>

#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>
#endif

namespace support_assist {
namespace {

Error tool_download_error(std::string operation,
                          std::string message,
                          std::string source = {},
                          std::int64_t native_code = 0) {
  Error error;
  error.component = "ToolDownload";
  error.operation = std::move(operation);
  error.message = std::move(message);
  error.source = std::move(source);
  error.native_code = native_code;
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

const ExternalToolDefinition* find_definition(std::string_view id) {
  const std::string folded = ascii_lower(id);
  for (const auto& definition : external_tool_catalog()) {
    if (ascii_lower(definition.id) == folded || ascii_lower(definition.name) == folded)
      return &definition;
  }
  return nullptr;
}

// ------------------------------------------------------------------------------------------------
// Editable download-source config (portable; the Qt port reuses this).
//
// The download must not be usable to attack a system, and its sources must stay easy to edit.
// The lockdown is split:
//   * The URL, the expected Authenticode publisher and the install kind come from an editable text
//     file in the managed Tools folder -- an engineer bumps a version by editing the URL, no
//     rebuild.
//   * The silent-execution command line and the install destination are FIXED IN THIS BINARY, keyed
//     only by the install kind. Nothing an engineer (or a tampered file) can put in the config
//     becomes part of a command line, and nothing is ever executed unless its signature chains to a
//     trusted root AND its signer subject matches the publisher named in the config.
// ------------------------------------------------------------------------------------------------

enum class ToolInstallKind {
  archive,      // download an archive and extract it with libarchive; nothing is executed
  portableapps, // download a PortableApps.com .paf.exe and open its installer on the Tools folder
  inno,         // download an Inno Setup installer and run it with fixed silent switches
  nsis,         // download an NSIS installer and run it with fixed silent switches
  msi,          // download a Windows Installer package and unpack it with msiexec /a; nothing installs
};

struct ToolSource {
  std::string url;       // HTTPS download location (editable)
  std::string signer;    // expected Authenticode subject (publisher); required for executable kinds
  std::string filename;  // download filename; derived from the URL when empty
  std::string archive;   // archive-format hint for the archive kind ("zip"); optional
  std::vector<std::string> extract; // the parts of the archive to unpack; empty: all of it
  std::string sha256;    // the download's SHA-256, for a tool whose publisher signs nothing
  ToolInstallKind kind = ToolInstallKind::archive;
};

ToolInstallKind parse_install_kind(const std::string& value) {
  const std::string folded = ascii_lower(value);
  if (folded == "portableapps" || folded == "paf")
    return ToolInstallKind::portableapps;
  if (folded == "inno" || folded == "innosetup")
    return ToolInstallKind::inno;
  if (folded == "nsis")
    return ToolInstallKind::nsis;
  if (folded == "msi")
    return ToolInstallKind::msi;
  return ToolInstallKind::archive;
}

[[maybe_unused]] const char* install_kind_name(ToolInstallKind kind) {
  switch (kind) {
    case ToolInstallKind::portableapps: return "portableapps";
    case ToolInstallKind::inno: return "inno";
    case ToolInstallKind::nsis: return "nsis";
    case ToolInstallKind::msi: return "msi";
    case ToolInstallKind::archive: break;
  }
  return "archive";
}

[[maybe_unused]] bool kind_executes_installer(ToolInstallKind kind) {
  return kind != ToolInstallKind::archive;
}

std::string trim_copy(const std::string& value) {
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos)
    return {};
  const auto last = value.find_last_not_of(" \t\r\n");
  return value.substr(first, last - first + 1);
}

std::string filename_from_url(const std::string& url) {
  const auto query = url.find_first_of("?#");
  const std::string path = query == std::string::npos ? url : url.substr(0, query);
  const auto slash = path.find_last_of('/');
  std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
  for (char& character : name) {
    const unsigned char code = static_cast<unsigned char>(character);
    if (std::isalnum(code) == 0 && character != '.' && character != '-' && character != '_')
      character = '_';
  }
  if (name.empty())
    return "download.bin";
  return name;
}

std::filesystem::path sources_config_path(const std::filesystem::path& destination_root) {
  return destination_root / "tool-sources.ini";
}

const std::string& compiled_sources_text();

// A minimal INI reader over the compiled sources text.
std::string read_ini_value(const std::string& text,
                           const std::string& section,
                           const std::string& key) {
  std::istringstream input(text);
  const std::string want_section = ascii_lower(section);
  const std::string want_key = ascii_lower(key);
  std::string current;
  std::string line;
  while (std::getline(input, line)) {
    const std::string trimmed = trim_copy(line);
    if (trimmed.empty() || trimmed.front() == ';' || trimmed.front() == '#')
      continue;
    if (trimmed.front() == '[' && trimmed.back() == ']') {
      current = ascii_lower(trim_copy(trimmed.substr(1, trimmed.size() - 2)));
      continue;
    }
    if (current != want_section)
      continue;
    const auto equals = trimmed.find('=');
    if (equals == std::string::npos)
      continue;
    if (ascii_lower(trim_copy(trimmed.substr(0, equals))) != want_key)
      continue;
    std::string value = trim_copy(trimmed.substr(equals + 1));
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
      value = value.substr(1, value.size() - 2);
    return value;
  }
  return {};
}

std::optional<ToolSource> load_source_from_config(const std::string& id) {
  const std::string& text = compiled_sources_text();
  ToolSource source;
  source.url = read_ini_value(text, id, "Url");
  if (source.url.empty())
    return std::nullopt;
  source.signer = read_ini_value(text, id, "Signer");
  source.sha256 = ascii_lower(read_ini_value(text, id, "Sha256"));
  source.filename = read_ini_value(text, id, "Filename");
  source.archive = read_ini_value(text, id, "Archive");
  for (const std::string& part : split(read_ini_value(text, id, "Extract"), ',')) {
    const std::string prefix = trim(part);
    if (!prefix.empty())
      source.extract.push_back(prefix);
  }
  source.kind = parse_install_kind(read_ini_value(text, id, "Kind"));
  if (source.filename.empty())
    source.filename = filename_from_url(source.url);
  return source;
}

// The compiled sources override the catalog's own URL. Without an entry there, whatever the catalog
// carries (always the archive kind) is used.
ToolSource resolve_tool_source(const ExternalToolDefinition& definition,
                               const std::filesystem::path& destination_root) {
  static_cast<void>(destination_root);
  if (auto configured = load_source_from_config(definition.id)) {
    if (configured->extract.empty())
      configured->extract = definition.download_extract;
    return *configured;
  }
  ToolSource source;
  source.extract = definition.download_extract;
  source.url = definition.download_url;
  source.filename = definition.download_filename.empty() ? filename_from_url(definition.download_url)
                                                         : definition.download_filename;
  source.archive = definition.download_archive;
  source.kind = ToolInstallKind::archive;
  return source;
}

// The download sources, compiled into SAT: a tool's link, its expected publisher and how it installs
// are part of the build and never read from a file beside it, so a new link takes a new build.
const std::string& compiled_sources_text() {
  static const std::string sources = [] {
    std::ostringstream out;
    out <<
      "; " << kProductName << " -- managed tool download sources, compiled into SAT\n"
      ";\n"
      "; SAT reads each tool's Url, expected code-signing publisher (Signer), install Kind and the\n"
      "; parts of its archive to unpack (Extract) from here.\n"
      ";\n"
      "; Locked-down execution -- this cannot be turned into a way to run arbitrary code:\n"
      ";   * Downloads must be HTTPS.\n"
      ";   * For an installer Kind (portableapps/inno/nsis/msi) SAT verifies the download is signed by a\n"
      ";     trusted publisher AND that the signer matches Signer= below before it runs anything.\n"
      ";   * The silent command line and the install folder are fixed inside SAT, never taken from\n"
      ";     this file. Editing this file cannot change what command is run.\n"
      ";\n"
      "; Kind values:\n"
      ";   archive       download an archive (zip/tar) and extract it; nothing is executed. Every\n"
      ";                 program in it (.exe, .dll, .sys) must be signed by one of the publishers in\n"
      ";                 Signer= (exact names, separated by |) before it is moved into the Tools\n"
      ";                 folder; for a tool whose publisher signs nothing, the download must match\n"
      ";                 Sha256= before it is unpacked.\n"
      ";   msi           a Windows Installer package, unpacked by msiexec /a into the Tools folder.\n"
      ";                 Nothing is installed or registered, and no administrator is needed.\n"
      ";   portableapps  a PortableApps.com .paf.exe. Its installer opens with the Tools folder filled\n"
      ";                 in, to be finished there: a PortableApps.com installer runs unattended only\n"
      ";                 from the PortableApps.com Platform.\n"
      ";   inno          an Inno Setup installer, run with /VERYSILENT into the Tools folder.\n"
      ";   nsis          an NSIS installer, run with /S into the Tools folder (path must have no\n"
      ";                 spaces -- an NSIS limitation).\n"
      ";\n"
      "; Confirm every Url and Signer against the vendor's official download page before relying on\n"
      "; it. The values below are starting points only.\n"
      "\n"
      "[wireshark]\n"
      "; The stable release's Windows Installer package, signed by the Wireshark Foundation, which SAT\n"
      "; verifies before unpacking it into the Tools folder. The version is pinned because Wireshark's\n"
      "; \"latest\" files are the development release; change the version in the Url for a newer stable\n"
      "; release (wireshark.org/download.html names it). A live capture also needs Npcap, installed\n"
      "; separately.\n"
      "Kind=msi\n"
      "Signer=Wireshark Foundation\n"
      "Url=https://www.wireshark.org/download/win64/all-versions/Wireshark-4.6.9-x64.msi\n"
      "\n"
      "[iperf3]\n"
      "; iPerf3's Windows build is not signed: the pinned 3.1.3 zip is checked by its SHA-256.\n"
      "Kind=archive\n"
      "Sha256=3c3db693c1bdcc902ca9198fc716339373658233b3392ffe3d467f7695762cd1\n"
      "Url=https://iperf.fr/download/windows/iperf-3.1.3-win64.zip\n"
      "\n"
      "[etl2pcapng]\n"
      "; GitHub's /releases/latest/download/<asset> redirects to the newest release, so this always\n"
      "; fetches the current build without a version-pinned URL. The release ships a bare\n"
      "; etl2pcapng.exe (no .zip); a non-archive, non-installer download is placed directly in the\n"
      "; Tools folder without extracting or running.\n"
      "Kind=archive\n"
      "Signer=Microsoft Corporation\n"
      "Url=https://github.com/microsoft/etl2pcapng/releases/latest/download/etl2pcapng.exe\n"
      "\n"
      "[procmon]\n"
      "Kind=archive\n"
      "Signer=Microsoft Corporation\n"
      "Url=https://download.sysinternals.com/files/ProcessMonitor.zip\n"
      "\n"
      "[diskspd]\n"
      "; The Disk Speed Test's engine. The release zip holds a build per processor (amd64, arm64);\n"
      "; SAT checks Microsoft's signature on diskspd.exe each time before it runs it.\n"
      "Kind=archive\n"
      "Signer=Microsoft Windows|Microsoft Corporation\n"
      "Url=https://github.com/microsoft/diskspd/releases/latest/download/DiskSpd.ZIP\n"
      "\n"
      "[vsstrace]\n"
      "; Microsoft's VSS Trace, signed by Microsoft, from Veeam's storage.\n"
      "Kind=archive\n"
      "Signer=Microsoft Corporation\n"
      "Url=https://storage.veeam.com/utils/Vsstrace.zip\n"
      "\n"
      "; Database clients are normally DETECTED from an existing install (a Veeam server already has\n"
      "; PostgreSQL, and SQL client tools ship with SQL Server). These URLs are the download fallback\n"
      "; for a machine that has neither.\n"
      "[sqlcmd]\n"
      "; /releases/latest/download keeps this on the newest go-sqlcmd without a version-pinned URL.\n"
      "Kind=archive\n"
      "Signer=Microsoft Corporation\n"
      "Url=https://github.com/microsoft/go-sqlcmd/releases/latest/download/sqlcmd-windows-amd64.zip\n"
      "\n"
      "[psql]\n"
      "Kind=archive\n"
      "; The EnterpriseDB binaries zip is the whole server with pgAdmin 4 (about 320 MiB to download,\n"
      "; 920 MiB unpacked). Extract= unpacks only pgsql/bin, psql and the libraries it loads (about\n"
      "; 71 MiB). psql.exe also needs the Microsoft Visual C++ 2015-2022 runtime (vcruntime140.dll).\n"
      "; EnterpriseDB signs neither the zip nor its programs: the pinned 16.4-1 zip is checked by its\n"
      "; SHA-256.\n"
      "Extract=pgsql/bin/\n"
      "Sha256=3508d8f085bc3980f38211a82e3f31e5fcae9952105d3dc2f8be67b64a822baa\n"
      "Url=https://get.enterprisedb.com/postgresql/postgresql-16.4-1-windows-x64-binaries.zip\n";
    return out.str();
  }();
  return sources;
}

#ifdef _WIN32
bool safe_relative_path(const std::filesystem::path& value) {
  if (value.empty() || value.is_absolute() || value.has_root_name() || value.has_root_directory())
    return false;
  for (const auto& component : value) {
    if (component == "..")
      return false;
  }
  return true;
}

std::string sanitize_version(std::string value) {
  if (value.empty())
    return "latest";
  for (char& character : value) {
    const unsigned char code = static_cast<unsigned char>(character);
    if (std::isalnum(code) == 0 && character != '.' && character != '-' && character != '_')
      character = '_';
  }
  return value;
}


struct InternetHandle {
  HINTERNET value = nullptr;
  InternetHandle() = default;
  explicit InternetHandle(HINTERNET input) : value(input) {}
  ~InternetHandle() {
    if (value != nullptr)
      WinHttpCloseHandle(value);
  }
  InternetHandle(const InternetHandle&) = delete;
  InternetHandle& operator=(const InternetHandle&) = delete;
};

Result<std::filesystem::path> download_https(const std::string& source_url,
                                             const std::string& download_filename,
                                             const std::string& display_name,
                                             const std::filesystem::path& directory,
                                             const CancellationToken& cancel,
                                             ProgressCallback progress) {
  if (!source_url.starts_with("https://")) {
    return Result<std::filesystem::path>::failure(tool_download_error(
        "validate download URL", "Automatic downloads require HTTPS", source_url));
  }

  const std::wstring url = wide_from_utf8(source_url);
  URL_COMPONENTSW components{};
  components.dwStructSize = sizeof(components);
  components.dwSchemeLength = static_cast<DWORD>(-1);
  components.dwHostNameLength = static_cast<DWORD>(-1);
  components.dwUrlPathLength = static_cast<DWORD>(-1);
  components.dwExtraInfoLength = static_cast<DWORD>(-1);
  if (WinHttpCrackUrl(url.c_str(), 0, 0, &components) == FALSE) {
    return Result<std::filesystem::path>::failure(tool_download_error(
        "parse download URL", "WinHttpCrackUrl failed", source_url, GetLastError()));
  }

  const std::wstring host(components.lpszHostName, components.dwHostNameLength);
  std::wstring path(components.lpszUrlPath, components.dwUrlPathLength);
  if (components.dwExtraInfoLength != 0U)
    path.append(components.lpszExtraInfo, components.dwExtraInfoLength);

  const std::wstring user_agent = wide_from_utf8(std::string(kExecutableName) + "/" +
                                                    std::string(kVersion));
  InternetHandle session(WinHttpOpen(user_agent.c_str(),
                                     WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS,
                                     0));
  if (session.value == nullptr) {
    return Result<std::filesystem::path>::failure(tool_download_error(
        "open HTTP session", "WinHttpOpen failed", source_url, GetLastError()));
  }
  // Generous receive timeout so a large tool (the PostgreSQL binaries zip is a few hundred MB) on a
  // slow link is not abandoned mid-download.
  WinHttpSetTimeouts(session.value, 15000, 15000, 30000, 120000);

  InternetHandle connection(WinHttpConnect(session.value, host.c_str(), components.nPort, 0));
  if (connection.value == nullptr) {
    return Result<std::filesystem::path>::failure(tool_download_error(
        "connect", "WinHttpConnect failed", source_url, GetLastError()));
  }

  InternetHandle request(WinHttpOpenRequest(connection.value,
                                            L"GET",
                                            path.c_str(),
                                            nullptr,
                                            WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            WINHTTP_FLAG_SECURE));
  if (request.value == nullptr) {
    return Result<std::filesystem::path>::failure(tool_download_error(
        "create request", "WinHttpOpenRequest failed", source_url, GetLastError()));
  }
  DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
  WinHttpSetOption(request.value,
                   WINHTTP_OPTION_REDIRECT_POLICY,
                   &redirect_policy,
                   sizeof(redirect_policy));
  if (WinHttpSendRequest(request.value,
                         WINHTTP_NO_ADDITIONAL_HEADERS,
                         0,
                         WINHTTP_NO_REQUEST_DATA,
                         0,
                         0,
                         0) == FALSE ||
      WinHttpReceiveResponse(request.value, nullptr) == FALSE) {
    return Result<std::filesystem::path>::failure(tool_download_error(
        "download", "The HTTPS request failed", source_url, GetLastError()));
  }

  DWORD status = 0;
  DWORD status_size = sizeof(status);
  if (WinHttpQueryHeaders(request.value,
                          WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                          WINHTTP_HEADER_NAME_BY_INDEX,
                          &status,
                          &status_size,
                          WINHTTP_NO_HEADER_INDEX) == FALSE ||
      status < 200U || status >= 300U) {
    std::string detail = "The server returned HTTP status " + std::to_string(status);
    if (status == 404U || status == 403U || status == 410U)
      detail += " - the download link is likely out of date. Place the tool in the Tools folder by hand "
                "(Integrations > Open tools folder); a newer SAT build carries the new link.";
    return Result<std::filesystem::path>::failure(
        tool_download_error("download", detail, source_url));
  }

  std::uint64_t total_bytes = 0;
  wchar_t content_length[64]{};
  DWORD length_size = sizeof(content_length);
  if (WinHttpQueryHeaders(request.value,
                          WINHTTP_QUERY_CONTENT_LENGTH,
                          WINHTTP_HEADER_NAME_BY_INDEX,
                          content_length,
                          &length_size,
                          WINHTTP_NO_HEADER_INDEX) != FALSE) {
    try {
      total_bytes = std::stoull(content_length);
    } catch (...) {
      total_bytes = 0;
    }
  }
  constexpr std::uint64_t maximum_download = 1024ULL * 1024ULL * 1024ULL;
  if (total_bytes > maximum_download) {
    return Result<std::filesystem::path>::failure(tool_download_error(
        "download", "The advertised download exceeds the 1 GiB safety limit", source_url));
  }

  std::error_code directory_error;
  std::filesystem::create_directories(directory, directory_error);
  if (directory_error) {
    return Result<std::filesystem::path>::failure(tool_download_error(
        "create download directory", directory_error.message(), path_to_utf8(directory)));
  }
  const std::filesystem::path output = directory / download_filename;
  std::ofstream stream(output, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return Result<std::filesystem::path>::failure(
        tool_download_error("create download", "Unable to create the download file", path_to_utf8(output)));
  }

  std::vector<unsigned char> buffer(64U * 1024U);
  std::uint64_t downloaded = 0;
  const auto started = std::chrono::steady_clock::now();
  // The first read reports at once; after that, ten reports a second at most (see below).
  auto last_report = started - std::chrono::seconds(1);
  for (;;) {
    if (cancel.is_cancelled()) {
      stream.close();
      std::filesystem::remove(output, directory_error);
      return Result<std::filesystem::path>::failure(
          tool_download_error("download", "Download cancelled", source_url));
    }
    DWORD available = 0;
    if (WinHttpQueryDataAvailable(request.value, &available) == FALSE) {
      return Result<std::filesystem::path>::failure(tool_download_error(
          "download", "WinHttpQueryDataAvailable failed", source_url, GetLastError()));
    }
    if (available == 0U)
      break;
    while (available != 0U) {
      const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(buffer.size(), available));
      DWORD read = 0;
      if (WinHttpReadData(request.value, buffer.data(), requested, &read) == FALSE) {
        return Result<std::filesystem::path>::failure(tool_download_error(
            "download", "WinHttpReadData failed", source_url, GetLastError()));
      }
      if (read == 0U)
        break;
      stream.write(reinterpret_cast<const char*>(buffer.data()), read);
      if (!stream) {
        return Result<std::filesystem::path>::failure(
            tool_download_error("download", "Writing the download failed", path_to_utf8(output)));
      }
      downloaded += read;
      if (downloaded > maximum_download) {
        return Result<std::filesystem::path>::failure(tool_download_error(
            "download", "The download exceeded the 1 GiB safety limit", source_url));
      }
      available -= read;
      // A read can be a few kilobytes, so a report per read is thousands a second. A tenth of a
      // second apart is as fast as anyone reads, and the read that completes the file reports.
      const auto now = std::chrono::steady_clock::now();
      if (progress && (now - last_report >= std::chrono::milliseconds(100) ||
                       (total_bytes != 0U && downloaded >= total_bytes))) {
        last_report = now;
        const double elapsed = std::chrono::duration<double>(now - started).count();
        progress(ProgressEvent{"optional-tool-download",
                               display_name,
                               downloaded,
                               0,
                               elapsed,
                               elapsed > 0.0 ? static_cast<double>(downloaded) / elapsed : 0.0,
                               total_bytes});
      }
    }
  }
  stream.close();
  return Result<std::filesystem::path>::success(output);
}

Result<std::string> sha256_file(const std::filesystem::path& path) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD object_size = 0;
  DWORD output_size = 0;
  DWORD returned = 0;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
      BCryptGetProperty(algorithm,
                        BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&object_size),
                        sizeof(object_size),
                        &returned,
                        0) < 0 ||
      BCryptGetProperty(algorithm,
                        BCRYPT_HASH_LENGTH,
                        reinterpret_cast<PUCHAR>(&output_size),
                        sizeof(output_size),
                        &returned,
                        0) < 0) {
    if (algorithm != nullptr)
      BCryptCloseAlgorithmProvider(algorithm, 0);
    return Result<std::string>::failure(
        tool_download_error("hash download", "Unable to initialize SHA-256", path_to_utf8(path)));
  }
  std::vector<unsigned char> object(object_size);
  std::vector<unsigned char> digest(output_size);
  if (BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0) < 0) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return Result<std::string>::failure(
        tool_download_error("hash download", "Unable to create SHA-256 context", path_to_utf8(path)));
  }
  std::ifstream input(path, std::ios::binary);
  std::vector<unsigned char> buffer(64U * 1024U);
  while (input) {
    input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
    const auto count = input.gcount();
    if (count > 0 && BCryptHashData(hash, buffer.data(), static_cast<ULONG>(count), 0) < 0) {
      BCryptDestroyHash(hash);
      BCryptCloseAlgorithmProvider(algorithm, 0);
      return Result<std::string>::failure(
          tool_download_error("hash download", "Unable to hash download data", path_to_utf8(path)));
    }
  }
  if (BCryptFinishHash(hash, digest.data(), output_size, 0) < 0) {
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return Result<std::string>::failure(
        tool_download_error("hash download", "Unable to finish SHA-256", path_to_utf8(path)));
  }
  BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  std::ostringstream encoded;
  encoded << std::hex << std::setfill('0');
  for (unsigned char byte : digest)
    encoded << std::setw(2) << static_cast<unsigned int>(byte);
  return Result<std::string>::success(encoded.str());
}

std::string executable_version(const std::filesystem::path& path) {
  DWORD ignored = 0;
  const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
  if (size == 0U)
    return {};
  std::vector<unsigned char> data(size);
  if (GetFileVersionInfoW(path.c_str(), 0, size, data.data()) == FALSE)
    return {};
  VS_FIXEDFILEINFO* info = nullptr;
  UINT info_size = 0;
  if (VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &info_size) == FALSE ||
      info == nullptr || info_size < sizeof(VS_FIXEDFILEINFO)) {
    return {};
  }
  std::ostringstream version;
  version << HIWORD(info->dwFileVersionMS) << '.' << LOWORD(info->dwFileVersionMS) << '.'
          << HIWORD(info->dwFileVersionLS) << '.' << LOWORD(info->dwFileVersionLS);
  return version.str();
}

std::string hex_status(LONG status) {
  std::ostringstream out;
  out << "0x" << std::hex << std::setw(8) << std::setfill('0')
      << static_cast<unsigned long>(static_cast<ULONG>(status));
  return out.str();
}

// Read the Authenticode signer subject (the publisher common name) from a signed file.
std::string authenticode_signer_subject(const std::filesystem::path& file) {
  const std::wstring path = file.wstring();
  HCERTSTORE store = nullptr;
  HCRYPTMSG message = nullptr;
  DWORD encoding = 0;
  DWORD content_type = 0;
  DWORD format_type = 0;
  if (CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                       path.c_str(),
                       CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                       CERT_QUERY_FORMAT_FLAG_BINARY,
                       0,
                       &encoding,
                       &content_type,
                       &format_type,
                       &store,
                       &message,
                       nullptr) == FALSE) {
    return {};
  }
  auto close_all = [&] {
    if (message != nullptr)
      CryptMsgClose(message);
    if (store != nullptr)
      CertCloseStore(store, 0);
  };

  DWORD signer_size = 0;
  if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signer_size) == FALSE ||
      signer_size == 0) {
    close_all();
    return {};
  }
  std::vector<unsigned char> signer_buffer(signer_size);
  if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, signer_buffer.data(), &signer_size) ==
      FALSE) {
    close_all();
    return {};
  }
  const auto* signer = reinterpret_cast<const CMSG_SIGNER_INFO*>(signer_buffer.data());
  CERT_INFO cert_info{};
  cert_info.Issuer = signer->Issuer;
  cert_info.SerialNumber = signer->SerialNumber;
  PCCERT_CONTEXT cert = CertFindCertificateInStore(store,
                                                   encoding,
                                                   0,
                                                   CERT_FIND_SUBJECT_CERT,
                                                   &cert_info,
                                                   nullptr);
  if (cert == nullptr) {
    close_all();
    return {};
  }
  const DWORD length =
      CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
  std::wstring subject;
  if (length > 1) {
    subject.resize(length);
    CertGetNameStringW(cert,
                       CERT_NAME_SIMPLE_DISPLAY_TYPE,
                       0,
                       nullptr,
                       subject.data(),
                       length);
    if (!subject.empty() && subject.back() == L'\0')
      subject.pop_back();
  }
  CertFreeCertificateContext(cert);
  close_all();
  return utf8_from_wide(subject);
}

// Run a verified installer silently. The argument line and the destination are FIXED here and keyed
// only by the install kind -- neither comes from the config file. The installer is confined to the
// destination folder inside the managed Tools directory.
Status run_silent_installer(const std::filesystem::path& installer,
                            const std::filesystem::path& destination,
                            ToolInstallKind kind) {
  std::error_code error;
  std::filesystem::create_directories(destination, error);
  if (error) {
    return Status::failure(
        tool_download_error("install", error.message(), path_to_utf8(destination)));
  }

  const std::wstring dest = destination.wstring();
  std::filesystem::path program = installer;
  std::wstring arguments;
  // An installer that waits for the engineer gets longer than one that runs unattended.
  DWORD install_timeout_ms = 5U * 60U * 1000U;
  switch (kind) {
    case ToolInstallKind::portableapps:
      // PortableApps.com Installer: /DESTINATION fills in the folder and /AUTOCLOSE closes it at the
      // end. Its wizard still opens: it runs unattended only from the PortableApps.com Platform.
      arguments = L"/DESTINATION=\"" + dest + L"\\\" /AUTOCLOSE=true";
      install_timeout_ms = 15U * 60U * 1000U;
      break;
    case ToolInstallKind::msi: {
      // Windows Installer's administrative install unpacks the package's files under TARGETDIR and
      // installs and registers nothing. msiexec comes from the system directory only.
      wchar_t system_directory[MAX_PATH]{};
      const UINT length = GetSystemDirectoryW(system_directory, MAX_PATH);
      if (length == 0 || length >= MAX_PATH)
        return Status::failure(tool_download_error("install", "The Windows system directory could not be read",
                                                   path_to_utf8(installer), GetLastError()));
      program = std::filesystem::path(system_directory) / L"msiexec.exe";
      arguments = L"/a \"" + installer.wstring() + L"\" /qn TARGETDIR=\"" + dest + L"\"";
      break;
    }
    case ToolInstallKind::inno:
      arguments = L"/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR=\"" + dest + L"\"";
      break;
    case ToolInstallKind::nsis:
      // NSIS /D must be the last switch and cannot be quoted, so it cannot carry a path with spaces.
      arguments = L"/S /D=" + dest;
      break;
    case ToolInstallKind::archive:
    default:
      return Status::failure(tool_download_error(
          "install", "This install kind does not run an installer", path_to_utf8(installer)));
  }

  std::wstring command_line = L"\"" + program.wstring() + L"\" " + arguments;
  std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
  mutable_command.push_back(L'\0');

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  if (CreateProcessW(program.wstring().c_str(),
                     mutable_command.data(),
                     nullptr,
                     nullptr,
                     FALSE,
                     CREATE_NO_WINDOW,
                     nullptr,
                     dest.c_str(),
                     &startup,
                     &process) == FALSE) {
    const DWORD start_error = GetLastError();
    if (start_error == ERROR_ELEVATION_REQUIRED)
      return Status::failure(tool_download_error(
          "install",
          "The installer needs administrator rights and would install into the system. Use the "
          "tool's MSI or portable build (Kind=msi, archive or portableapps), or run SAT as administrator.",
          path_to_utf8(installer), start_error));
    return Status::failure(tool_download_error(
        "install", "Unable to start the installer", path_to_utf8(installer), start_error));
  }
  CloseHandle(process.hThread);
  const DWORD wait = WaitForSingleObject(process.hProcess, install_timeout_ms);
  if (wait != WAIT_OBJECT_0) {
    TerminateProcess(process.hProcess, 1);
    CloseHandle(process.hProcess);
    return Status::failure(tool_download_error(
        "install",
        "The installer did not finish within " + std::to_string(install_timeout_ms / 60000U) + " minutes",
        path_to_utf8(installer)));
  }
  DWORD exit_code = 0;
  GetExitCodeProcess(process.hProcess, &exit_code);
  CloseHandle(process.hProcess);
  // msiexec reports 3010 when a restart would finish an install; an unpacked package needs none.
  if (kind == ToolInstallKind::msi && exit_code == ERROR_SUCCESS_REBOOT_REQUIRED)
    exit_code = 0;
  if (exit_code != 0U) {
    return Status::failure(tool_download_error(
        "install", "The installer reported failure (exit code " + std::to_string(exit_code) + ")",
        path_to_utf8(installer), static_cast<std::int64_t>(exit_code)));
  }
  return Status::success();
}

#endif

#if defined(_WIN32) && defined(SUPPORT_ASSIST_HAS_LIBARCHIVE)
Result<std::vector<std::filesystem::path>> extract_archive(const std::filesystem::path& archive_path,
                                                           const std::filesystem::path& destination,
                                                           const std::vector<std::string>& wanted,
                                                           const CancellationToken& cancel,
                                                           ProgressCallback progress) {
  struct ArchiveReader {
    archive* value = archive_read_new();
    ~ArchiveReader() {
      if (value != nullptr)
        archive_read_free(value);
    }
  } reader;
  if (reader.value == nullptr)
    return Result<std::vector<std::filesystem::path>>::failure(
        tool_download_error("extract", "Unable to allocate archive reader", path_to_utf8(archive_path)));
  archive_read_support_filter_all(reader.value);
  archive_read_support_format_all(reader.value);
#ifdef _WIN32
  // libarchive reads a narrow filename through the ANSI code page on Windows, so a UTF-8
  // name with any non-ANSI character opens the wrong file or none at all. Every other
  // archive open in the product takes the _w variant; this one was missed.
  if (archive_read_open_filename_w(reader.value, archive_path.wstring().c_str(), 64 * 1024) !=
      ARCHIVE_OK) {
#else
  if (archive_read_open_filename(reader.value, path_to_utf8(archive_path).c_str(), 64 * 1024) !=
      ARCHIVE_OK) {
#endif
    return Result<std::vector<std::filesystem::path>>::failure(tool_download_error(
        "extract", archive_error_string(reader.value), path_to_utf8(archive_path)));
  }

  std::vector<std::filesystem::path> files;
  std::uint64_t expanded = 0;
  std::uint64_t entries = 0;
  std::uint64_t scanned = 0;
  constexpr std::uint64_t maximum_expanded = 2ULL * 1024ULL * 1024ULL * 1024ULL;
  // The limits apply to what is unpacked; entries passed over are only read past, up to a bound.
  constexpr std::uint64_t maximum_entries = 20000;
  constexpr std::uint64_t maximum_scanned = 1000000;
  archive_entry* entry = nullptr;
  while (archive_read_next_header(reader.value, &entry) == ARCHIVE_OK) {
    if (cancel.is_cancelled()) {
      return Result<std::vector<std::filesystem::path>>::failure(
          tool_download_error("extract", "Extraction cancelled", path_to_utf8(archive_path)));
    }
    if (++scanned > maximum_scanned) {
      return Result<std::vector<std::filesystem::path>>::failure(tool_download_error(
          "extract", "Archive exceeds the 1,000,000-entry safety limit", path_to_utf8(archive_path)));
    }
    const char* raw_name = archive_entry_pathname_utf8(entry);
    if (raw_name == nullptr)
      raw_name = archive_entry_pathname(entry);
    if (!tool_download_detail::archive_entry_wanted(raw_name != nullptr ? raw_name : "", wanted)) {
      archive_read_data_skip(reader.value);
      continue;
    }
    if (++entries > maximum_entries) {
      return Result<std::vector<std::filesystem::path>>::failure(tool_download_error(
          "extract", "Archive exceeds the 20,000-entry safety limit", path_to_utf8(archive_path)));
    }
    const std::filesystem::path relative = raw_name != nullptr ? std::filesystem::path(raw_name)
                                                               : std::filesystem::path{};
    if (!safe_relative_path(relative)) {
      return Result<std::vector<std::filesystem::path>>::failure(tool_download_error(
          "extract", "Archive contains an unsafe path", path_to_utf8(relative)));
    }
    if (archive_entry_filetype(entry) == AE_IFLNK || archive_entry_filetype(entry) == AE_IFSOCK) {
      archive_read_data_skip(reader.value);
      continue;
    }
    const std::filesystem::path output = destination / relative;
    std::error_code error;
    if (archive_entry_filetype(entry) == AE_IFDIR) {
      std::filesystem::create_directories(output, error);
      if (error) {
        return Result<std::vector<std::filesystem::path>>::failure(
            tool_download_error("extract", error.message(), path_to_utf8(output)));
      }
      continue;
    }
    std::filesystem::create_directories(output.parent_path(), error);
    if (error) {
      return Result<std::vector<std::filesystem::path>>::failure(
          tool_download_error("extract", error.message(), path_to_utf8(output.parent_path())));
    }
    std::ofstream stream(output, std::ios::binary | std::ios::trunc);
    if (!stream) {
      return Result<std::vector<std::filesystem::path>>::failure(
          tool_download_error("extract", "Unable to create extracted file", path_to_utf8(output)));
    }
    std::vector<char> buffer(64U * 1024U);
    for (;;) {
      const la_ssize_t read = archive_read_data(reader.value, buffer.data(), buffer.size());
      if (read == 0)
        break;
      if (read < 0) {
        return Result<std::vector<std::filesystem::path>>::failure(tool_download_error(
            "extract", archive_error_string(reader.value), path_to_utf8(archive_path)));
      }
      expanded += static_cast<std::uint64_t>(read);
      if (expanded > maximum_expanded) {
        return Result<std::vector<std::filesystem::path>>::failure(tool_download_error(
            "extract", "Archive exceeds the 2 GiB expanded-size safety limit", path_to_utf8(archive_path)));
      }
      stream.write(buffer.data(), read);
      if (!stream) {
        return Result<std::vector<std::filesystem::path>>::failure(
            tool_download_error("extract", "Unable to write extracted file", path_to_utf8(output)));
      }
    }
    files.push_back(output);
    if (progress) {
      progress(ProgressEvent{"optional-tool-extract",
                             path_to_utf8(relative),
                             entries,
                             0,
                             0.0,
                             0.0});
    }
  }
  return Result<std::vector<std::filesystem::path>>::success(std::move(files));
}
#endif

} // namespace

// The gate that keeps the installer-execution download from becoming an attack vector: prove the
// file is signed by a trusted publisher AND that the signer matches the publisher named in the
// editable config. A trust-chain failure or a publisher mismatch refuses execution; only an
// inability to REACH revocation servers is downgraded to a warning (a segmented support network must
// not block a validly signed installer).
DownloadPublisherCheck verify_installer_publisher(const std::filesystem::path& installer,
                                                  const std::string& expected_signer) {
  DownloadPublisherCheck result;
#ifndef _WIN32
  static_cast<void>(installer);
  static_cast<void>(expected_signer);
  result.failure = "Publisher verification is only available in the Windows build.";
  return result;
#else
  const std::wstring path = installer.wstring();

  WINTRUST_FILE_INFO file_info{};
  file_info.cbStruct = sizeof(file_info);
  file_info.pcwszFilePath = path.c_str();

  WINTRUST_DATA trust{};
  trust.cbStruct = sizeof(trust);
  trust.dwUIChoice = WTD_UI_NONE;
  trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
  trust.dwUnionChoice = WTD_CHOICE_FILE;
  trust.pFile = &file_info;
  trust.dwStateAction = WTD_STATEACTION_VERIFY;
  trust.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN | WTD_SAFER_FLAG;

  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  const LONG status = WinVerifyTrust(nullptr, &action, &trust);
  trust.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &action, &trust);

  if (status == ERROR_SUCCESS) {
    result.trusted = true;
  } else if (status == CERT_E_REVOCATION_FAILURE ||
             static_cast<DWORD>(status) == CRYPT_E_REVOCATION_OFFLINE ||
             static_cast<DWORD>(status) == CRYPT_E_NO_REVOCATION_CHECK) {
    // The chain validated but a revocation server was unreachable. Accept with a recorded warning.
    result.trusted = true;
    result.warning = "The download's certificate chain is valid but its revocation status could not "
                     "be checked (" + hex_status(status) + ").";
  } else {
    result.failure = "The download is not signed by a trusted publisher (WinVerifyTrust " +
                     hex_status(status) + ").";
    return result;
  }

  result.signer_subject = authenticode_signer_subject(installer);
  if (result.signer_subject.empty()) {
    result.trusted = false;
    result.failure = "The download's signer could not be read.";
    return result;
  }
  if (!expected_signer.empty() &&
      ascii_lower(result.signer_subject).find(ascii_lower(expected_signer)) == std::string::npos) {
    result.trusted = false;
    result.failure = "The download is signed by \"" + result.signer_subject +
                     "\" but the configured publisher is \"" + expected_signer +
                     "\". SAT will not run an installer from an unexpected publisher.";
  }
  return result;
#endif
}

namespace tool_download_detail {

std::string download_check(std::string_view tool_id) {
  const auto source = load_source_from_config(std::string(tool_id));
  if (!source)
    return {};
  if (!source->sha256.empty())
    return "SHA-256";
  return source->signer;
}

Status verify_archive_programs(const std::vector<std::filesystem::path>& files, const std::string& signers,
                               const std::string& url, std::string& publisher, std::vector<std::string>& warnings) {
  std::vector<std::string> accepted;
  for (const std::string& name : split(signers, '|')) {
    const std::string trimmed = trim(name);
    if (!trimmed.empty())
      accepted.push_back(ascii_lower(trimmed));
  }
  std::size_t checked = 0;
  for (const auto& file : files) {
    const std::string extension = ascii_lower(path_to_utf8(file.extension()));
    if (extension != ".exe" && extension != ".dll" && extension != ".sys")
      continue;
    const std::string name = path_to_utf8(file.filename());
    const DownloadPublisherCheck verdict = verify_installer_publisher(file, "");
    if (!verdict.trusted)
      return Status::failure(tool_download_error(
          "verify publisher", name + " in the download: " + verdict.failure +
                                  " Nothing from the download was placed in the Tools folder.",
          url));
    if (std::find(accepted.begin(), accepted.end(), ascii_lower(verdict.signer_subject)) == accepted.end())
      return Status::failure(tool_download_error(
          "verify publisher", name + " in the download is signed by \"" + verdict.signer_subject +
                                  "\", not by " + signers +
                                  ". Nothing from the download was placed in the Tools folder.",
          url));
    if (!verdict.warning.empty() && std::find(warnings.begin(), warnings.end(), verdict.warning) == warnings.end())
      warnings.push_back(verdict.warning);
    if (publisher.empty())
      publisher = verdict.signer_subject;
    ++checked;
  }
  if (checked == 0)
    return Status::failure(tool_download_error(
        "verify publisher",
        "The download holds no program to check against its publisher, so nothing from it was placed in the "
        "Tools folder.",
        url));
  return Status::success();
}

} // namespace tool_download_detail

Result<ExternalToolInstallResult>
install_external_tool(const ExternalToolInstallOptions& options,
                      const CancellationToken& cancel,
                      ProgressCallback progress) {
  write_debug_log("ToolDownload", "Install requested for " + options.tool_id);
  const ExternalToolDefinition* definition = find_definition(options.tool_id);
  if (definition == nullptr) {
    return Result<ExternalToolInstallResult>::failure(
        tool_download_error("install", "Unknown optional tool", options.tool_id));
  }
  if (options.destination_root.empty()) {
    return Result<ExternalToolInstallResult>::failure(
        tool_download_error("install", "A destination Tools folder is required", definition->name));
  }
  // The source: the compiled download sources, else the catalog's own URL.
  const ToolSource source = resolve_tool_source(*definition, options.destination_root);
  if (source.url.empty()) {
    write_debug_log("ToolDownload", "No download source configured for " + options.tool_id);
    return Result<ExternalToolInstallResult>::failure(tool_download_error(
        "install",
        "SAT has no download link for this tool. Place it in the Tools folder by hand, from its "
        "official source page.",
        definition->source_url));
  }
#ifndef _WIN32
  static_cast<void>(cancel);
  static_cast<void>(progress);
  // The locked-down downloader (WinHTTP + Authenticode) is Windows-only. On Linux the tool is almost
  // always already installed (detected in place) or belongs to the distribution's package manager, so
  // point there rather than failing opaquely.
  return Result<ExternalToolInstallResult>::failure(tool_download_error(
      "install",
      "Install " + definition->name +
          " with your package manager (e.g. apt install / dnf install), or from its official page; "
          "SAT then detects it in place. The managed download is available on the Windows build.",
      definition->source_url));
#else
  const std::filesystem::path staging =
      options.destination_root / ".downloads" / (definition->id + "-" + make_uuid_v4());
  std::error_code error;
  std::filesystem::create_directories(staging, error);
  if (error) {
    return Result<ExternalToolInstallResult>::failure(
        tool_download_error("install", error.message(), path_to_utf8(staging)));
  }
  auto cleanup = [&] { std::filesystem::remove_all(staging, error); };
  auto downloaded = download_https(source.url, source.filename, definition->name, staging, cancel, progress);
  if (!downloaded.ok()) {
    write_debug_log("ToolDownload", "Download failed for " + options.tool_id + ": " +
                                        describe_error(downloaded.error()));
    cleanup();
    return Result<ExternalToolInstallResult>::failure(downloaded.error());
  }
  auto digest = sha256_file(downloaded.value());
  if (!digest.ok()) {
    cleanup();
    return Result<ExternalToolInstallResult>::failure(digest.error());
  }

  // A download whose publisher signs nothing is checked against the SHA-256 this build pins, before
  // it is unpacked.
  if (!kind_executes_installer(source.kind) && !source.sha256.empty() && ascii_lower(digest.value()) != source.sha256) {
    write_debug_log("ToolDownload", "SHA-256 check refused " + options.tool_id + ": " + digest.value());
    cleanup();
    return Result<ExternalToolInstallResult>::failure(tool_download_error(
        "verify download",
        "The download's SHA-256 is " + digest.value() + ", not the " + source.sha256 +
            " this build of SAT expects, so it was not unpacked.",
        source.url));
  }

  std::vector<std::string> warnings;
  std::string verified_publisher;
  bool executed_installer = false;
  const std::filesystem::path extracted = staging / "content";
  std::vector<std::filesystem::path> installed;

  if (kind_executes_installer(source.kind)) {
    // Locked-down execution. Nothing runs unless it is signed by a trusted publisher AND the signer
    // matches the publisher named in the config; the command line and destination are fixed above.
    if (source.signer.empty()) {
      cleanup();
      return Result<ExternalToolInstallResult>::failure(tool_download_error(
          "install",
          std::string("The configured install kind (") + install_kind_name(source.kind) +
              ") runs an installer, but SAT has no expected publisher for it, so the installer is not "
              "run.",
          source.url));
    }
    const DownloadPublisherCheck verdict = verify_installer_publisher(downloaded.value(), source.signer);
    if (!verdict.trusted) {
      write_debug_log("ToolDownload", "Authenticode check refused " + options.tool_id + ": " +
                                          verdict.failure);
      cleanup();
      return Result<ExternalToolInstallResult>::failure(tool_download_error(
          "verify publisher", verdict.failure, source.url));
    }
    verified_publisher = verdict.signer_subject;
    if (!verdict.warning.empty())
      warnings.push_back(verdict.warning);

    const Status ran = run_silent_installer(downloaded.value(), extracted, source.kind);
    if (!ran.ok()) {
      cleanup();
      return Result<ExternalToolInstallResult>::failure(ran.error());
    }
    executed_installer = true;
    for (std::filesystem::recursive_directory_iterator
             iterator(extracted, std::filesystem::directory_options::skip_permission_denied, error),
         end;
         iterator != end && !error;
         iterator.increment(error)) {
      if (iterator->is_regular_file(error))
        installed.push_back(iterator->path());
    }
    error.clear();
    if (installed.empty()) {
      cleanup();
      return Result<ExternalToolInstallResult>::failure(tool_download_error(
          "install", "The installer completed but produced no files in the Tools folder", source.url));
    }
  } else if (source.archive == "zip" || source.archive == "tar" || source.archive == "tar.gz" ||
             (source.archive.empty() && ascii_lower(path_to_utf8(downloaded.value().extension())) == ".zip")) {
#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
    auto result = extract_archive(downloaded.value(), extracted, source.extract, cancel, progress);
    if (!result.ok()) {
      cleanup();
      return Result<ExternalToolInstallResult>::failure(result.error());
    }
    installed = std::move(result.value());
    if (installed.empty() && !source.extract.empty()) {
      cleanup();
      std::string parts;
      for (const std::string& prefix : source.extract)
        parts += (parts.empty() ? "" : ", ") + prefix;
      return Result<ExternalToolInstallResult>::failure(tool_download_error(
          "extract", "The archive has nothing under " + parts + ", the part SAT unpacks", source.url));
    }
#else
    cleanup();
    return Result<ExternalToolInstallResult>::failure(tool_download_error(
        "extract", "This build does not include archive extraction support", definition->name));
#endif
  } else {
    std::filesystem::create_directories(extracted, error);
    const std::filesystem::path target = extracted / downloaded.value().filename();
    std::filesystem::copy_file(downloaded.value(), target, std::filesystem::copy_options::overwrite_existing, error);
    if (error) {
      cleanup();
      return Result<ExternalToolInstallResult>::failure(
          tool_download_error("install", error.message(), path_to_utf8(target)));
    }
    installed.push_back(target);
  }

  // An archive's programs are checked in the staging folder, before anything moves into Tools.
  if (!kind_executes_installer(source.kind)) {
    if (!source.signer.empty()) {
      const Status signed_by = tool_download_detail::verify_archive_programs(installed, source.signer, source.url, verified_publisher, warnings);
      if (!signed_by.ok()) {
        write_debug_log("ToolDownload", "Authenticode check refused " + options.tool_id + ": " +
                                            signed_by.error().message);
        cleanup();
        return Result<ExternalToolInstallResult>::failure(signed_by.error());
      }
    } else if (source.sha256.empty()) {
      warnings.push_back("This download has no publisher signature or pinned SHA-256 to check it against; its "
                         "SHA-256 is recorded in the tool's manifest.");
    }
  }

  std::string version;
  for (const auto& file : installed) {
    const std::string extension = ascii_lower(path_to_utf8(file.extension()));
    if (extension == ".exe") {
      version = executable_version(file);
      if (!version.empty())
        break;
    }
  }
  version = sanitize_version(version.empty() ? "latest" : version);
  const std::filesystem::path final_directory = options.destination_root / definition->id / version;
  if (std::filesystem::exists(final_directory, error)) {
    if (!options.replace_existing_version) {
      cleanup();
      return Result<ExternalToolInstallResult>::failure(tool_download_error(
          "install", "The detected version is already installed", path_to_utf8(final_directory)));
    }
    std::filesystem::remove_all(final_directory, error);
    if (error) {
      cleanup();
      return Result<ExternalToolInstallResult>::failure(
          tool_download_error("install", error.message(), path_to_utf8(final_directory)));
    }
  }
  std::filesystem::create_directories(final_directory.parent_path(), error);
  std::filesystem::rename(extracted, final_directory, error);
  if (error) {
    cleanup();
    return Result<ExternalToolInstallResult>::failure(
        tool_download_error("install", error.message(), path_to_utf8(final_directory)));
  }

  std::vector<std::filesystem::path> final_files;
  for (const auto& file : installed) {
    const auto relative = std::filesystem::relative(file, extracted, error);
    if (!error)
      final_files.push_back(final_directory / relative);
    error.clear();
  }
  std::ofstream manifest(final_directory / "support-assist-tool-manifest.txt",
                         std::ios::binary | std::ios::trunc);
  manifest << "Tool ID: " << definition->id << '\n'
           << "Tool Name: " << definition->name << '\n'
           << "Version: " << version << '\n'
           << "Install kind: " << install_kind_name(source.kind) << '\n'
           << "Source URL: " << source.url << '\n'
           << "Downloaded UTC: " << utc_now_iso8601() << '\n'
           << "SHA-256: " << digest.value() << '\n'
           << "Installer executed: " << (executed_installer ? "Yes" : "No") << '\n';
  if (!verified_publisher.empty())
    manifest << "Verified publisher: " << verified_publisher << '\n';
  if (!source.sha256.empty())
    manifest << "Pinned SHA-256: matched" << '\n';
  manifest.close();
  cleanup();
  // An update replaces the earlier versions SAT installed, so the tool that runs is this one.
  for (std::string& warning :
       tool_download_detail::remove_earlier_versions(options.destination_root / definition->id, final_directory))
    warnings.push_back(std::move(warning));

  ExternalToolInstallResult result;
  result.tool_id = definition->id;
  result.tool_name = definition->name;
  result.version = version;
  result.source_url = source.url;
  result.sha256 = digest.value();
  result.verified_publisher = verified_publisher;
  result.executed_installer = executed_installer;
  result.installed_directory = final_directory;
  result.installed_files = std::move(final_files);
  result.warnings = std::move(warnings);
  write_debug_log("ToolDownload", "Installed " + definition->id + " to " +
                                      path_to_utf8(final_directory) +
                                      (executed_installer ? " (installer verified: " + verified_publisher + ")" : ""));
  return Result<ExternalToolInstallResult>::success(std::move(result));
#endif
}

Status remove_managed_external_tool(std::string_view tool_id,
                                    const std::filesystem::path& destination_root) {
  write_debug_log("ToolDownload", "Remove requested for " + std::string(tool_id));
  const ExternalToolDefinition* definition = find_definition(tool_id);
  if (definition == nullptr)
    return Status::failure(tool_download_error("remove", "Unknown optional tool", std::string(tool_id)));
  const std::filesystem::path directory = destination_root / definition->id;
  std::error_code error;
  if (!std::filesystem::exists(directory, error))
    return Status::success();
  bool managed = false;
  for (std::filesystem::recursive_directory_iterator iterator(
           directory, std::filesystem::directory_options::skip_permission_denied, error),
       end;
       iterator != end && !error;
       iterator.increment(error)) {
    const auto filename = iterator->path().filename();
    if (filename == "support-assist-tool-manifest.txt" ||
        filename == "support-assis-tool-manifest.txt") {
      managed = true;
      break;
    }
  }
  if (!managed) {
    return Status::failure(tool_download_error(
        "remove",
        "The folder does not contain a " + std::string(kProductName) +
          " download manifest and will not be deleted automatically.",
        path_to_utf8(directory)));
  }
  std::filesystem::remove_all(directory, error);
  if (error)
    return Status::failure(tool_download_error("remove", error.message(), path_to_utf8(directory)));
  return Status::success();
}

std::filesystem::path tool_sources_config_path(const std::filesystem::path& destination_root) {
  return sources_config_path(destination_root);
}

std::vector<std::string> tool_extract_paths(std::string_view tool_id, const std::filesystem::path& destination_root) {
  const ExternalToolDefinition* definition = find_definition(tool_id);
  if (definition == nullptr)
    return {};
  return resolve_tool_source(*definition, destination_root).extract;
}

std::vector<std::string> tool_download_detail::remove_earlier_versions(const std::filesystem::path& tool_folder,
                                                                       const std::filesystem::path& keep) {
  std::vector<std::filesystem::path> earlier;
  std::error_code error;
  for (std::filesystem::directory_iterator entry(tool_folder, std::filesystem::directory_options::skip_permission_denied,
                                                 error),
       end;
       !error && entry != end; entry.increment(error)) {
    std::error_code kind_error;
    if (!entry->is_directory(kind_error) || entry->path() == keep)
      continue;
    // Only what SAT installed: its manifest is in the version's folder.
    std::error_code manifest_error;
    if (std::filesystem::is_regular_file(entry->path() / "support-assist-tool-manifest.txt", manifest_error))
      earlier.push_back(entry->path());
  }
  std::vector<std::string> warnings;
  for (const std::filesystem::path& folder : earlier) {
    std::error_code remove_error;
    std::filesystem::remove_all(folder, remove_error);
    if (remove_error)
      warnings.push_back("The earlier version in " + path_to_utf8(folder) +
                         " could not be removed: " + remove_error.message());
  }
  return warnings;
}

bool tool_download_detail::archive_entry_wanted(std::string_view entry, const std::vector<std::string>& prefixes) {
  if (prefixes.empty())
    return true;
  std::string name = ascii_lower(entry);
  std::replace(name.begin(), name.end(), '\\', '/');
  while (name.rfind("./", 0) == 0)
    name.erase(0, 2);
  for (const std::string& prefix : prefixes) {
    std::string wanted = ascii_lower(prefix);
    std::replace(wanted.begin(), wanted.end(), '\\', '/');
    if (!wanted.empty() && name.rfind(wanted, 0) == 0)
      return true;
  }
  return false;
}

bool tool_supports_locked_down_download(std::string_view tool_id,
                                        const std::filesystem::path& destination_root) {
  const ExternalToolDefinition* definition = find_definition(tool_id);
  if (definition == nullptr)
    return false;
  static_cast<void>(destination_root);
  // The compiled sources win; otherwise the catalog's own URL still counts.
  if (auto configured = load_source_from_config(definition->id))
    return !configured->url.empty();
  return !definition->download_url.empty();
}

} // namespace support_assist
