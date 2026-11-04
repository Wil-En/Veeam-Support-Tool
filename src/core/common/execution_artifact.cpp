#include "support_assist/execution_artifact.hpp"

#include "support_assist/log_collection.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <sstream>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/utsname.h>
#endif

namespace support_assist {
namespace {

// Minimal readers for the manifest shape SAT itself writes. Deliberately not a general JSON parser:
// the same local-helper approach is already used to read case.json in src/core/case/case_workspace.cpp,
// and pulling a JSON dependency into Core for one fixed, self-authored schema is not worth the cost.
std::string extract_artifact_json_string(std::string_view json, std::string_view key) {
  const std::string marker = "\"" + std::string(key) + "\"";
  const std::size_t key_position = json.find(marker);
  if (key_position == std::string_view::npos) return {};
  const std::size_t colon = json.find(':', key_position + marker.size());
  if (colon == std::string_view::npos) return {};
  const std::size_t quote = json.find('"', colon + 1U);
  if (quote == std::string_view::npos) return {};
  std::string result;
  bool escaped = false;
  for (std::size_t index = quote + 1U; index < json.size(); ++index) {
    const char c = json[index];
    if (escaped) {
      switch (c) {
      case 'n': result.push_back('\n'); break;
      case 'r': result.push_back('\r'); break;
      case 't': result.push_back('\t'); break;
      case '\\': result.push_back('\\'); break;
      case '"': result.push_back('"'); break;
      default: result.push_back(c); break;
      }
      escaped = false;
    } else if (c == '\\') {
      escaped = true;
    } else if (c == '"') {
      return result;
    } else {
      result.push_back(c);
    }
  }
  return result;
}

std::uint64_t extract_artifact_json_uint(std::string_view json, std::string_view key) {
  const std::string marker = "\"" + std::string(key) + "\"";
  const std::size_t key_position = json.find(marker);
  if (key_position == std::string_view::npos) return 0U;
  const std::size_t colon = json.find(':', key_position + marker.size());
  if (colon == std::string_view::npos) return 0U;
  std::uint64_t value = 0U;
  bool any = false;
  for (std::size_t index = colon + 1U; index < json.size(); ++index) {
    const unsigned char c = static_cast<unsigned char>(json[index]);
    if (std::isdigit(c) != 0) {
      any = true;
      // Saturate rather than overflow on a hostile or corrupt size field.
      if (value > (std::numeric_limits<std::uint64_t>::max() - 9U) / 10U)
        return std::numeric_limits<std::uint64_t>::max();
      value = value * 10U + static_cast<std::uint64_t>(c - '0');
    } else if (any || c == ',' || c == '}') {
      break;
    } else if (std::isspace(c) == 0) {
      break;
    }
  }
  return value;
}

Error artifact_error(std::string operation,
                     const std::filesystem::path& source,
                     std::string message,
                     std::int64_t native_code = 0) {
  Error error;
  error.component = "ExecutionArtifact";
  error.operation = std::move(operation);
  error.source = path_to_utf8(source);
  error.native_code = native_code;
  error.message = std::move(message);
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

std::string machine_name() {
#ifdef _WIN32
  wchar_t buffer[256]{};
  DWORD length = static_cast<DWORD>(std::size(buffer));
  if (GetComputerNameW(buffer, &length))
    return utf8_from_wide(std::wstring_view(buffer, length));
  return "unknown-host";
#else
  utsname info{};
  if (uname(&info) == 0)
    return info.nodename;
  return "unknown-host";
#endif
}

std::string safe_token(std::string_view value, std::string_view fallback) {
  std::string output;
  output.reserve(value.size());
  bool previous_dash = false;
  for (unsigned char c : value) {
    const bool valid = std::isalnum(c) != 0 || c == '.' || c == '_' || c == '-';
    const char next = valid ? static_cast<char>(c) : '-';
    if (next == '-') {
      if (previous_dash)
        continue;
      previous_dash = true;
    } else {
      previous_dash = false;
    }
    output.push_back(next);
  }
  while (!output.empty() && (output.front() == '-' || output.front() == '.'))
    output.erase(output.begin());
  while (!output.empty() && (output.back() == '-' || output.back() == '.'))
    output.pop_back();
  return output.empty() ? std::string(fallback) : output;
}

std::string compact_timestamp() {
  std::string value = utc_now_iso8601();
  for (char& c : value) {
    if (c == ':' || c == ' ')
      c = '-';
  }
  return safe_token(value, "timestamp");
}

std::string json_escape(std::string_view value) {
  std::ostringstream output;
  for (unsigned char c : value) {
    switch (c) {
    case '\\': output << "\\\\"; break;
    case '"': output << "\\\""; break;
    case '\b': output << "\\b"; break;
    case '\f': output << "\\f"; break;
    case '\n': output << "\\n"; break;
    case '\r': output << "\\r"; break;
    case '\t': output << "\\t"; break;
    default:
      if (c < 0x20U) {
        output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
               << static_cast<unsigned int>(c) << std::dec;
      } else {
        output << static_cast<char>(c);
      }
      break;
    }
  }
  return output.str();
}

constexpr std::string_view kArtifactStateFile = "tool-state.txt";
constexpr std::string_view kLegacyArtifactStateFile = "artifact-state.txt";

Status write_artifact_state(const ExecutionArtifactManifest& artifact,
                            std::string_view state,
                            std::string_view detail = {}) {
  const std::filesystem::path path = artifact.root / kArtifactStateFile;
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(artifact_error("write artifact state", path,
                                          "Unable to create tool-state.txt"));
  output << "SAT_EXECUTION_ARTIFACT_STATE\t1\n"
         << "state\t" << state << "\n"
         << "updated_utc\t" << utc_now_iso8601() << "\n"
         << "artifact_id\t" << artifact.artifact_id << "\n"
         << "tool\t" << artifact.tool_name << "\n";
  if (!detail.empty())
    output << "detail\t" << detail << "\n";
  output.flush();
  if (!output)
    return Status::failure(artifact_error("write artifact state", path,
                                          "Artifact state write failed"));
  return Status::success();
}

std::string read_artifact_state(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    return {};
  std::string line;
  while (std::getline(input, line)) {
    if (line.rfind("state\t", 0) == 0)
      return line.substr(6U);
  }
  return {};
}

// Small self-contained SHA-256 implementation used for support-artifact manifests.
// This keeps evidence hashing available in portable validation builds without adding
// another runtime dependency.
class Sha256 {
public:
  void update(const std::uint8_t* data, std::size_t length) {
    for (std::size_t i = 0; i < length; ++i) {
      buffer_[buffer_size_++] = data[i];
      bit_length_ += 8U;
      if (buffer_size_ == 64U) {
        transform(buffer_.data());
        buffer_size_ = 0;
      }
    }
  }

  std::array<std::uint8_t, 32> finish() {
    const std::uint64_t original_bits = bit_length_;
    buffer_[buffer_size_++] = 0x80U;
    if (buffer_size_ > 56U) {
      while (buffer_size_ < 64U)
        buffer_[buffer_size_++] = 0;
      transform(buffer_.data());
      buffer_size_ = 0;
    }
    while (buffer_size_ < 56U)
      buffer_[buffer_size_++] = 0;
    for (int shift = 56; shift >= 0; shift -= 8)
      buffer_[buffer_size_++] = static_cast<std::uint8_t>((original_bits >> shift) & 0xffU);
    transform(buffer_.data());

    std::array<std::uint8_t, 32> digest{};
    for (std::size_t i = 0; i < state_.size(); ++i) {
      digest[i * 4U] = static_cast<std::uint8_t>((state_[i] >> 24U) & 0xffU);
      digest[i * 4U + 1U] = static_cast<std::uint8_t>((state_[i] >> 16U) & 0xffU);
      digest[i * 4U + 2U] = static_cast<std::uint8_t>((state_[i] >> 8U) & 0xffU);
      digest[i * 4U + 3U] = static_cast<std::uint8_t>(state_[i] & 0xffU);
    }
    return digest;
  }

private:
  static constexpr std::array<std::uint32_t, 64> k_{
      0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
      0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
      0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
      0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
      0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
      0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
      0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
      0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};

  static std::uint32_t rotr(std::uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32U - bits));
  }

  void transform(const std::uint8_t* block) {
    std::array<std::uint32_t, 64> words{};
    for (std::size_t i = 0; i < 16U; ++i) {
      words[i] = (static_cast<std::uint32_t>(block[i * 4U]) << 24U) |
                 (static_cast<std::uint32_t>(block[i * 4U + 1U]) << 16U) |
                 (static_cast<std::uint32_t>(block[i * 4U + 2U]) << 8U) |
                 static_cast<std::uint32_t>(block[i * 4U + 3U]);
    }
    for (std::size_t i = 16U; i < words.size(); ++i) {
      const std::uint32_t s0 = rotr(words[i - 15U], 7U) ^ rotr(words[i - 15U], 18U) ^
                               (words[i - 15U] >> 3U);
      const std::uint32_t s1 = rotr(words[i - 2U], 17U) ^ rotr(words[i - 2U], 19U) ^
                               (words[i - 2U] >> 10U);
      words[i] = words[i - 16U] + s0 + words[i - 7U] + s1;
    }

    std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (std::size_t i = 0; i < words.size(); ++i) {
      const std::uint32_t s1 = rotr(e, 6U) ^ rotr(e, 11U) ^ rotr(e, 25U);
      const std::uint32_t choice = (e & f) ^ ((~e) & g);
      const std::uint32_t temp1 = h + s1 + choice + k_[i] + words[i];
      const std::uint32_t s0 = rotr(a, 2U) ^ rotr(a, 13U) ^ rotr(a, 22U);
      const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t temp2 = s0 + majority;
      h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }
    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
  }

  std::array<std::uint32_t, 8> state_{
      0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
      0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t buffer_size_ = 0;
  std::uint64_t bit_length_ = 0;
};

Result<std::string> sha256_file(const std::filesystem::path& path,
                                const CancellationToken& cancel) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    return Result<std::string>::failure(artifact_error("hash file", path, "Unable to open file"));
  Sha256 hash;
  // Keep the large streaming buffer on the heap. Windows worker/test threads may
  // have a ~1 MiB stack, so a 1 MiB local array can overflow before hashing starts.
  constexpr std::size_t kHashReadBufferBytes = 1024U * 1024U;
  std::vector<std::uint8_t> buffer(kHashReadBufferBytes);
  while (input) {
    if (cancel.is_cancelled())
      return Result<std::string>::failure(artifact_error("hash file", path, "Cancelled"));
    input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
    const std::streamsize count = input.gcount();
    if (count > 0)
      hash.update(buffer.data(), static_cast<std::size_t>(count));
  }
  if (!input.eof())
    return Result<std::string>::failure(artifact_error("hash file", path, "Read failed"));
  const auto digest = hash.finish();
  std::ostringstream text;
  text << std::hex << std::setfill('0');
  for (const std::uint8_t value : digest)
    text << std::setw(2) << static_cast<unsigned int>(value);
  return Result<std::string>::success(text.str());
}

Status write_manifest(const ExecutionArtifactManifest& artifact) {
  std::ofstream output(artifact.manifest_path, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(artifact_error("write manifest", artifact.manifest_path,
                                          "Unable to create manifest"));
  output << "{\n"
         << "  \"schema\": 1,\n"
         << "  \"artifact_id\": \"" << json_escape(artifact.artifact_id) << "\",\n"
         << "  \"tool\": \"" << json_escape(artifact.tool_name) << "\",\n"
         << "  \"host\": \"" << json_escape(artifact.host_name) << "\",\n"
         << "  \"started_utc\": \"" << json_escape(artifact.started_utc) << "\",\n"
         << "  \"completed_utc\": \"" << json_escape(artifact.completed_utc) << "\",\n"
         << "  \"execution_status\": \"" << to_string(artifact.execution_status) << "\",\n"
         << "  \"diagnostic_status\": \"" << to_string(artifact.diagnostic_status) << "\",\n"
         << "  \"summary\": \"" << json_escape(artifact.summary) << "\",\n"
         << "  \"files\": [\n";
  for (std::size_t i = 0; i < artifact.files.size(); ++i) {
    const auto& file = artifact.files[i];
    output << "    {\"path\":\"" << json_escape(support_assist::generic_path_to_utf8(file.relative_path))
           << "\",\"size\":" << file.size_bytes
           << ",\"sha256\":\"" << file.sha256 << "\"}";
    if (i + 1U != artifact.files.size())
      output << ',';
    output << '\n';
  }
  output << "  ]\n}\n";
  output.flush();
  if (!output)
    return Status::failure(artifact_error("write manifest", artifact.manifest_path,
                                          "Manifest write failed"));
  return Status::success();
}

} // namespace

std::string to_string(ExecutionStatus status) {
  switch (status) {
  case ExecutionStatus::completed: return "Completed";
  case ExecutionStatus::failed: return "Failed";
  case ExecutionStatus::cancelled: return "Cancelled";
  case ExecutionStatus::unavailable: return "Unavailable";
  }
  return "Failed";
}

std::string to_string(DiagnosticStatus status) {
  switch (status) {
  case DiagnosticStatus::pass: return "Pass";
  case DiagnosticStatus::finding: return "Finding";
  case DiagnosticStatus::neutral: return "Neutral";
  case DiagnosticStatus::not_applicable: return "Not Applicable";
  case DiagnosticStatus::unknown: return "Unknown";
  }
  return "Unknown";
}

Result<ExecutionStatus> parse_execution_status(std::string_view value) {
  const std::string folded = ascii_lower(trim(value));
  if (folded == "completed") return Result<ExecutionStatus>::success(ExecutionStatus::completed);
  if (folded == "failed") return Result<ExecutionStatus>::success(ExecutionStatus::failed);
  if (folded == "cancelled" || folded == "canceled")
    return Result<ExecutionStatus>::success(ExecutionStatus::cancelled);
  if (folded == "unavailable") return Result<ExecutionStatus>::success(ExecutionStatus::unavailable);
  return Result<ExecutionStatus>::failure(
      artifact_error("parse execution status", {}, "Unknown execution status: " + std::string(value)));
}

Result<DiagnosticStatus> parse_diagnostic_status(std::string_view value) {
  const std::string folded = ascii_lower(trim(value));
  if (folded == "pass") return Result<DiagnosticStatus>::success(DiagnosticStatus::pass);
  if (folded == "finding") return Result<DiagnosticStatus>::success(DiagnosticStatus::finding);
  if (folded == "neutral") return Result<DiagnosticStatus>::success(DiagnosticStatus::neutral);
  if (folded == "not applicable" || folded == "not_applicable")
    return Result<DiagnosticStatus>::success(DiagnosticStatus::not_applicable);
  if (folded == "unknown") return Result<DiagnosticStatus>::success(DiagnosticStatus::unknown);
  return Result<DiagnosticStatus>::failure(
      artifact_error("parse diagnostic status", {}, "Unknown diagnostic status: " + std::string(value)));
}

Result<ExecutionArtifactManifest>
read_execution_artifact_manifest(const std::filesystem::path& manifest_path) {
  std::error_code exists_error;
  if (!std::filesystem::is_regular_file(manifest_path, exists_error))
    return Result<ExecutionArtifactManifest>::failure(
        artifact_error("read artifact manifest", manifest_path, "Manifest file does not exist"));

  std::string text;
  {
    std::ifstream input(manifest_path, std::ios::binary);
    if (!input)
      return Result<ExecutionArtifactManifest>::failure(
          artifact_error("read artifact manifest", manifest_path, "Unable to open manifest"));
    // Manifests are small and SAT-authored. Bound the read anyway: this parser may be pointed at a
    // customer-supplied bundle, and an unbounded read of an arbitrary file is the same defect class
    // that SAT-SEC-01 fixed in the log reader.
    constexpr std::streamsize kMaximumManifestBytes = 4 * 1024 * 1024;
    std::ostringstream buffer;
    std::array<char, 8192> chunk{};
    std::streamsize total = 0;
    while (input.read(chunk.data(), static_cast<std::streamsize>(chunk.size())) || input.gcount() > 0) {
      const std::streamsize got = input.gcount();
      total += got;
      if (total > kMaximumManifestBytes)
        return Result<ExecutionArtifactManifest>::failure(artifact_error(
            "read artifact manifest", manifest_path, "Manifest exceeds the 4 MiB bound"));
      buffer.write(chunk.data(), got);
    }
    text = buffer.str();
  }

  ExecutionArtifactManifest manifest;
  manifest.artifact_id = extract_artifact_json_string(text, "artifact_id");
  manifest.tool_name = extract_artifact_json_string(text, "tool");
  manifest.host_name = extract_artifact_json_string(text, "host");
  manifest.started_utc = extract_artifact_json_string(text, "started_utc");
  manifest.completed_utc = extract_artifact_json_string(text, "completed_utc");
  manifest.summary = extract_artifact_json_string(text, "summary");
  manifest.manifest_path = manifest_path;
  manifest.root = manifest_path.parent_path();
  manifest.hashes_path = manifest.root / "SHA256SUMS.txt";

  // A manifest without a tool name is not a SAT execution artifact. Refuse rather than inventing
  // an empty tool, so a directory that merely happens to contain a manifest.json is skipped.
  if (manifest.tool_name.empty())
    return Result<ExecutionArtifactManifest>::failure(artifact_error(
        "read artifact manifest", manifest_path, "Manifest has no tool name; not a SAT artifact"));

  if (const auto status = parse_execution_status(extract_artifact_json_string(text, "execution_status"));
      status.ok())
    manifest.execution_status = status.value();
  if (const auto status = parse_diagnostic_status(extract_artifact_json_string(text, "diagnostic_status"));
      status.ok())
    manifest.diagnostic_status = status.value();

  // The files array is a flat list of {"path","size","sha256"} objects. Walk it positionally rather
  // than pulling a general JSON parser into Core for one known, SAT-authored shape.
  const std::size_t files_key = text.find("\"files\"");
  if (files_key != std::string::npos) {
    std::size_t cursor = files_key;
    while (true) {
      const std::size_t entry = text.find("\"path\"", cursor);
      if (entry == std::string::npos) break;
      const std::string_view remainder(text.data() + entry, text.size() - entry);
      ExecutionArtifactFile file;
      file.relative_path = std::filesystem::path(extract_artifact_json_string(remainder, "path"));
      file.sha256 = extract_artifact_json_string(remainder, "sha256");
      file.size_bytes = extract_artifact_json_uint(remainder, "size");
      if (!file.relative_path.empty()) manifest.files.push_back(std::move(file));
      cursor = entry + 6U;
    }
  }
  return Result<ExecutionArtifactManifest>::success(std::move(manifest));
}

Result<std::vector<ExecutionArtifactManifest>>
discover_execution_artifacts(const std::filesystem::path& root) {
  std::vector<ExecutionArtifactManifest> found;
  std::error_code exists_error;
  if (!std::filesystem::is_directory(root, exists_error))
    return Result<std::vector<ExecutionArtifactManifest>>::failure(
        artifact_error("discover artifacts", root, "Source is not a directory"));

  std::error_code walk_error;
  std::filesystem::recursive_directory_iterator iterator(
      root, std::filesystem::directory_options::skip_permission_denied, walk_error);
  if (walk_error)
    return Result<std::vector<ExecutionArtifactManifest>>::failure(
        artifact_error("discover artifacts", root, walk_error.message()));

  const std::filesystem::recursive_directory_iterator end;
  for (; iterator != end; iterator.increment(walk_error)) {
    if (walk_error) break;
    const auto& entry = iterator->path();
    if (entry.filename() != "manifest.json") continue;
    // A manifest that does not parse, or belongs to something else, is skipped rather than
    // failing the whole scan: one unreadable directory must not cost the engineer every other
    // tool result in the bundle.
    if (auto manifest = read_execution_artifact_manifest(entry); manifest.ok())
      found.push_back(std::move(manifest).value());
  }

  std::stable_sort(found.begin(), found.end(),
                   [](const ExecutionArtifactManifest& left, const ExecutionArtifactManifest& right) {
                     if (left.started_utc != right.started_utc)
                       return left.started_utc < right.started_utc;
                     return left.tool_name < right.tool_name;
                   });
  return Result<std::vector<ExecutionArtifactManifest>>::success(std::move(found));
}

std::string tool_folder_name(std::string_view tool_title) {
  std::string name = safe_token(tool_title, "Tool");
  if (name.size() > kToolFolderNameLimit) {
    const std::size_t dash = name.rfind('-', kToolFolderNameLimit);
    name.resize(dash != std::string::npos && dash >= kToolFolderNameLimit / 2 ? dash : kToolFolderNameLimit);
    while (!name.empty() && (name.back() == '-' || name.back() == '.'))
      name.pop_back();
  }
  return name.empty() ? std::string("Tool") : name;
}

Result<ExecutionArtifactManifest>
begin_execution_artifact(const std::filesystem::path& base_directory,
                         std::string_view tool_name) {
  if (base_directory.empty())
    return Result<ExecutionArtifactManifest>::failure(
        artifact_error("create artifact", {}, "An artifact base directory is required"));
  ExecutionArtifactManifest artifact;
  artifact.artifact_id = make_uuid_v4();
  artifact.tool_name = tool_name.empty() ? "Support Assist operation" : std::string(tool_name);
  artifact.host_name = machine_name();
  artifact.started_utc = utc_now_iso8601();
  const std::string short_id = artifact.artifact_id.substr(0, std::min<std::size_t>(8U, artifact.artifact_id.size()));
  // The on-disk implementation is still an ExecutionArtifact, but the transfer
  // identity must tell an engineer what tool produced it at a glance.
  const std::string directory_name = safe_token(artifact.host_name, "unknown-host") + "-SAT-" +
                                     (tool_name.empty() ? std::string("operation") : tool_folder_name(tool_name)) + "-" +
                                     compact_timestamp() + "-" + short_id;
  artifact.root = base_directory / directory_name;
  artifact.manifest_path = artifact.root / "manifest.json";
  artifact.hashes_path = artifact.root / "SHA256SUMS.txt";
  std::error_code error;
  std::filesystem::create_directories(artifact.root, error);
  if (error)
    return Result<ExecutionArtifactManifest>::failure(
        artifact_error("create artifact", artifact.root, error.message(), error.value()));
  if (auto state = write_artifact_state(artifact, "Running"); !state.ok()) {
    std::error_code remove_error;
    std::filesystem::remove_all(artifact.root, remove_error);
    return Result<ExecutionArtifactManifest>::failure(state.error());
  }
  return Result<ExecutionArtifactManifest>::success(std::move(artifact));
}

Result<std::size_t>
recover_interrupted_execution_artifacts(const std::filesystem::path& base_directory) {
  std::error_code error;
  if (base_directory.empty() || !std::filesystem::exists(base_directory, error))
    return Result<std::size_t>::success(0U);
  if (error)
    return Result<std::size_t>::failure(
        artifact_error("recover artifacts", base_directory, error.message(), error.value()));

  std::size_t recovered = 0U;
  std::filesystem::recursive_directory_iterator iterator(
      base_directory, std::filesystem::directory_options::skip_permission_denied, error);
  const std::filesystem::recursive_directory_iterator end;
  for (; iterator != end; iterator.increment(error)) {
    if (error) {
      error.clear();
      continue;
    }
    if (!iterator->is_directory(error)) {
      error.clear();
      continue;
    }
    const std::filesystem::path root = iterator->path();
    std::filesystem::path state_path = root / kArtifactStateFile;
    if (!std::filesystem::exists(state_path, error)) {
      error.clear();
      const std::filesystem::path legacy = root / kLegacyArtifactStateFile;
      if (!std::filesystem::exists(legacy, error)) {
        error.clear();
        continue;
      }
      state_path = legacy;
    }
    const std::string previous = read_artifact_state(state_path);
    if (previous != "Running" && previous != "Finalizing")
      continue;

    ExecutionArtifactManifest artifact;
    artifact.root = root;
    artifact.artifact_id = support_assist::path_to_utf8(root.filename());
    artifact.tool_name = "Unknown (recovered)";
    if (auto state = write_artifact_state(artifact, "Interrupted",
                                          "Previous state: " + previous); !state.ok())
      return Result<std::size_t>::failure(state.error());
    ++recovered;
  }
  return Result<std::size_t>::success(recovered);
}

Status write_execution_artifact_text(const ExecutionArtifactManifest& artifact,
                                     std::string_view relative_name,
                                     std::string_view text) {
  if (relative_name.empty())
    return Status::failure(artifact_error("write artifact file", artifact.root,
                                          "A relative file name is required"));
  const std::filesystem::path relative(relative_name);
  bool escapes_root = relative.is_absolute() || relative.has_root_name() || relative.has_root_directory();
  for (const auto& component : relative) {
    if (component == "..") {
      escapes_root = true;
      break;
    }
  }
  if (escapes_root)
    return Status::failure(artifact_error("write artifact file", relative,
                                          "Artifact files must stay beneath the artifact root"));
  const std::filesystem::path output_path = artifact.root / relative.lexically_normal();
  std::error_code error;
  std::filesystem::create_directories(output_path.parent_path(), error);
  if (error)
    return Status::failure(artifact_error("create artifact directory", output_path.parent_path(),
                                          error.message(), error.value()));
  std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(artifact_error("write artifact file", output_path,
                                          "Unable to create file"));
  output.write(text.data(), static_cast<std::streamsize>(text.size()));
  output.flush();
  if (!output)
    return Status::failure(artifact_error("write artifact file", output_path,
                                          "Artifact write failed"));
  return Status::success();
}

Status finalize_execution_artifact(ExecutionArtifactManifest& artifact,
                                   ExecutionStatus execution_status,
                                   DiagnosticStatus diagnostic_status,
                                   std::string summary,
                                   const CancellationToken& cancel) {
  artifact.execution_status = execution_status;
  artifact.diagnostic_status = diagnostic_status;
  artifact.summary = std::move(summary);
  artifact.completed_utc.clear();
  artifact.files.clear();

  if (auto state = write_artifact_state(artifact, "Finalizing"); !state.ok())
    return state;

  std::error_code error;
  for (std::filesystem::recursive_directory_iterator
           iterator(artifact.root, std::filesystem::directory_options::skip_permission_denied, error), end;
       iterator != end; iterator.increment(error)) {
    if (cancel.is_cancelled())
      return Status::failure(artifact_error("finalize artifact", artifact.root, "Cancelled"));
    if (error) {
      error.clear();
      continue;
    }
    if (!iterator->is_regular_file(error)) {
      error.clear();
      continue;
    }
    const std::filesystem::path path = iterator->path();
    if (path == artifact.manifest_path || path == artifact.hashes_path ||
        (path.filename() == kArtifactStateFile || path.filename() == kLegacyArtifactStateFile))
      continue;
    auto digest = sha256_file(path, cancel);
    if (!digest.ok())
      return Status::failure(digest.error());
    ExecutionArtifactFile file;
    file.relative_path = std::filesystem::relative(path, artifact.root, error);
    if (error) {
      error.clear();
      file.relative_path = path.filename();
    }
    file.size_bytes = iterator->file_size(error);
    if (error) {
      error.clear();
      file.size_bytes = 0;
    }
    file.sha256 = std::move(digest.value());
    artifact.files.push_back(std::move(file));
  }
  std::sort(artifact.files.begin(), artifact.files.end(), [](const auto& left, const auto& right) {
    return support_assist::generic_path_to_utf8(left.relative_path) < support_assist::generic_path_to_utf8(right.relative_path);
  });

  std::ofstream sums(artifact.hashes_path, std::ios::binary | std::ios::trunc);
  if (!sums)
    return Status::failure(artifact_error("write hashes", artifact.hashes_path,
                                          "Unable to create SHA256SUMS.txt"));
  for (const auto& file : artifact.files)
    sums << file.sha256 << "  " << support_assist::generic_path_to_utf8(file.relative_path) << '\n';
  sums.flush();
  if (!sums)
    return Status::failure(artifact_error("write hashes", artifact.hashes_path,
                                          "Hash list write failed"));

  // Include SHA256SUMS itself in the manifest, but not recursively in SHA256SUMS.
  auto sums_hash = sha256_file(artifact.hashes_path, cancel);
  if (!sums_hash.ok())
    return Status::failure(sums_hash.error());
  ExecutionArtifactFile sums_file;
  sums_file.relative_path = artifact.hashes_path.filename();
  sums_file.size_bytes = std::filesystem::file_size(artifact.hashes_path, error);
  if (error) {
    error.clear();
    sums_file.size_bytes = 0;
  }
  sums_file.sha256 = std::move(sums_hash.value());
  artifact.files.push_back(std::move(sums_file));
  artifact.completed_utc = utc_now_iso8601();
  if (auto manifest = write_manifest(artifact); !manifest.ok()) {
    artifact.completed_utc.clear();
    return manifest;
  }
  return write_artifact_state(artifact, to_string(execution_status));
}

Result<std::filesystem::path>
prepare_support_artifact(ExecutionArtifactManifest& artifact,
                         const CancellationToken& cancel) {
  if (artifact.completed_utc.empty()) {
    auto finalized = finalize_execution_artifact(artifact,
                                                 artifact.execution_status,
                                                 artifact.diagnostic_status,
                                                 artifact.summary,
                                                 cancel);
    if (!finalized.ok())
      return Result<std::filesystem::path>::failure(finalized.error());
  }
  std::filesystem::path archive = artifact.root;
  archive += ".zip";
  auto zipped = create_zip_archive(artifact.root, archive);
  if (!zipped.ok())
    return Result<std::filesystem::path>::failure(zipped.error());
  return Result<std::filesystem::path>::success(std::move(archive));
}

} // namespace support_assist
