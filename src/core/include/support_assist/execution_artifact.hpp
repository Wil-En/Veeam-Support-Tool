#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

enum class ExecutionStatus { completed, failed, cancelled, unavailable };
enum class DiagnosticStatus { pass, finding, neutral, not_applicable, unknown };

std::string to_string(ExecutionStatus status);
std::string to_string(DiagnosticStatus status);

struct ExecutionArtifactFile {
  std::filesystem::path relative_path;
  std::uint64_t size_bytes = 0;
  std::string sha256;
};

struct ExecutionArtifactManifest {
  std::string artifact_id;
  std::string tool_name;
  std::string host_name;
  std::string started_utc;
  std::string completed_utc;
  std::filesystem::path root;
  std::filesystem::path manifest_path;
  std::filesystem::path hashes_path;
  ExecutionStatus execution_status = ExecutionStatus::completed;
  DiagnosticStatus diagnostic_status = DiagnosticStatus::neutral;
  std::string summary;
  std::vector<ExecutionArtifactFile> files;
};

// A tool's title as a folder name: letters, digits and dashes, at most kToolFolderNameLimit
// characters, cut at a dash ("Certificate-or-TLS-error-between"); "Tool" when nothing is left. Both
// the per-tool folder and the tool part of a run's folder use it, so a run's files stay inside the
// Windows path limit from a deep folder.
constexpr std::size_t kToolFolderNameLimit = 32;
std::string tool_folder_name(std::string_view tool_title);

Result<ExecutionArtifactManifest>
begin_execution_artifact(const std::filesystem::path& base_directory,
                         std::string_view tool_name);

// Marks artifact directories left in Running/Finalizing state by a previous
// interrupted SAT process. Completed artifacts are never modified.
Result<std::size_t>
recover_interrupted_execution_artifacts(const std::filesystem::path& base_directory);

Status write_execution_artifact_text(const ExecutionArtifactManifest& artifact,
                                     std::string_view relative_name,
                                     std::string_view text);

Status finalize_execution_artifact(ExecutionArtifactManifest& artifact,
                                   ExecutionStatus execution_status,
                                   DiagnosticStatus diagnostic_status,
                                   std::string summary,
                                   const CancellationToken& cancel = {});

Result<std::filesystem::path>
prepare_support_artifact(ExecutionArtifactManifest& artifact,
                         const CancellationToken& cancel = {});

// --- Reading artifacts back ---------------------------------------------------------------
//
// SAT wrote structured, self-describing tool artifacts from the beginning but had no way to read
// them again, so Customer/Lab tool evidence sat on disk and had to be retyped by hand. These
// restore the other half of that contract.

// Parses a single manifest.json produced by finalize_execution_artifact().
Result<ExecutionArtifactManifest>
read_execution_artifact_manifest(const std::filesystem::path& manifest_path);

// Recursively finds every completed artifact directory beneath `root` (any directory containing a
// manifest.json SAT recognises). Results are ordered by start time, oldest first, so callers get a
// chronological view across tools and machines without sorting again.
Result<std::vector<ExecutionArtifactManifest>>
discover_execution_artifacts(const std::filesystem::path& root);

Result<ExecutionStatus> parse_execution_status(std::string_view value);
Result<DiagnosticStatus> parse_diagnostic_status(std::string_view value);

} // namespace support_assist
