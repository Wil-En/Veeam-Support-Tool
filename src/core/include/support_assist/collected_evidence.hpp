#pragma once

// Rebuild SAT's environment.log and SystemHealth report formats from a collection that holds only
// raw evidence.
//
// Universal Log Collection normally writes environment.log (SAT_ENVIRONMENT_V2) and
// <MACHINE>-SystemHealth.txt by sampling the live machine at collection time. A customer
// collection often has neither: only the WindowsSupport/ raw command tree (systeminfo,
// Get-ComputerInfo, Get-NetAdapter and the rest), marked "raw-evidence-only" in
// windows-support-index.json and not read by the Environment or Health pages that display those
// two documents. This module converts the raw tree into the same two formats so the existing
// loaders, dashboards and report writer work unchanged.
//
// Reconstruction is limited to what the evidence actually contains. A collection carries no
// Get-Volume, Get-PhysicalDisk or process list, so volumes, storage devices and top processes
// cannot be rebuilt; they are listed in `unavailable` rather than rendered as an empty section,
// which would read as a machine with no disks. Reconstructed findings come from
// evaluate_system_health(), the same evaluator the live samplers use, so a reconstructed snapshot
// is judged by the same thresholds as a sampled one.

#include "support_assist/error.hpp"
#include "support_assist/system_health.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

// One command capture as Universal Log Collection writes it: a fixed envelope, a blank line, then
// whatever the command printed.
//
//   Command: "systeminfo.exe"
//   ExitCode: 0
//   TimedOut: false
//   Cancelled: false
//
//   Host Name: SPECTR
//   ...
struct CollectedCommand {
  std::string command;
  int exit_code = 0;
  bool timed_out = false;
  bool cancelled = false;
  std::string body;

  // A command that failed still has evidentiary value - "Access is denied" is a finding - but its
  // body must never be parsed for facts.
  bool succeeded() const {
    return exit_code == 0 && !timed_out && !cancelled;
  }
};

// Returns nothing when the text does not carry the envelope, which is how a file that is not a
// collected capture is told apart from one that is.
std::optional<CollectedCommand> parse_collected_command(std::string_view text);

// A `Name : Value` record block as PowerShell's Format-List writes it. Consecutive records are
// separated by a blank line. Values wrapped onto continuation lines are joined.
using EvidenceRecord = std::vector<std::pair<std::string, std::string>>;
std::vector<EvidenceRecord> parse_format_list(std::string_view body);
std::optional<std::string> record_value(const EvidenceRecord& record, std::string_view key);

// One section of environment.log and the collected file it is built from, relative to the
// collection root. This is the single definition of that mapping: universal_collection.cpp writes
// environment.log from this table and the reconstruction below reads it back through the same
// table, so a section added to one cannot go missing from the other.
struct CollectedEnvironmentSection {
  std::string_view name;
  std::string_view relative_path;
  std::size_t maximum_bytes;
  bool windows;
  // Basenames the same evidence arrives under when the collection was written by the Veeam Agent
  // log collector rather than SAT itself. Reconstruction resolves a section by relative_path first,
  // then by the basename of relative_path or any of these anywhere in the tree, case-insensitively -
  // so a Veeam bundle's SysInfo/dism_pack.log satisfies the section SAT writes as dism_packages.log.
  std::vector<std::string_view> alt_basenames{};
};

const std::vector<CollectedEnvironmentSection>& environment_sections();

struct EvidenceReconstruction {
  SystemHealthSnapshot health;
  std::string environment_text;

  // What was rebuilt, and the file it came from, so a reconstructed report can trace every number
  // in it back to its source.
  std::vector<std::string> recovered;

  // What could not be rebuilt, and why. Never left empty on a partial collection.
  std::vector<std::string> unavailable;

  bool health_reconstructed = false;
  bool environment_reconstructed = false;
  std::filesystem::path collection_root;

  // Which machine this evidence describes. Taken from the health snapshot, then from the
  // environment document's Machine= line, then from the collection folder name. Empty only when a
  // collection carries no identity at all.
  std::string machine_name;
  // True when the name above is the folder name rather than something the evidence stated. Recorded
  // so the README can say so: a wrong name silently splits one machine into two index rows.
  bool machine_name_inferred = false;
};

// `root` may be the collection, a sub-folder of it, a folder containing collections, or a file
// inside one. Anything that resolves to readable evidence is accepted; the point is that an
// engineer should not have to know which level to select.
Result<EvidenceReconstruction> reconstruct_collected_evidence(const std::filesystem::path& root);

// Write the rebuilt documents into a case so the next open is a file read rather than another walk
// of the collection - the same shape as a saved log review.
//
// Returns the directory written to. Nothing else in the case is touched.
struct SavedEvidencePaths {
  std::filesystem::path directory;
  std::filesystem::path environment_log;
  std::filesystem::path health_report;
};
Result<SavedEvidencePaths> save_reconstructed_evidence(const EvidenceReconstruction& rebuilt,
                                                       const std::filesystem::path& case_root);

// The directory save_reconstructed_evidence() uses, so a caller can look for an earlier rebuild
// before paying for a new one.
std::filesystem::path reconstructed_evidence_directory(const std::filesystem::path& case_root);

// Whether this build can read a collection out of a .zip. False only where libarchive was not
// compiled in, in which case a zip import is refused with that reason rather than failing obscurely.
bool collected_evidence_archive_supported() noexcept;

// True for a path this build can import: a directory, or an archive when the support above is
// present. Lets a caller offer the right file picker rather than discovering the answer on failure.
bool importable_collection_path(const std::filesystem::path& path);

// Rebuild EVERY collection found under `root`, so an engineer can point SAT at a folder holding
// several machines' collections and import them in one go. A folder that is itself one collection
// yields one result. Never returns an empty vector on success.
//
// `root` may also be a .zip, or a folder containing .zip collections: the useful members are
// unpacked into a temporary directory that is removed before this returns, and every reconstruction
// still reports the ARCHIVE as its collection_root, because that is the path that will still exist
// when someone reads the saved README.
Result<std::vector<EvidenceReconstruction>> reconstruct_all_collected_evidence(
    const std::filesystem::path& root);

// One machine's rebuilt evidence inside a case.
struct ImportedMachine {
  std::string machine_name;
  std::filesystem::path directory;
  // Either may be empty: a collection can support one document and not the other.
  std::filesystem::path environment_log;
  std::filesystem::path health_report;
  std::string source_collection;
  std::string imported_utc;
};

// Every machine imported into this case, in the order they were imported. Empty is a normal answer.
//
// Falls back to reading documents that sit directly in reconstructed/ when there is no index, so a
// case written before the index existed still opens.
std::vector<ImportedMachine> load_imported_machines(const std::filesystem::path& case_root);

// Where a collection root would keep the two documents, if it has them.
std::filesystem::path existing_environment_log(const std::filesystem::path& root);
std::filesystem::path existing_health_report(const std::filesystem::path& root);

} // namespace support_assist
