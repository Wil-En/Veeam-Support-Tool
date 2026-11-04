#pragma once

// Engineer-configured external tools.
//
// Each entry is explicit: the engineer names a tool, points at an executable, and writes the
// argument line. SAT never scans a directory, never auto-registers anything, and never launches
// something the engineer did not configure by hand. A directory-scanned executable has no
// configured arguments, so it could be launched but not aimed at specific evidence; the rejected
// drop-folder design is recorded in docs/REVIEW_MODS_PLUGINS.md.
//
// What it does NOT do, deliberately
// ---------------------------------
//   * No elevation. A configured tool runs with SAT's own token, like every other local action.
//   * No download, no update, no discovery. SAT does not fetch or verify a third-party binary here;
//     curated downloads are handled by external_tool_catalog(), not by this file.
//   * No shell. Windows takes a single command line, so one is built - but CreateProcess is given
//     the executable explicitly as lpApplicationName, so cmd.exe is never involved and no argument
//     can redirect the launch to a different program. Arguments are expanded to a vector first and
//     quoted individually, so a path with spaces cannot split into two.

#include "support_assist/error.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace support_assist {

struct ConfiguredTool {
  // Stable across edits so a rename does not orphan the entry.
  std::string id;
  std::string name;
  std::filesystem::path executable;
  // Placeholders substituted at launch: {case}, {evidence}, {selected}. Anything else is passed
  // through untouched, because an unknown placeholder is far more likely to be a literal brace in
  // an argument than a typo SAT should silently swallow.
  std::string arguments;
  // Start the tool in the active case folder, so whatever it writes lands beside the evidence and
  // is picked up as case material.
  bool start_in_case_folder = true;
  std::string notes;
};

// What the placeholders resolve to. Any of these may be empty; a template that needs an empty one
// is refused rather than launched with a blank argument.
struct ToolLaunchContext {
  std::filesystem::path case_root;
  std::filesystem::path evidence_path;
  std::filesystem::path selected_path;
};

// Rejects an entry that could not be launched, or that would launch something other than what it
// appears to. Checked when saving AND before launching, because the file is editable by hand.
Status validate_configured_tool(const ConfiguredTool& tool);

// Returns the argument list, already split, so the caller passes it to CreateProcess/exec as
// separate arguments and never builds a command string.
Result<std::vector<std::string>> expand_tool_arguments(std::string_view arguments,
                                                       const ToolLaunchContext& context);

// What a first-run configured-tools file contains: the format, an example, and nothing that
// runs. Every line is a comment, so an engineer opens it to a description of the fields rather
// than to an empty file they have to guess the shape of.
std::string default_configured_tools_file_contents();

// One record per line, tab separated. A text file so an engineer can read what SAT will run.
Result<std::vector<ConfiguredTool>> load_configured_tools(const std::filesystem::path& file);
Status save_configured_tools(const std::filesystem::path& file,
                             const std::vector<ConfiguredTool>& tools);

} // namespace support_assist
