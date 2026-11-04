#include "support_assist/case_workspace.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"

#include <cctype>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <system_error>

namespace support_assist {
namespace {

Error workspace_error(std::string operation,
                      const std::filesystem::path& source,
                      std::string message,
                      std::int64_t native_code = 0) {
  Error error;
  error.component = "CaseWorkspace";
  error.operation = std::move(operation);
  error.source = path_to_utf8(source);
  error.message = std::move(message);
  error.native_code = native_code;
  return error;
}

std::string extract_json_string(std::string_view json, std::string_view key) {
  const std::string marker = "\"" + std::string(key) + "\"";
  const std::size_t key_position = json.find(marker);
  if (key_position == std::string_view::npos)
    return {};
  const std::size_t colon = json.find(':', key_position + marker.size());
  if (colon == std::string_view::npos)
    return {};
  const std::size_t quote = json.find('"', colon + 1U);
  if (quote == std::string_view::npos)
    return {};
  std::string result;
  bool escaped = false;
  for (std::size_t index = quote + 1U; index < json.size(); ++index) {
    const char c = json[index];
    if (escaped) {
      switch (c) {
      case 'n':
        result.push_back('\n');
        break;
      case 'r':
        result.push_back('\r');
        break;
      case 't':
        result.push_back('\t');
        break;
      case '\\':
        result.push_back('\\');
        break;
      case '"':
        result.push_back('"');
        break;
      default:
        result.push_back(c);
        break;
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
  return {};
}


std::string encode_state_field(std::string_view value) {
  std::ostringstream out;
  const char hex[] = "0123456789ABCDEF";
  for (const unsigned char c : value) {
    if (c == '%' || c == '\t' || c == '\n' || c == '\r') {
      out << '%' << hex[(c >> 4U) & 0x0FU] << hex[c & 0x0FU];
    } else {
      out << static_cast<char>(c);
    }
  }
  return out.str();
}

std::string decode_state_field(std::string_view value) {
  const auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
  };
  std::string out;
  out.reserve(value.size());
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '%' && i + 2U < value.size()) {
      const int hi = nibble(value[i + 1U]);
      const int lo = nibble(value[i + 2U]);
      if (hi >= 0 && lo >= 0) {
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2U;
        continue;
      }
    }
    out.push_back(value[i]);
  }
  return out;
}

bool extract_json_bool(std::string_view json, std::string_view key, bool default_value) {
  const std::string marker = "\"" + std::string(key) + "\"";
  const std::size_t key_position = json.find(marker);
  if (key_position == std::string_view::npos)
    return default_value;
  const std::size_t colon = json.find(':', key_position + marker.size());
  if (colon == std::string_view::npos)
    return default_value;
  const std::size_t value = json.find_first_not_of(" \t\r\n", colon + 1U);
  if (value == std::string_view::npos)
    return default_value;
  if (json.substr(value, 4U) == "true")
    return true;
  if (json.substr(value, 5U) == "false")
    return false;
  return default_value;
}

Status create_directory_checked(const std::filesystem::path& path) {
  std::error_code error_code;
  std::filesystem::create_directories(path, error_code);
  if (error_code) {
    return Status::failure(
        workspace_error("create directory", path, error_code.message(), error_code.value()));
  }
  return Status::success();
}

Status migrate_legacy_case_file(const std::filesystem::path& source,
                                const std::filesystem::path& destination) {
  std::error_code error;
  if (!std::filesystem::exists(source, error) || error || std::filesystem::exists(destination))
    return Status::success();
  std::filesystem::rename(source, destination, error);
  if (!error)
    return Status::success();
  error.clear();
  std::filesystem::copy_file(source, destination, std::filesystem::copy_options::none, error);
  if (error)
    return Status::failure(
        workspace_error("migrate legacy parser file", source, error.message(), error.value()));
  std::filesystem::remove(source, error);
  return Status::success();
}

Status ensure_case_parsed_layout(const CaseWorkspace& workspace) {
  if (auto status = create_directory_checked(workspace.parsed); !status.ok())
    return status;
  if (auto status = create_directory_checked(workspace.parser_cache); !status.ok())
    return status;

  if (auto status = migrate_legacy_case_file(
          workspace.root / "case-review-state.json",
          workspace.parsed / "case-review-state.json"); !status.ok())
    return status;
  if (auto status = migrate_legacy_case_file(
          workspace.root / "case-review-model.sat",
          workspace.parsed / "case-review-model.sat"); !status.ok())
    return status;

  const std::filesystem::path legacy_cache = workspace.root / "parser-cache";
  std::error_code error;
  if (std::filesystem::is_directory(legacy_cache, error) && !error) {
    std::filesystem::copy(legacy_cache, workspace.parser_cache,
                          std::filesystem::copy_options::recursive |
                              std::filesystem::copy_options::skip_existing,
                          error);
    if (error)
      return Status::failure(
          workspace_error("migrate legacy parser cache", legacy_cache,
                          error.message(), error.value()));
    std::filesystem::remove_all(legacy_cache, error);
    if (error)
      return Status::failure(
          workspace_error("remove legacy parser cache", legacy_cache,
                          error.message(), error.value()));
  }
  return Status::success();
}

} // namespace

namespace {

// The list both frontends build their dropdown from.
//
// Mutable so it can be replaced from a text file at startup without editing this line and
// rebuilding all three editions. A status is stored on a case as TEXT, so a case carrying a
// status that is later removed from the file keeps showing it rather than being rewritten to
// something it never was.
std::vector<CaseStatusOption>& mutable_case_status_entries() {
  static std::vector<CaseStatusOption> options{{"Opened", CaseStatusColor::green},
                                               {"Waiting On Response", CaseStatusColor::yellow},
                                               {"R&T", CaseStatusColor::orange}};
  return options;
}

// Kept in step with the entries above on every load, because case_status_options() is on the
// interface and several callers only ever want the names.
std::vector<std::string>& mutable_case_status_options() {
  static std::vector<std::string> names{"Opened", "Waiting On Response", "R&T"};
  return names;
}

// The colour SAT ships for a status name, if it ships one.
//
// Used only when a line names no colour of its own. An existing case-statuses.txt has no colours
// in it at all, and seeding never overwrites it, so this fallback is what keeps every status in
// an established install from rendering grey by default.
std::optional<CaseStatusColor> built_in_status_color(std::string_view name) {
  static const std::vector<CaseStatusOption> defaults{{"Opened", CaseStatusColor::green},
                                                      {"Waiting On Response", CaseStatusColor::yellow},
                                                      {"R&T", CaseStatusColor::orange}};
  for (const auto& entry : defaults) {
    if (entry.name == name)
      return entry.color;
  }
  return std::nullopt;
}

void republish_status_names() {
  auto& names = mutable_case_status_options();
  names.clear();
  names.reserve(mutable_case_status_entries().size());
  for (const auto& entry : mutable_case_status_entries())
    names.push_back(entry.name);
}

} // namespace

std::optional<CaseStatusColor> parse_case_status_color(std::string_view name) {
  const std::string folded = ascii_lower(trim(name));
  if (folded == "grey" || folded == "gray")
    return CaseStatusColor::grey;
  if (folded == "green")
    return CaseStatusColor::green;
  if (folded == "yellow")
    return CaseStatusColor::yellow;
  if (folded == "orange")
    return CaseStatusColor::orange;
  if (folded == "red")
    return CaseStatusColor::red;
  if (folded == "blue")
    return CaseStatusColor::blue;
  if (folded == "purple")
    return CaseStatusColor::purple;
  if (folded == "teal")
    return CaseStatusColor::teal;
  if (folded == "pink") return CaseStatusColor::pink;
  if (folded == "cyan" || folded == "aqua") return CaseStatusColor::cyan;
  if (folded == "magenta" || folded == "fuchsia") return CaseStatusColor::magenta;
  if (folded == "lime") return CaseStatusColor::lime;
  if (folded == "olive") return CaseStatusColor::olive;
  if (folded == "navy") return CaseStatusColor::navy;
  if (folded == "maroon") return CaseStatusColor::maroon;
  if (folded == "brown") return CaseStatusColor::brown;
  if (folded == "gold") return CaseStatusColor::gold;
  if (folded == "indigo") return CaseStatusColor::indigo;
  if (folded == "coral") return CaseStatusColor::coral;
  if (folded == "slate") return CaseStatusColor::slate;
  if (folded == "rose") return CaseStatusColor::rose;
  if (folded == "mint") return CaseStatusColor::mint;
  if (folded == "lavender") return CaseStatusColor::lavender;
  if (folded == "amber") return CaseStatusColor::amber;
  return std::nullopt;
}

std::string case_status_color_name(CaseStatusColor color) {
  switch (color) {
  case CaseStatusColor::green: return "Green";
  case CaseStatusColor::yellow: return "Yellow";
  case CaseStatusColor::orange: return "Orange";
  case CaseStatusColor::red: return "Red";
  case CaseStatusColor::blue: return "Blue";
  case CaseStatusColor::purple: return "Purple";
  case CaseStatusColor::teal: return "Teal";
  case CaseStatusColor::pink: return "Pink";
  case CaseStatusColor::cyan: return "Cyan";
  case CaseStatusColor::magenta: return "Magenta";
  case CaseStatusColor::lime: return "Lime";
  case CaseStatusColor::olive: return "Olive";
  case CaseStatusColor::navy: return "Navy";
  case CaseStatusColor::maroon: return "Maroon";
  case CaseStatusColor::brown: return "Brown";
  case CaseStatusColor::gold: return "Gold";
  case CaseStatusColor::indigo: return "Indigo";
  case CaseStatusColor::coral: return "Coral";
  case CaseStatusColor::slate: return "Slate";
  case CaseStatusColor::rose: return "Rose";
  case CaseStatusColor::mint: return "Mint";
  case CaseStatusColor::lavender: return "Lavender";
  case CaseStatusColor::amber: return "Amber";
  case CaseStatusColor::grey: break;
  }
  return "Grey";
}

const std::vector<CaseStatusColor>& case_status_color_palette() {
  static const std::vector<CaseStatusColor> palette{
      CaseStatusColor::grey,    CaseStatusColor::green,   CaseStatusColor::yellow,
      CaseStatusColor::orange,  CaseStatusColor::red,     CaseStatusColor::blue,
      CaseStatusColor::purple,  CaseStatusColor::teal,    CaseStatusColor::pink,
      CaseStatusColor::cyan,    CaseStatusColor::magenta, CaseStatusColor::lime,
      CaseStatusColor::olive,   CaseStatusColor::navy,    CaseStatusColor::maroon,
      CaseStatusColor::brown,   CaseStatusColor::gold,    CaseStatusColor::indigo,
      CaseStatusColor::coral,   CaseStatusColor::slate,   CaseStatusColor::rose,
      CaseStatusColor::mint,    CaseStatusColor::lavender, CaseStatusColor::amber};
  return palette;
}

const std::vector<CaseStatusOption>& case_status_entries() {
  return mutable_case_status_entries();
}

CaseStatusColor case_status_color(std::string_view status) {
  const std::string wanted = trim(status);
  for (const auto& entry : mutable_case_status_entries()) {
    if (entry.name == wanted)
      return entry.color;
  }
  return CaseStatusColor::grey;
}

const std::vector<std::string>& case_status_options() { return mutable_case_status_options(); }

std::filesystem::path case_status_options_path(const std::filesystem::path& state_directory) {
  return state_directory / "case-statuses.txt";
}

std::string default_case_status_file_contents() {
  return "# Support Assist Tool - case statuses\n"
         "#\n"
         "# One status per line, in the order they should appear in the dropdown. The first line is\n"
         "# the status a new case starts in. Blank lines and lines starting with # are ignored.\n"
         "#\n"
         "# Edit this file and restart SAT; no rebuild is needed. A case already carrying a status\n"
         "# you remove here keeps it - statuses are stored as text, not as a number.\n"
         "#\n"
         "# COLOURS\n"
         "#\n"
         "#   Add a colour after the status, separated by a colon:\n"
         "#\n"
         "#       Opened:Green\n"
         "#\n"
         "#   Spaces around the colon are fine, and the colour is not case sensitive.\n"
         "#\n"
         "#   The seven colours are:\n"
         "#\n"
         "#       Green    Yellow    Orange    Red    Blue    Purple    Teal\n"
         "#\n"
         "#   Grey is the default. A status with no colour, or with a word that is not one of the\n"
         "#   seven, is drawn grey - the status keeps the text you wrote either way.\n"
         "\n"
         "Opened:Green\n"
         "Waiting On Response:Yellow\n"
         "R&T:Orange\n"
         "\n"
         "# Examples - remove the '#' to use one:\n"
         "#\n"
         "# Customer 1:Blue\n"
         "# Custom 2\n";
}

Status load_case_status_options(const std::filesystem::path& file) {
  // The answer, not the answer OR the error code - see load_configured_tools().
  std::error_code error;
  if (!std::filesystem::exists(file, error))
    return Status::success();          // no file is not a problem; the built-in list stands

  std::ifstream input(file, std::ios::binary);
  if (!input) {
    Error failure;
    failure.component = "CaseWorkspace";
    failure.operation = "load case statuses";
    failure.message = "Could not read " + path_to_utf8(file) + ". The built-in statuses are in use.";
    return Status::failure(std::move(failure));
  }
  std::ostringstream contents;
  contents << input.rdbuf();
  return load_case_status_options_text(contents.str(), path_to_utf8(file));
}

Status load_case_status_options_text(std::string_view text, std::string_view source) {
  std::istringstream input{std::string(text)};
  std::vector<CaseStatusOption> loaded;
  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    const std::string value = trim(line);
    if (value.empty() || value.front() == '#')
      continue;

    // "<name>:<colour>", split at the LAST colon and only when the tail is a colour SAT knows.
    // Anchoring on the last one keeps a name that contains a colon intact, and requiring a known
    // colour means a typo leaves the whole line as the status name in grey rather than quietly
    // truncating it.
    CaseStatusOption option;
    option.name = value;
    bool colored = false;
    if (const auto separator = value.rfind(':'); separator != std::string::npos) {
      if (const auto color = parse_case_status_color(value.substr(separator + 1U))) {
        const std::string name = trim(value.substr(0, separator));
        if (!name.empty()) {
          option.name = name;
          option.color = *color;
          colored = true;
        }
      }
    }
    // A status with no explicit colour keeps the colour SAT ships for that name, if any, so a
    // file that predates colours renders unchanged. Writing "Opened:Grey" still yields grey,
    // because that is an explicit colour choice rather than an absence of one.
    if (!colored) {
      if (const auto inherited = built_in_status_color(option.name))
        option.color = *inherited;
    }

    // A duplicate would show twice in the dropdown and mean nothing different. Compared by NAME:
    // the same status listed twice in two colours is one status, and the first wins.
    const auto exists = std::find_if(loaded.begin(), loaded.end(), [&](const auto& existing) {
      return existing.name == option.name;
    });
    if (exists == loaded.end())
      loaded.push_back(std::move(option));
  }

  if (loaded.empty()) {
    Error failure;
    failure.component = "CaseWorkspace";
    failure.operation = "load case statuses";
    failure.message = std::string(source) +
                      " lists no statuses. The built-in statuses are in use, because a case with "
                      "no status to choose from cannot be worked.";
    return Status::failure(std::move(failure));
  }

  mutable_case_status_entries() = std::move(loaded);
  republish_status_names();
  return Status::success();
}

std::string case_status_or_default(const CaseWorkspace& workspace) {
  return workspace.status.empty() ? case_status_options().front() : workspace.status;
}

std::string sanitize_case_identifier(std::string_view value) {
  std::string output;
  output.reserve(value.size());
  bool previous_separator = false;
  for (const char raw : value) {
    const unsigned char c = static_cast<unsigned char>(raw);
    if (std::isalnum(c) != 0 || raw == '-' || raw == '_') {
      output.push_back(raw);
      previous_separator = false;
    } else if (!previous_separator && !output.empty()) {
      output.push_back('-');
      previous_separator = true;
    }
  }
  while (!output.empty() && output.back() == '-')
    output.pop_back();
  if (output.size() > 96U)
    output.resize(96U);
  return output;
}

namespace {

// The single writer for case.json. Keeping case creation and editing on one code path stops a
// field from being saved by one path and dropped by the other.
void write_case_manifest(std::ostream& manifest, const CaseWorkspace& workspace) {
  manifest << "{\n"
           << "  \"schema\": 2,\n"
           << "  \"case_id\": \"" << json_escape(workspace.case_id) << "\",\n"
           << "  \"title\": \"" << json_escape(workspace.title) << "\",\n"
           << "  \"engineer\": \"" << json_escape(workspace.engineer) << "\",\n"
           << "  \"created_utc\": \"" << json_escape(workspace.created_utc) << "\",\n"
           << "  \"status\": \"" << json_escape(workspace.status) << "\",\n"
           << "  \"next_steps\": \"" << json_escape(workspace.next_steps) << "\",\n"
           << "  \"notes\": \"" << json_escape(workspace.notes_text) << "\"\n"
           << "}\n";
}

}  // namespace

Status save_case_workspace_metadata(const CaseWorkspace& workspace) {
  if (workspace.manifest.empty()) {
    return Status::failure(
        workspace_error("save metadata", workspace.root, "This case has no manifest path"));
  }
  // Written to a sibling and renamed over the original. A case.json truncated by a crash or a full
  // disk midway through the write would leave the case unopenable, and the evidence beside it is
  // not reproducible.
  const auto temporary = workspace.manifest.parent_path() / "case.json.tmp";
  {
    std::ofstream manifest(temporary, std::ios::binary | std::ios::trunc);
    if (!manifest) {
      return Status::failure(
          workspace_error("save metadata", temporary, "Could not write case.json"));
    }
    write_case_manifest(manifest, workspace);
    if (!manifest) {
      return Status::failure(
          workspace_error("save metadata", temporary, "Failed while writing case.json"));
    }
  }
  std::error_code error;
  std::filesystem::rename(temporary, workspace.manifest, error);
  if (error) {
    std::filesystem::remove(temporary, error);
    return Status::failure(
        workspace_error("save metadata", workspace.manifest, "Could not replace case.json"));
  }
  return Status::success();
}

Result<CaseWorkspace> create_case_workspace(const CaseWorkspaceOptions& options) {
  if (options.parent_directory.empty()) {
    return Result<CaseWorkspace>::failure(
        workspace_error("create workspace", {}, "A parent directory is required"));
  }
  const std::string case_id = sanitize_case_identifier(options.case_id);
  if (case_id.empty()) {
    return Result<CaseWorkspace>::failure(
        workspace_error("create workspace",
                        options.parent_directory,
                        "The case identifier contains no usable characters"));
  }

  CaseWorkspace workspace;
  workspace.root = options.parent_directory / case_id;
  workspace.logs = workspace.root / "logs";
  workspace.captures = workspace.root / "captures";
  workspace.reports = workspace.root / "reports";
  workspace.baselines = workspace.root / "baselines";
  workspace.third_party = workspace.root / "third-party";
  workspace.notes = workspace.root / "notes";
  workspace.evidence = workspace.root / "evidence";
  workspace.parsed = workspace.root / "parsed";
  workspace.parser_cache = workspace.parsed / "cache";
  workspace.manifest = workspace.root / "case.json";
  workspace.case_id = case_id;
  workspace.title = options.title;
  workspace.engineer = options.engineer;
  workspace.created_utc = utc_now_iso8601();

  for (const auto& directory : {workspace.root,
                                workspace.logs,
                                workspace.captures,
                                workspace.reports,
                                workspace.baselines,
                                workspace.third_party,
                                workspace.notes,
                                workspace.evidence,
                                workspace.parsed,
                                workspace.parser_cache}) {
    if (auto status = create_directory_checked(directory); !status.ok()) {
      return Result<CaseWorkspace>::failure(status.error());
    }
  }

  std::ofstream manifest(workspace.manifest, std::ios::binary | std::ios::trunc);
  if (!manifest) {
    return Result<CaseWorkspace>::failure(
        workspace_error("write manifest", workspace.manifest, "Could not create case.json"));
  }
  workspace.status = case_status_options().front();
  workspace.notes_text = options.notes;
  write_case_manifest(manifest, workspace);
  if (!manifest) {
    return Result<CaseWorkspace>::failure(
        workspace_error("write manifest", workspace.manifest, "Failed while writing case.json"));
  }
  return Result<CaseWorkspace>::success(std::move(workspace));
}

Result<CaseWorkspace> open_case_workspace(const std::filesystem::path& root) {
  const std::filesystem::path manifest_path = root / "case.json";
  std::ifstream manifest(manifest_path, std::ios::binary);
  if (!manifest) {
    return Result<CaseWorkspace>::failure(
        workspace_error("open workspace", manifest_path, "case.json was not found"));
  }
  std::ostringstream buffer;
  buffer << manifest.rdbuf();
  const std::string text = buffer.str();

  CaseWorkspace workspace;
  workspace.root = root;
  workspace.logs = root / "logs";
  workspace.captures = root / "captures";
  workspace.reports = root / "reports";
  workspace.baselines = root / "baselines";
  workspace.third_party = root / "third-party";
  workspace.notes = root / "notes";
  workspace.evidence = root / "evidence";
  workspace.parsed = root / "parsed";
  workspace.parser_cache = workspace.parsed / "cache";
  workspace.manifest = manifest_path;
  workspace.case_id = extract_json_string(text, "case_id");
  workspace.title = extract_json_string(text, "title");
  workspace.engineer = extract_json_string(text, "engineer");
  workspace.created_utc = extract_json_string(text, "created_utc");
  // Absent in a schema-1 case. An absent status reads as the first option rather than as an empty
  // cell, so an older case appears in the right place in the list instead of nowhere.
  workspace.status = extract_json_string(text, "status");
  workspace.next_steps = extract_json_string(text, "next_steps");
  workspace.notes_text = extract_json_string(text, "notes");
  if (workspace.case_id.empty()) {
    return Result<CaseWorkspace>::failure(
        workspace_error("open workspace", manifest_path, "case.json has no case_id"));
  }
  if (auto status = ensure_case_parsed_layout(workspace); !status.ok())
    return Result<CaseWorkspace>::failure(status.error());
  return Result<CaseWorkspace>::success(std::move(workspace));
}


Result<std::vector<CaseWorkspace>> discover_case_workspaces(const std::filesystem::path& parent) {
  std::vector<CaseWorkspace> workspaces;
  if (parent.empty())
    return Result<std::vector<CaseWorkspace>>::success(std::move(workspaces));
  std::error_code error;
  if (!std::filesystem::exists(parent, error))
    return Result<std::vector<CaseWorkspace>>::success(std::move(workspaces));
  std::filesystem::directory_iterator iterator(
      parent, std::filesystem::directory_options::skip_permission_denied, error);
  if (error) {
    return Result<std::vector<CaseWorkspace>>::failure(
        workspace_error("discover workspaces", parent, error.message(), error.value()));
  }
  const std::filesystem::directory_iterator end;
  for (; iterator != end; iterator.increment(error)) {
    if (error) {
      error.clear();
      continue;
    }
    if (!iterator->is_directory(error)) {
      error.clear();
      continue;
    }
    auto opened = open_case_workspace(iterator->path());
    if (opened.ok())
      workspaces.push_back(std::move(opened.value()));
  }
  std::stable_sort(workspaces.begin(), workspaces.end(), [](const auto& left, const auto& right) {
    if (left.created_utc != right.created_utc)
      return left.created_utc > right.created_utc;
    return left.case_id < right.case_id;
  });
  return Result<std::vector<CaseWorkspace>>::success(std::move(workspaces));
}

namespace {

// SAT-SEC-02: case deletion is recursive and therefore the single most destructive operation in
// SAT. Without canonicalisation, confinement, and reparse-point rejection, any directory merely
// containing a readable case.json with a case_id could be removed: a case.json copied, extracted
// from a bundle, or left behind in a directory that also holds unrelated data would turn that
// directory into a deletable "case". The realistic trigger is an engineer registering the wrong
// folder; the consequence is the same either way.
//
// These guards are deliberately conservative. They reject rather than repair, and they never
// widen the set of things SAT will delete.

constexpr std::size_t kMinimumCaseRootDepth = 2U;

bool path_component_is_reparse_point(const std::filesystem::path& path) {
  // Only a POSITIVE symlink identification rejects. Do not reject on a query error.
  //
  // The non-throwing filesystem overloads answer through their return value; the error_code is
  // not a reliable "everything was fine" signal. MSVC can leave a benign or residual code set on
  // a call that succeeded, while libstdc++ clears it - so treating a non-empty error_code as
  // failure passes on Linux and rejects every legitimate deletion on Windows.
  //
  // Security is not weakened by this: refusing to delete is not the control that protects the
  // filesystem here. The case.json + case_id requirement below is what prevents SAT deleting a
  // directory that is not a case workspace, and it is a positive test that cannot silently pass.
  std::error_code error;
  const auto status = std::filesystem::symlink_status(path, error);
  if (error)
    return false;
  return std::filesystem::is_symlink(status);
}

// Only the deletion TARGET is checked, not its ancestors.
//
// The security property needed is that SAT must not delete *through* a link: if the supplied path
// is a symlink or junction, remove_all() would operate on whatever it points at. Checking the
// supplied leaf and the canonical leaf covers that completely, because the canonical form is the
// path actually passed to remove_all() and it is separately validated as a real case workspace.
//
// Ancestors are deliberately not checked, since checking them breaks legitimate deletion on two platforms:
//   * Windows splits a path root into two components ("C:" then "\\"), so a single root-equality
//     skip never matches and symlink_status() would be called on the bare drive designator;
//   * macOS /tmp is itself a symlink to /private/tmp, so every temporary case root would be
//     refused.
// An ancestor link is also not a real escape: weakly_canonical() resolves it, and the resolved
// target is then required to contain a valid case.json before anything is removed.
bool deletion_target_is_reparse_point(const std::filesystem::path& supplied,
                                      const std::filesystem::path& canonical) {
  return path_component_is_reparse_point(supplied) || path_component_is_reparse_point(canonical);
}

std::size_t path_depth(const std::filesystem::path& path) {
  std::size_t depth = 0;
  for (const auto& component : path.relative_path())
    if (!component.empty() && component != ".")
      ++depth;
  return depth;
}

} // namespace

Status delete_case_workspace(const std::filesystem::path& root) {
  if (root.empty()) {
    return Status::failure(
        workspace_error("delete workspace", root, "No case workspace path was supplied"));
  }

  // Resolve before any check so that "..", "." and links cannot smuggle the real target past
  // the guards below.
  std::error_code canonical_error;
  const auto canonical_root = std::filesystem::weakly_canonical(root, canonical_error);
  if (canonical_error || canonical_root.empty()) {
    return Status::failure(workspace_error(
        "delete workspace", root,
        "The case workspace path could not be resolved to a canonical location"));
  }

  // Trust the return value, not the error_code (see path_component_is_reparse_point).
  std::error_code directory_error;
  if (!std::filesystem::is_directory(canonical_root, directory_error)) {
    return Status::failure(workspace_error("delete workspace", canonical_root,
                                           "The case workspace path is not a directory"));
  }

  // Refuse a filesystem or drive root, and refuse anything shallow enough that a mistake would
  // be catastrophic (C:\, /, C:\Users, /home and similar).
  if (canonical_root == canonical_root.root_path() ||
      path_depth(canonical_root) < kMinimumCaseRootDepth) {
    return Status::failure(workspace_error(
        "delete workspace", canonical_root,
        "Refusing to delete a filesystem root or a top-level directory as a case workspace"));
  }

  // Check the path AS SUPPLIED as well as the canonical form. weakly_canonical() resolves
  // symlinks, so a link inspected only after canonicalisation has already been followed and the
  // guard would pass while the delete still traverses it. Both forms must be clean.
  if (deletion_target_is_reparse_point(root, canonical_root)) {
    return Status::failure(workspace_error(
        "delete workspace", root,
        "Refusing to delete through a symbolic link, junction or reparse point"));
  }

  // Only a directory SAT actually recognises as a case workspace may be removed. This is a
  // read-only check: it must not provision the parsed layout on a workspace being deleted.
  const auto manifest_path = canonical_root / "case.json";
  std::error_code manifest_error;
  if (!std::filesystem::is_regular_file(manifest_path, manifest_error)) {
    return Status::failure(workspace_error("delete workspace", canonical_root,
                                           "case.json was not found; refusing to delete a "
                                           "directory that is not a SAT case workspace"));
  }
  // The manifest handle MUST be closed before remove_all(). POSIX permits unlinking a file that
  // is still open, so an unscoped stream here passes on Linux; Windows opens without
  // FILE_SHARE_DELETE and the live handle makes remove_all() fail with ERROR_SHARING_VIOLATION
  // (32) on the very case workspace SAT is trying to delete. Scope the read explicitly.
  std::string manifest_text;
  {
    std::ifstream manifest(manifest_path, std::ios::binary);
    if (!manifest) {
      return Status::failure(
          workspace_error("delete workspace", manifest_path, "case.json could not be read"));
    }
    std::ostringstream manifest_buffer;
    manifest_buffer << manifest.rdbuf();
    manifest_text = manifest_buffer.str();
  }
  if (extract_json_string(manifest_text, "case_id").empty()) {
    return Status::failure(workspace_error("delete workspace", manifest_path,
                                           "case.json has no case_id; refusing to delete"));
  }

  std::error_code error;
  const auto removed = std::filesystem::remove_all(canonical_root, error);
  if (error) {
    return Status::failure(
        workspace_error("delete workspace", canonical_root, error.message(), error.value()));
  }
  if (removed == 0U) {
    return Status::failure(
        workspace_error("delete workspace", canonical_root, "No case workspace files were removed"));
  }
  return Status::success();
}

Status save_case_review_note(const CaseWorkspace& workspace, CaseReviewNote note) {
  if (note.scope_type.empty() || note.scope_key.empty()) {
    return Status::failure(workspace_error(
        "save review note", workspace.root, "A note scope type and scope key are required"));
  }
  std::error_code error;
  std::filesystem::create_directories(workspace.notes, error);
  if (error) {
    return Status::failure(
        workspace_error("create notes directory", workspace.notes, error.message(), error.value()));
  }
  note.updated_utc = utc_now_iso8601();
  const std::string file_name = sanitize_case_identifier(note.scope_type + "-" + note.scope_key);
  const std::filesystem::path path = workspace.notes / (file_name + ".json");
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(workspace_error("save review note", path, "Could not create note file"));
  output << "{\n"
         << "  \"schema\": 1,\n"
         << "  \"scope_type\": \"" << json_escape(note.scope_type) << "\",\n"
         << "  \"scope_key\": \"" << json_escape(note.scope_key) << "\",\n"
         << "  \"machine_name\": \"" << json_escape(note.machine_name) << "\",\n"
         << "  \"job_name\": \"" << json_escape(note.job_name) << "\",\n"
         << "  \"observations\": \"" << json_escape(note.observations) << "\",\n"
         << "  \"hypothesis\": \"" << json_escape(note.hypothesis) << "\",\n"
         << "  \"next_action\": \"" << json_escape(note.next_action) << "\",\n"
         << "  \"engineer_notes\": \"" << json_escape(note.engineer_notes) << "\",\n"
         << "  \"evidence_ids\": \"" << json_escape(note.evidence_ids) << "\",\n"
         << "  \"updated_utc\": \"" << json_escape(note.updated_utc) << "\"\n"
         << "}\n";
  if (!output)
    return Status::failure(workspace_error("save review note", path, "Failed while writing note"));
  return Status::success();
}

Result<std::vector<CaseReviewNote>> load_case_review_notes(const CaseWorkspace& workspace) {
  std::vector<CaseReviewNote> notes;
  std::error_code error;
  if (!std::filesystem::exists(workspace.notes, error))
    return Result<std::vector<CaseReviewNote>>::success(std::move(notes));
  std::filesystem::directory_iterator iterator(
      workspace.notes, std::filesystem::directory_options::skip_permission_denied, error);
  if (error) {
    return Result<std::vector<CaseReviewNote>>::failure(
        workspace_error("load review notes", workspace.notes, error.message(), error.value()));
  }
  const std::filesystem::directory_iterator end;
  for (; iterator != end; iterator.increment(error)) {
    if (error) {
      error.clear();
      continue;
    }
    if (!iterator->is_regular_file(error) || iterator->path().extension() != ".json") {
      error.clear();
      continue;
    }
    std::ifstream input(iterator->path(), std::ios::binary);
    if (!input)
      continue;
    std::ostringstream buffer;
    buffer << input.rdbuf();
    const std::string text = buffer.str();
    CaseReviewNote note;
    note.scope_type = extract_json_string(text, "scope_type");
    note.scope_key = extract_json_string(text, "scope_key");
    note.machine_name = extract_json_string(text, "machine_name");
    note.job_name = extract_json_string(text, "job_name");
    note.observations = extract_json_string(text, "observations");
    note.hypothesis = extract_json_string(text, "hypothesis");
    note.next_action = extract_json_string(text, "next_action");
    note.engineer_notes = extract_json_string(text, "engineer_notes");
    note.evidence_ids = extract_json_string(text, "evidence_ids");
    note.updated_utc = extract_json_string(text, "updated_utc");
    if (!note.scope_type.empty() && !note.scope_key.empty())
      notes.push_back(std::move(note));
  }
  std::stable_sort(notes.begin(), notes.end(), [](const auto& left, const auto& right) {
    return left.updated_utc > right.updated_utc;
  });
  return Result<std::vector<CaseReviewNote>>::success(std::move(notes));
}


Status save_case_review_state(const CaseWorkspace& workspace, CaseReviewState state) {
  state.updated_utc = utc_now_iso8601();
  std::string sources;
  for (std::size_t index = 0; index < state.sources.size(); ++index) {
    if (index != 0U)
      sources.push_back('\n');
    sources += state.sources[index];
  }
  std::string source_profiles;
  for (const auto& source : state.source_profiles) {
    if (source.path.empty())
      continue;
    if (!source_profiles.empty())
      source_profiles.push_back('\n');
    source_profiles += encode_state_field(source.path);
    source_profiles.push_back('\t');
    source_profiles += encode_state_field(source.requested_profile.empty() ? "automatic" : source.requested_profile);
    source_profiles.push_back('\t');
    source_profiles += encode_state_field(source.detected_profile);
    source_profiles.push_back('\t');
    source_profiles += encode_state_field(source.product_type);
    source_profiles.push_back('\t');
    source_profiles += encode_state_field(source.product_version);
    source_profiles.push_back('\t');
    source_profiles += encode_state_field(source.source_owner);
  }
  if (auto status = create_directory_checked(workspace.parsed); !status.ok())
    return status;
  const std::filesystem::path path = workspace.parsed / "case-review-state.json";
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(workspace_error("save review state", path, "Could not create review state"));
  output << "{\n"
         << "  \"schema\": 2,\n"
         << "  \"profile\": \"" << json_escape(state.profile) << "\",\n"
         << "  \"sources\": \"" << json_escape(sources) << "\",\n"
         << "  \"source_profiles\": \"" << json_escape(source_profiles) << "\",\n"
         << "  \"fast_index\": \"" << (state.fast_index ? "true" : "false") << "\",\n"
         << "  \"selected_machine_key\": \"" << json_escape(state.selected_machine_key) << "\",\n"
         << "  \"selected_job_name\": \"" << json_escape(state.selected_job_name) << "\",\n"
         << "  \"selected_run_key\": \"" << json_escape(state.selected_run_key) << "\",\n"
         << "  \"rescans_only\": \"" << (state.rescans_only ? "true" : "false") << "\",\n"
         << "  \"updated_utc\": \"" << json_escape(state.updated_utc) << "\"\n"
         << "}\n";
  if (!output)
    return Status::failure(workspace_error("save review state", path, "Failed while writing review state"));
  return Status::success();
}

Result<CaseReviewState> load_case_review_state(const CaseWorkspace& workspace) {
  std::filesystem::path path = workspace.parsed / "case-review-state.json";
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    // v0.4.1 compatibility: read legacy root state, but all future saves use parsed/.
    path = workspace.root / "case-review-state.json";
    input.clear();
    input.open(path, std::ios::binary);
  }
  if (!input) {
    return Result<CaseReviewState>::failure(
        workspace_error("load review state", path, "No saved log-review state was found"));
  }
  std::ostringstream buffer;
  buffer << input.rdbuf();
  const std::string text = buffer.str();

  CaseReviewState state;
  state.profile = extract_json_string(text, "profile");
  state.fast_index = extract_json_string(text, "fast_index") != "false";
  state.selected_machine_key = extract_json_string(text, "selected_machine_key");
  state.selected_job_name = extract_json_string(text, "selected_job_name");
  state.selected_run_key = extract_json_string(text, "selected_run_key");
  state.rescans_only = extract_json_string(text, "rescans_only") == "true";
  state.updated_utc = extract_json_string(text, "updated_utc");
  std::istringstream sources(extract_json_string(text, "sources"));
  std::string line;
  while (std::getline(sources, line)) {
    if (!line.empty())
      state.sources.push_back(std::move(line));
  }
  std::istringstream source_profiles(extract_json_string(text, "source_profiles"));
  while (std::getline(source_profiles, line)) {
    if (line.empty())
      continue;
    std::vector<std::string> fields;
    std::size_t start = 0;
    for (;;) {
      const std::size_t tab = line.find('\t', start);
      fields.push_back(decode_state_field(std::string_view(line).substr(
          start, tab == std::string::npos ? line.size() - start : tab - start)));
      if (tab == std::string::npos)
        break;
      start = tab + 1U;
    }
    if (fields.empty() || fields[0].empty())
      continue;
    CaseReviewSource source;
    source.path = fields[0];
    if (fields.size() > 1U && !fields[1].empty()) source.requested_profile = fields[1];
    if (fields.size() > 2U) source.detected_profile = fields[2];
    if (fields.size() > 3U) source.product_type = fields[3];
    if (fields.size() > 4U) source.product_version = fields[4];
    if (fields.size() > 5U) source.source_owner = fields[5];
    state.source_profiles.push_back(std::move(source));
  }
  // Schema-1 migration: retain the exact legacy profile for every source.
  if (state.source_profiles.empty()) {
    for (const auto& source_path : state.sources) {
      CaseReviewSource source;
      source.path = source_path;
      source.requested_profile = state.profile.empty() ? "automatic" : state.profile;
      state.source_profiles.push_back(std::move(source));
    }
  }
  if (state.profile.empty() || state.sources.empty()) {
    return Result<CaseReviewState>::failure(
        workspace_error("load review state", path, "Saved review state is incomplete"));
  }
  return Result<CaseReviewState>::success(std::move(state));
}

Result<std::string> save_case_evidence_bookmark(const CaseWorkspace& workspace,
                                                CaseEvidenceBookmark bookmark) {
  std::error_code error;
  std::filesystem::create_directories(workspace.evidence, error);
  if (error) {
    return Result<std::string>::failure(
        workspace_error("create evidence directory", workspace.evidence, error.message(), error.value()));
  }
  if (bookmark.scope_type.empty())
    bookmark.scope_type = "case";
  if (bookmark.scope_key.empty())
    bookmark.scope_key = workspace.case_id;
  if (bookmark.evidence_id.empty()) {
    // Reuse the same persisted evidence object when the user marks an item
    // again. Bookmark state and #note inclusion can then be toggled without
    // creating duplicate case artifacts.
    auto existing = load_case_evidence_bookmarks(workspace);
    if (existing.ok()) {
      const auto found = std::find_if(existing.value().begin(), existing.value().end(),
                                      [&](const auto& item) {
        return item.scope_type == bookmark.scope_type && item.scope_key == bookmark.scope_key &&
               item.source_path == bookmark.source_path && item.line_number == bookmark.line_number &&
               item.title == bookmark.title;
      });
      if (found != existing.value().end()) {
        bookmark.evidence_id = found->evidence_id;
        if (bookmark.raw_text.empty()) bookmark.raw_text = found->raw_text;
        if (bookmark.timestamp_original.empty()) bookmark.timestamp_original = found->timestamp_original;
        if (bookmark.timestamp_utc_ms == 0) bookmark.timestamp_utc_ms = found->timestamp_utc_ms;
        if (bookmark.machine_name.empty()) bookmark.machine_name = found->machine_name;
        if (bookmark.job_name.empty()) bookmark.job_name = found->job_name;
        bookmark.created_utc = found->created_utc;
      }
    }
  }
  if (bookmark.evidence_id.empty())
    bookmark.evidence_id = make_uuid_v4();
  if (bookmark.created_utc.empty())
    bookmark.created_utc = utc_now_iso8601();

  const std::filesystem::path path =
      workspace.evidence / (sanitize_case_identifier(bookmark.evidence_id) + ".json");
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    return Result<std::string>::failure(
        workspace_error("save evidence bookmark", path, "Could not create evidence bookmark"));
  }
  output << "{\n"
         << "  \"schema\": 4,\n"
         << "  \"evidence_id\": \"" << json_escape(bookmark.evidence_id) << "\",\n"
         << "  \"scope_type\": \"" << json_escape(bookmark.scope_type) << "\",\n"
         << "  \"scope_key\": \"" << json_escape(bookmark.scope_key) << "\",\n"
         << "  \"title\": \"" << json_escape(bookmark.title) << "\",\n"
         << "  \"machine_name\": \"" << json_escape(bookmark.machine_name) << "\",\n"
         << "  \"job_name\": \"" << json_escape(bookmark.job_name) << "\",\n"
         << "  \"source_path\": \"" << json_escape(bookmark.source_path) << "\",\n"
         << "  \"line_number\": \"" << bookmark.line_number << "\",\n"
         << "  \"timestamp_original\": \"" << json_escape(bookmark.timestamp_original) << "\",\n"
         << "  \"timestamp_utc_ms\": \"" << bookmark.timestamp_utc_ms << "\",\n"
         << "  \"raw_text\": \"" << json_escape(bookmark.raw_text) << "\",\n"
         << "  \"bookmarked\": " << (bookmark.bookmarked ? "true" : "false") << ",\n"
         << "  \"include_in_note\": " << (bookmark.include_in_note ? "true" : "false") << ",\n"
         << "  \"created_utc\": \"" << json_escape(bookmark.created_utc) << "\"\n"
         << "}\n";
  if (!output) {
    return Result<std::string>::failure(
        workspace_error("save evidence bookmark", path, "Failed while writing evidence bookmark"));
  }
  return Result<std::string>::success(bookmark.evidence_id);
}

Result<std::vector<CaseEvidenceBookmark>> load_case_evidence_bookmarks(
    const CaseWorkspace& workspace) {
  std::vector<CaseEvidenceBookmark> bookmarks;
  std::error_code error;
  if (!std::filesystem::exists(workspace.evidence, error))
    return Result<std::vector<CaseEvidenceBookmark>>::success(std::move(bookmarks));

  std::filesystem::directory_iterator iterator(
      workspace.evidence, std::filesystem::directory_options::skip_permission_denied, error);
  if (error) {
    return Result<std::vector<CaseEvidenceBookmark>>::failure(
        workspace_error("load evidence bookmarks", workspace.evidence, error.message(), error.value()));
  }
  const std::filesystem::directory_iterator end;
  for (; iterator != end; iterator.increment(error)) {
    if (error) {
      error.clear();
      continue;
    }
    if (!iterator->is_regular_file(error) || iterator->path().extension() != ".json") {
      error.clear();
      continue;
    }
    std::ifstream input(iterator->path(), std::ios::binary);
    if (!input)
      continue;
    std::ostringstream buffer;
    buffer << input.rdbuf();
    const std::string text = buffer.str();

    CaseEvidenceBookmark bookmark;
    bookmark.evidence_id = extract_json_string(text, "evidence_id");
    bookmark.scope_type = extract_json_string(text, "scope_type");
    bookmark.scope_key = extract_json_string(text, "scope_key");
    bookmark.title = extract_json_string(text, "title");
    bookmark.machine_name = extract_json_string(text, "machine_name");
    bookmark.job_name = extract_json_string(text, "job_name");
    bookmark.source_path = extract_json_string(text, "source_path");
    bookmark.timestamp_original = extract_json_string(text, "timestamp_original");
    const std::string timestamp_utc_ms = extract_json_string(text, "timestamp_utc_ms");
    if (!timestamp_utc_ms.empty()) {
      try {
        bookmark.timestamp_utc_ms = std::stoll(timestamp_utc_ms);
      } catch (...) {
        bookmark.timestamp_utc_ms = 0;
      }
    }
    bookmark.raw_text = extract_json_string(text, "raw_text");
    bookmark.bookmarked = extract_json_bool(text, "bookmarked", true);
    // Schema 1 bookmarks predate the explicit note-evidence flag and were all
    // included in generated notes, so preserve that legacy behavior when the
    // field is absent.
    bookmark.include_in_note = extract_json_bool(text, "include_in_note", true);
    bookmark.created_utc = extract_json_string(text, "created_utc");
    const std::string line_number = extract_json_string(text, "line_number");
    if (!line_number.empty()) {
      try {
        bookmark.line_number = static_cast<std::uint64_t>(std::stoull(line_number));
      } catch (...) {
        bookmark.line_number = 0;
      }
    }
    if (!bookmark.evidence_id.empty())
      bookmarks.push_back(std::move(bookmark));
  }
  std::stable_sort(bookmarks.begin(), bookmarks.end(), [](const auto& left, const auto& right) {
    if (left.timestamp_utc_ms != 0 && right.timestamp_utc_ms != 0 && left.timestamp_utc_ms != right.timestamp_utc_ms)
      return left.timestamp_utc_ms > right.timestamp_utc_ms;
    if (left.timestamp_utc_ms != 0 && right.timestamp_utc_ms == 0) return true;
    if (left.timestamp_utc_ms == 0 && right.timestamp_utc_ms != 0) return false;
    if (left.created_utc != right.created_utc)
      return left.created_utc > right.created_utc;
    return left.evidence_id < right.evidence_id;
  });
  return Result<std::vector<CaseEvidenceBookmark>>::success(std::move(bookmarks));
}

Status delete_case_evidence_bookmark(const CaseWorkspace& workspace, std::string_view evidence_id) {
  if (evidence_id.empty())
    return Status::success();
  const std::filesystem::path path =
      workspace.evidence / (sanitize_case_identifier(evidence_id) + ".json");
  std::error_code error;
  const bool removed = std::filesystem::remove(path, error);
  if (error)
    return Status::failure(workspace_error("delete evidence bookmark", path, error.message(), error.value()));
  static_cast<void>(removed);
  return Status::success();
}

Result<std::filesystem::path> save_case_ticket_note(const CaseWorkspace& workspace,
                                                    std::string_view note_text,
                                                    std::string_view name_hint) {
  if (note_text.empty()) {
    return Result<std::filesystem::path>::failure(
        workspace_error("save ticket note", workspace.root, "The ticket note is empty"));
  }
  std::error_code error;
  std::filesystem::create_directories(workspace.notes, error);
  if (error) {
    return Result<std::filesystem::path>::failure(
        workspace_error("create notes directory", workspace.notes, error.message(), error.value()));
  }
  std::string base = sanitize_case_identifier(name_hint);
  if (base.empty())
    base = "log-review";
  std::string stamp = utc_now_iso8601();
  for (char& c : stamp) {
    if (c == ':' || c == '.' || c == '+' || c == '-')
      c = '_';
  }
  const std::filesystem::path path = workspace.notes / (base + "-" + stamp + ".txt");
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    return Result<std::filesystem::path>::failure(
        workspace_error("save ticket note", path, "Could not create ticket note"));
  }
  output.write(note_text.data(), static_cast<std::streamsize>(note_text.size()));
  if (!output) {
    return Result<std::filesystem::path>::failure(
        workspace_error("save ticket note", path, "Failed while writing ticket note"));
  }
  return Result<std::filesystem::path>::success(path);
}

Status copy_case_artifact(const CaseWorkspace& workspace,
                          const std::filesystem::path& source,
                          std::string_view category) {
  if (source.empty())
    return Status::failure(workspace_error("copy artifact", source, "Source artifact is required"));
  std::filesystem::path destination_root = workspace.reports;
  const std::string folded = ascii_lower(category);
  if (folded == "logs")
    destination_root = workspace.logs;
  else if (folded == "captures")
    destination_root = workspace.captures;
  else if (folded == "baselines")
    destination_root = workspace.baselines;
  else if (folded == "third-party" || folded == "tools")
    destination_root = workspace.third_party;
  else if (folded == "parsed" || folded == "parser" || folded == "log-review")
    destination_root = workspace.parsed / "reports";
  std::error_code error;
  std::filesystem::create_directories(destination_root, error);
  if (error)
    return Status::failure(workspace_error("copy artifact", destination_root, error.message(), error.value()));
  const std::filesystem::path destination = destination_root / source.filename();
  if (std::filesystem::equivalent(source, destination, error) && !error)
    return Status::success();
  error.clear();
  std::filesystem::copy_file(source, destination, std::filesystem::copy_options::overwrite_existing, error);
  if (error)
    return Status::failure(workspace_error("copy artifact", source, error.message(), error.value()));
  return Status::success();
}

} // namespace support_assist
