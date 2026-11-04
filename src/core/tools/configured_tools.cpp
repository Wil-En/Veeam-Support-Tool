#include "support_assist/configured_tools.hpp"

#include "support_assist/strings.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <system_error>

namespace support_assist {
namespace {

Error tool_error(std::string operation, std::string message) {
  Error error;
  error.component = "ConfiguredTools";
  error.operation = std::move(operation);
  error.message = std::move(message);
  return error;
}

// Tab separates the fields, so a tab inside one would silently split a record and shift every
// field after it. Escaped rather than rejected, because a Windows argument line can legitimately
// contain almost anything.
std::string encode_field(std::string_view value) {
  std::string encoded;
  encoded.reserve(value.size());
  for (const char character : value) {
    switch (character) {
    case '\\': encoded += "\\\\"; break;
    case '\t': encoded += "\\t"; break;
    case '\r': encoded += "\\r"; break;
    case '\n': encoded += "\\n"; break;
    default: encoded.push_back(character); break;
    }
  }
  return encoded;
}

std::string decode_field(std::string_view value) {
  std::string decoded;
  decoded.reserve(value.size());
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (value[index] != '\\' || index + 1U >= value.size()) {
      decoded.push_back(value[index]);
      continue;
    }
    ++index;
    switch (value[index]) {
    case 't': decoded.push_back('\t'); break;
    case 'r': decoded.push_back('\r'); break;
    case 'n': decoded.push_back('\n'); break;
    case '\\': decoded.push_back('\\'); break;
    default: decoded.push_back(value[index]); break;
    }
  }
  return decoded;
}

// Split on whitespace, honouring double quotes, so a path with spaces stays one argument. This is
// NOT shell parsing: there is no expansion, no globbing and no operator handling, because the
// result goes straight to the process as an argument vector.
std::vector<std::string> split_arguments(std::string_view text) {
  std::vector<std::string> arguments;
  std::string current;
  bool quoted = false;
  bool has_content = false;
  for (const char character : text) {
    if (character == '"') {
      quoted = !quoted;
      has_content = true;
      continue;
    }
    if (!quoted && (character == ' ' || character == '\t')) {
      if (has_content) {
        arguments.push_back(current);
        current.clear();
        has_content = false;
      }
      continue;
    }
    current.push_back(character);
    has_content = true;
  }
  if (has_content)
    arguments.push_back(current);
  return arguments;
}

} // namespace

Status validate_configured_tool(const ConfiguredTool& tool) {
  if (trim(tool.name).empty())
    return Status::failure(tool_error("validate", "Give the tool a name so it can be told apart in the list."));
  if (tool.executable.empty())
    return Status::failure(tool_error("validate", "Choose the executable this entry runs."));

  // An absolute path only.
  //
  // A relative one resolves against whatever the working directory happens to be at launch, so the
  // same entry could run different executables on different days - and the engineer reviewing the
  // list could not tell which. This is the entire security value of the explicit-entry design and
  // it must not be negotiable.
  if (!tool.executable.is_absolute()) {
    return Status::failure(tool_error(
        "validate",
        "Enter the full path to the executable. A relative path resolves against the working "
        "directory at launch, so the entry would not always run the same program: " +
            path_to_utf8(tool.executable)));
  }

  std::error_code error;
  if (!std::filesystem::exists(tool.executable, error) || error) {
    return Status::failure(tool_error(
        "validate", "That executable is not there: " + path_to_utf8(tool.executable)));
  }
  if (!std::filesystem::is_regular_file(tool.executable, error) || error) {
    return Status::failure(tool_error(
        "validate", "That path is not a file: " + path_to_utf8(tool.executable)));
  }
  return Status::success();
}

Result<std::vector<std::string>> expand_tool_arguments(std::string_view arguments,
                                                       const ToolLaunchContext& context) {
  std::string expanded;
  expanded.reserve(arguments.size() + 128U);

  for (std::size_t index = 0; index < arguments.size(); ++index) {
    if (arguments[index] != '{') {
      expanded.push_back(arguments[index]);
      continue;
    }
    const std::size_t close = arguments.find('}', index);
    if (close == std::string_view::npos) {
      expanded.push_back(arguments[index]);
      continue;
    }
    const std::string_view name = arguments.substr(index + 1U, close - index - 1U);
    const std::filesystem::path* value = nullptr;
    if (name == "case")
      value = &context.case_root;
    else if (name == "evidence")
      value = &context.evidence_path;
    else if (name == "selected")
      value = &context.selected_path;

    if (value == nullptr) {
      // Not a placeholder SAT knows. Far more likely to be a literal brace the tool wants than a
      // typo worth failing over, so it is passed through unchanged.
      expanded.push_back(arguments[index]);
      continue;
    }
    if (value->empty()) {
      // Refuse rather than substitute nothing. An empty expansion silently changes what the tool
      // is pointed at - most often to the working directory - and the engineer would have no way
      // to see that from the launch.
      return Result<std::vector<std::string>>::failure(tool_error(
          "expand arguments",
          "This entry uses {" + std::string(name) +
              "}, and there is nothing to put there yet. Open a case and select the evidence "
              "first, or remove the placeholder from the argument line."));
    }
    expanded += path_to_utf8(*value);
    index = close;
  }

  return Result<std::vector<std::string>>::success(split_arguments(expanded));
}

std::string default_configured_tools_file_contents() {
  // Tab separated, six fields. Written as comments so a first run explains the format instead of
  // presenting an empty file, and so nothing is launched until an engineer removes a '#'.
  return "# Support Assist Tool - external tools\n"
         "#\n"
         "# One tool per line, TAB separated, six fields:\n"
         "#\n"
         "#   id <TAB> name <TAB> executable <TAB> arguments <TAB> start-in-case <TAB> notes\n"
         "#\n"
         "#   id             anything unique; it never appears in the interface\n"
         "#   name           what the button says\n"
         "#   executable     an ABSOLUTE path to a .exe; a bare name is refused\n"
         "#   arguments      may be empty. {case} {evidence} {selected} are substituted\n"
         "#   start-in-case  1 to start in the active case folder, 0 for the tool's own\n"
         "#   notes          may be empty; shown beside the tool\n"
         "#\n"
         "# Remove the leading '#' from a line below and edit it, or add your own. Restart SAT to\n"
         "# pick up the change. A tool runs at SAT's own privilege level.\n"
         "#\n"
         "# notepad\tNotepad\tC:\\Windows\\System32\\notepad.exe\t\t1\tExample - edit and uncomment\n";
}

Result<std::vector<ConfiguredTool>> load_configured_tools(const std::filesystem::path& file) {
  std::vector<ConfiguredTool> tools;
  // Ask the query for its ANSWER, never for its answer OR its error code: MSVC may leave a
  // benign code set after a successful test, and libstdc++ clears it.
  std::error_code error;
  if (!std::filesystem::exists(file, error))
    return Result<std::vector<ConfiguredTool>>::success(std::move(tools));

  std::ifstream input(file, std::ios::binary);
  if (!input) {
    return Result<std::vector<ConfiguredTool>>::failure(
        tool_error("load", "The configured tools file could not be read: " + path_to_utf8(file)));
  }

  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    if (line.empty() || line.front() == '#')
      continue;
    const auto fields = split(line, '\t');
    if (fields.size() < 5U)
      continue;                     // a short record is a hand-edit mistake, not a tool
    ConfiguredTool tool;
    tool.id = decode_field(fields[0]);
    tool.name = decode_field(fields[1]);
    tool.executable = std::filesystem::path(decode_field(fields[2]));
    tool.arguments = decode_field(fields[3]);
    tool.start_in_case_folder = decode_field(fields[4]) == "1";
    if (fields.size() > 5U)
      tool.notes = decode_field(fields[5]);
    tools.push_back(std::move(tool));
  }
  return Result<std::vector<ConfiguredTool>>::success(std::move(tools));
}

Status save_configured_tools(const std::filesystem::path& file,
                             const std::vector<ConfiguredTool>& tools) {
  std::error_code error;
  std::filesystem::create_directories(file.parent_path(), error);
  std::ofstream output(file, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(tool_error("save", "Could not write " + path_to_utf8(file)));

  output << "# Support Assist Tool - configured external tools\n"
         << "# id\tname\texecutable\targuments\tstart_in_case_folder\tnotes\n"
         << "# Placeholders in arguments: {case} {evidence} {selected}\n"
         << "# SAT launches only what is listed here.\n";
  for (const auto& tool : tools) {
    output << encode_field(tool.id) << '\t' << encode_field(tool.name) << '\t'
           << encode_field(path_to_utf8(tool.executable)) << '\t' << encode_field(tool.arguments)
           << '\t' << (tool.start_in_case_folder ? "1" : "0") << '\t' << encode_field(tool.notes)
           << '\n';
  }
  output.flush();
  if (!output)
    return Status::failure(tool_error("save", "Could not completely write " + path_to_utf8(file)));
  return Status::success();
}

} // namespace support_assist
