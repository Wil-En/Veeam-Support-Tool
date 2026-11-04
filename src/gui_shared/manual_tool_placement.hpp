#pragma once

// Getting a tool without an engineer licence. A licensed copy of SAT downloads a tool from its
// official source into the Tools folder. An unlicensed copy downloads nothing: Acquire and Update
// open the tool's official page and show the folder to place the tool in by hand, with Copy path
// and Open folder. Both editions show this text.

#include "support_assist/strings.hpp"
#include "support_assist/tool_catalog.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>

namespace support_assist::gui {

struct ManualToolPlacement {
  std::string title;             // "Get DiskSpd"
  std::string instruction;       // the heading
  std::string steps;             // what to do, ending at the folder
  std::filesystem::path folder;  // where the tool goes: Tools/<id>
  std::string after;             // what to do once it is there
  std::string page;              // the official page
};

// What the Integrations page says about downloading, by licence.
inline std::string tool_download_note(bool licensed) {
  return licensed ? "Acquire downloads it from the official source into the tools folder after you confirm; "
                    "Remove copy deletes that copy."
                  : "Downloading needs an engineer licence: Acquire names the official page and the folder to "
                    "place the tool in.";
}

inline ManualToolPlacement manual_tool_placement(std::string_view tool_id, const std::filesystem::path& tools_root,
                                                 bool page_opened) {
  const ExternalToolDefinition* tool = nullptr;
  for (const ExternalToolDefinition& candidate : external_tool_catalog()) {
    if (candidate.id == tool_id)
      tool = &candidate;
  }
  const std::string name = tool != nullptr ? tool->name : std::string(tool_id);
  std::string files;
  if (tool != nullptr) {
    for (std::size_t index = 0; index < tool->executable_names.size() && index < 2U; ++index)
      files += (index == 0U ? std::string() : std::string(" or ")) + tool->executable_names[index];
  }
  ManualToolPlacement placement;
  placement.title = "Get " + name;
  placement.instruction = "Downloading a tool needs an engineer licence";
  placement.steps = "This copy of SAT has none. " +
                    (page_opened ? name + "'s official page is open in your browser"
                                 : "Open " + name + "'s official page") +
                    ": download it there, then place " + (files.empty() ? std::string("the tool") : files) +
                    " in this folder (a subfolder in it is fine):";
  placement.folder = tools_root / path_from_utf8(std::string(tool_id));
  placement.after = "Then choose Refresh on the Integrations page.";
  if (tool != nullptr)
    placement.page = tool->source_url;
  return placement;
}

// The whole prompt as plain text: the fallback message box and the tests.
inline std::string manual_tool_placement_text(const ManualToolPlacement& placement) {
  std::string text = placement.instruction + ".\n\n" + placement.steps + "\n\n" + path_to_utf8(placement.folder) +
                     "\n\n" + placement.after;
  if (!placement.page.empty())
    text += "\n\nOfficial page: " + placement.page;
  return text;
}

} // namespace support_assist::gui
