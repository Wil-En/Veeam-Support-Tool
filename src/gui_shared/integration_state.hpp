#pragma once

// The state of a known tool as both editions' Integrations and Diagnostics pages show it: built into
// the operating system, detected where it was installed, managed in SAT's tools folder, not present,
// or not applicable (a tool for the other platform).

#include "support_assist/strings.hpp"
#include "support_assist/tool_catalog.hpp"

#include <filesystem>
#include <string>

namespace support_assist::gui {

enum class IntegrationState { built_in, detected, managed, not_present, not_applicable };

// Whether a path is the folder or inside it. Windows paths compare without case and with either
// separator; a sibling that only starts with the same name ("Tools-old") is not inside "Tools".
inline bool path_is_inside(const std::filesystem::path& path, const std::filesystem::path& folder) {
  std::string inner = path_to_utf8(path);
  std::string outer = path_to_utf8(folder);
#ifdef _WIN32
  for (std::string* text : {&inner, &outer}) {
    for (char& character : *text) {
      if (character >= 'A' && character <= 'Z')
        character = static_cast<char>(character - 'A' + 'a');
      else if (character == '\\')
        character = '/';
    }
  }
#endif
  while (outer.size() > 1U && outer.back() == '/')
    outer.pop_back();
  if (outer.empty() || inner.size() < outer.size() || inner.compare(0, outer.size(), outer) != 0)
    return false;
  return inner.size() == outer.size() || inner[outer.size()] == '/' || outer.back() == '/';
}

inline IntegrationState integration_state(const ExternalToolStatus& tool, const std::filesystem::path& managed_root) {
  if (tool.availability == ToolAvailability::unsupported)
    return IntegrationState::not_applicable;
  if (tool.availability != ToolAvailability::available)
    return IntegrationState::not_present;
  if (tool.definition.bundled_by_windows)
    return IntegrationState::built_in;
  return !managed_root.empty() && path_is_inside(tool.resolved_path, managed_root) ? IntegrationState::managed
                                                                                   : IntegrationState::detected;
}

inline std::string integration_state_text(IntegrationState state) {
  switch (state) {
  case IntegrationState::built_in:
    return "Built-in";
  case IntegrationState::detected:
    return "Detected";
  case IntegrationState::managed:
    return "Managed";
  case IntegrationState::not_present:
    return "Not present";
  case IntegrationState::not_applicable:
    return "Not applicable";
  }
  return "Not present";
}

} // namespace support_assist::gui
