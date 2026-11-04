#pragma once

// VSS Tools' test snapshot: the writers it includes, ticked in a list of the writers an Enumerate
// writers run found (SQL Server, Active Directory, Exchange and the rest a machine carries), instead
// of typed class ids.

#include <winsock2.h>
#include <windows.h>

#include <optional>
#include <string>
#include <vector>

struct VssWriterChoice {
  std::wstring name;
  std::wstring class_id;
};

// The class ids ticked, in the list's order; nothing when the engineer cancels. `ticked` are the
// class ids already in the field.
std::optional<std::vector<std::wstring>> pick_vss_writers(HWND owner, HINSTANCE instance,
                                                          const std::vector<VssWriterChoice>& writers,
                                                          const std::vector<std::wstring>& ticked, HFONT font);
