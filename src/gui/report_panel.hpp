#pragma once

// A quick tool's result on Windows: the report from gui_shared/quick_tool_reports.hpp drawn as a
// headline in its tone's colour and a card per section, scrolled when it is taller than the panel.

#include "quick_tool_reports.hpp"

#include <winsock2.h>
#include <windows.h>

#include <string>
#include <string_view>

struct ReportPanelStyle {
  HFONT headline = nullptr;
  HFONT title = nullptr;  // section titles
  HFONT text = nullptr;   // row values
  HFONT caption = nullptr; // row labels, notes
  int scale_percent = 100;
};

HWND create_report_panel(HWND parent, HINSTANCE instance, const ReportPanelStyle& style);
void set_report_panel_style(HWND panel, const ReportPanelStyle& style);
void set_report_panel_report(HWND panel, const support_assist::gui::QuickToolReport& report);
// No report: the panel shows this text instead, centred.
void set_report_panel_empty(HWND panel, const std::wstring& text);
// Text every panel draws passes through this filter when one is set: the screenshot harness's
// redaction of names. A shipped build sets none.
void set_report_panel_text_filter(std::wstring (*filter)(std::wstring_view));
