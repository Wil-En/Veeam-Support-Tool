// Diagnostics as one page on Windows: System information, Products and integrations and the SAT
// Self-Test in one report (gui_shared/diagnostics_report.hpp), read on a worker when the
// page opens and again on Run again.

#include "app_window.hpp"

#include "diagnostics_report.hpp"
#include "integration_state.hpp"
#include "quick_tool_reports.hpp"
#include "report_panel.hpp"
#include "ui_theme.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/tool_catalog.hpp"

#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace gui = support_assist::gui;

constexpr UINT kDiagnosticsReportMessage = WM_APP + 10;
constexpr int kDiagnosticsRunId = 8170;
constexpr int kDiagnosticsCopyId = 8171;

std::string text_of(const std::wstring& text) { return support_assist::utf8_from_wide(text); }

} // namespace

void AppWindow::create_diagnostics_page() {
  const ReportPanelStyle style{card_font_, heading_font_, ui_font_, small_font_, ui_scale_percent_};
  diagnostics_report_ = create_report_panel(window_, instance_, style);
  set_report_panel_empty(diagnostics_report_, L"Reading this machine...");
  const auto make_button = [&](const wchar_t* text, int id) {
    HWND button = CreateWindowExW(0, WC_BUTTONW, text, WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 0, 0, window_,
                                  reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), instance_, nullptr);
    SendMessageW(button, WM_SETFONT, reinterpret_cast<WPARAM>(ui_font_), TRUE);
    apply_control_theme(button);
    return button;
  };
  diagnostics_run_ = make_button(L"Run again", kDiagnosticsRunId);
  diagnostics_copy_ = make_button(L"Copy", kDiagnosticsCopyId);
  EnableWindow(diagnostics_copy_, FALSE);
}

void AppWindow::refresh_diagnostics_report() {
  if (diagnostics_reading_ || diagnostics_report_ == nullptr)
    return;
  diagnostics_reading_ = true;
  EnableWindow(diagnostics_run_, FALSE);
  set_status_message(L"Diagnostics: reading this machine, its Veeam products and SAT's self-test...");
  if (diagnostics_worker_.joinable())
    diagnostics_worker_.join();
  // The Integrations page's folder, read here: settings belong to this thread.
  diagnostics_worker_ = std::jthread([this, window = window_, tools_root = default_tools_folder()](std::stop_token) {
    const auto read = [this](int mode) {
      OperationRequest request{};
      request.page = Page::diagnostics;
      request.mode = mode;
      return run_diagnostics(request);
    };
    auto input = std::make_unique<gui::DiagnosticsInput>();
    for (const Row& row : read(1).rows)
      input->system.push_back({text_of(row[1]), text_of(row[2]), gui::ReportTone::normal});
    // The Veeam products first, then the integrations SAT knows, as the Integrations page shows them.
    for (const Row& row : installed_veeam_product_rows()) {
      const std::wstring where = row[2].empty() ? std::wstring() : L" | " + row[2];
      input->products.push_back({text_of(row[1]), text_of(row[3] + where), gui::ReportTone::normal});
    }
    for (auto& row : gui::integration_report_rows(support_assist::inspect_external_tools(tools_root), tools_root))
      input->products.push_back(std::move(row));
    for (const Row& row : read(4).rows)
      input->self_test.push_back({text_of(row[1]), text_of(row[2]),
                                  row[3] == L"PASS" ? gui::ReportTone::good : gui::ReportTone::problem});
    // What the tools need on this machine, read only.
    input->requirements = gui::requirement_report_rows(support_assist::read_tool_requirements(tools_root));
    input->read_unix_millis = support_assist::unix_millis_now();
    if (PostMessageW(window, kDiagnosticsReportMessage, 0, reinterpret_cast<LPARAM>(input.get())) != FALSE)
      static_cast<void>(input.release());
  });
}

bool AppWindow::handle_diagnostics_message(UINT message, WPARAM, LPARAM lparam) {
  if (message != kDiagnosticsReportMessage)
    return false;
  std::unique_ptr<gui::DiagnosticsInput> input(reinterpret_cast<gui::DiagnosticsInput*>(lparam));
  diagnostics_reading_ = false;
  EnableWindow(diagnostics_run_, TRUE);
  gui::QuickToolReport report = gui::diagnostics_report(std::move(*input));
  set_report_panel_report(diagnostics_report_, report);
  EnableWindow(diagnostics_copy_, TRUE);
  if (page_ == Page::diagnostics)
    set_status_message(support_assist::wide_from_utf8(report.headline));
  diagnostics_last_ = std::move(report);
  return true;
}

bool AppWindow::handle_diagnostics_command(int id) {
  if (id == kDiagnosticsRunId) {
    refresh_diagnostics_report();
    return true;
  }
  if (id == kDiagnosticsCopyId) {
    if (diagnostics_last_ && copy_text_to_clipboard(support_assist::wide_from_utf8(gui::report_text(*diagnostics_last_))))
      set_status_message(L"Diagnostics copied.");
    return true;
  }
  return false;
}

void AppWindow::layout_diagnostics_page(int left, int top, int width, int height) {
  const int button_height = sx(32);
  MoveWindow(diagnostics_run_, left, top, sx(130), button_height, TRUE);
  MoveWindow(diagnostics_copy_, left + sx(140), top, sx(100), button_height, TRUE);
  const int report_top = top + button_height + sx(10);
  MoveWindow(diagnostics_report_, left, report_top, width, std::max(0, top + height - report_top), TRUE);
}
