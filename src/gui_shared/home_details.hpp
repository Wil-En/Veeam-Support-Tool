#pragma once

// What Customer / Lab Home's VEEAM PRODUCTS and VEEAM SERVICES tiles count, as a report each, on
// both editions: the products installed with their version and install date, and the services
// with their state, process and ports (Service and Process Watch's own reading).

#include "quick_tool_reports.hpp"

#include "support_assist/installed_products.hpp"
#include "support_assist/veeam_watch.hpp"

#include <string>
#include <vector>

namespace support_assist::gui {

inline QuickToolReport veeam_products_report(const std::vector<InstalledProduct>& products) {
  QuickToolReport report;
  report.tool = "Veeam products";
  report.headline = products.empty() ? std::string("No Veeam product is installed on this machine")
                                     : std::to_string(products.size()) + (products.size() == 1U ? " Veeam product" : " Veeam products") +
                                           " installed";
  report.headline_tone = ReportTone::normal;
  ReportSection listed;
  listed.title = "Installed";
  for (const auto& product : products) {
    std::string value = product.version.empty() ? std::string("version not recorded") : product.version;
    if (!product.install_date.empty())
      value += ", installed " + product.install_date;
    if (product.hidden)
      value += " (a component Programs and Features does not list)";
    listed.rows.push_back({product.name, value, ReportTone::normal, -1.0});
  }
  if (!listed.rows.empty())
    report.sections.push_back(std::move(listed));
  return report;
}

inline QuickToolReport veeam_services_report(const WatchSnapshot& snapshot) {
  QuickToolReport report;
  report.tool = "Veeam services";
  ReportSection services;
  services.title = "Services";
  std::size_t running = 0;
  for (const auto& item : snapshot.items) {
    if (item.kind != WatchKind::service)
      continue;
    const bool up = item.state == "running";
    running += up ? 1U : 0U;
    std::string value = item.state;
    if (item.pid != 0U)
      value += ", PID " + std::to_string(item.pid);
    if (!item.listening.empty())
      value += ", listening on " + item.listening;
    services.rows.push_back({item.display_name.empty() ? item.name : item.display_name + " (" + item.name + ")", value,
                             up ? ReportTone::normal : ReportTone::attention, -1.0});
  }
  report.headline = services.rows.empty()
                        ? std::string("No Veeam service on this machine")
                        : std::to_string(running) + " of " + std::to_string(services.rows.size()) +
                              (services.rows.size() == 1U ? " Veeam service" : " Veeam services") + " running";
  report.headline_tone = running < services.rows.size() ? ReportTone::attention : ReportTone::normal;
  if (!services.rows.empty())
    report.sections.push_back(std::move(services));
  if (!snapshot.note.empty())
    report.notes.push_back(snapshot.note);
  return report;
}

} // namespace support_assist::gui
