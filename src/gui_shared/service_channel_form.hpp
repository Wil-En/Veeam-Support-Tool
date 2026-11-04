#pragma once

// The Veeam Service Channel form for both editions: its fields to the test's options, and to the
// CLI's arguments for Show CLI (support_assist/service_channel.hpp runs the test).

#include "support_assist/service_channel.hpp"
#include "support_assist/strings.hpp"

#include <cstdlib>
#include <string>
#include <vector>

namespace support_assist::gui {

inline constexpr int kServiceChannelMode = 27;

inline ServiceChannelOptions service_channel_options(const std::string& product, const std::string& folder,
                                                     const std::string& hours, bool logs_only) {
  ServiceChannelOptions options;
  const std::string chosen(trim(product));
  options.product = chosen.empty() ? std::string("agent") : ascii_lower(chosen.substr(0, chosen.find(' ')));
  if (!trim(folder).empty())
    options.log_folder = path_from_utf8(trim(folder));
  const int parsed = std::atoi(std::string(trim(hours)).c_str());
  options.hours = parsed > 0 ? parsed : 24;
  options.live = !logs_only;
  return options;
}

inline std::vector<std::string> service_channel_cli_arguments(const ServiceChannelOptions& options) {
  std::vector<std::string> arguments{"network", "service-channel", "--product", options.product};
  if (!options.log_folder.empty()) {
    arguments.push_back("--folder");
    arguments.push_back(path_to_utf8(options.log_folder));
  }
  if (options.hours != 24) {
    arguments.push_back("--hours");
    arguments.push_back(std::to_string(options.hours));
  }
  if (!options.live)
    arguments.push_back("--logs-only");
  return arguments;
}

} // namespace support_assist::gui
