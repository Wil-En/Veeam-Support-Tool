// The data files the build embeds (SUPPORT_ASSIST_DATA_FILES in CMakeLists.txt), parsed once each.
#include "support_assist/data_files.hpp"

#include <cstddef>
#include <map>
#include <mutex>

namespace support_assist {
namespace {

struct EmbeddedDataFile {
  const char* name;
  const unsigned char* data;
  std::size_t size;
};

#include "support_assist/embedded_data_files.inc"

} // namespace

std::string_view embedded_data_file(std::string_view name) {
  for (const EmbeddedDataFile& file : kEmbeddedDataFiles) {
    if (name == file.name)
      return {reinterpret_cast<const char*>(file.data), file.size};
  }
  return {};
}

std::vector<std::string> embedded_data_file_names() {
  std::vector<std::string> names;
  for (const EmbeddedDataFile& file : kEmbeddedDataFiles)
    names.emplace_back(file.name);
  return names;
}

const JsonValue& data_file(std::string_view name) {
  static std::mutex lock;
  static std::map<std::string, JsonValue, std::less<>> parsed;
  static const JsonValue missing;
  const std::lock_guard<std::mutex> guard(lock);
  if (const auto found = parsed.find(name); found != parsed.end())
    return found->second;
  const std::string_view text = embedded_data_file(name);
  if (text.empty())
    return missing;
  auto result = parse_json(text);
  auto& slot = parsed[std::string(name)];
  if (result.ok())
    slot = std::move(result.value());
  return slot;
}

} // namespace support_assist
