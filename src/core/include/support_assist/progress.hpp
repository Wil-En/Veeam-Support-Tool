#pragma once
#include <cstdint>
#include <functional>
#include <string>
namespace support_assist {
struct ProgressEvent {
  std::string phase;
  std::string current_scope;
  std::uint64_t processed = 0;
  std::uint64_t errors = 0;
  double elapsed_seconds = 0.0;
  double items_per_second = 0.0;
  // Optional bounded total for operations that know their full extent (for example a VSS hold).
  // Kept last so existing aggregate initializers remain source-compatible.
  std::uint64_t total = 0;
};
using ProgressCallback = std::function<void(const ProgressEvent&)>;
} // namespace support_assist
