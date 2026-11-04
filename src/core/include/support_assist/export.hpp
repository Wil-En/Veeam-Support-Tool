#pragma once

#include "support_assist/version.hpp"
#include "support_assist/error.hpp"
#include "support_assist/models.hpp"
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
namespace support_assist {
enum class ExportFormat { text, json, csv, html };
Result<ExportFormat> parse_export_format(std::string_view text);
class DiffWriter {
public:
  DiffWriter() = default;
  ~DiffWriter();
  DiffWriter(const DiffWriter&) = delete;
  DiffWriter& operator=(const DiffWriter&) = delete;
  DiffWriter(DiffWriter&&) noexcept;
  DiffWriter& operator=(DiffWriter&&) noexcept;
  static Result<DiffWriter> open(const std::filesystem::path& path,
                                 ExportFormat format,
                                 std::string title = std::string(kProductName) + " Comparison");
  Status write(const DiffRecord& record);
  Status finish();

private:
  explicit DiffWriter(std::ofstream stream, ExportFormat format, std::string title);
  std::ofstream stream_;
  ExportFormat format_ = ExportFormat::text;
  std::string title_;
  bool first_ = true;
  bool finished_ = false;
};
Status export_log_matches(const std::filesystem::path& path,
                          ExportFormat format,
                          const std::vector<LogMatch>& matches);
} // namespace support_assist
