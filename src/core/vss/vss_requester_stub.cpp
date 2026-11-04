#include "support_assist/vss.hpp"
namespace support_assist {
namespace {
Error unsupported(std::string op) {
  Error e;
  e.component = "VSS";
  e.operation = std::move(op);
  e.message = "VSS is available only in a Windows build running with sufficient privileges.";
  e.elevation_may_help = true;
  return e;
}
} // namespace
Result<std::vector<VssWriterInfo>> enumerate_vss_writers() {
  return Result<std::vector<VssWriterInfo>>::failure(unsupported("enumerate writers"));
}
Result<std::unique_ptr<VssSession>>
create_vss_test_session(const VssTestOptions&, const CancellationToken&, ProgressCallback) {
  return Result<std::unique_ptr<VssSession>>::failure(unsupported("create test session"));
}
} // namespace support_assist
