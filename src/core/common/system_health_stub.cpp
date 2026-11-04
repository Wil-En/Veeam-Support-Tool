#include "support_assist/system_health.hpp"
#include "support_assist/time.hpp"
#include <memory>
namespace support_assist {
struct SystemHealthSampler::Impl {};
SystemHealthSampler::SystemHealthSampler():impl_(std::make_unique<Impl>()){}
SystemHealthSampler::~SystemHealthSampler()=default;
SystemHealthSampler::SystemHealthSampler(SystemHealthSampler&&) noexcept=default;
SystemHealthSampler& SystemHealthSampler::operator=(SystemHealthSampler&&) noexcept=default;
Result<SystemHealthSnapshot> SystemHealthSampler::sample(const SystemHealthSampleOptions&) {
  SystemHealthSnapshot snapshot;
  snapshot.captured_utc=utc_now_iso8601();
  snapshot.warnings.push_back("System Health Monitor is not implemented for this operating system target.");
  evaluate_system_health(snapshot);
  return Result<SystemHealthSnapshot>::success(std::move(snapshot));
}
} // namespace support_assist
