#include "support_assist/security.hpp"

#include <cstdlib>
#include <utility>

namespace support_assist {

Result<SecurityContext> current_security_context() {
  SecurityContext context;
  const char* user = std::getenv("USER");
  context.user = user != nullptr ? user : "unknown";
  return Result<SecurityContext>::success(std::move(context));
}

Status enable_privilege(std::string_view) {
  Error error;
  error.component = "Security";
  error.operation = "enable privilege";
  error.message = "Windows privilege APIs are unavailable in this build.";
  return Status::failure(std::move(error));
}

} // namespace support_assist
