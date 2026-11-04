#pragma once
#include "support_assist/error.hpp"
#include <string>
#include <vector>
namespace support_assist {
struct SecurityContext {
  bool elevated = false;
  std::string user;
  std::uint32_t session_id = 0;
  std::vector<std::string> enabled_privileges;
};
Result<SecurityContext> current_security_context();
Status enable_privilege(std::string_view privilege_name);
} // namespace support_assist
