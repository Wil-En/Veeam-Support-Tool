#pragma once
#include "portable_workspace_model.hpp"

namespace support_assist::gui {

inline std::vector<PortableCapability> linux_capability_catalog(bool ssh_available,
                                                                 bool native_odbc_available = false) {
  return portable_tool_catalog(PortablePlatform::linux, ssh_available, native_odbc_available);
}

inline std::vector<PortableCapability> macos_capability_catalog(bool ssh_available,
                                                                 bool native_odbc_available = false) {
  return portable_tool_catalog(PortablePlatform::macos, ssh_available, native_odbc_available);
}

inline std::string capability_state_label(PortableCapabilityState state) {
#if defined(__APPLE__)
  return capability_state_label(state, PortablePlatform::macos);
#else
  return capability_state_label(state, PortablePlatform::linux);
#endif
}

} // namespace support_assist::gui
