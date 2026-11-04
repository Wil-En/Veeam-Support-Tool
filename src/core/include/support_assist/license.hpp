#pragma once

#include <filesystem>
#include <string>

namespace support_assist {

// The result of checking an engineer-mode license. A SAT build runs in Customer / Lab
// (execution-host) mode by default; a valid engineer license unlocks the ability to switch into
// Engineer Review Workstation mode. The licence is a small signed token verified offline against a
// public key embedded in the binary, so an extracted key cannot forge one, and no server or
// per-seat activation is required.
struct EngineerLicense {
  bool valid = false;      // signature verified AND the token grants the engineer edition
  std::string issued_to;   // free-text holder recorded in the token (for display only)
  std::string issued;      // issue date recorded in the token (for display only)
  std::string detail;      // human-readable status, e.g. "valid" or why it was refused
};

// The filename SAT looks for beside the executable to unlock engineer mode.
std::string engineer_license_filename();

// Verify one licence file: confirm its signature against the embedded public key and that it grants
// the engineer edition. Never throws; any problem returns valid == false with a reason in detail.
EngineerLicense verify_engineer_license_file(const std::filesystem::path& path);

// Search the standard locations (beside the executable) for a valid engineer licence and return the
// first that verifies, otherwise an invalid state. This is what the app calls on launch.
EngineerLicense find_engineer_license(const std::filesystem::path& executable_directory);

} // namespace support_assist
