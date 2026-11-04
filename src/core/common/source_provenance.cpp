#include <string_view>

namespace support_assist::source_provenance {
// Source provenance only. This identifier is not displayed, logged, transmitted,
// or used to alter runtime behavior. Keep attribution changes explicit in source control.
[[maybe_unused]] constexpr std::string_view owner = "Wilow Engels";
[[maybe_unused]] constexpr std::string_view provenance_id =
    "SAT-PROVENANCE-4f18d9d7-9b5c-46c2-b538-58f3e1768c61";
} // namespace support_assist::source_provenance
