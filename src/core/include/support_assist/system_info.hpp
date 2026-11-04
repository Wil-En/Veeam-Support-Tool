#pragma once
#include "support_assist/models.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace support_assist {
SnapshotMetadata
make_snapshot_metadata(SnapshotKind kind, std::string user_scope, std::string options_json = "{}");

// The Windows filesystem minifilter load-order group that owns `altitude`.
//
// Microsoft allocates minifilter altitudes in documented bands by class, so the band alone says
// what a filter DOES - anti-virus, replication, encryption, HSM - without needing to recognise the
// filter itself. That is most of the diagnostic value when a third-party filter sitting above the
// volume is the cause of a VSS or I/O failure.
//
// Source: Microsoft "Allocated altitudes" (Installable File System drivers).
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes
//
// Altitudes outside the documented bands return no value. They are reported as unrecognised rather
// than guessed at: a wrong attribution in support evidence is worse than none.
std::optional<std::string_view> minifilter_altitude_group(std::uint32_t altitude);

// Parses one `fltmc instances` row and returns its altitude, if the row carries one.
//
// The command prints a fixed-column table whose columns are separated by runs of spaces:
//   Filter          Volume Name       Altitude   Instance Name        Frame  SprtFtrs  VlStatus
// Header, rule and blank rows return no value.
std::optional<std::uint32_t> parse_minifilter_altitude(std::string_view row);
} // namespace support_assist
