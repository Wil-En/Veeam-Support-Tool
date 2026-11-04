#pragma once
#include "support_assist/cancellation.hpp"
#include <string>
#include <vector>
namespace support_assist::cli {
int dispatch(const std::vector<std::string>& args, const CancellationToken& cancel);
void print_help();
} // namespace support_assist::cli
