#pragma once
#include <cstdint>
#include <string>
int run_elevated_pipe_client(const std::wstring& pipe_name,
                             const std::string& expected_nonce,
                             std::uint32_t parent_pid);
