#pragma once

#include <atomic>
#include <memory>

namespace support_assist {

class CancellationToken {
public:
  CancellationToken() : state_(std::make_shared<std::atomic_bool>(false)) {}
  void cancel() const noexcept {
    state_->store(true, std::memory_order_relaxed);
  }
  [[nodiscard]] bool is_cancelled() const noexcept {
    return state_->load(std::memory_order_relaxed);
  }

private:
  explicit CancellationToken(std::shared_ptr<std::atomic_bool> state) : state_(std::move(state)) {}
  friend class CancellationSource;
  std::shared_ptr<std::atomic_bool> state_;
};

class CancellationSource {
public:
  CancellationSource() : state_(std::make_shared<std::atomic_bool>(false)) {}
  [[nodiscard]] CancellationToken token() const {
    return CancellationToken(state_);
  }
  void cancel() const noexcept {
    state_->store(true, std::memory_order_relaxed);
  }
  [[nodiscard]] bool is_cancelled() const noexcept {
    return state_->load(std::memory_order_relaxed);
  }

private:
  std::shared_ptr<std::atomic_bool> state_;
};

} // namespace support_assist
