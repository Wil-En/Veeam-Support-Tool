#pragma once

// The Running Jobs window, shared by both GUIs: one row per session tab, with its state, how long
// it has run and its newest progress report. Running jobs are listed first. A row opens its
// session, and a running job can be cancelled from the list.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

namespace support_assist::gui {

enum class JobState { running, cancelling, finalizing, finished, not_run };

struct JobEntry {
  std::size_t key = 0;   // the frontend's own handle for the session
  std::string session;   // the tab's title
  std::string page;      // the page the tab belongs to
  std::string case_id;   // the case the session works in; empty without one
  JobState state = JobState::not_run;
  std::chrono::seconds elapsed{0};  // while running: how long it has run
  std::string progress;  // the newest progress report or status line
};

inline constexpr const char* kJobColumns[] = {"Session", "Page", "Case", "State", "Progress"};
inline constexpr int kJobColumnCount = 5;

inline std::string job_elapsed_text(std::chrono::seconds elapsed) {
  const long long seconds = std::max<long long>(0, elapsed.count());
  const long long remainder = seconds % 60;
  return std::to_string(seconds / 60) + ":" + (remainder < 10 ? "0" : "") +
         std::to_string(remainder);
}

inline std::string job_state_text(const JobEntry& job) {
  switch (job.state) {
  case JobState::running:
    return "Running " + job_elapsed_text(job.elapsed);
  case JobState::cancelling:
    return "Cancelling";
  case JobState::finalizing:
    return "Finalizing output";
  case JobState::finished:
    return "Finished";
  case JobState::not_run:
    break;
  }
  return "Not run";
}

inline std::string job_column_text(const JobEntry& job, int column) {
  switch (column) {
  case 0:
    return job.session;
  case 1:
    return job.page;
  case 2:
    return job.case_id.empty() ? std::string("No case") : job.case_id;
  case 3:
    return job_state_text(job);
  case 4:
    return job.progress;
  default:
    return {};
  }
}

inline bool job_can_cancel(const JobEntry& job) { return job.state == JobState::running; }

// Running and cancelling jobs first, then output still being finalized, then the rest, each group
// in tab order.
inline void order_jobs(std::vector<JobEntry>& jobs) {
  const auto rank = [](JobState state) {
    switch (state) {
    case JobState::running:
    case JobState::cancelling:
      return 0;
    case JobState::finalizing:
      return 1;
    case JobState::finished:
    case JobState::not_run:
      break;
    }
    return 2;
  };
  std::stable_sort(jobs.begin(), jobs.end(), [&](const JobEntry& left, const JobEntry& right) {
    return rank(left.state) < rank(right.state);
  });
}

// The line above the list.
inline std::string jobs_summary(const std::vector<JobEntry>& jobs) {
  if (jobs.empty())
    return "No session is open. Jobs appear here when a tool or review runs in a session tab.";
  std::size_t running = 0;
  for (const auto& job : jobs)
    running += job.state == JobState::running || job.state == JobState::cancelling ? 1U : 0U;
  const std::string sessions =
      std::to_string(jobs.size()) + (jobs.size() == 1U ? " session" : " sessions");
  if (running == 0U)
    return "Nothing is running. " + sessions + " open.";
  return std::to_string(running) + " running of " + sessions + " open.";
}

}  // namespace support_assist::gui
