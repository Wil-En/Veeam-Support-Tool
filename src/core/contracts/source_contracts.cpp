#include "support_assist/tool_catalog.hpp"
#include "support_assist/tool_download.hpp"
#include "support_assist/system_health.hpp"
#include "support_assist/process.hpp"
#include "support_assist/support_tools.hpp"
#include "support_assist/execution_artifact.hpp"
#include "support_assist/veeam_log_review.hpp"
#include "support_assist/version.hpp"

#ifdef _WIN32
#include "system_health_windows_sdk.hpp"
#endif

#include <concepts>
#include <filesystem>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace support_assist::source_contracts {

#ifdef _WIN32
// Compile the modern IP Helper types and entry points in the first Windows
// target. This prevents a missing SDK declaration from surfacing only after
// the much longer SupportAssistCore build reaches system_health_win.cpp.
using GetIfTable2Contract = decltype(&GetIfTable2);
using FreeMibTableContract = decltype(&FreeMibTable);
static_assert(std::is_pointer_v<PMIB_IF_TABLE2>);
static_assert(sizeof(MIB_IF_ROW2) > 0);
static_assert(sizeof(MIB_IF_TABLE2) > 0);
static_assert(std::is_pointer_v<GetIfTable2Contract>);
static_assert(std::is_pointer_v<FreeMibTableContract>);
#endif

static_assert(!kProductName.empty());
static_assert(!kProductSlug.empty());
static_assert(!kVersion.empty());
static_assert(!kExecutableName.empty());

static_assert(requires(ExternalToolDefinition definition) {
  { definition.id } -> std::same_as<std::string&>;
  { definition.name } -> std::same_as<std::string&>;
  { definition.executable_names } -> std::same_as<std::vector<std::string>&>;
  { definition.source_url } -> std::same_as<std::string&>;
  { definition.download_url } -> std::same_as<std::string&>;
  { definition.download_filename } -> std::same_as<std::string&>;
  { definition.download_archive } -> std::same_as<std::string&>;
  { definition.published_hash } -> std::same_as<std::string&>;
  { definition.automatic_download_supported } -> std::same_as<bool&>;
  { definition.bundled_by_windows } -> std::same_as<bool&>;
  { definition.optional_integration } -> std::same_as<bool&>;
});

static_assert(requires(ExternalToolInstallOptions options) {
  { options.tool_id } -> std::same_as<std::string&>;
  { options.destination_root } -> std::same_as<std::filesystem::path&>;
  { options.replace_existing_version } -> std::same_as<bool&>;
});

static_assert(requires(ExternalToolInstallResult result) {
  { result.tool_id } -> std::same_as<std::string&>;
  { result.tool_name } -> std::same_as<std::string&>;
  { result.version } -> std::same_as<std::string&>;
  { result.sha256 } -> std::same_as<std::string&>;
  { result.installed_directory } -> std::same_as<std::filesystem::path&>;
});

static_assert(requires(VeeamIncidentLocation location) {
  { location.machine_key } -> std::same_as<std::string&>;
  { location.explicit_job_run_key } -> std::same_as<std::string&>;
  { location.correlated_job_run_keys } -> std::same_as<std::vector<std::string>&>;
});

static_assert(requires(VeeamLogReviewResult result) {
  { result.product_type } -> std::same_as<std::string&>;
  { result.product_confidence } -> std::same_as<ParserConfidence&>;
  { result.parser_profile } -> std::same_as<std::string&>;
  { result.parser_scope_note } -> std::same_as<std::string&>;
  { result.machine } -> std::same_as<VeeamMachineSummary&>;
  { result.machines } -> std::same_as<std::vector<VeeamMachineRecord>&>;
  { result.job_sessions } -> std::same_as<std::vector<VeeamJobSession>&>;
  { result.incidents } -> std::same_as<std::vector<VeeamIncident>&>;
  { result.report_path } -> std::same_as<std::filesystem::path&>;
  { result.workers_used } -> std::same_as<std::size_t&>;
  { result.lines_per_second } -> std::same_as<double&>;
});

static_assert(requires(ProcessOptions options, ProcessResult result) {
  { options.merge_standard_error } -> std::same_as<bool&>;
  { options.maximum_output_bytes } -> std::same_as<std::size_t&>;
  { options.maximum_standard_error_bytes } -> std::same_as<std::size_t&>;
  { result.output } -> std::same_as<std::string&>;
  { result.standard_error } -> std::same_as<std::string&>;
  { result.output_truncated } -> std::same_as<bool&>;
  { result.standard_error_truncated } -> std::same_as<bool&>;
});

static_assert(requires(PacketCaptureSession packet, ProcmonSession procmon) {
  { packet.session_id } -> std::same_as<std::string&>;
  { packet.output_etl } -> std::same_as<std::filesystem::path&>;
  { packet.active } -> std::same_as<bool&>;
  { procmon.session_id } -> std::same_as<std::string&>;
  { procmon.output_pml } -> std::same_as<std::filesystem::path&>;
  { procmon.process_id } -> std::same_as<std::uint32_t&>;
  { procmon.active } -> std::same_as<bool&>;
});

static_assert(requires(ExecutionArtifactManifest artifact) {
  { artifact.root } -> std::same_as<std::filesystem::path&>;
  { artifact.execution_status } -> std::same_as<ExecutionStatus&>;
  { artifact.diagnostic_status } -> std::same_as<DiagnosticStatus&>;
});

static_assert(requires(SystemHealthSnapshot snapshot) {
  { snapshot.memory } -> std::same_as<MemoryHealth&>;
  { snapshot.volumes } -> std::same_as<std::vector<VolumeHealth>&>;
  { snapshot.storage_devices } -> std::same_as<std::vector<StorageDeviceHealth>&>;
  { snapshot.network_adapters } -> std::same_as<std::vector<NetworkAdapterHealth>&>;
  { snapshot.top_processes } -> std::same_as<std::vector<ProcessHealth>&>;
  { snapshot.findings } -> std::same_as<std::vector<HealthFinding>&>;
});

static_assert(requires(const ExternalToolInstallOptions& options,
                       const CancellationToken& cancel,
                       ProgressCallback progress) {
  { install_external_tool(options, cancel, std::move(progress)) }
      -> std::same_as<Result<ExternalToolInstallResult>>;
});

static_assert(requires(std::string_view tool_id, const std::filesystem::path& root) {
  { remove_managed_external_tool(tool_id, root) } -> std::same_as<Status>;
});

} // namespace support_assist::source_contracts
