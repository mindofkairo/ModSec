using System.Text.Json.Serialization;

namespace ModSec.Server.Models;

public static class ModSecConstants
{
    public const string Version = "0.2.47";
    public const string ServerGuid = "com.kairo.modsec.server";
    public const string ClientGuid = "com.kairo.modsec.client";
}

public class ModSecConfig
{
    public bool Enabled { get; set; } = true;
    public string Mode { get; set; } = "WarnOnly";
    public bool StrictWhitelist { get; set; } = true;
    public bool StartupCheck { get; set; } = true;
    public bool BackgroundChecks { get; set; } = true;
    public int BackgroundIntervalSeconds { get; set; } = 60;
    public int MinimumIntervalSeconds { get; set; } = 15;
    public int MaximumIntervalSeconds { get; set; } = 300;
    public int StrikeLimit { get; set; } = 3;
    public int StrikeDecayMinutes { get; set; } = 1440;
    public int CooldownMinutes { get; set; } = 1;
    public string ServerTimeZoneId { get; set; } = "UTC";
    public List<int> AutoBlockDurationsHours { get; set; } = [24, 72, 168, 0];
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<int>? AutoBanDurationsHours { get; set; }
    public DashboardOptions Dashboard { get; set; } = new();
    public PrivacyOptions Privacy { get; set; } = new();
    public AutoWhitelistOptions AutoWhitelist { get; set; } = new();
    public ReportSanityOptions ReportSanity { get; set; } = new();
    public ClientPresenceOptions ClientPresence { get; set; } = new();
    public IncidentMailOptions IncidentMail { get; set; } = new();
    public List<string> ScanPaths { get; set; } = ["BepInEx/plugins"];
    public List<FileRule> RequiredFiles { get; set; } = [];
    public List<FileRule> AllowedFiles { get; set; } = [];
    public List<FileRule> BlockedFiles { get; set; } = [];
    public List<PluginRule> BlockedPlugins { get; set; } = [];
    public List<ConfigFileRule> ConfigFiles { get; set; } = [];
    public List<ConfigRule> ConfigRules { get; set; } = [];
}

public class PolicyPackage
{
    public string PackageType { get; set; } = "modsec-policy";
    public string Name { get; set; } = "ModSec Policy";
    public string Notes { get; set; } = "";
    public string ModSecVersion { get; set; } = ModSecConstants.Version;
    public DateTime ExportedAtUtc { get; set; } = DateTime.UtcNow;
    public ShareablePolicy Policy { get; set; } = new();
}

public class PolicyImportRequest
{
    public PolicyPackage? Package { get; set; }
    public ModSecConfig? Policy { get; set; }
}

public class ShareablePolicy
{
    public bool Enabled { get; set; } = true;
    public string Mode { get; set; } = "WarnOnly";
    public bool StrictWhitelist { get; set; } = true;
    public bool StartupCheck { get; set; } = true;
    public bool BackgroundChecks { get; set; } = true;
    public int BackgroundIntervalSeconds { get; set; } = 60;
    public int MinimumIntervalSeconds { get; set; } = 15;
    public int MaximumIntervalSeconds { get; set; } = 300;
    public int StrikeLimit { get; set; } = 3;
    public int StrikeDecayMinutes { get; set; } = 1440;
    public int CooldownMinutes { get; set; } = 1;
    public List<int> AutoBlockDurationsHours { get; set; } = [24, 72, 168, 0];
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<int>? AutoBanDurationsHours { get; set; }
    public AutoWhitelistOptions AutoWhitelist { get; set; } = new();
    public PrivacyOptions Privacy { get; set; } = new();
    public ReportSanityOptions ReportSanity { get; set; } = new();
    public ClientPresenceOptions ClientPresence { get; set; } = new();
    public IncidentMailOptions IncidentMail { get; set; } = new();
    public List<string> ScanPaths { get; set; } = ["BepInEx/plugins"];
    public List<FileRule> RequiredFiles { get; set; } = [];
    public List<FileRule> AllowedFiles { get; set; } = [];
    public List<FileRule> BlockedFiles { get; set; } = [];
    public List<PluginRule> BlockedPlugins { get; set; } = [];
    public List<ConfigFileRule> ConfigFiles { get; set; } = [];
    public List<ConfigRule> ConfigRules { get; set; } = [];
}

public class DashboardOptions
{
    public bool Enabled { get; set; }
    public string AdminToken { get; set; } = "";
    public bool AllowRemoteAdmin { get; set; }
    public int SessionMinutes { get; set; } = 120;
    public int FailedAttemptWindowSeconds { get; set; } = 300;
    public int MaxFailedAttempts { get; set; } = 5;
    public int LockoutSeconds { get; set; } = 300;
}

public class PrivacyOptions
{
    public bool RequireClientConsent { get; set; } = true;
    public bool AllowOutsideSptScanPaths { get; set; }
    public bool SendFullSnapshotsAfterConsent { get; set; } = true;
    public int ConsentVersion { get; set; } = 2;
}

public class AutoWhitelistOptions
{
    public bool Enabled { get; set; }
    public List<string> Paths { get; set; } = ["BepInEx/plugins"];
    public string TargetList { get; set; } = "allowedFiles";
    public bool WriteGeneratedFile { get; set; } = true;
    public bool RefreshGeneratedFile { get; set; }
    public string GeneratedFileName { get; set; } = "auto-whitelist.generated.json";
}

public class ReportSanityOptions
{
    public bool Enabled { get; set; } = true;
    public string EmptyReportSeverity { get; set; } = "block";
    public bool RequireKnownClientVersion { get; set; } = true;
    public bool AllowNewerClientVersion { get; set; } = true;
    public string VersionMismatchSeverity { get; set; } = "warn";
    public bool FlagSuspiciousLoadedPlugins { get; set; } = true;
    public bool FlagSuspiciousUnreportedDlls { get; set; } = true;
    public string SuspiciousSeverity { get; set; } = "warn";
    public List<string> SuspiciousNamePatterns { get; set; } = [];
}

public class ClientPresenceOptions
{
    public bool Enabled { get; set; } = true;
    public string MissingClientAction { get; set; } = "block";
    public int GraceSeconds { get; set; } = 45;
    public int HeartbeatIntervalSeconds { get; set; } = 120;
    public int HeartbeatTimeoutSeconds { get; set; } = 120;
    public List<string> GateRoutes { get; set; } = ["/client/match/local/start", "/fika/raid/create", "/fika/raid/join", "/fika/update/addplayer", "/fika/raid/registerPlayer", "/fika/update/playerspawn"];
}

public class IncidentMailOptions
{
    public bool Enabled { get; set; } = true;
    public string SenderName { get; set; } = "Hall of Shame";
    public bool SendToAllProfiles { get; set; } = true;
    public bool IncludeMissingClientBlocks { get; set; } = true;
    public bool IncludePolicyViolations { get; set; } = true;
    public bool IncludeAutomaticBans { get; set; } = true;
    public int CooldownSeconds { get; set; } = 300;
    public int MaxViolationsListed { get; set; } = 8;
    public IncidentMailTemplates Templates { get; set; } = new();
}

public class IncidentMailTemplates
{
    public string MissingClient { get; set; } = "";
    public string PolicyViolation { get; set; } = "";
    public string AutomaticBan { get; set; } = "";
    public List<string> MissingClientLines { get; set; } = [];
    public List<string> PolicyViolationLines { get; set; } = [];
    public List<string> AutomaticBanLines { get; set; } = [];
}

public class FileRule
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public string Glob { get; set; } = "";
    public string Hash { get; set; } = "";
    public string Reason { get; set; } = "";
    public string Severity { get; set; } = "block";
}

public class ConfigRule
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public string Format { get; set; } = "bepinex";
    public string Section { get; set; } = "";
    public string Key { get; set; } = "";
    public string JsonPath { get; set; } = "";
    public string Operator { get; set; } = "equals";
    public object? AllowedValue { get; set; }
    public List<object?> AllowedValues { get; set; } = [];
    public List<object?> BlockedValues { get; set; } = [];
    public double? MinValue { get; set; }
    public double? MaxValue { get; set; }
    public bool Required { get; set; }
    public string Severity { get; set; } = "block";
}

public class ConfigFileRule
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public string Format { get; set; } = "bepinex";
    public bool Required { get; set; }
    public List<ConfigRule> Rules { get; set; } = [];
}

public class PluginRule
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Guid { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Reason { get; set; } = "";
    public string Severity { get; set; } = "block";
}

public class PolicyResponse
{
    public bool Enabled { get; set; }
    public string Version { get; set; } = ModSecConstants.Version;
    public string Mode { get; set; } = "WarnOnly";
    public bool StrictWhitelist { get; set; }
    public bool StartupCheck { get; set; }
    public bool BackgroundChecks { get; set; }
    public int BackgroundIntervalSeconds { get; set; }
    public int MinimumIntervalSeconds { get; set; }
    public int MaximumIntervalSeconds { get; set; }
    public int HeartbeatIntervalSeconds { get; set; } = 120;
    public PrivacyOptions Privacy { get; set; } = new();
    public PolicyDisclosure Disclosure { get; set; } = new();
    public List<string> ScanPaths { get; set; } = [];
    public List<ConfigRule> ConfigRules { get; set; } = [];
}

public class PolicyDisclosure
{
    public int ConsentVersion { get; set; } = 2;
    public List<string> ScannedFolders { get; set; } = [];
    public List<string> DataSent { get; set; } = [];
    public string StoredWhere { get; set; } = "The host stores ModSec state as JSON files under the server's SPT/user/mods/modSec/config folder.";
    public string WhoCanView { get; set; } = "Host admins with the ModSec dashboard token/session, and anyone with access to the host computer's ModSec JSON files, can view collected ModSec data.";
    public bool ExternalTelemetry { get; set; }
    public bool FileModification { get; set; }
    public string DeclineEffect { get; set; } = "Declining prevents raid access on this host when ModSec checks are required.";
    public string ResetInstructions { get; set; } = "Consent can be reset or changed in SPT/ModSec_Data/consent.json. Consent changes require a game restart to take effect before joining raids.";
}

public class ClientReport
{
    public string ProfileId { get; set; } = "";
    public string PlayerName { get; set; } = "";
    public string InstallId { get; set; } = "";
    public string TimeZoneId { get; set; } = "";
    public string ClientVersion { get; set; } = "";
    public string CheckKind { get; set; } = "startup";
    public bool InRaid { get; set; }
    public bool IsFikaHost { get; set; }
    public int HumanPlayerCount { get; set; }
    public bool MainPluginPresent { get; set; } = true;
    public bool CompanionPresent { get; set; }
    public List<ClientPluginReport> Plugins { get; set; } = [];
    public List<ClientFileReport> Files { get; set; } = [];
    public List<ClientConfigValue> ConfigValues { get; set; } = [];
}

public class ClientPluginReport
{
    public string Guid { get; set; } = "";
    public string Name { get; set; } = "";
    public string Version { get; set; } = "";
    public string Location { get; set; } = "";
}

public class ClientHeartbeat
{
    public string ProfileId { get; set; } = "";
    public string PlayerName { get; set; } = "";
    public string InstallId { get; set; } = "";
    public string TimeZoneId { get; set; } = "";
    public string ClientVersion { get; set; } = "";
    public bool InRaid { get; set; }
    public bool IsFikaHost { get; set; }
    public int HumanPlayerCount { get; set; }
}

public class ClientPopupPoll
{
    public string ProfileId { get; set; } = "";
    public string PlayerName { get; set; } = "";
    public string InstallId { get; set; } = "";
    public string ClientVersion { get; set; } = "";
}

public class PopupPollResponse
{
    public List<AdminPopup> Popups { get; set; } = [];
}

public class ClientFileReport
{
    public string Path { get; set; } = "";
    public string Hash { get; set; } = "";
    public long Size { get; set; }
    public DateTime LastWriteUtc { get; set; }
}

public class ServerFileInventoryItem
{
    public string Path { get; set; } = "";
    public string Hash { get; set; } = "";
    public long Size { get; set; }
    public DateTime LastWriteUtc { get; set; }
}

public class PlayerInventoryResponse
{
    public string ProfileId { get; set; } = "";
    public string PlayerName { get; set; } = "";
    public string InstallId { get; set; } = "";
    public DateTime? LastReportAtUtc { get; set; }
    public string LastReportKind { get; set; } = "";
    public List<ClientPluginReport> Plugins { get; set; } = [];
    public List<ClientFileReport> Files { get; set; } = [];
    public List<ClientConfigValue> ConfigValues { get; set; } = [];
}

public class ClientConfigValue
{
    public string RuleId { get; set; } = "";
    public string Path { get; set; } = "";
    public string Section { get; set; } = "";
    public string Key { get; set; } = "";
    public string JsonPath { get; set; } = "";
    public string? Value { get; set; }
    public bool FileExists { get; set; }
    public bool Found { get; set; }
}

public class EnforcementResponse
{
    public string Status { get; set; } = "pass";
    public string Message { get; set; } = "";
    public int Strikes { get; set; }
    public int StrikeLimit { get; set; }
    public DateTime? CooldownUntilUtc { get; set; }
    public int NextCheckSeconds { get; set; } = 60;
    public List<Violation> Violations { get; set; } = [];
    public List<AdminPopup> Popups { get; set; } = [];
    public List<RaidCommand> RaidCommands { get; set; } = [];
}

public class RaidCommand
{
    public string Id { get; set; } = "";
    public string Action { get; set; } = "";
    public string Reason { get; set; } = "";
    public int DelaySeconds { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public string PopupTitle { get; set; } = "";
    public string PopupMessage { get; set; } = "";
    public string PopupSeverity { get; set; } = "info";
    public string PopupKind { get; set; } = "dialog";
    public int PopupDurationSeconds { get; set; } = 8;
}

public class Violation
{
    public string Severity { get; set; } = "audit";
    public string Reason { get; set; } = "";
    public string Path { get; set; } = "";
    public string RuleId { get; set; } = "";
    public string Category { get; set; } = "";
    public string Setting { get; set; } = "";
    public string ActualValue { get; set; } = "";
    public string ExpectedValue { get; set; } = "";
}

public class AdminPopup
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "Server Notice";
    public string Message { get; set; } = "";
    public string Kind { get; set; } = "dialog";
    public string Position { get; set; } = "topRight";
    public string Severity { get; set; } = "info";
    public int DurationSeconds { get; set; } = 6;
    public bool Blocking { get; set; }
    public bool RequiresQuit { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}

public class AdminPopupRequest
{
    public string TargetProfileId { get; set; } = "";
    public string Title { get; set; } = "Server Notice";
    public string Message { get; set; } = "";
    public string Kind { get; set; } = "dialog";
    public string Position { get; set; } = "topRight";
    public string Severity { get; set; } = "info";
    public int DurationSeconds { get; set; } = 6;
    public bool Blocking { get; set; }
    public bool RequiresQuit { get; set; }
}

public class AdminBanRequest
{
    public string ProfileId { get; set; } = "";
    public string Reason { get; set; } = "";
    public int Minutes { get; set; } = 0;
}

public class AdminPlayerAction
{
    public string ProfileId { get; set; } = "";
}

public class AdminLoginRequest
{
    public string Token { get; set; } = "";
}

public class PlayerState
{
    public string ProfileId { get; set; } = "";
    public string PlayerName { get; set; } = "";
    public string InstallId { get; set; } = "";
    public string LastKnownIp { get; set; } = "";
    public int Strikes { get; set; }
    public int RiskScore { get; set; }
    public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastCleanAtUtc { get; set; }
    public DateTime? FirstServerSeenAtUtc { get; set; }
    public DateTime? LastServerSeenAtUtc { get; set; }
    public DateTime? LastGameStartAtUtc { get; set; }
    public string LastServerRoute { get; set; } = "";
    public DateTime? LastClientReportAtUtc { get; set; }
    public DateTime? LastHeartbeatAtUtc { get; set; }
    public string LastReportKind { get; set; } = "";
    public string ComplianceStatus { get; set; } = "unknown";
    public int MissingClientAttempts { get; set; }
    public DateTime? LastMissingClientAttemptAtUtc { get; set; }
    public DateTime? LastViolationAtUtc { get; set; }
    public string ActiveEnforcementStatus { get; set; } = "";
    public List<Violation> ActiveViolations { get; set; } = [];
    public string LastPublishedEnforcementSignature { get; set; } = "";
    public DateTime? LastPublishedEnforcementAtUtc { get; set; }
    public string LastRaidCommandSignature { get; set; } = "";
    public DateTime? LastRaidCommandAtUtc { get; set; }
    public DateTime? CooldownUntilUtc { get; set; }
    public DateTime? BannedUntilUtc { get; set; }
    public string BanReason { get; set; } = "";
    public int BanCount { get; set; }
    public string TimeZoneId { get; set; } = "";
    public string LastViolationSignature { get; set; } = "";
    public List<Violation> RecentViolations { get; set; } = [];
    public List<ClientPluginReport> LatestPlugins { get; set; } = [];
    public List<ClientFileReport> LatestFiles { get; set; } = [];
    public List<ClientConfigValue> LatestConfigValues { get; set; } = [];
}

public class AdminEvent
{
    public string Id { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public string Type { get; set; } = "";
    public string ProfileId { get; set; } = "";
    public string PlayerName { get; set; } = "";
    public string Severity { get; set; } = "info";
    public string Message { get; set; } = "";
    public List<Violation> Violations { get; set; } = [];
}
