namespace ModSec.Models;

public static class ModSecConstants
{
    public const string Version = "0.2.43";
    public const string ClientGuid = "com.kairo.modsec.client";
}

public class PolicyResponse
{
    public bool Enabled { get; set; }
    public string Version { get; set; } = "";
    public string Mode { get; set; } = "WarnOnly";
    public bool StrictWhitelist { get; set; } = true;
    public bool StartupCheck { get; set; }
    public bool BackgroundChecks { get; set; }
    public int BackgroundIntervalSeconds { get; set; } = 60;
    public int MinimumIntervalSeconds { get; set; } = 15;
    public int MaximumIntervalSeconds { get; set; } = 300;
    public int HeartbeatIntervalSeconds { get; set; } = 120;
    public PrivacyOptions Privacy { get; set; } = new();
    public PolicyDisclosure Disclosure { get; set; } = new();
    public List<string> ScanPaths { get; set; } = new();
    public List<ConfigRule> ConfigRules { get; set; } = new();
}

public class PrivacyOptions
{
    public bool RequireClientConsent { get; set; } = true;
    public bool AllowOutsideSptScanPaths { get; set; }
    public bool SendFullSnapshotsAfterConsent { get; set; } = true;
    public int ConsentVersion { get; set; } = 2;
}

public class PolicyDisclosure
{
    public int ConsentVersion { get; set; } = 2;
    public List<string> ScannedFolders { get; set; } = new();
    public List<string> DataSent { get; set; } = new();
    public string StoredWhere { get; set; } = "";
    public string WhoCanView { get; set; } = "";
    public bool ExternalTelemetry { get; set; }
    public bool FileModification { get; set; }
    public string DeclineEffect { get; set; } = "";
    public string ResetInstructions { get; set; } = "";
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
    public List<object?> AllowedValues { get; set; } = new();
    public List<object?> BlockedValues { get; set; } = new();
    public double? MinValue { get; set; }
    public double? MaxValue { get; set; }
    public bool Required { get; set; }
    public string Severity { get; set; } = "block";
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
    public List<ClientPluginReport> Plugins { get; set; } = new();
    public List<ClientFileReport> Files { get; set; } = new();
    public List<ClientConfigValue> ConfigValues { get; set; } = new();
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
    public List<AdminPopup> Popups { get; set; } = new();
}

public class ClientFileReport
{
    public string Path { get; set; } = "";
    public string Hash { get; set; } = "";
    public long Size { get; set; }
    public DateTime LastWriteUtc { get; set; }
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
    public List<Violation> Violations { get; set; } = new();
    public List<AdminPopup> Popups { get; set; } = new();
    public List<RaidCommand> RaidCommands { get; set; } = new();
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
    public DateTime CreatedAtUtc { get; set; }
}
