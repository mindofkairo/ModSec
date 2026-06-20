using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using ModSec.Server.Models;
using SPTarkov.DI.Annotations;

namespace ModSec.Server.Services;

[Injectable]
public class ModSecConfigService
{
    private static readonly string[] AllowedScanRoots =
    [
        "BepInEx/plugins",
        "BepInEx/config",
        "user/mods",
        "SPT/user/mods",
        "SPT/user/profiles",
        "SPT/user/cache",
        "ModSec_Data"
    ];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    private string _configPath = "";
    private string _configDirectory = "";
    private DateTime _lastWriteUtc = DateTime.MinValue;
    private ModSecConfig _currentConfig = ModSecConfigFactory.CreateDefault();

    public string ConfigPath => _configPath;
    public DateTime LastWriteUtc => _lastWriteUtc;

    public void Initialize(string modPath)
    {
        _configPath = Path.Combine(modPath, "config", "modsec.json");
        _configDirectory = Path.GetDirectoryName(_configPath) ?? modPath;
        _currentConfig = LoadAndValidate();
        Console.WriteLine($"[ModSec] Loaded config: mode={_currentConfig.Mode}, scanPaths={_currentConfig.ScanPaths.Count}, blockedFiles={_currentConfig.BlockedFiles.Count}, blockedPlugins={_currentConfig.BlockedPlugins.Count}");
    }

    public ModSecConfig GetCurrent()
    {
        RefreshIfChanged();
        return _currentConfig;
    }

    public ModSecConfig GetEditableConfig()
    {
        if (string.IsNullOrWhiteSpace(_configPath) || !File.Exists(_configPath))
        {
            return _currentConfig;
        }

        var json = File.ReadAllText(_configPath);
        var config = JsonSerializer.Deserialize<ModSecConfig>(json, JsonOptions) ?? ModSecConfigFactory.CreateDefault();
        Normalize(config);
        return config;
    }

    public ModSecConfig SaveConfig(ModSecConfig config)
    {
        Normalize(config);
        Directory.CreateDirectory(_configDirectory);
        File.WriteAllText(_configPath, JsonSerializer.Serialize(config, JsonOptions));
        _lastWriteUtc = File.GetLastWriteTimeUtc(_configPath);
        _currentConfig = LoadAndValidate();
        Console.WriteLine("[ModSec] Config saved from admin dashboard.");
        return _currentConfig;
    }

    public PolicyPackage ExportPolicyPackage(string name = "ModSec Policy", string notes = "")
    {
        var config = GetEditableConfig();
        return new PolicyPackage
        {
            PackageType = "modsec-policy",
            Name = string.IsNullOrWhiteSpace(name) ? "ModSec Policy" : name.Trim(),
            Notes = notes.Trim(),
            ModSecVersion = ModSecConstants.Version,
            ExportedAtUtc = DateTime.UtcNow,
            Policy = ToShareablePolicy(config)
        };
    }

    public ModSecConfig ImportPolicyPackage(PolicyPackage package)
    {
        var current = GetEditableConfig();
        var imported = FromShareablePolicy(package.Policy, current);
        return SaveConfig(imported);
    }

    public ModSecConfig MergePolicyPackage(PolicyPackage package)
    {
        var current = GetEditableConfig();
        MergeShareablePolicy(current, package.Policy);
        return SaveConfig(current);
    }

    public ModSecConfig ForceReload()
    {
        _currentConfig = LoadAndValidate();
        Console.WriteLine("[ModSec] Config force-reloaded.");
        return _currentConfig;
    }

    private static ShareablePolicy ToShareablePolicy(ModSecConfig config)
    {
        return new ShareablePolicy
        {
            Enabled = config.Enabled,
            Mode = config.Mode,
            StrictWhitelist = config.StrictWhitelist,
            StartupCheck = config.StartupCheck,
            BackgroundChecks = config.BackgroundChecks,
            BackgroundIntervalSeconds = config.BackgroundIntervalSeconds,
            MinimumIntervalSeconds = config.MinimumIntervalSeconds,
            MaximumIntervalSeconds = config.MaximumIntervalSeconds,
            StrikeLimit = config.StrikeLimit,
            StrikeDecayMinutes = config.StrikeDecayMinutes,
            CooldownMinutes = config.CooldownMinutes,
            AutoBlockDurationsHours = config.AutoBlockDurationsHours,
            AutoWhitelist = config.AutoWhitelist,
            Privacy = config.Privacy,
            ReportSanity = config.ReportSanity,
            ClientPresence = config.ClientPresence,
            IncidentMail = config.IncidentMail,
            ScanPaths = config.ScanPaths,
            RequiredFiles = config.RequiredFiles,
            AllowedFiles = config.AllowedFiles,
            BlockedFiles = config.BlockedFiles,
            BlockedPlugins = config.BlockedPlugins,
            ConfigFiles = config.ConfigFiles,
            ConfigRules = config.ConfigRules
        };
    }

    private static ModSecConfig FromShareablePolicy(ShareablePolicy policy, ModSecConfig current)
    {
        return new ModSecConfig
        {
            Enabled = policy.Enabled,
            Mode = policy.Mode,
            StrictWhitelist = policy.StrictWhitelist,
            StartupCheck = policy.StartupCheck,
            BackgroundChecks = policy.BackgroundChecks,
            BackgroundIntervalSeconds = policy.BackgroundIntervalSeconds,
            MinimumIntervalSeconds = policy.MinimumIntervalSeconds,
            MaximumIntervalSeconds = policy.MaximumIntervalSeconds,
            StrikeLimit = policy.StrikeLimit,
            StrikeDecayMinutes = policy.StrikeDecayMinutes,
            CooldownMinutes = policy.CooldownMinutes,
            ServerTimeZoneId = current.ServerTimeZoneId,
            AutoBlockDurationsHours = policy.AutoBlockDurationsHours.Count > 0
                ? policy.AutoBlockDurationsHours
                : policy.AutoBanDurationsHours ?? [],
            Dashboard = current.Dashboard,
            AutoWhitelist = policy.AutoWhitelist,
            Privacy = policy.Privacy,
            ReportSanity = policy.ReportSanity,
            ClientPresence = policy.ClientPresence,
            IncidentMail = policy.IncidentMail,
            ScanPaths = policy.ScanPaths,
            RequiredFiles = policy.RequiredFiles,
            AllowedFiles = policy.AllowedFiles,
            BlockedFiles = policy.BlockedFiles,
            BlockedPlugins = policy.BlockedPlugins,
            ConfigFiles = policy.ConfigFiles,
            ConfigRules = policy.ConfigRules
        };
    }

    private static void MergeShareablePolicy(ModSecConfig target, ShareablePolicy source)
    {
        target.ScanPaths = UnionStrings(target.ScanPaths, source.ScanPaths);
        target.AutoBlockDurationsHours = target.AutoBlockDurationsHours.Count > 0
            ? target.AutoBlockDurationsHours
            : source.AutoBlockDurationsHours;
        target.ReportSanity.SuspiciousNamePatterns = UnionStrings(
            target.ReportSanity.SuspiciousNamePatterns,
            source.ReportSanity.SuspiciousNamePatterns);

        AppendUnique(target.RequiredFiles, source.RequiredFiles, SameRuleIdentity);
        AppendUnique(target.AllowedFiles, source.AllowedFiles, SameRuleIdentity);
        AppendUnique(target.BlockedFiles, source.BlockedFiles, SameRuleIdentity);
        AppendUnique(target.BlockedPlugins, source.BlockedPlugins, SamePluginRule);
        AppendUnique(target.ConfigRules, source.ConfigRules, SameConfigRule);
        MergeConfigFiles(target.ConfigFiles, source.ConfigFiles);
    }

    private static void MergeConfigFiles(List<ConfigFileRule> target, IEnumerable<ConfigFileRule> source)
    {
        foreach (var incoming in source)
        {
            var existing = target.FirstOrDefault(current => SameConfigFileRule(current, incoming));
            if (existing == null)
            {
                target.Add(incoming);
                continue;
            }

            AppendUnique(existing.Rules, incoming.Rules, SameConfigRule);
        }
    }

    private static void AppendUnique<T>(List<T> target, IEnumerable<T> source, Func<T, T, bool> same)
    {
        foreach (var item in source)
        {
            if (!target.Any(existing => same(existing, item)))
            {
                target.Add(item);
            }
        }
    }

    private static List<string> UnionStrings(List<string> first, List<string> second)
    {
        return first
            .Concat(second)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static bool SamePluginRule(PluginRule first, PluginRule second)
    {
        return string.Equals(first.Id, second.Id, StringComparison.OrdinalIgnoreCase)
               || !string.IsNullOrWhiteSpace(first.Guid)
               && string.Equals(first.Guid, second.Guid, StringComparison.OrdinalIgnoreCase)
               || !string.IsNullOrWhiteSpace(first.DisplayName)
               && string.Equals(first.DisplayName, second.DisplayName, StringComparison.OrdinalIgnoreCase);
    }

    private static bool SameConfigFileRule(ConfigFileRule first, ConfigFileRule second)
    {
        return string.Equals(first.Id, second.Id, StringComparison.OrdinalIgnoreCase)
               || string.Equals(NormalizePath(first.Path), NormalizePath(second.Path), StringComparison.OrdinalIgnoreCase);
    }

    private static bool SameConfigRule(ConfigRule first, ConfigRule second)
    {
        return string.Equals(first.Id, second.Id, StringComparison.OrdinalIgnoreCase)
               || string.Equals(NormalizePath(first.Path), NormalizePath(second.Path), StringComparison.OrdinalIgnoreCase)
               && string.Equals(first.Section, second.Section, StringComparison.OrdinalIgnoreCase)
               && string.Equals(first.Key, second.Key, StringComparison.OrdinalIgnoreCase)
               && string.Equals(first.JsonPath, second.JsonPath, StringComparison.OrdinalIgnoreCase);
    }

    public PolicyResponse GetPolicy()
    {
        var config = GetCurrent();
        return new PolicyResponse
        {
            Enabled = config.Enabled,
            Version = ModSecConstants.Version,
            Mode = config.Mode,
            StrictWhitelist = config.StrictWhitelist,
            StartupCheck = config.StartupCheck,
            BackgroundChecks = config.BackgroundChecks,
            BackgroundIntervalSeconds = config.BackgroundIntervalSeconds,
            MinimumIntervalSeconds = config.MinimumIntervalSeconds,
            MaximumIntervalSeconds = config.MaximumIntervalSeconds,
            HeartbeatIntervalSeconds = config.ClientPresence.HeartbeatIntervalSeconds,
            Privacy = config.Privacy,
            Disclosure = BuildPolicyDisclosure(config),
            ScanPaths = config.ScanPaths,
            ConfigRules = GetEffectiveConfigRules(config)
        };
    }

    private static PolicyDisclosure BuildPolicyDisclosure(ModSecConfig config)
    {
        var dataSent = new List<string>
        {
            "SPT profile ID and profile nickname",
            "Random ModSec Install ID",
            "ModSec client version",
            "Selected config rule results only: rule ID, relative config path, section/key/json path, found status, and value"
        };

        if (config.Privacy.SendFullSnapshotsAfterConsent)
        {
            dataSent.Insert(3, "BepInEx plugin GUID, name, version, and SPT-relative location");
            dataSent.Insert(4, "SPT-relative file paths, SHA-256 hashes, file sizes, and last-write timestamps for configured scan folders");
        }

        var scannedFolders = config.ScanPaths.ToList();
        scannedFolders.Add("ModSec_Data");
        if (GetEffectiveConfigRules(config).Count > 0)
        {
            scannedFolders.Add("BepInEx/config");
        }

        return new PolicyDisclosure
        {
            ConsentVersion = config.Privacy.ConsentVersion,
            ScannedFolders = scannedFolders
                .Select(NormalizePath)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            DataSent = dataSent,
            StoredWhere = "The host stores ModSec player state and event history as JSON files under SPT/user/mods/modSec/config on the server.",
            WhoCanView = "Host admins with the ModSec dashboard token/session, and anyone with access to the host computer's ModSec JSON files, can view client-reported ModSec data.",
            ExternalTelemetry = false,
            FileModification = false,
            DeclineEffect = "Declining prevents raid access on this host when ModSec checks are required.",
            ResetInstructions = "Consent can be reset or changed in ModSec_Data/consent.json in your SPT game folder. Consent changes require a game restart to take effect before joining raids."
        };
    }

    public List<ConfigRule> GetEffectiveConfigRules()
    {
        return GetEffectiveConfigRules(GetCurrent());
    }

    public static List<ConfigRule> GetEffectiveConfigRules(ModSecConfig config)
    {
        var rules = new List<ConfigRule>();
        rules.AddRange(config.ConfigRules);

        foreach (var file in config.ConfigFiles)
        {
            foreach (var rule in file.Rules)
            {
                rules.Add(new ConfigRule
                {
                    Id = string.IsNullOrWhiteSpace(rule.Id) ? $"{file.Id}-{rule.Key}".Trim('-') : rule.Id,
                    Name = rule.Name,
                    Path = string.IsNullOrWhiteSpace(rule.Path) ? file.Path : rule.Path,
                    Format = string.IsNullOrWhiteSpace(rule.Format) ? file.Format : rule.Format,
                    Section = rule.Section,
                    Key = rule.Key,
                    JsonPath = rule.JsonPath,
                    Operator = rule.Operator,
                    AllowedValue = rule.AllowedValue,
                    AllowedValues = rule.AllowedValues,
                    BlockedValues = rule.BlockedValues,
                    MinValue = rule.MinValue,
                    MaxValue = rule.MaxValue,
                    Required = file.Required || rule.Required,
                    Severity = rule.Severity
                });
            }
        }

        return rules
            .Where(rule => !string.IsNullOrWhiteSpace(rule.Path)
                           && (!string.IsNullOrWhiteSpace(rule.Key) || !string.IsNullOrWhiteSpace(rule.JsonPath)))
            .ToList();
    }

    public List<ServerFileInventoryItem> GetServerFileInventory()
    {
        var config = GetCurrent();
        var paths = config.ScanPaths
            .Concat(config.AutoWhitelist.Paths)
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(NormalizePath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (paths.Count == 0)
        {
            paths.Add("BepInEx/plugins");
        }

        var gameRoot = ResolveGameRoot();
        var files = new List<ServerFileInventoryItem>();

        foreach (var path in paths)
        {
            var fullPath = Path.GetFullPath(Path.Combine(gameRoot, path));
            if (File.Exists(fullPath))
            {
                TryAddInventoryFile(gameRoot, fullPath, files);
                continue;
            }

            if (!Directory.Exists(fullPath))
            {
                continue;
            }

            foreach (var filePath in Directory.EnumerateFiles(fullPath, "*", SearchOption.AllDirectories))
            {
                TryAddInventoryFile(gameRoot, filePath, files);
            }
        }

        return files
            .GroupBy(file => file.Path, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(file => file.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public List<ServerFileInventoryItem> GetProtectedClientFileFingerprints()
    {
        var gameRoot = ResolveGameRoot();
        var paths = new[]
        {
            "BepInEx/plugins/modSec/modSec.dll",
            "BepInEx/plugins/modSec/modSec.pdb",
            "BepInEx/plugins/spt/ConfigurationManager/ConfigurationManager.dll",
            "BepInEx/plugins/spt/ConfigurationManager/ConfigurationManager.xml",
            "BepInEx/plugins/spt/spt-common.dll",
            "BepInEx/plugins/spt/spt-core.dll",
            "BepInEx/plugins/spt/spt-custom.dll",
            "BepInEx/plugins/spt/spt-debugging.dll",
            "BepInEx/plugins/spt/spt-reflection.dll",
            "BepInEx/plugins/spt/spt-singleplayer.dll",
            "BepInEx/plugins/Fika/Fika.Core.dll",
            "BepInEx/plugins/Fika/LICENSE.md",
            "BepInEx/plugins/Fika/LICENSE-K40s-LZ4.md",
            "BepInEx/plugins/Fika/LICENSE-LiteNetLib.md",
            "BepInEx/plugins/Fika/LICENSE-Mirror.md",
            "BepInEx/plugins/Fika/LICENSE-Open.NAT.md",
            "BepInEx/plugins/Fika/LICENSE-SIT.md"
        };

        var files = new List<ServerFileInventoryItem>();
        foreach (var path in paths)
        {
            TryAddInventoryFile(gameRoot, Path.GetFullPath(Path.Combine(gameRoot, path)), files);
        }

        return files;
    }

    private void RefreshIfChanged()
    {
        if (string.IsNullOrEmpty(_configPath) || !File.Exists(_configPath))
        {
            return;
        }

        var writeUtc = File.GetLastWriteTimeUtc(_configPath);
        if (writeUtc <= _lastWriteUtc)
        {
            return;
        }

        try
        {
            _currentConfig = LoadAndValidate();
            Console.WriteLine("[ModSec] Config hot-reloaded.");
        }
        catch (Exception ex)
        {
            _lastWriteUtc = writeUtc;
            Console.WriteLine($"[ModSec] Config reload failed. Keeping previous config. Error: {ex.Message}");
        }
    }

    private ModSecConfig LoadAndValidate()
    {
        if (!File.Exists(_configPath))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_configPath)!);
            var defaultConfig = ModSecConfigFactory.CreateDefault();
            File.WriteAllText(_configPath, JsonSerializer.Serialize(defaultConfig, JsonOptions));
            Console.WriteLine($"[ModSec] Created default config at {_configPath}");
        }

        var json = File.ReadAllText(_configPath);
        var config = JsonSerializer.Deserialize<ModSecConfig>(json, JsonOptions) ?? ModSecConfigFactory.CreateDefault();
        Normalize(config);
        ApplyAutoWhitelist(config);

        _lastWriteUtc = File.GetLastWriteTimeUtc(_configPath);
        return config;
    }

    private static void Normalize(ModSecConfig config)
    {
        config.Dashboard ??= new DashboardOptions();
        config.Privacy ??= new PrivacyOptions();
        config.AutoWhitelist ??= new AutoWhitelistOptions();
        config.ReportSanity ??= new ReportSanityOptions();
        config.ClientPresence ??= new ClientPresenceOptions();
        config.IncidentMail ??= new IncidentMailOptions();
        config.IncidentMail.Templates ??= new IncidentMailTemplates();

        config.Mode = NormalizeMode(config.Mode);
        config.ScanPaths = config.ScanPaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(NormalizePath)
            .Where(path => config.Privacy.AllowOutsideSptScanPaths || IsAllowedSptPath(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (config.ScanPaths.Count == 0)
        {
            config.ScanPaths.Add("BepInEx/plugins");
        }

        config.BackgroundIntervalSeconds = Math.Clamp(config.BackgroundIntervalSeconds, 10, 3600);
        config.MinimumIntervalSeconds = Math.Clamp(config.MinimumIntervalSeconds, 5, config.BackgroundIntervalSeconds);
        config.MaximumIntervalSeconds = Math.Clamp(config.MaximumIntervalSeconds, config.MinimumIntervalSeconds, 7200);
        config.StrikeLimit = Math.Clamp(config.StrikeLimit, 1, 20);
        config.CooldownMinutes = Math.Clamp(config.CooldownMinutes, 0, 10080);
        config.StrikeDecayMinutes = Math.Clamp(config.StrikeDecayMinutes, 1, 43200);
        config.ServerTimeZoneId = NormalizeTimeZoneId(config.ServerTimeZoneId);
        if (config.AutoBlockDurationsHours.Count == 0 && config.AutoBanDurationsHours is { Count: > 0 })
        {
            config.AutoBlockDurationsHours = config.AutoBanDurationsHours;
        }

        config.AutoBanDurationsHours = null;
        config.AutoBlockDurationsHours = config.AutoBlockDurationsHours
            .Select(hours => Math.Clamp(hours, 0, 87600))
            .ToList();

        if (config.AutoBlockDurationsHours.Count == 0)
        {
            config.AutoBlockDurationsHours = [24, 72, 168, 0];
        }

        config.AutoWhitelist.Paths = config.AutoWhitelist.Paths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(NormalizePath)
            .Where(path => config.Privacy.AllowOutsideSptScanPaths || IsAllowedSptPath(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (config.AutoWhitelist.Paths.Count == 0)
        {
            config.AutoWhitelist.Paths.Add("BepInEx/plugins");
        }

        config.AutoWhitelist.TargetList = NormalizeRuleListTarget(config.AutoWhitelist.TargetList);
        config.RequiredFiles = NormalizeFileRules(config.RequiredFiles, "block", clearPathForHashRules: false);
        config.AllowedFiles = NormalizeFileRules(config.AllowedFiles, "allow", clearPathForHashRules: true);
        config.BlockedFiles = NormalizeFileRules(config.BlockedFiles, "block", clearPathForHashRules: true);
        config.BlockedPlugins = NormalizePluginRules(config.BlockedPlugins);

        config.Privacy.ConsentVersion = Math.Clamp(config.Privacy.ConsentVersion, 2, 1000000);

        config.ReportSanity.EmptyReportSeverity = NormalizeSeverity(config.ReportSanity.EmptyReportSeverity, "block");
        config.ReportSanity.VersionMismatchSeverity = NormalizeSeverity(config.ReportSanity.VersionMismatchSeverity, "warn");
        config.ReportSanity.SuspiciousSeverity = NormalizeSeverity(config.ReportSanity.SuspiciousSeverity, "warn");
        config.ReportSanity.SuspiciousNamePatterns = config.ReportSanity.SuspiciousNamePatterns
            .Where(pattern => !string.IsNullOrWhiteSpace(pattern))
            .Select(pattern => pattern.Trim().ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        config.ClientPresence.MissingClientAction = NormalizeSeverity(config.ClientPresence.MissingClientAction, "block");
        config.ClientPresence.GraceSeconds = Math.Clamp(config.ClientPresence.GraceSeconds, 5, 600);
        config.ClientPresence.HeartbeatIntervalSeconds = Math.Clamp(config.ClientPresence.HeartbeatIntervalSeconds, 30, 900);
        config.ClientPresence.HeartbeatTimeoutSeconds = Math.Clamp(config.ClientPresence.HeartbeatTimeoutSeconds, Math.Max(60, config.ClientPresence.HeartbeatIntervalSeconds * 2), 3600);
        config.ClientPresence.GateRoutes = config.ClientPresence.GateRoutes
            .Where(route => !string.IsNullOrWhiteSpace(route))
            .Select(route => route.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (config.ClientPresence.GateRoutes.Count == 0)
        {
            config.ClientPresence.GateRoutes = ModSecConfigFactory.DefaultGateRoutes();
        }

        config.IncidentMail.SenderName = string.IsNullOrWhiteSpace(config.IncidentMail.SenderName)
            ? "Hall of Shame"
            : config.IncidentMail.SenderName.Trim();
        config.IncidentMail.CooldownSeconds = Math.Clamp(config.IncidentMail.CooldownSeconds, 0, 3600);
        config.IncidentMail.MaxViolationsListed = Math.Clamp(config.IncidentMail.MaxViolationsListed, 1, 25);
        config.IncidentMail.Templates.MissingClient = config.IncidentMail.Templates.MissingClient.Trim();
        config.IncidentMail.Templates.PolicyViolation = config.IncidentMail.Templates.PolicyViolation.Trim();
        config.IncidentMail.Templates.AutomaticBan = config.IncidentMail.Templates.AutomaticBan.Trim();
        config.IncidentMail.Templates.MissingClientLines = NormalizeTemplateLines(config.IncidentMail.Templates.MissingClientLines);
        config.IncidentMail.Templates.PolicyViolationLines = NormalizeTemplateLines(config.IncidentMail.Templates.PolicyViolationLines);
        config.IncidentMail.Templates.AutomaticBanLines = NormalizeTemplateLines(config.IncidentMail.Templates.AutomaticBanLines);

        if (string.IsNullOrWhiteSpace(config.IncidentMail.Templates.MissingClient)
            && config.IncidentMail.Templates.MissingClientLines.Count == 0)
        {
            config.IncidentMail.Templates.MissingClientLines = ModSecIncidentMailService.DefaultMissingClientLines();
        }

        if (string.IsNullOrWhiteSpace(config.IncidentMail.Templates.PolicyViolation)
            && config.IncidentMail.Templates.PolicyViolationLines.Count == 0)
        {
            config.IncidentMail.Templates.PolicyViolationLines = ModSecIncidentMailService.DefaultPolicyViolationLines();
        }

        if (string.IsNullOrWhiteSpace(config.IncidentMail.Templates.AutomaticBan)
            && config.IncidentMail.Templates.AutomaticBanLines.Count == 0)
        {
            config.IncidentMail.Templates.AutomaticBanLines = ModSecIncidentMailService.DefaultAutomaticBanLines();
        }

        config.ConfigFiles = config.ConfigFiles
            .Where(file => !string.IsNullOrWhiteSpace(file.Path))
            .Select(file =>
            {
                file.Path = NormalizePath(file.Path);
                file.Format = NormalizeConfigFormat(file.Format);
                file.Rules = NormalizeConfigRules(file.Rules);
                return file;
            })
            .Where(file => config.Privacy.AllowOutsideSptScanPaths || IsAllowedSptPath(file.Path))
            .ToList();

        config.ConfigRules = NormalizeConfigRules(config.ConfigRules)
            .Where(rule => config.Privacy.AllowOutsideSptScanPaths || IsAllowedSptPath(rule.Path))
            .ToList();
    }

    private static List<ConfigRule> NormalizeConfigRules(List<ConfigRule> rules)
    {
        return rules
            .Where(rule => !string.IsNullOrWhiteSpace(rule.Key) || !string.IsNullOrWhiteSpace(rule.JsonPath))
            .Select(rule =>
            {
                rule.Path = string.IsNullOrWhiteSpace(rule.Path) ? "" : NormalizePath(rule.Path);
                rule.Format = NormalizeConfigFormat(rule.Format);
                rule.Operator = NormalizeConfigOperator(rule.Operator);
                rule.Severity = NormalizeSeverity(rule.Severity, "block");
                rule.Section = rule.Section.Trim();
                rule.Key = rule.Key.Trim();
                rule.JsonPath = rule.JsonPath.Trim();
                return rule;
            })
            .ToList();
    }

    private static List<FileRule> NormalizeFileRules(List<FileRule> rules, string fallbackSeverity, bool clearPathForHashRules)
    {
        return (rules ?? [])
            .Where(rule => !string.IsNullOrWhiteSpace(rule.Path)
                           || !string.IsNullOrWhiteSpace(rule.Glob)
                           || !string.IsNullOrWhiteSpace(rule.Hash)
                           || !string.IsNullOrWhiteSpace(rule.Name))
            .Select(rule =>
            {
                rule.Id = (rule.Id ?? "").Trim();
                rule.Name = (rule.Name ?? "").Trim();
                rule.Path = string.IsNullOrWhiteSpace(rule.Path) ? "" : NormalizePath(rule.Path);
                rule.Glob = string.IsNullOrWhiteSpace(rule.Glob) ? "" : NormalizePath(rule.Glob);
                rule.Hash = (rule.Hash ?? "").Trim().ToLowerInvariant();
                rule.Reason = (rule.Reason ?? "").Trim();
                rule.Severity = NormalizeSeverity(rule.Severity, fallbackSeverity);

                if (clearPathForHashRules && !string.IsNullOrWhiteSpace(rule.Hash))
                {
                    rule.Path = "";
                    rule.Glob = "";
                }

                return rule;
            })
            .ToList();
    }

    private static List<PluginRule> NormalizePluginRules(List<PluginRule> rules)
    {
        return (rules ?? [])
            .Where(rule => !string.IsNullOrWhiteSpace(rule.Guid)
                           || !string.IsNullOrWhiteSpace(rule.DisplayName)
                           || !string.IsNullOrWhiteSpace(rule.Name))
            .Select(rule =>
            {
                rule.Id = (rule.Id ?? "").Trim();
                rule.Name = (rule.Name ?? "").Trim();
                rule.Guid = (rule.Guid ?? "").Trim();
                rule.DisplayName = (rule.DisplayName ?? "").Trim();
                rule.Reason = (rule.Reason ?? "").Trim();
                rule.Severity = NormalizeSeverity(rule.Severity, "block");
                return rule;
            })
            .ToList();
    }

    private static List<string> NormalizeTemplateLines(List<string> lines)
    {
        return lines
            .Select(line => line ?? "")
            .ToList();
    }

    private static string NormalizeConfigFormat(string format)
    {
        return format.Equals("json", StringComparison.OrdinalIgnoreCase) ? "json" : "bepinex";
    }

    private static string NormalizeConfigOperator(string op)
    {
        return (op ?? "equals").Replace("-", "", StringComparison.Ordinal).Replace("_", "", StringComparison.Ordinal).ToLowerInvariant() switch
        {
            "notequals" => "notequals",
            "contains" => "contains",
            "notcontains" => "notcontains",
            "lessthanorequal" or "lte" or "max" => "lessthanorequal",
            "greaterthanorequal" or "gte" or "min" => "greaterthanorequal",
            "in" or "anyof" => "in",
            "notin" or "noneof" => "notin",
            "range" or "inrange" or "between" => "range",
            "notrange" or "notinrange" or "outsiderange" => "notrange",
            _ => "equals"
        };
    }

    private void ApplyAutoWhitelist(ModSecConfig config)
    {
        if (!config.AutoWhitelist.Enabled)
        {
            return;
        }

        var generatedRules = GenerateWhitelistRules(config.AutoWhitelist.Paths, config.AutoWhitelist.TargetList);
        var generatedFileRules = LoadGeneratedRules(config.AutoWhitelist.GeneratedFileName);
        var rulesToApply = generatedFileRules.Count > 0 ? generatedFileRules : generatedRules;

        if (rulesToApply.Count > 0)
        {
            ApplyGeneratedRules(config, rulesToApply, config.AutoWhitelist.TargetList);
        }

        if (generatedRules.Count == 0)
        {
            Console.WriteLine("[ModSec] Auto-whitelist enabled, but no files were found.");
            return;
        }

        if (config.AutoWhitelist.WriteGeneratedFile
            && (config.AutoWhitelist.RefreshGeneratedFile || generatedFileRules.Count == 0))
        {
            WriteGeneratedWhitelist(config.AutoWhitelist.GeneratedFileName, generatedRules);
        }

        Console.WriteLine($"[ModSec] Auto-generated {generatedRules.Count} file rule(s) from server install; applied {rulesToApply.Count} rule(s) to policy.");
    }

    private List<FileRule> GenerateWhitelistRules(List<string> paths, string targetList)
    {
        var gameRoot = ResolveGameRoot();
        var rules = new List<FileRule>();
        var severity = targetList.Equals("blockedFiles", StringComparison.OrdinalIgnoreCase) ? "block" : "allow";

        foreach (var path in paths)
        {
            var fullPath = Path.GetFullPath(Path.Combine(gameRoot, path));
            if (File.Exists(fullPath))
            {
                TryAddWhitelistRule(gameRoot, fullPath, severity, rules);
                continue;
            }

            if (!Directory.Exists(fullPath))
            {
                Console.WriteLine($"[ModSec] Auto-whitelist path does not exist: {path}");
                continue;
            }

            foreach (var filePath in Directory.EnumerateFiles(fullPath, "*", SearchOption.AllDirectories))
            {
                TryAddWhitelistRule(gameRoot, filePath, severity, rules);
            }
        }

        return rules
            .OrderBy(rule => rule.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(rule => rule.Hash, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private void ApplyGeneratedRules(ModSecConfig config, List<FileRule> rules, string defaultTargetList)
    {
        foreach (var rule in rules)
        {
            var target = RuleTargetsBlockedList(rule, defaultTargetList)
                ? config.BlockedFiles
                : config.AllowedFiles;

            if (!target.Any(existing => SameRuleIdentity(existing, rule)))
            {
                target.Add(rule);
            }
        }
    }

    private List<FileRule> LoadGeneratedRules(string configuredFileName)
    {
        var path = ResolveGeneratedFilePath(configuredFileName);
        if (!File.Exists(path))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<FileRule>>(File.ReadAllText(path), JsonOptions) ?? [];
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ModSec] Could not load generated auto-rule file '{path}': {ex.Message}");
            return [];
        }
    }

    private static void TryAddWhitelistRule(string gameRoot, string filePath, string severity, List<FileRule> rules)
    {
        try
        {
            var relativePath = NormalizePath(Path.GetRelativePath(gameRoot, filePath));
            if (IsPluginFolderPath(relativePath) && !IsPluginCandidateFile(filePath))
            {
                return;
            }

            var hash = HashFile(filePath);
            rules.Add(new FileRule
            {
                Id = $"auto-whitelist-{MakeRuleId(relativePath)}",
                Name = Path.GetFileName(filePath),
                Path = "",
                Hash = hash,
                Reason = $"Auto-whitelisted from the server install. Observed path: {relativePath}",
                Severity = severity
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ModSec] Could not auto-whitelist '{filePath}': {ex.Message}");
        }
    }

    private static void TryAddInventoryFile(string gameRoot, string filePath, List<ServerFileInventoryItem> files)
    {
        try
        {
            var relativePath = NormalizePath(Path.GetRelativePath(gameRoot, filePath));
            if (IsPluginFolderPath(relativePath) && !IsPluginCandidateFile(filePath))
            {
                return;
            }

            var info = new FileInfo(filePath);
            files.Add(new ServerFileInventoryItem
            {
                Path = relativePath,
                Hash = HashFile(filePath),
                Size = info.Length,
                LastWriteUtc = info.LastWriteTimeUtc
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ModSec] Could not inventory '{filePath}': {ex.Message}");
        }
    }

    private static bool IsPluginFolderPath(string relativePath)
    {
        var normalized = NormalizePath(relativePath);
        return normalized.Equals("BepInEx/plugins", StringComparison.OrdinalIgnoreCase)
               || normalized.StartsWith("BepInEx/plugins/", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPluginCandidateFile(string filePath)
    {
        return Path.GetExtension(filePath).Equals(".dll", StringComparison.OrdinalIgnoreCase)
               || HasManagedAssemblyHeader(filePath);
    }

    private static bool HasManagedAssemblyHeader(string filePath)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new BinaryReader(stream);
            if (stream.Length < 0x100 || reader.ReadUInt16() != 0x5A4D)
            {
                return false;
            }

            stream.Position = 0x3C;
            var peOffset = reader.ReadInt32();
            if (peOffset <= 0 || peOffset > stream.Length - 0x108)
            {
                return false;
            }

            stream.Position = peOffset;
            if (reader.ReadUInt32() != 0x00004550)
            {
                return false;
            }

            stream.Position += 20;
            var optionalHeaderStart = stream.Position;
            var magic = reader.ReadUInt16();
            var dataDirectoryStart = magic switch
            {
                0x10B => optionalHeaderStart + 96,
                0x20B => optionalHeaderStart + 112,
                _ => -1
            };

            if (dataDirectoryStart < 0 || dataDirectoryStart + 14 * 8 + 8 > stream.Length)
            {
                return false;
            }

            stream.Position = dataDirectoryStart + 14 * 8;
            var cliHeaderRva = reader.ReadUInt32();
            var cliHeaderSize = reader.ReadUInt32();
            return cliHeaderRva != 0 && cliHeaderSize != 0;
        }
        catch
        {
            return false;
        }
    }

    private void WriteGeneratedWhitelist(string configuredFileName, List<FileRule> rules)
    {
        var path = ResolveGeneratedFilePath(configuredFileName);
        File.WriteAllText(path, JsonSerializer.Serialize(rules, JsonOptions));
    }

    private string ResolveGeneratedFilePath(string configuredFileName)
    {
        var fileName = string.IsNullOrWhiteSpace(configuredFileName)
            ? "auto-whitelist.generated.json"
            : Path.GetFileName(configuredFileName);
        return Path.Combine(_configDirectory, fileName);
    }

    private static string ResolveGameRoot()
    {
        var cwd = Directory.GetCurrentDirectory();
        var directory = new DirectoryInfo(cwd);
        while (directory != null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "BepInEx"))
                && Directory.Exists(Path.Combine(directory.FullName, "SPT")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        return cwd.EndsWith($"{Path.DirectorySeparatorChar}SPT", StringComparison.OrdinalIgnoreCase)
            ? Directory.GetParent(cwd)?.FullName ?? cwd
            : cwd;
    }

    private static string HashFile(string filePath)
    {
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var sha = SHA256.Create();
        return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }

    private static string MakeRuleId(string relativePath)
    {
        var safe = new string(relativePath
            .Select(character => char.IsLetterOrDigit(character) ? char.ToLowerInvariant(character) : '-')
            .ToArray());
        return safe.Length <= 96 ? safe : safe[..96];
    }

    private static bool RuleTargetsBlockedList(FileRule rule, string defaultTargetList)
    {
        return defaultTargetList.Equals("blockedFiles", StringComparison.OrdinalIgnoreCase)
               || rule.Severity.Equals("block", StringComparison.OrdinalIgnoreCase)
               || rule.Severity.Equals("strike", StringComparison.OrdinalIgnoreCase)
               || rule.Severity.Equals("warn", StringComparison.OrdinalIgnoreCase);
    }

    private static bool SameRuleIdentity(FileRule first, FileRule second)
    {
        return string.Equals(first.Id, second.Id, StringComparison.OrdinalIgnoreCase)
               || !string.IsNullOrWhiteSpace(first.Hash)
               && string.Equals(first.Hash, second.Hash, StringComparison.OrdinalIgnoreCase)
               || !string.IsNullOrWhiteSpace(first.Path)
               && string.Equals(NormalizePath(first.Path), NormalizePath(second.Path), StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeRuleListTarget(string? targetList)
    {
        return (targetList ?? "allowedFiles").Equals("blockedFiles", StringComparison.OrdinalIgnoreCase)
            ? "blockedFiles"
            : "allowedFiles";
    }

    private static string NormalizeMode(string? mode)
    {
        return (mode ?? "WarnOnly").Replace("-", "", StringComparison.Ordinal).Replace("_", "", StringComparison.Ordinal).ToLowerInvariant() switch
        {
            "disabled" or "off" => "Disabled",
            "audit" or "warn" or "warnonly" => "WarnOnly",
            "enforce" or "block" or "blockraid" => "BlockRaid",
            "strikethenblock" or "strikeblock" => "StrikeThenBlock",
            _ => "WarnOnly"
        };
    }

    private static string NormalizeSeverity(string? severity, string fallback)
    {
        return (severity ?? fallback).ToLowerInvariant() switch
        {
            "audit" => "audit",
            "warn" => "warn",
            "warning" => "warn",
            "strike" => "strike",
            "block" => "block",
            _ => fallback
        };
    }

    private static string NormalizeTimeZoneId(string? timeZoneId)
    {
        if (string.IsNullOrWhiteSpace(timeZoneId))
        {
            return "UTC";
        }

        try
        {
            _ = TimeZoneInfo.FindSystemTimeZoneById(timeZoneId);
            return timeZoneId;
        }
        catch
        {
            return "UTC";
        }
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('\\', '/').Trim().TrimStart('/');
    }

    private static bool IsAllowedSptPath(string path)
    {
        var normalized = NormalizePath(path);
        if (string.IsNullOrWhiteSpace(normalized)
            || Path.IsPathRooted(normalized)
            || normalized.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        return AllowedScanRoots.Any(root =>
            normalized.Equals(root, StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(root.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase));
    }
}

public static class ModSecConfigFactory
{
    public static ModSecConfig CreateDefault()
    {
        return new ModSecConfig
        {
            Enabled = true,
            Mode = "BlockRaid",
            ServerTimeZoneId = "UTC",
            AutoBlockDurationsHours = [24, 72, 168, 0],
            Dashboard = new DashboardOptions
            {
                Enabled = true,
                AdminToken = "modsec-dev-token",
                AllowRemoteAdmin = false,
                SessionMinutes = 120,
                FailedAttemptWindowSeconds = 300,
                MaxFailedAttempts = 5,
                LockoutSeconds = 300
            },
            Privacy = new PrivacyOptions
            {
                RequireClientConsent = true,
                AllowOutsideSptScanPaths = false,
                SendFullSnapshotsAfterConsent = true,
                ConsentVersion = 2
            },
            AutoWhitelist = new AutoWhitelistOptions
            {
                Enabled = false,
                Paths = ["BepInEx/plugins"],
                TargetList = "allowedFiles",
                WriteGeneratedFile = true,
                RefreshGeneratedFile = false,
                GeneratedFileName = "auto-whitelist.generated.json"
            },
            ReportSanity = new ReportSanityOptions
            {
                Enabled = true,
                EmptyReportSeverity = "block",
                RequireKnownClientVersion = true,
                AllowNewerClientVersion = true,
                VersionMismatchSeverity = "warn",
                FlagSuspiciousLoadedPlugins = true,
                FlagSuspiciousUnreportedDlls = true,
                SuspiciousSeverity = "warn",
                SuspiciousNamePatterns = []
            },
            ClientPresence = new ClientPresenceOptions
            {
                Enabled = true,
                MissingClientAction = "block",
                GraceSeconds = 45,
                HeartbeatIntervalSeconds = 120,
                HeartbeatTimeoutSeconds = 300,
                GateRoutes = DefaultGateRoutes()
            },
            IncidentMail = new IncidentMailOptions
            {
                Enabled = true,
                SenderName = "Hall of Shame",
                SendToAllProfiles = true,
                IncludeMissingClientBlocks = true,
                IncludePolicyViolations = true,
                IncludeAutomaticBans = true,
                CooldownSeconds = 300,
                MaxViolationsListed = 8,
                Templates = new IncidentMailTemplates
                {
                    MissingClientLines = ModSecIncidentMailService.DefaultMissingClientLines(),
                    PolicyViolationLines = ModSecIncidentMailService.DefaultPolicyViolationLines(),
                    AutomaticBanLines = ModSecIncidentMailService.DefaultAutomaticBanLines()
                }
            },
            ScanPaths = ["BepInEx/plugins"],
            BlockedPlugins =
            [
                new PluginRule
                {
                    Id = "block-drakia-botdebug-guid",
                    Name = "DrakiaXYZ BotDebug",
                    Guid = "xyz.drakia.botdebug",
                    DisplayName = "DrakiaXYZ-BotDebug",
                    Reason = "DrakiaXYZ BotDebug is not allowed on this server.",
                    Severity = "block"
                }
            ],
            BlockedFiles =
            [
                new FileRule
                {
                    Id = "block-drakia-botdebug-exact",
                    Name = "DrakiaXYZ BotDebug",
                    Path = "BepInEx/plugins/DrakiaXYZ-BotDebug.dll",
                    Reason = "DrakiaXYZ BotDebug is not allowed on this server.",
                    Severity = "block"
                },
                new FileRule
                {
                    Id = "block-any-botdebug-top-level",
                    Name = "Any top-level BotDebug plugin",
                    Glob = "BepInEx/plugins/*BotDebug*.dll",
                    Reason = "BotDebug plugins are not allowed on this server.",
                    Severity = "block"
                },
                new FileRule
                {
                    Id = "block-any-botdebug-nested",
                    Name = "Any nested BotDebug plugin",
                    Glob = "BepInEx/plugins/**/*BotDebug*.dll",
                    Reason = "BotDebug plugins are not allowed on this server.",
                    Severity = "block"
                },
                new FileRule
                {
                    Id = "example-block-spt-bot-debug-top-level",
                    Name = "Example blocked debug plugin",
                    Glob = "BepInEx/plugins/SPT-BotDebug*.dll",
                    Reason = "Debug plugin is not allowed on this server.",
                    Severity = "block"
                },
                new FileRule
                {
                    Id = "example-block-spt-bot-debug-nested",
                    Name = "Example blocked debug plugin",
                    Glob = "BepInEx/plugins/**/SPT-BotDebug*.dll",
                    Reason = "Debug plugin is not allowed on this server.",
                    Severity = "block"
                }
            ],
            ConfigFiles =
            [
                new ConfigFileRule
                {
                    Id = "megamod-example-settings",
                    Name = "MegaMod example config rules",
                    Path = "BepInEx/config/com.cwx.megamod.cfg",
                    Format = "bepinex",
                    Required = false,
                    Rules =
                    [
                        new ConfigRule
                        {
                            Id = "megamod-master-key-disabled",
                            Name = "MegaMod MasterKey disabled",
                            Section = "1- All Mods",
                            Key = "MasterKey - On/Off",
                            Operator = "in",
                            AllowedValues = ["false"],
                            Severity = "block"
                        },
                        new ConfigRule
                        {
                            Id = "megamod-god-mode-disabled",
                            Name = "MegaMod GodMode disabled",
                            Section = "2- Debug Mods",
                            Key = "GodMode - On/Off",
                            Operator = "in",
                            AllowedValues = ["false"],
                            Severity = "block"
                        }
                    ]
                }
            ],
            ConfigRules = []
        };
    }

    public static List<string> DefaultGateRoutes()
    {
        return
        [
            "/client/match/local/start",
            "/fika/raid/create",
            "/fika/raid/join",
            "/fika/update/addplayer",
            "/fika/raid/registerPlayer",
            "/fika/update/playerspawn"
        ];
    }
}
