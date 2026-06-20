using System.Text.Json;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using ModSec.Server.Models;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.DI;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Servers.Http;

namespace ModSec.Server.Services;

[Injectable(InjectionType = InjectionType.Singleton, TypePriority = OnLoadOrder.PostDBModLoader)]
public class ModSecHttpListener(ModSecConfigService configService, ModSecIncidentMailService incidentMailService) : IHttpListener
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = false
    };

    private readonly object _stateLock = new();
    private readonly Dictionary<string, PlayerState> _players = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<AdminPopup>> _targetedPopups = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _adminSessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, AdminFailureState> _adminFailures = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<QueuedBroadcastPopup> _broadcastPopups = [];
    private readonly List<QueuedRaidCommand> _raidCommands = [];
    private readonly List<AdminEvent> _events = [];
    private string _statePath = "";
    private string _eventsPath = "";
    private bool _initialized;
    private const int LaunchFreshnessGraceSeconds = 30;

    public void Initialize(string modPath)
    {
        _statePath = Path.Combine(modPath, "config", "players.json");
        _eventsPath = Path.Combine(modPath, "config", "events.json");
        LoadState();
        LoadEvents();
        _initialized = true;
    }

    public bool CanHandle(MongoId sessionId, HttpContext context)
    {
        return context.Request.Path.StartsWithSegments("/modsec");
    }

    public async Task Handle(MongoId sessionId, HttpContext context)
    {
        if (!_initialized)
        {
            context.Response.StatusCode = 503;
            await context.Response.WriteAsync("ModSec is not initialized.");
            return;
        }

        try
        {
            var path = context.Request.Path.Value ?? "";
            var method = context.Request.Method.ToUpperInvariant();

            if (method == "GET" && path == "/modsec/version")
            {
                await WriteJson(context, ModSecConstants.Version);
                return;
            }

            if (method == "GET" && path == "/modsec/policy")
            {
                await WriteJson(context, configService.GetPolicy());
                return;
            }

            if (method == "POST" && path == "/modsec/report")
            {
                var report = await ReadJson<ClientReport>(context);
                await WriteJson(context, EvaluateReport(report, context.Connection.RemoteIpAddress?.ToString() ?? "unknown"));
                return;
            }

            if (method == "POST" && path == "/modsec/heartbeat")
            {
                var heartbeat = await ReadJson<ClientHeartbeat>(context);
                await WriteJson(context, HandleHeartbeat(heartbeat, context.Connection.RemoteIpAddress?.ToString() ?? "unknown"));
                return;
            }

            if (method == "POST" && path == "/modsec/popups")
            {
                var poll = await ReadJson<ClientPopupPoll>(context);
                await WriteJson(context, HandlePopupPoll(poll, context.Connection.RemoteIpAddress?.ToString() ?? "unknown"));
                return;
            }

            if (path.StartsWith("/modsec/admin/", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/modsec/dashboard", StringComparison.OrdinalIgnoreCase))
            {
                await HandleAdmin(context, method, path);
                return;
            }

            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("ModSec: unknown route.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ModSec] Route error: {ex}");
            if (!context.Response.HasStarted)
            {
                context.Response.StatusCode = 500;
                await context.Response.WriteAsync($"ModSec route error: {ex.Message}");
            }
        }
    }

    private EnforcementResponse EvaluateReport(ClientReport report, string ip)
    {
        var config = configService.GetCurrent();
        var state = GetPlayerState(report.ProfileId, report.PlayerName, ip, report.InstallId);
        state.TimeZoneId = string.IsNullOrWhiteSpace(report.TimeZoneId) ? state.TimeZoneId : report.TimeZoneId;
        RecordClientReport(state, report);
        DecayStrikes(state, config);

        var response = new EnforcementResponse
        {
            StrikeLimit = config.StrikeLimit,
            Strikes = state.Strikes,
            NextCheckSeconds = GetNextInterval(config, state)
        };

        if (!config.Enabled)
        {
            response.Status = "pass";
            response.Message = "ModSec is disabled.";
            response.Popups = DrainPopups(state.ProfileId);
            response.RaidCommands = DrainRaidCommands(state.ProfileId);
            AddEvent("report", state, "info", "Report received while ModSec is disabled.", []);
            SaveState();
            return response;
        }

        if (state.BannedUntilUtc is { } bannedUntil && bannedUntil > DateTime.UtcNow)
        {
            response.Status = "banned";
            response.Message = BuildBanMessage(state, config);
            response.CooldownUntilUtc = bannedUntil;
            response.Popups = DrainPopups(state.ProfileId);
            response.RaidCommands = BuildRaidRemovalCommands(config, report, state, response);
            state.ActiveEnforcementStatus = "banned";
            if (ShouldPublishEnforcement(state, response.Status, [], strikeApplied: false))
            {
                Console.WriteLine($"[ModSec] BANNED {state.PlayerName} ({state.ProfileId}) - active local server lockout.");
                AddEvent("server-lockout-block", state, "block", "Restricted player attempted to report.", []);
            }
            SaveState();
            return response;
        }

        var violations = DeduplicateViolations(FindViolations(config, report));
        response.Violations = violations;
        response.Popups = DrainPopups(state.ProfileId);

        if (violations.Count == 0)
        {
            MarkCleanReport(state, report);
            state.RiskScore = Math.Max(0, state.RiskScore - 5);
            response.Status = "pass";
            response.Message = "ModSec check passed.";
            response.Strikes = state.Strikes;
            response.NextCheckSeconds = GetNextInterval(config, state);
            response.RaidCommands = DrainRaidCommands(state.ProfileId);
            AddEvent("pass", state, "info", "ModSec check passed.", []);
            SaveState();
            return response;
        }

        state.LastViolationAtUtc = DateTime.UtcNow;
        state.RecentViolations = violations.TakeLast(20).ToList();
        var violationSignature = GetViolationSignature(violations);

        var shouldStrike = violations.Any(v => IsStrikeSeverity(v.Severity));
        var canApplyStrike = shouldStrike
                             && ModeAllowsStrikes(config.Mode)
                             && ShouldApplyStrike(state, violationSignature);
        if (canApplyStrike)
        {
            state.Strikes++;
            response.Strikes = state.Strikes;
            state.RiskScore = Math.Min(100, state.RiskScore + violations.Sum(GetRiskDelta));
            state.CooldownUntilUtc = config.CooldownMinutes > 0
                ? DateTime.UtcNow.AddMinutes(config.CooldownMinutes)
                : null;
            state.LastViolationSignature = violationSignature;
        }
        else
        {
            response.Strikes = state.Strikes;
        }

        var hasBlock = violations.Any(v => IsBlockSeverity(v.Severity));
        if (state.Strikes >= config.StrikeLimit && ModeAllowsStrikes(config.Mode))
        {
            ApplyAutomaticBan(state, config);
            response.Status = "banned";
            response.Message = BuildBanMessage(state, config);
            response.CooldownUntilUtc = state.BannedUntilUtc;
            response.NextCheckSeconds = GetNextInterval(config, state);
            response.RaidCommands = BuildRaidRemovalCommands(config, report, state, response);
            state.ActiveEnforcementStatus = "banned";
            state.ActiveViolations = violations.TakeLast(20).ToList();
            AddEvent("auto-lockout", state, "block", state.BanReason, violations);
            if (!report.InRaid)
            {
                QueueLockoutToast(state, config);
            }

            incidentMailService.BroadcastAutomaticBan(state, config, violations);
            SaveState();
            return response;
        }

        response.Status = config.Mode switch
        {
            "Disabled" => "audit",
            "WarnOnly" => "warn",
            "BlockRaid" => hasBlock ? "blocked" : "warn",
            "StrikeThenBlock" => hasBlock || state.Strikes >= config.StrikeLimit ? "blocked" : "warn",
            _ => "warn"
        };

        response.CooldownUntilUtc = state.CooldownUntilUtc is { } strikeCooldownUntil && strikeCooldownUntil > DateTime.UtcNow
            ? strikeCooldownUntil
            : null;

        response.Message = BuildEnforcementMessage(response.Status, canApplyStrike, state, config, response.CooldownUntilUtc, violations);
        response.NextCheckSeconds = GetNextInterval(config, state);
        response.RaidCommands = BuildRaidRemovalCommands(config, report, state, response);
        state.ActiveEnforcementStatus = response.Status;
        state.ActiveViolations = response.Status is "blocked" or "banned"
            ? violations.TakeLast(20).ToList()
            : [];

        var publishEnforcement = ShouldPublishEnforcement(state, response.Status, violations, canApplyStrike);
        if (publishEnforcement)
        {
            Console.WriteLine($"[ModSec] {response.Status.ToUpperInvariant()} {state.PlayerName} ({state.ProfileId}) - {violations.Count} violation(s), strikes={state.Strikes}, risk={state.RiskScore}, strikeApplied={canApplyStrike}");
            foreach (var violation in violations.Where(IsConfigViolation))
            {
                var path = string.IsNullOrWhiteSpace(violation.Path) ? "" : $" @ {violation.Path}";
                Console.WriteLine($"[ModSec]   violation: {violation.Severity} {violation.RuleId}{path} - {violation.Reason}");
            }

            AddEvent(response.Status, state, hasBlock ? "block" : "warning", $"{violations.Count} violation(s), strikeApplied={canApplyStrike}.", violations);
            if (canApplyStrike)
            {
                QueueStrikeToast(state, config);
            }

            incidentMailService.BroadcastPolicyIncident(state, response.Status, canApplyStrike, config, violations);
        }

        SaveState();
        return response;
    }

    private EnforcementResponse HandleHeartbeat(ClientHeartbeat heartbeat, string ip)
    {
        var config = configService.GetCurrent();
        var state = GetPlayerState(heartbeat.ProfileId, heartbeat.PlayerName, ip, heartbeat.InstallId);
        state.TimeZoneId = string.IsNullOrWhiteSpace(heartbeat.TimeZoneId) ? state.TimeZoneId : heartbeat.TimeZoneId;
        state.LastHeartbeatAtUtc = DateTime.UtcNow;
        state.ComplianceStatus = "client-seen";
        NormalizeClearedEnforcementState(state);
        DecayStrikes(state, config);

        var isLockedOut = state.BannedUntilUtc is { } bannedUntil && bannedUntil > DateTime.UtcNow;
        var isPolicyBlocked = !isLockedOut && HasActiveRaidBlockingViolation(state, config);

        var response = new EnforcementResponse
        {
            Status = isLockedOut ? "banned" : isPolicyBlocked ? "blocked" : "pass",
            Message = isLockedOut
                ? BuildBanMessage(state, config)
                : isPolicyBlocked
                    ? "Raid access is blocked by this host until the listed ModSec policy issues are fixed. Recheck after correcting the blocked mod or config value."
                : "",
            Strikes = state.Strikes,
            StrikeLimit = config.StrikeLimit,
            CooldownUntilUtc = state.BannedUntilUtc,
            Violations = isPolicyBlocked ? state.ActiveViolations.TakeLast(20).ToList() : [],
            NextCheckSeconds = GetNextInterval(config, state),
            Popups = DrainPopups(state.ProfileId),
            RaidCommands = []
        };

        response.RaidCommands = response.Status == "banned"
            ? BuildRaidRemovalCommands(config, new ClientReport
            {
                ProfileId = heartbeat.ProfileId,
                PlayerName = heartbeat.PlayerName,
                InstallId = heartbeat.InstallId,
                InRaid = heartbeat.InRaid,
                IsFikaHost = heartbeat.IsFikaHost,
                HumanPlayerCount = heartbeat.HumanPlayerCount
            }, state, response)
            : DrainRaidCommands(state.ProfileId);

        if (response.Status == "banned")
        {
            AddEvent("heartbeat-lockout-block", state, "block", "Restricted heartbeat blocked.", []);
        }

        SaveState();
        return response;
    }

    private PopupPollResponse HandlePopupPoll(ClientPopupPoll poll, string ip)
    {
        var config = configService.GetCurrent();
        if (!config.Enabled || string.IsNullOrWhiteSpace(poll.ProfileId))
        {
            return new PopupPollResponse();
        }

        var state = GetPlayerState(poll.ProfileId, poll.PlayerName, ip, poll.InstallId);
        state.LastHeartbeatAtUtc = DateTime.UtcNow;
        return new PopupPollResponse
        {
            Popups = DrainPopups(state.ProfileId)
        };
    }

    private List<Violation> FindViolations(ModSecConfig config, ClientReport report)
    {
        var violations = new List<Violation>();
        var fileByPath = report.Files.ToDictionary(f => NormalizePath(f.Path), StringComparer.OrdinalIgnoreCase);
        var protectedFiles = configService.GetProtectedClientFileFingerprints();

        AddReportSanityViolations(config, report, violations);

        if (!report.MainPluginPresent)
        {
            violations.Add(new Violation
            {
                Severity = "block",
                Reason = "Main ModSec client plugin is missing."
            });
        }

        foreach (var plugin in report.Plugins)
        {
            if (IsProtectedClientPlugin(plugin, fileByPath, protectedFiles))
            {
                continue;
            }

            var blockedPlugin = config.BlockedPlugins.FirstOrDefault(rule => MatchesPluginRule(rule, plugin));
            if (blockedPlugin != null)
            {
                violations.Add(new Violation
                {
                    Severity = blockedPlugin.Severity,
                    Reason = string.IsNullOrWhiteSpace(blockedPlugin.Reason) ? "Plugin is blocked by server policy." : blockedPlugin.Reason,
                    Path = plugin.Location,
                    RuleId = blockedPlugin.Id
                });
            }
        }

        foreach (var rule in config.RequiredFiles)
        {
            if (!report.Files.Any(file => MatchesRule(rule, file)))
            {
                violations.Add(new Violation
                {
                    Severity = rule.Severity,
                    Reason = string.IsNullOrWhiteSpace(rule.Reason) ? "Required file is missing." : rule.Reason,
                    Path = rule.Path,
                    RuleId = rule.Id
                });
            }
        }

        foreach (var file in report.Files)
        {
            if (IsProtectedClientFile(file.Path, file.Hash, protectedFiles))
            {
                continue;
            }

            var blockedRule = config.BlockedFiles.FirstOrDefault(rule => MatchesRule(rule, file));
            if (blockedRule != null)
            {
                violations.Add(new Violation
                {
                    Severity = blockedRule.Severity,
                    Reason = string.IsNullOrWhiteSpace(blockedRule.Reason) ? "File is blocked by server policy." : blockedRule.Reason,
                    Path = file.Path,
                    RuleId = blockedRule.Id
                });
                continue;
            }

            if (config.StrictWhitelist && !config.AllowedFiles.Any(rule => MatchesRule(rule, file)))
            {
                violations.Add(new Violation
                {
                    Severity = "block",
                    Reason = "File hash is not on this host's allowed-file list.",
                    Path = file.Path
                });
            }
        }

        foreach (var rule in ModSecConfigService.GetEffectiveConfigRules(config))
        {
            var value = FindConfigReportValue(rule, report.ConfigValues);

            if (value == null || !value.Found)
            {
                if (value is { FileExists: false } && !rule.Required)
                {
                    continue;
                }

                if (value == null && !rule.Required)
                {
                    continue;
                }

                violations.Add(BuildMissingConfigViolation(rule, value));
                continue;
            }

            if (!ConfigValuePasses(rule, value.Value))
            {
                violations.Add(new Violation
                {
                    Severity = rule.Severity,
                    Reason = BuildConfigViolationReason(rule, value.Value),
                    Path = rule.Path,
                    RuleId = rule.Id,
                    Category = "config",
                    Setting = DisplayConfigKey(rule),
                    ActualValue = value.Value ?? "(missing)",
                    ExpectedValue = DescribeConfigExpectation(rule)
                });
            }
        }

        return violations;
    }

    private static void AddReportSanityViolations(ModSecConfig config, ClientReport report, List<Violation> violations)
    {
        var sanity = config.ReportSanity;
        if (!sanity.Enabled)
        {
            return;
        }

        if (report.Plugins.Count == 0 || report.Files.Count == 0)
        {
            violations.Add(new Violation
            {
                Severity = sanity.EmptyReportSeverity,
                Reason = $"Client report is incomplete: plugins={report.Plugins.Count}, files={report.Files.Count}.",
                RuleId = "report-empty"
            });
        }

        if (sanity.RequireKnownClientVersion && !ClientVersionAllowed(report.ClientVersion, sanity.AllowNewerClientVersion))
        {
            violations.Add(new Violation
            {
                Severity = sanity.VersionMismatchSeverity,
                Reason = $"Client ModSec version '{report.ClientVersion}' does not match server version '{ModSecConstants.Version}'.",
                Path = "BepInEx/plugins/modSec/modSec.dll",
                RuleId = "client-version"
            });
        }

        var patterns = sanity.SuspiciousNamePatterns
            .Where(pattern => !string.IsNullOrWhiteSpace(pattern))
            .ToList();

        if (patterns.Count == 0)
        {
            return;
        }

        if (sanity.FlagSuspiciousLoadedPlugins)
        {
            foreach (var plugin in report.Plugins.Where(plugin => ContainsSuspiciousPattern(plugin.Guid, plugin.Name, plugin.Location, patterns)))
            {
                violations.Add(new Violation
                {
                    Severity = sanity.SuspiciousSeverity,
                    Reason = "Loaded plugin matches a suspicious name pattern.",
                    Path = plugin.Location,
                    RuleId = "suspicious-plugin"
                });
            }
        }

        if (!sanity.FlagSuspiciousUnreportedDlls)
        {
            return;
        }

        var pluginLocations = report.Plugins
            .Select(plugin => NormalizePath(plugin.Location))
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var file in report.Files.Where(file => IsPluginDll(file.Path) && !pluginLocations.Contains(NormalizePath(file.Path))))
        {
            if (!ContainsSuspiciousPattern(file.Path, Path.GetFileNameWithoutExtension(file.Path), "", patterns))
            {
                continue;
            }

            violations.Add(new Violation
            {
                Severity = sanity.SuspiciousSeverity,
                Reason = "Plugin DLL exists on disk but was not reported as a loaded BepInEx plugin and matches a suspicious name pattern.",
                Path = file.Path,
                RuleId = "suspicious-unreported-dll"
            });
        }
    }

    private static bool ClientVersionAllowed(string clientVersion, bool allowNewer)
    {
        if (string.Equals(clientVersion, ModSecConstants.Version, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!allowNewer)
        {
            return false;
        }

        return Version.TryParse(clientVersion, out var client)
               && Version.TryParse(ModSecConstants.Version, out var server)
               && client >= server;
    }

    private static bool ContainsSuspiciousPattern(string first, string second, string third, List<string> patterns)
    {
        return patterns.Any(pattern =>
            first.Contains(pattern, StringComparison.OrdinalIgnoreCase)
            || second.Contains(pattern, StringComparison.OrdinalIgnoreCase)
            || third.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsPluginDll(string path)
    {
        var normalized = NormalizePath(path);
        return normalized.StartsWith("BepInEx/plugins/", StringComparison.OrdinalIgnoreCase)
               && normalized.EndsWith(".dll", StringComparison.OrdinalIgnoreCase);
    }

    private static List<Violation> DeduplicateViolations(List<Violation> violations)
    {
        var byTarget = new Dictionary<string, Violation>(StringComparer.OrdinalIgnoreCase);
        var dedupedViolations = new List<Violation>();

        foreach (var violation in violations)
        {
            var key = GetViolationDedupeKey(violation);
            if (string.IsNullOrWhiteSpace(key))
            {
                dedupedViolations.Add(violation);
                continue;
            }

            if (!byTarget.TryGetValue(key, out var existing))
            {
                byTarget[key] = violation;
                dedupedViolations.Add(violation);
                continue;
            }

            if (GetSeverityRank(violation.Severity) > GetSeverityRank(existing.Severity))
            {
                var index = dedupedViolations.IndexOf(existing);
                byTarget[key] = violation;
                if (index >= 0)
                {
                    dedupedViolations[index] = violation;
                }
            }
        }

        return dedupedViolations;
    }

    private static string GetViolationDedupeKey(Violation violation)
    {
        if (string.IsNullOrWhiteSpace(violation.Path))
        {
            return "";
        }

        var normalizedPath = NormalizePath(violation.Path);
        if (IsConfigViolation(violation))
        {
            return $"{normalizedPath}:{violation.RuleId}";
        }

        return normalizedPath;
    }

    private static bool ShouldApplyStrike(PlayerState state, string violationSignature)
    {
        if (state.CooldownUntilUtc is { } cooldownUntil && cooldownUntil > DateTime.UtcNow)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(violationSignature))
        {
            return true;
        }

        if (!string.Equals(state.LastViolationSignature, violationSignature, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private static bool IsConfigViolation(Violation violation)
    {
        return violation.Category.Equals("config", StringComparison.OrdinalIgnoreCase)
               || violation.Path.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase)
               || violation.Path.EndsWith(".json", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetViolationSignature(List<Violation> violations)
    {
        return string.Join("|", violations
            .Select(violation => $"{NormalizePath(violation.Path)}:{violation.RuleId}:{violation.Severity}")
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase));
    }

    private static bool ShouldPublishEnforcement(PlayerState state, string status, List<Violation> violations, bool strikeApplied)
    {
        if (status.Equals("pass", StringComparison.OrdinalIgnoreCase)
            || status.Equals("audit", StringComparison.OrdinalIgnoreCase))
        {
            state.LastPublishedEnforcementSignature = "";
            state.LastPublishedEnforcementAtUtc = null;
            return true;
        }

        var now = DateTime.UtcNow;
        var signature = string.Join("|",
            status,
            state.Strikes.ToString(),
            strikeApplied ? "strike" : "no-strike",
            state.BannedUntilUtc?.ToString("O") ?? "",
            GetViolationSignature(violations));

        if (!strikeApplied
            && string.Equals(state.LastPublishedEnforcementSignature, signature, StringComparison.Ordinal)
            && state.LastPublishedEnforcementAtUtc is { } lastPublished
            && lastPublished.AddSeconds(120) > now)
        {
            return false;
        }

        state.LastPublishedEnforcementSignature = signature;
        state.LastPublishedEnforcementAtUtc = now;
        return true;
    }

    private static string BuildEnforcementMessage(string status, bool strikeApplied, PlayerState state, ModSecConfig config, DateTime? strikeCooldownUntil, List<Violation> violations)
    {
        var summary = status switch
        {
            "audit" => "Host rule issue logged for the server admin.",
            "warn" => "Host rule issue detected. Fix the listed items before joining raids.",
            "blocked" => "Raid access is blocked by this host until the listed issues are fixed.",
            _ => "Host rule issue detected."
        };

        var strikeLine = strikeApplied
            ? "A strike was applied to your profile."
            : "No additional strike was applied for this repeated unresolved issue.";

        var lines = new List<string>
        {
            "<b>STATUS</b>",
            summary,
            "",
            "<b>PROFILE</b>",
            $"Strikes: {state.Strikes}/{config.StrikeLimit}",
            strikeLine
        };

        if (strikeCooldownUntil != null)
        {
            lines.Add($"Strike protection until {FormatDateTime(strikeCooldownUntil.Value, ResolveTimeZone(state, config))}");
        }

        lines.Add("");
        lines.Add("<b>REQUIRED ACTION</b>");
        lines.Add(HasConfigViolation(violations)
            ? BuildConfigRequiredAction(violations)
            : "Quit the game and remove or correct the listed item before reconnecting.");

        return string.Join("\n", lines);
    }

    private static string BuildConfigRequiredAction(List<Violation> violations)
    {
        var configViolations = violations.Where(violation =>
            violation.Category.Equals("config", StringComparison.OrdinalIgnoreCase)
            || violation.Path.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase)
            || violation.Path.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (configViolations.Count == 0 || configViolations.All(violation => string.IsNullOrWhiteSpace(violation.Setting)))
        {
            return "Open the mod's F12/config menu, change the listed setting back to an allowed value, then press Recheck Now.";
        }

        var lines = new List<string>
        {
            "Open the mod's F12/config menu and change these settings, then press Recheck Now:"
        };

        lines.AddRange(configViolations
            .Where(violation => !string.IsNullOrWhiteSpace(violation.Setting))
            .Take(6)
            .Select(violation => $"- {violation.Setting}: current {EmptyToUnknown(violation.ActualValue)}, allowed {EmptyToUnknown(violation.ExpectedValue)}"));

        if (configViolations.Count > 6)
        {
            lines.Add($"- plus {configViolations.Count - 6} more setting(s)");
        }

        return string.Join("\n", lines);
    }

    private static string EmptyToUnknown(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? "unknown" : value;
    }

    private static bool HasConfigViolation(List<Violation> violations)
    {
        return violations.Any(violation =>
            violation.Path.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase)
            || violation.Path.EndsWith(".json", StringComparison.OrdinalIgnoreCase));
    }

    private static void ApplyAutomaticBan(PlayerState state, ModSecConfig config)
    {
        var ladderIndex = Math.Max(0, state.BanCount);
        var hours = ladderIndex < config.AutoBlockDurationsHours.Count
            ? config.AutoBlockDurationsHours[ladderIndex]
            : 0;

        state.BanCount++;
        state.Strikes = 0;
        state.CooldownUntilUtc = null;
        state.LastViolationSignature = "";
        state.BanReason = $"Automatic ModSec server lockout after reaching {config.StrikeLimit} local strikes.";
        state.BannedUntilUtc = hours <= 0 ? DateTime.MaxValue : DateTime.UtcNow.AddHours(hours);
    }

    private static string BuildBanMessage(PlayerState state, ModSecConfig config)
    {
        var timeZone = ResolveTimeZone(state, config);
        var unlock = state.BannedUntilUtc == DateTime.MaxValue
            ? "Permanent"
            : FormatDateTime(state.BannedUntilUtc ?? DateTime.UtcNow, timeZone);

        return string.Join("\n", new[]
        {
            "<b>LOCKOUT STATUS</b>",
            "Raid access is currently restricted by this host.",
            "",
            "<b>REASON</b>",
            string.IsNullOrWhiteSpace(state.BanReason) ? "Profile restricted by this host." : state.BanReason,
            "",
            "<b>UNLOCK</b>",
            unlock
        });
    }

    private static TimeZoneInfo ResolveTimeZone(PlayerState state, ModSecConfig config)
    {
        foreach (var candidate in new[] { state.TimeZoneId, config.ServerTimeZoneId, "UTC" })
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                continue;
            }

            try
            {
                return TimeZoneInfo.FindSystemTimeZoneById(candidate);
            }
            catch
            {
                // Try the next configured fallback.
            }
        }

        return TimeZoneInfo.Utc;
    }

    private static string FormatDateTime(DateTime utc, TimeZoneInfo timeZone)
    {
        var local = TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utc, DateTimeKind.Utc), timeZone);
        return $"{local:yyyy-MM-dd HH:mm:ss} {timeZone.StandardName}";
    }

    private static int GetSeverityRank(string severity)
    {
        return severity.ToLowerInvariant() switch
        {
            "block" => 4,
            "strike" => 3,
            "warn" => 2,
            "audit" => 1,
            _ => 0
        };
    }

    private async Task HandleAdmin(HttpContext context, string method, string path)
    {
        if (method == "GET" && (path == "/modsec/admin" || path == "/modsec/admin/dashboard" || path == "/modsec/dashboard"))
        {
            await HandleDashboard(context);
            return;
        }

        if (method == "POST" && path == "/modsec/admin/login")
        {
            await HandleAdminLogin(context);
            return;
        }

        if (!IsAdminRequest(context))
        {
            context.Response.StatusCode = 403;
            await context.Response.WriteAsync("ModSec admin access denied.");
            return;
        }

        switch (method, path)
        {
            case ("GET", "/modsec/admin/players"):
                List<PlayerState> players;
                var config = configService.GetCurrent();
                lock (_stateLock)
                {
                    foreach (var player in _players.Values)
                    {
                        player.ComplianceStatus = GetComplianceStatus(player, config);
                    }

                    players = GetVisiblePlayers(_players.Values).ToList();
                }
                await WriteJson(context, players);
                return;

            case ("GET", "/modsec/admin/events"):
                List<AdminEvent> events;
                lock (_stateLock)
                {
                    events = _events
                        .OrderByDescending(e => e.CreatedAtUtc)
                        .Take(200)
                        .ToList();
                }
                await WriteJson(context, events);
                return;

            case ("GET", "/modsec/admin/diagnostics"):
                await WriteJson(context, GetDashboardDiagnostics());
                return;

            case ("GET", "/modsec/admin/config"):
                await WriteJson(context, configService.GetCurrent());
                return;

            case ("GET", "/modsec/admin/config/editable"):
                await WriteJson(context, configService.GetEditableConfig());
                return;

            case ("GET", "/modsec/admin/policy/export"):
                await WriteJson(context, configService.ExportPolicyPackage(
                    context.Request.Query["name"].ToString(),
                    context.Request.Query["notes"].ToString()));
                return;

            case ("GET", "/modsec/admin/server-files"):
                await WriteJson(context, configService.GetServerFileInventory());
                return;

            case ("GET", "/modsec/admin/player-inventory"):
                await WriteJson(context, GetPlayerInventory(context.Request.Query["profileId"].ToString()));
                return;

            case ("POST", "/modsec/admin/config"):
                var configRequest = await ReadJson<ModSecConfig>(context);
                var savedConfig = configService.SaveConfig(configRequest);
                AddEvent("admin-config-save", null, "info", "Config saved from dashboard.", []);
                await WriteJson(context, new { success = true, config = savedConfig });
                return;

            case ("POST", "/modsec/admin/policy/import"):
                var importPackage = await ReadJson<PolicyPackage>(context);
                var importedConfig = configService.ImportPolicyPackage(importPackage);
                AddEvent("admin-policy-import", null, "info", $"Imported policy package '{importPackage.Name}'. Local dashboard token and timezone were preserved.", []);
                await WriteJson(context, new { success = true, config = importedConfig });
                return;

            case ("POST", "/modsec/admin/policy/merge"):
                var mergePackage = await ReadJson<PolicyPackage>(context);
                var mergedConfig = configService.MergePolicyPackage(mergePackage);
                AddEvent("admin-policy-merge", null, "info", $"Merged policy package '{mergePackage.Name}'. Local dashboard token and timezone were preserved.", []);
                await WriteJson(context, new { success = true, config = mergedConfig });
                return;

            case ("POST", "/modsec/admin/reload"):
                configService.ForceReload();
                AddEvent("admin-reload", null, "info", "Config reloaded from dashboard.", []);
                await WriteJson(context, new { success = true });
                return;

            case ("POST", "/modsec/admin/popup"):
                var popupRequest = await ReadJson<AdminPopupRequest>(context);
                var popup = QueuePopup(popupRequest);
                await WriteJson(context, new { success = true, popup });
                return;

            case ("POST", "/modsec/admin/ban"):
                var banRequest = await ReadJson<AdminBanRequest>(context);
                await WriteJson(context, BanPlayer(banRequest));
                return;

            case ("POST", "/modsec/admin/unban"):
                var unbanRequest = await ReadJson<AdminPlayerAction>(context);
                await WriteJson(context, UnbanPlayer(unbanRequest.ProfileId));
                return;

            case ("POST", "/modsec/admin/pardon"):
                var pardonRequest = await ReadJson<AdminPlayerAction>(context);
                await WriteJson(context, PardonPlayer(pardonRequest.ProfileId));
                return;
        }

        context.Response.StatusCode = 404;
        await context.Response.WriteAsync("ModSec: unknown admin route.");
    }

    private async Task HandleAdminLogin(HttpContext context)
    {
        var config = configService.GetCurrent();
        if (!config.Dashboard.Enabled)
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("ModSec dashboard is disabled.");
            return;
        }

        if (!config.Dashboard.AllowRemoteAdmin && !IsLocalRequest(context))
        {
            context.Response.StatusCode = 403;
            await context.Response.WriteAsync("ModSec dashboard is local-only.");
            return;
        }

        var failureKey = GetAdminFailureKey(context);
        var lockoutUntil = GetAdminLockoutUntil(failureKey, config);
        if (lockoutUntil is { } until && until > DateTime.UtcNow)
        {
            await WriteJson(context, new { success = false, error = "locked", lockedUntilUtc = until }, StatusCodes.Status429TooManyRequests);
            return;
        }

        var request = await ReadJson<AdminLoginRequest>(context);
        if (!SecureEquals(request.Token, config.Dashboard.AdminToken))
        {
            RegisterFailedAdminAttempt(failureKey, config);
            AddEvent("admin-auth-failed", null, "warning", $"Dashboard login failed from {failureKey}.", []);
            await WriteJson(context, new { success = false, error = "invalid_token" }, StatusCodes.Status403Forbidden);
            return;
        }

        var session = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var expiresAt = DateTime.UtcNow.AddMinutes(config.Dashboard.SessionMinutes);
        lock (_stateLock)
        {
            _adminFailures.Remove(failureKey);
            _adminSessions[session] = expiresAt;
        }

        AddEvent("admin-login", null, "info", $"Dashboard login succeeded from {failureKey}.", []);
        await WriteJson(context, new { success = true, sessionToken = session, expiresAtUtc = expiresAt });
    }

    private object GetDashboardDiagnostics()
    {
        var config = configService.GetCurrent();
        List<PlayerState> allPlayers;
        List<PlayerState> visiblePlayers;
        List<AdminEvent> events;

        lock (_stateLock)
        {
            foreach (var player in _players.Values)
            {
                player.ComplianceStatus = GetComplianceStatus(player, config);
            }

            allPlayers = _players.Values.ToList();
            visiblePlayers = GetVisiblePlayers(allPlayers).ToList();
            events = _events.ToList();
        }

        var configFileExists = !string.IsNullOrWhiteSpace(configService.ConfigPath) && File.Exists(configService.ConfigPath);
        var statusCounts = visiblePlayers
            .GroupBy(player => string.IsNullOrWhiteSpace(player.ComplianceStatus) ? "unknown" : player.ComplianceStatus, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);

        return new
        {
            serverVersion = ModSecConstants.Version,
            generatedAtUtc = DateTime.UtcNow,
            configPath = "config/modsec.json",
            configFileExists,
            configLastWriteUtc = configService.LastWriteUtc,
            policy = new
            {
                enabled = config.Enabled,
                mode = config.Mode,
                strictWhitelist = config.StrictWhitelist,
                dashboardEnabled = config.Dashboard.Enabled,
                autoWhitelistEnabled = config.AutoWhitelist.Enabled,
                autoWhitelistTargetList = config.AutoWhitelist.TargetList,
                clientPresenceEnabled = config.ClientPresence.Enabled,
                missingClientAction = config.ClientPresence.MissingClientAction,
                heartbeatIntervalSeconds = config.ClientPresence.HeartbeatIntervalSeconds,
                heartbeatTimeoutSeconds = config.ClientPresence.HeartbeatTimeoutSeconds,
                ruleCounts = GetPolicyRuleCounts(config)
            },
            players = new
            {
                tracked = allPlayers.Count,
                visible = visiblePlayers.Count,
                clientSeen = CountStatus(statusCounts, "client-seen"),
                pendingClient = CountStatus(statusCounts, "pending-client"),
                missingClient = CountStatus(statusCounts, "missing-client"),
                staleClient = CountStatus(statusCounts, "stale-client"),
                banned = visiblePlayers.Count(player => player.BannedUntilUtc is { } bannedUntil && bannedUntil > DateTime.UtcNow),
                withStrikes = visiblePlayers.Count(player => player.Strikes > 0),
                withMissingClientAttempts = visiblePlayers.Count(player => player.MissingClientAttempts > 0)
            },
            events = new
            {
                stored = events.Count,
                newestUtc = events.OrderByDescending(item => item.CreatedAtUtc).FirstOrDefault()?.CreatedAtUtc,
                blocks = events.Count(item => item.Severity.Equals("block", StringComparison.OrdinalIgnoreCase)),
                warnings = events.Count(item => item.Severity.Equals("warning", StringComparison.OrdinalIgnoreCase))
            }
        };
    }

    private static int CountStatus(Dictionary<string, int> statusCounts, string status)
    {
        return statusCounts.TryGetValue(status, out var count) ? count : 0;
    }

    private static object GetPolicyRuleCounts(ModSecConfig config)
    {
        return new
        {
            scanPaths = config.ScanPaths.Count,
            requiredFiles = config.RequiredFiles.Count,
            allowedFiles = config.AllowedFiles.Count,
            blockedFiles = config.BlockedFiles.Count,
            blockedPlugins = config.BlockedPlugins.Count,
            configFiles = config.ConfigFiles.Count,
            flatConfigRules = config.ConfigRules.Count,
            effectiveConfigRules = ModSecConfigService.GetEffectiveConfigRules(config).Count,
            suspiciousNamePatterns = config.ReportSanity.SuspiciousNamePatterns.Count,
            gateRoutes = config.ClientPresence.GateRoutes.Count
        };
    }

    public string ObserveSptRoute(MongoId sessionId, string route, string output, string playerName = "")
    {
        var profileId = sessionId.ToString();
        var config = configService.GetCurrent();
        PlayerState state;
        lock (_stateLock)
        {
            state = GetPlayerState(profileId, playerName, "spt-route");
            NormalizeClearedEnforcementState(state);
            state.FirstServerSeenAtUtc ??= DateTime.UtcNow;
            state.LastServerSeenAtUtc = DateTime.UtcNow;
            state.LastServerRoute = route;
            state.ComplianceStatus = GetComplianceStatus(state, config);
        }

        var isConfiguredGateRoute = config.ClientPresence.Enabled
                                    && config.ClientPresence.GateRoutes.Contains(route, StringComparer.OrdinalIgnoreCase);
        var isBlockingGateRoute = isConfiguredGateRoute && IsRaidEntryGateRoute(route);
        var shouldLockoutGate = isBlockingGateRoute && IsActiveLockout(state);
        var shouldGate = isBlockingGateRoute && IsMissingClientForGate(state, config);
        var shouldPolicyGate = isBlockingGateRoute && HasActiveRaidBlockingViolation(state, config);

        if (shouldLockoutGate)
        {
            var message = $"ModSec blocked raid access for active local server lockout; profile={profileId}; route={route}.";
            Console.WriteLine($"[ModSec] {message}");
            AddEvent("server-lockout-gate", state, "block", message, state.ActiveViolations);
            SaveState();
            return "{\"err\":1,\"errmsg\":\"Raid access is locked by this host. Check the ModSec notice for unlock details.\"}";
        }

        if (shouldGate)
        {
            var now = DateTime.UtcNow;
            var canLogIncident = CanLogMissingClientIncident(state, config, now);
            var shouldNotifyOthers = canLogIncident
                                     && (state.LastMissingClientAttemptAtUtc == null
                                         || state.LastMissingClientAttemptAtUtc.Value.AddSeconds(60) < now);
            state.MissingClientAttempts++;
            state.LastMissingClientAttemptAtUtc = now;
            state.ComplianceStatus = "missing-client";
            var message = $"ModSec client has not reported or sent a heartbeat for this launch; profile={profileId}; route={route}; action={config.ClientPresence.MissingClientAction}.";
            Console.WriteLine($"[ModSec] {message}");
            if (canLogIncident)
            {
                AddEvent("missing-client", state, config.ClientPresence.MissingClientAction, message, []);
            }
            if (shouldNotifyOthers)
            {
                QueueMissingClientToast(state, route);
                incidentMailService.BroadcastMissingClientBlock(state, route, config);
            }

            if (config.ClientPresence.MissingClientAction.Equals("block", StringComparison.OrdinalIgnoreCase))
            {
                SaveState();
                return "{\"err\":1,\"errmsg\":\"ModSec checks are required by this host for raid access. Install and consent to the ModSec BepInEx plugin, restart the game, and try again.\"}";
            }
        }

        if (shouldPolicyGate)
        {
            var message = $"ModSec blocked raid access for unresolved policy violations; profile={profileId}; route={route}.";
            Console.WriteLine($"[ModSec] {message}");
            AddEvent("policy-raid-gate", state, "block", message, state.ActiveViolations);
            SaveState();
            return "{\"err\":1,\"errmsg\":\"Raid access is blocked by this host until the listed ModSec policy issues are fixed. Recheck after correcting the blocked mod or config value.\"}";
        }

        if (IsLaunchMarkerRoute(route))
        {
            state.LastGameStartAtUtc = DateTime.UtcNow;
        }

        SaveState();
        return output;
    }

    private static bool IsLaunchMarkerRoute(string route)
    {
        return route.Equals("/client/game/start", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRaidEntryGateRoute(string route)
    {
        return route.Equals("/client/match/local/start", StringComparison.OrdinalIgnoreCase)
               || route.Equals("/fika/raid/create", StringComparison.OrdinalIgnoreCase)
               || route.Equals("/fika/raid/join", StringComparison.OrdinalIgnoreCase)
               || route.Equals("/fika/update/addplayer", StringComparison.OrdinalIgnoreCase)
               || route.Equals("/fika/raid/registerPlayer", StringComparison.OrdinalIgnoreCase)
               || route.Equals("/fika/update/playerspawn", StringComparison.OrdinalIgnoreCase);
    }

    private async Task HandleDashboard(HttpContext context)
    {
        var config = configService.GetCurrent();
        if (!config.Dashboard.Enabled)
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("ModSec dashboard is disabled.");
            return;
        }

        if (!IsLocalRequest(context) && !config.Dashboard.AllowRemoteAdmin)
        {
            context.Response.StatusCode = 403;
            await context.Response.WriteAsync("ModSec dashboard is local-only unless allowRemoteAdmin is enabled.");
            return;
        }

        context.Response.ContentType = "text/html; charset=utf-8";
        await context.Response.WriteAsync(DashboardHtml);
    }

    private PlayerState GetPlayerState(string profileId, string playerName, string ip, string installId = "")
    {
        var key = string.IsNullOrWhiteSpace(profileId) ? $"unknown-{ip}" : profileId;
        lock (_stateLock)
        {
            if (!_players.TryGetValue(key, out var state))
            {
                state = new PlayerState { ProfileId = key };
                _players[key] = state;
            }

            UpdatePlayerNames(state, playerName, installId);
            MergeFallbackClientRows(state, ip, installId);
            state.LastKnownIp = RedactEndpoint(ip);
            state.LastSeenUtc = DateTime.UtcNow;
            return state;
        }
    }

    private void MergeFallbackClientRows(PlayerState canonical, string ip, string installId)
    {
        if (!LooksLikeSptProfileId(canonical.ProfileId))
        {
            return;
        }

        var fallbackKeys = _players
            .Where(pair => !pair.Key.Equals(canonical.ProfileId, StringComparison.OrdinalIgnoreCase)
                           && LooksLikeGeneratedClientId(pair.Key)
                           && IsLikelyFallbackFor(pair.Value, canonical, ip, installId))
            .Select(pair => pair.Key)
            .ToList();

        foreach (var key in fallbackKeys)
        {
            var fallback = _players[key];
            canonical.InstallId = string.IsNullOrWhiteSpace(canonical.InstallId)
                ? fallback.InstallId
                : canonical.InstallId;
            canonical.RiskScore = Math.Max(canonical.RiskScore, fallback.RiskScore);
            canonical.MissingClientAttempts += fallback.MissingClientAttempts;
            MergeFallbackEnforcementState(canonical, fallback);
            _players.Remove(key);
        }
    }

    private static void MergeFallbackEnforcementState(PlayerState canonical, PlayerState fallback)
    {
        if (fallback.BannedUntilUtc is { } fallbackBan
            && (canonical.BannedUntilUtc == null || fallbackBan > canonical.BannedUntilUtc))
        {
            canonical.BannedUntilUtc = fallbackBan;
            canonical.BanReason = fallback.BanReason;
            canonical.BanCount = Math.Max(canonical.BanCount, fallback.BanCount);
        }

        if (fallback.Strikes > canonical.Strikes)
        {
            canonical.Strikes = fallback.Strikes;
            canonical.CooldownUntilUtc = fallback.CooldownUntilUtc;
            canonical.LastViolationSignature = fallback.LastViolationSignature;
        }

        if (fallback.ActiveEnforcementStatus.Equals("blocked", StringComparison.OrdinalIgnoreCase)
            || fallback.ActiveEnforcementStatus.Equals("banned", StringComparison.OrdinalIgnoreCase))
        {
            canonical.ActiveEnforcementStatus = fallback.ActiveEnforcementStatus;
            canonical.ActiveViolations = fallback.ActiveViolations.TakeLast(20).ToList();
            canonical.LastViolationAtUtc = fallback.LastViolationAtUtc;
            canonical.RecentViolations = fallback.RecentViolations.TakeLast(20).ToList();
            canonical.LastPublishedEnforcementSignature = fallback.LastPublishedEnforcementSignature;
            canonical.LastPublishedEnforcementAtUtc = fallback.LastPublishedEnforcementAtUtc;
        }
    }

    private static bool IsLikelyFallbackFor(PlayerState fallback, PlayerState canonical, string ip, string installId)
    {
        if (!string.IsNullOrWhiteSpace(fallback.LastServerRoute)
            || fallback.FirstServerSeenAtUtc != null)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(installId)
            && (fallback.InstallId.Equals(installId, StringComparison.OrdinalIgnoreCase)
                || fallback.ProfileId.Equals(installId, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return false;
    }

    private static string RedactEndpoint(string ip)
    {
        return ip.Equals("spt-route", StringComparison.OrdinalIgnoreCase)
            ? "server-route"
            : "client-endpoint";
    }

    private static IEnumerable<PlayerState> GetVisiblePlayers(IEnumerable<PlayerState> players)
    {
        return players
            .Where(player => !IsFallbackOnlyRow(player))
            .GroupBy(PlayerDisplayKey, StringComparer.OrdinalIgnoreCase)
            .Select(group => group
                .OrderByDescending(player => LooksLikeSptProfileId(player.ProfileId))
                .ThenByDescending(player => player.LastSeenUtc)
                .First())
            .OrderByDescending(player => player.LastSeenUtc);
    }

    private static string PlayerDisplayKey(PlayerState player)
    {
        if (LooksLikeSptProfileId(player.ProfileId))
        {
            return $"profile:{player.ProfileId}";
        }

        if (!string.IsNullOrWhiteSpace(player.PlayerName))
        {
            return $"name:{player.PlayerName}";
        }

        return $"profile:{player.ProfileId}";
    }

    private static bool IsFallbackOnlyRow(PlayerState player)
    {
        return LooksLikeGeneratedClientId(player.ProfileId)
               && string.IsNullOrWhiteSpace(player.InstallId)
               && string.IsNullOrWhiteSpace(player.LastServerRoute);
    }

    private static bool LooksLikeSptProfileId(string value)
    {
        return IsHexId(value, 24);
    }

    private static bool LooksLikeGeneratedClientId(string value)
    {
        return IsHexId(value, 32);
    }

    private static bool IsHexId(string value, int length)
    {
        return value.Length == length
               && value.All(Uri.IsHexDigit);
    }

    private static void RecordClientReport(PlayerState state, ClientReport report)
    {
        state.LastClientReportAtUtc = DateTime.UtcNow;
        state.LastHeartbeatAtUtc = DateTime.UtcNow;
        state.LastReportKind = report.CheckKind;
        state.ComplianceStatus = "client-seen";
        if (!string.IsNullOrWhiteSpace(report.InstallId))
        {
            state.InstallId = report.InstallId;
        }
        state.LatestPlugins = report.Plugins
            .OrderBy(plugin => plugin.Name, StringComparer.OrdinalIgnoreCase)
            .Take(250)
            .ToList();
        state.LatestFiles = report.Files
            .OrderBy(file => file.Path, StringComparer.OrdinalIgnoreCase)
            .Take(500)
            .ToList();
        state.LatestConfigValues = report.ConfigValues
            .OrderBy(value => value.Path, StringComparer.OrdinalIgnoreCase)
            .ThenBy(value => value.Key, StringComparer.OrdinalIgnoreCase)
            .Take(250)
            .ToList();
    }

    private void MarkCleanReport(PlayerState state, ClientReport report)
    {
        var now = DateTime.UtcNow;
        ApplyCleanState(state, now);

        if (string.IsNullOrWhiteSpace(report.InstallId))
        {
            return;
        }

        lock (_stateLock)
        {
            foreach (var linkedState in _players.Values)
            {
                if (ReferenceEquals(linkedState, state)
                    || !linkedState.InstallId.Equals(report.InstallId, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                linkedState.LastClientReportAtUtc = state.LastClientReportAtUtc;
                linkedState.LastHeartbeatAtUtc = state.LastHeartbeatAtUtc;
                linkedState.LastReportKind = state.LastReportKind;
                linkedState.LastCleanAtUtc = now;
                linkedState.ComplianceStatus = "client-seen";
                linkedState.LatestPlugins = state.LatestPlugins;
                linkedState.LatestFiles = state.LatestFiles;
                linkedState.LatestConfigValues = state.LatestConfigValues;
                ApplyCleanState(linkedState, now);
            }
        }
    }

    private static void ApplyCleanState(PlayerState state, DateTime now)
    {
        state.LastCleanAtUtc = now;
        state.CooldownUntilUtc = null;
        state.LastViolationSignature = "";
        state.LastRaidCommandSignature = "";
        state.LastRaidCommandAtUtc = null;
        NormalizeClearedEnforcementState(state, forcePass: true);
    }

    private static void NormalizeClearedEnforcementState(PlayerState state, bool forcePass = false)
    {
        if (state.BannedUntilUtc is { } bannedUntil)
        {
            if (bannedUntil > DateTime.UtcNow)
            {
                return;
            }

            state.BannedUntilUtc = null;
            state.BanReason = "";
        }

        if (!forcePass
            && state.ActiveEnforcementStatus.Equals("blocked", StringComparison.OrdinalIgnoreCase)
            && state.ActiveViolations.Count > 0
            && (state.LastCleanAtUtc is null
                || state.LastViolationAtUtc is null
                || state.LastCleanAtUtc <= state.LastViolationAtUtc))
        {
            return;
        }

        if (forcePass
            || state.ActiveEnforcementStatus.Equals("banned", StringComparison.OrdinalIgnoreCase)
            || state.ActiveEnforcementStatus.Equals("blocked", StringComparison.OrdinalIgnoreCase))
        {
            state.ActiveEnforcementStatus = "pass";
            state.ActiveViolations = [];
            state.LastPublishedEnforcementSignature = "";
            state.LastPublishedEnforcementAtUtc = null;
        }
    }

    private static void UpdatePlayerNames(PlayerState state, string playerName, string installId)
    {
        if (!string.IsNullOrWhiteSpace(installId))
        {
            state.InstallId = installId;
        }

        if (string.IsNullOrWhiteSpace(playerName))
        {
            return;
        }

        state.PlayerName = playerName;
    }

    private object GetPlayerInventory(string profileId)
    {
        lock (_stateLock)
        {
            if (!_players.TryGetValue(profileId, out var state))
            {
                return new { success = false, error = "player_not_found" };
            }

            return new PlayerInventoryResponse
            {
                ProfileId = state.ProfileId,
                PlayerName = state.PlayerName,
                InstallId = state.InstallId,
                LastReportAtUtc = state.LastClientReportAtUtc,
                LastReportKind = state.LastReportKind,
                Plugins = state.LatestPlugins,
                Files = state.LatestFiles,
                ConfigValues = state.LatestConfigValues
            };
        }
    }

    private static string GetComplianceStatus(PlayerState state, ModSecConfig config)
    {
        if (state.BannedUntilUtc is { } bannedUntil && bannedUntil > DateTime.UtcNow)
        {
            return "banned";
        }

        var lastClientSeenAt = GetLastClientSeenAt(state);
        if (lastClientSeenAt == null || ClientSeenBeforeCurrentLaunch(state, lastClientSeenAt.Value))
        {
            return state.FirstServerSeenAtUtc is { } firstSeen
                   && firstSeen.AddSeconds(config.ClientPresence.GraceSeconds) < DateTime.UtcNow
                ? "missing-client"
                : "pending-client";
        }

        if (lastClientSeenAt.Value.AddSeconds(config.ClientPresence.HeartbeatTimeoutSeconds) < DateTime.UtcNow)
        {
            return "stale-client";
        }

        return "client-seen";
    }

    private static bool IsMissingClientForGate(PlayerState state, ModSecConfig config)
    {
        if (state.FirstServerSeenAtUtc is { } firstSeen
            && firstSeen.AddSeconds(config.ClientPresence.GraceSeconds) > DateTime.UtcNow)
        {
            return false;
        }

        var lastClientSeenAt = GetLastClientSeenAt(state);
        return lastClientSeenAt == null
               || ClientSeenBeforeCurrentLaunch(state, lastClientSeenAt.Value)
               || lastClientSeenAt.Value.AddSeconds(config.ClientPresence.HeartbeatTimeoutSeconds) < DateTime.UtcNow;
    }

    private static bool IsActiveLockout(PlayerState state)
    {
        return state.BannedUntilUtc is { } bannedUntil && bannedUntil > DateTime.UtcNow;
    }

    private static bool HasActiveRaidBlockingViolation(PlayerState state, ModSecConfig config)
    {
        if (config.Mode.Equals("Disabled", StringComparison.OrdinalIgnoreCase)
            || config.Mode.Equals("WarnOnly", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (state.ActiveViolations.Count == 0
            || !state.ActiveEnforcementStatus.Equals("blocked", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (state.LastCleanAtUtc is { } lastClean
            && state.LastViolationAtUtc is { } lastViolation
            && lastClean > lastViolation)
        {
            return false;
        }

        var lastClientSeenAt = GetLastClientSeenAt(state);
        return lastClientSeenAt != null
               && !ClientSeenBeforeCurrentLaunch(state, lastClientSeenAt.Value)
               && state.ActiveViolations.Any(violation => IsBlockSeverity(violation.Severity));
    }

    private static bool ClientSeenBeforeCurrentLaunch(PlayerState state, DateTime lastClientSeenAt)
    {
        return state.LastGameStartAtUtc is { } gameStartAt
               && lastClientSeenAt.AddSeconds(LaunchFreshnessGraceSeconds) < gameStartAt;
    }

    private static bool CanLogMissingClientIncident(PlayerState state, ModSecConfig config, DateTime now)
    {
        var quietSeconds = Math.Max(config.ClientPresence.GraceSeconds, 300);
        return state.FirstServerSeenAtUtc is not { } firstSeen
               || firstSeen.AddSeconds(quietSeconds) <= now;
    }

    private static DateTime? GetLastClientSeenAt(PlayerState state)
    {
        if (state.LastClientReportAtUtc == null)
        {
            return state.LastHeartbeatAtUtc;
        }

        if (state.LastHeartbeatAtUtc == null)
        {
            return state.LastClientReportAtUtc;
        }

        return state.LastClientReportAtUtc > state.LastHeartbeatAtUtc
            ? state.LastClientReportAtUtc
            : state.LastHeartbeatAtUtc;
    }

    private List<AdminPopup> DrainPopups(string profileId)
    {
        lock (_stateLock)
        {
            var popups = new List<AdminPopup>();
            if (_targetedPopups.TryGetValue(profileId, out var targeted))
            {
                popups.AddRange(targeted);
                _targetedPopups.Remove(profileId);
            }

            foreach (var queued in _broadcastPopups)
            {
                if (queued.DeliveredTo.Add(profileId))
                {
                    popups.Add(queued.Popup);
                }
            }

            _broadcastPopups.RemoveAll(queued => queued.DeliveredTo.Count >= Math.Max(1, _players.Count));

            return popups;
        }
    }

    private List<RaidCommand> BuildRaidRemovalCommands(ModSecConfig config, ClientReport report, PlayerState state, EnforcementResponse response)
    {
        var commands = DrainRaidCommands(state.ProfileId);
        if (!report.InRaid || response.Status != "banned")
        {
            return commands;
        }

        var signature = $"{response.Status}:{GetViolationSignature(response.Violations)}:{report.IsFikaHost}:{report.HumanPlayerCount}";
        if (string.Equals(state.LastRaidCommandSignature, signature, StringComparison.Ordinal)
            && state.LastRaidCommandAtUtc is { } lastCommand
            && lastCommand.AddMinutes(3) > DateTime.UtcNow)
        {
            return commands;
        }

        state.LastRaidCommandSignature = signature;
        state.LastRaidCommandAtUtc = DateTime.UtcNow;

        var reason = response.Violations.FirstOrDefault()?.Reason
                     ?? response.Message
                     ?? "Host rule enforcement restricted raid access.";

        if (report.IsFikaHost && report.HumanPlayerCount > 1)
        {
            QueueRaidCommandForOthers(state.ProfileId, new RaidCommand
            {
                Id = NewCommandId("raid-evac"),
                Action = "extract-local-safe",
                Reason = $"Host rule enforcement removed the raid host. Your raid will be safely extracted. Host: {state.PlayerName}",
                DelaySeconds = 0,
                PopupTitle = "Raid Ended by Host Rules",
                PopupMessage = $"The raid host ({RaidNoticeName(state)}) reached this server's configured ModSec strike limit and was restricted by the host rules.\n\nYou were safely extracted because the raid had to end. Your progress and gear should be preserved.",
                PopupSeverity = "info",
                PopupKind = "dialog",
                PopupDurationSeconds = 12
            });

            commands.Add(new RaidCommand
            {
                Id = NewCommandId("raid-loss"),
                Action = "remove-local-loss-delayed",
                Reason = reason,
                DelaySeconds = 10
            });
            AddEvent("raid-host-evacuation", state, "block", $"Queued safe extraction for other players before removing blocked host. players={report.HumanPlayerCount}.", response.Violations);
            return commands;
        }

        if (report.HumanPlayerCount > 1)
        {
            QueueRaidParticipantRemovedToast(state, config);
        }

        commands.Add(new RaidCommand
        {
            Id = NewCommandId("raid-loss"),
            Action = "remove-local-loss",
            Reason = reason,
            DelaySeconds = 0
        });
        return commands;
    }

    private List<RaidCommand> DrainRaidCommands(string profileId)
    {
        lock (_stateLock)
        {
            var commands = new List<RaidCommand>();
            foreach (var queued in _raidCommands)
            {
                if (queued.ExcludedProfileIds.Contains(profileId))
                {
                    continue;
                }

                if (queued.DeliveredTo.Add(profileId))
                {
                    commands.Add(queued.Command);
                }
            }

            _raidCommands.RemoveAll(command =>
                command.Command.CreatedAtUtc.AddMinutes(10) < DateTime.UtcNow
                || command.DeliveredTo.Count >= Math.Max(1, _players.Count - command.ExcludedProfileIds.Count));

            return commands;
        }
    }

    private void QueueRaidCommandForOthers(string excludedProfileId, RaidCommand command)
    {
        lock (_stateLock)
        {
            _raidCommands.Add(new QueuedRaidCommand(command, [excludedProfileId]));
            if (_raidCommands.Count > 50)
            {
                _raidCommands.RemoveRange(0, _raidCommands.Count - 50);
            }
        }
    }

    private static string RaidNoticeName(PlayerState state)
    {
        if (!string.IsNullOrWhiteSpace(state.PlayerName))
        {
            return state.PlayerName;
        }

        return string.IsNullOrWhiteSpace(state.ProfileId) ? "the host" : state.ProfileId;
    }

    private static string ToastNoticeName(PlayerState state)
    {
        return string.IsNullOrWhiteSpace(state.PlayerName) ? "A player" : state.PlayerName;
    }

    private static string NewCommandId(string prefix)
    {
        return $"{prefix}-{DateTime.UtcNow:yyyyMMddHHmmssfff}-{RandomNumberGenerator.GetInt32(1000, 9999)}";
    }

    private AdminPopup QueuePopup(AdminPopupRequest request)
    {
        var popup = new AdminPopup
        {
            Id = $"popup-{DateTime.UtcNow:yyyyMMddHHmmssfff}",
            Title = string.IsNullOrWhiteSpace(request.Title) ? "Server Notice" : request.Title,
            Message = request.Message,
            Kind = NormalizePopupKind(request.Kind),
            Position = NormalizePopupPosition(request.Position),
            Severity = string.IsNullOrWhiteSpace(request.Severity) ? "info" : request.Severity,
            DurationSeconds = Math.Clamp(request.DurationSeconds, 2, 60),
            Blocking = request.Blocking,
            RequiresQuit = request.RequiresQuit,
            CreatedAtUtc = DateTime.UtcNow
        };

        lock (_stateLock)
        {
            if (string.IsNullOrWhiteSpace(request.TargetProfileId))
            {
                _broadcastPopups.Add(new QueuedBroadcastPopup(popup));
            }
            else
            {
                if (!_targetedPopups.TryGetValue(request.TargetProfileId, out var queue))
                {
                    queue = [];
                    _targetedPopups[request.TargetProfileId] = queue;
                }

                queue.Add(popup);
            }
        }

        Console.WriteLine($"[ModSec] Queued popup '{popup.Title}' for {(string.IsNullOrWhiteSpace(request.TargetProfileId) ? "all players" : request.TargetProfileId)}");
        AddEvent("admin-popup", null, popup.Severity, $"Queued {popup.Kind} popup '{popup.Title}' for {(string.IsNullOrWhiteSpace(request.TargetProfileId) ? "all players" : request.TargetProfileId)}.", []);
        return popup;
    }

    private void QueueMissingClientToast(PlayerState state, string route)
    {
        var name = ToastNoticeName(state);
        QueueBroadcastToastExcept(
            state.ProfileId,
            "ModSec Player Blocked",
            $"{name} was blocked from joining because their ModSec client did not report for this launch.",
            "warning",
            8);

        AddEvent("missing-client-toast", state, "warning", $"Queued broadcast toast for missing-client block on {route}.", []);
    }

    private void QueueStrikeToast(PlayerState state, ModSecConfig config)
    {
        QueueBroadcastToastExcept(
            state.ProfileId,
            "ModSec Strike",
            $"{ToastNoticeName(state)} received a ModSec strike {state.Strikes}/{config.StrikeLimit}.",
            "warning",
            8);
    }

    private void QueueLockoutToast(PlayerState state, ModSecConfig config)
    {
        QueueBroadcastToastExcept(
            state.ProfileId,
            "ModSec Server Lockout",
            $"{ToastNoticeName(state)} reached {config.StrikeLimit}/{config.StrikeLimit} strikes and is now restricted from this server{FormatRestrictionDuration(state.BannedUntilUtc)}",
            "block",
            10);
    }

    private void QueueRaidParticipantRemovedToast(PlayerState state, ModSecConfig config)
    {
        QueueBroadcastToastExcept(
            state.ProfileId,
            "ModSec Player Removed",
            $"{ToastNoticeName(state)} reached this server's ModSec strike limit ({config.StrikeLimit}/{config.StrikeLimit}) and was removed from the raid.",
            "warning",
            10);
    }

    private void QueueBroadcastToastExcept(string excludedProfileId, string title, string message, string severity, int durationSeconds)
    {
        var popup = new AdminPopup
        {
            Id = $"popup-{DateTime.UtcNow:yyyyMMddHHmmssfff}",
            Title = title,
            Message = message,
            Kind = "toast",
            Position = "topRight",
            Severity = severity,
            DurationSeconds = durationSeconds,
            Blocking = false,
            RequiresQuit = false,
            CreatedAtUtc = DateTime.UtcNow
        };

        lock (_stateLock)
        {
            var queued = new QueuedBroadcastPopup(popup);
            if (!string.IsNullOrWhiteSpace(excludedProfileId))
            {
                queued.DeliveredTo.Add(excludedProfileId);
            }

            _broadcastPopups.Add(queued);
            if (_broadcastPopups.Count > 50)
            {
                _broadcastPopups.RemoveRange(0, _broadcastPopups.Count - 50);
            }
        }

    }

    private static string FormatRestrictionDuration(DateTime? restrictedUntilUtc)
    {
        if (restrictedUntilUtc == null)
        {
            return ".";
        }

        if (restrictedUntilUtc == DateTime.MaxValue)
        {
            return " permanently.";
        }

        var remaining = restrictedUntilUtc.Value - DateTime.UtcNow;
        if (remaining.TotalMinutes <= 1)
        {
            return " for about 1 minute.";
        }

        if (remaining.TotalHours < 1)
        {
            return $" for about {Math.Ceiling(remaining.TotalMinutes)} minutes.";
        }

        if (remaining.TotalDays < 1)
        {
            return $" for about {Math.Ceiling(remaining.TotalHours)} hours.";
        }

        return $" for about {Math.Ceiling(remaining.TotalDays)} days.";
    }

    private static string NormalizePopupKind(string? kind)
    {
        return (kind ?? "dialog").ToLowerInvariant() switch
        {
            "toast" => "toast",
            "notification" => "toast",
            "information" => "information",
            "warning" => "warning",
            "kick" => "kick",
            "ban" => "ban",
            _ => "dialog"
        };
    }

    private static string NormalizePopupPosition(string? position)
    {
        return (position ?? "topRight").ToLowerInvariant() switch
        {
            "topleft" => "topLeft",
            "bottomleft" => "bottomLeft",
            "bottomright" => "bottomRight",
            _ => "topRight"
        };
    }

    private object BanPlayer(AdminBanRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.ProfileId))
        {
            return new { success = false, error = "missing_profile_id" };
        }

        PlayerState state;
        lock (_stateLock)
        {
            if (!_players.TryGetValue(request.ProfileId, out var existingState) || existingState == null)
            {
                existingState = new PlayerState { ProfileId = request.ProfileId };
                _players[request.ProfileId] = existingState;
            }

            state = existingState;
            state.BannedUntilUtc = request.Minutes <= 0 ? DateTime.MaxValue : DateTime.UtcNow.AddMinutes(request.Minutes);
            state.BanReason = string.IsNullOrWhiteSpace(request.Reason) ? "Profile restricted by this host." : request.Reason;
        }

        Console.WriteLine($"[ModSec] Server lockout {request.ProfileId}: {request.Reason}");
        AddEvent("admin-lockout", state, "block", $"Manual server lockout: {request.Reason}", []);
        SaveState();
        return new { success = true };
    }

    private object UnbanPlayer(string profileId)
    {
        lock (_stateLock)
        {
            if (_players.TryGetValue(profileId, out var state))
            {
                state.BannedUntilUtc = null;
                state.BanReason = "";
                NormalizeClearedEnforcementState(state, forcePass: true);
            }
        }

        AddEvent("admin-unlock", _players.GetValueOrDefault(profileId), "info", "Manual server lockout cleared.", []);
        SaveState();
        return new { success = true };
    }

    private object PardonPlayer(string profileId)
    {
        lock (_stateLock)
        {
            if (_players.TryGetValue(profileId, out var state))
            {
                state.Strikes = 0;
                state.RiskScore = 0;
                state.CooldownUntilUtc = null;
                NormalizeClearedEnforcementState(state, forcePass: true);
            }
        }

        AddEvent("admin-pardon", _players.GetValueOrDefault(profileId), "info", "Manual pardon: strikes/risk/cooldown cleared.", []);
        SaveState();
        return new { success = true };
    }

    private void AddEvent(string type, PlayerState? state, string severity, string message, List<Violation> violations)
    {
        lock (_stateLock)
        {
            _events.Add(new AdminEvent
            {
                Id = $"evt-{DateTime.UtcNow:yyyyMMddHHmmssfff}-{_events.Count % 1000:D3}",
                CreatedAtUtc = DateTime.UtcNow,
                Type = type,
                ProfileId = state?.ProfileId ?? "",
                PlayerName = state?.PlayerName ?? "",
                Severity = severity,
                Message = message,
                Violations = violations.Take(10).ToList()
            });

            if (_events.Count > 500)
            {
                _events.RemoveRange(0, _events.Count - 500);
            }
        }

        SaveEvents();
    }

    private void LoadState()
    {
        if (string.IsNullOrWhiteSpace(_statePath) || !File.Exists(_statePath))
        {
            return;
        }

        try
        {
            var players = JsonSerializer.Deserialize<List<PlayerState>>(File.ReadAllText(_statePath), JsonOptions) ?? [];
            lock (_stateLock)
            {
                _players.Clear();
                foreach (var player in players.Where(player => !string.IsNullOrWhiteSpace(player.ProfileId)))
                {
                    _players[player.ProfileId] = player;
                }
            }

            Console.WriteLine($"[ModSec] Loaded {players.Count} persisted player state record(s).");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ModSec] Could not load player state file '{_statePath}': {ex.Message}");
        }
    }

    private void LoadEvents()
    {
        if (string.IsNullOrWhiteSpace(_eventsPath) || !File.Exists(_eventsPath))
        {
            return;
        }

        try
        {
            var events = JsonSerializer.Deserialize<List<AdminEvent>>(File.ReadAllText(_eventsPath), JsonOptions) ?? [];
            lock (_stateLock)
            {
                _events.Clear();
                _events.AddRange(events.TakeLast(500));
            }

            Console.WriteLine($"[ModSec] Loaded {_events.Count} persisted event record(s).");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ModSec] Could not load event file '{_eventsPath}': {ex.Message}");
        }
    }

    private void SaveState()
    {
        if (string.IsNullOrWhiteSpace(_statePath))
        {
            return;
        }

        try
        {
            List<PlayerState> players;
            lock (_stateLock)
            {
                players = _players.Values
                    .OrderByDescending(player => player.LastSeenUtc)
                    .ToList();
            }

            Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
            File.WriteAllText(_statePath, JsonSerializer.Serialize(players, new JsonSerializerOptions(JsonOptions)
            {
                WriteIndented = true
            }));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ModSec] Could not save player state file '{_statePath}': {ex.Message}");
        }
    }

    private void SaveEvents()
    {
        if (string.IsNullOrWhiteSpace(_eventsPath))
        {
            return;
        }

        try
        {
            List<AdminEvent> events;
            lock (_stateLock)
            {
                events = _events
                    .OrderByDescending(e => e.CreatedAtUtc)
                    .Take(500)
                    .OrderBy(e => e.CreatedAtUtc)
                    .ToList();
            }

            Directory.CreateDirectory(Path.GetDirectoryName(_eventsPath)!);
            File.WriteAllText(_eventsPath, JsonSerializer.Serialize(events, new JsonSerializerOptions(JsonOptions)
            {
                WriteIndented = true
            }));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ModSec] Could not save event file '{_eventsPath}': {ex.Message}");
        }
    }

    private bool IsAdminRequest(HttpContext context)
    {
        var config = configService.GetCurrent();
        if (!config.Dashboard.Enabled)
        {
            return false;
        }

        if (!config.Dashboard.AllowRemoteAdmin && !IsLocalRequest(context))
        {
            return false;
        }

        if (!context.Request.Headers.TryGetValue("modsec-admin-session", out var header))
        {
            return false;
        }

        var session = header.ToString();
        lock (_stateLock)
        {
            if (!_adminSessions.TryGetValue(session, out var expiresAt))
            {
                return false;
            }

            if (expiresAt <= DateTime.UtcNow)
            {
                _adminSessions.Remove(session);
                return false;
            }

            return true;
        }
    }

    private string GetAdminFailureKey(HttpContext context)
    {
        var remote = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return IsLocalRequest(context) ? "local" : remote;
    }

    private DateTime? GetAdminLockoutUntil(string key, ModSecConfig config)
    {
        lock (_stateLock)
        {
            if (!_adminFailures.TryGetValue(key, out var failure))
            {
                return null;
            }

            return failure.LockedUntilUtc;
        }
    }

    private void RegisterFailedAdminAttempt(string key, ModSecConfig config)
    {
        var now = DateTime.UtcNow;
        lock (_stateLock)
        {
            if (!_adminFailures.TryGetValue(key, out var failure)
                || failure.WindowStartedUtc.AddSeconds(config.Dashboard.FailedAttemptWindowSeconds) < now)
            {
                failure = new AdminFailureState { WindowStartedUtc = now };
                _adminFailures[key] = failure;
            }

            failure.Count++;
            if (failure.Count >= config.Dashboard.MaxFailedAttempts)
            {
                failure.LockedUntilUtc = now.AddSeconds(config.Dashboard.LockoutSeconds);
            }
        }
    }

    private static bool SecureEquals(string first, string second)
    {
        if (string.IsNullOrEmpty(first) || string.IsNullOrEmpty(second))
        {
            return false;
        }

        var firstBytes = System.Text.Encoding.UTF8.GetBytes(first);
        var secondBytes = System.Text.Encoding.UTF8.GetBytes(second);
        return firstBytes.Length == secondBytes.Length
               && CryptographicOperations.FixedTimeEquals(firstBytes, secondBytes);
    }

    private static bool IsLocalRequest(HttpContext context)
    {
        var remoteIp = context.Connection.RemoteIpAddress;
        if (remoteIp == null)
        {
            return true;
        }

        return System.Net.IPAddress.IsLoopback(remoteIp)
               || remoteIp.ToString() == "::1"
               || remoteIp.ToString() == "127.0.0.1";
    }

    private static bool MatchesRule(FileRule rule, ClientFileReport file)
    {
        var path = NormalizePath(file.Path);
        var hasHash = !string.IsNullOrWhiteSpace(rule.Hash);
        var hasLocationMatcher = !string.IsNullOrWhiteSpace(rule.Path)
                                 || !string.IsNullOrWhiteSpace(rule.Glob)
                                 || !hasHash && !string.IsNullOrWhiteSpace(rule.Name);

        var locationMatches = !hasLocationMatcher
                              || !string.IsNullOrWhiteSpace(rule.Path)
                              && string.Equals(NormalizePath(rule.Path), path, StringComparison.OrdinalIgnoreCase)
                              || !string.IsNullOrWhiteSpace(rule.Glob)
                              && GlobMatches(rule.Glob, path)
                              || !hasHash
                              && !string.IsNullOrWhiteSpace(rule.Name)
                              && string.Equals(rule.Name, Path.GetFileName(path), StringComparison.OrdinalIgnoreCase);

        if (!locationMatches)
        {
            return false;
        }

        if (hasHash)
        {
            return string.Equals(rule.Hash, file.Hash, StringComparison.OrdinalIgnoreCase);
        }

        return hasLocationMatcher;
    }

    private static bool IsProtectedClientFile(string path, string hash, List<ServerFileInventoryItem> protectedFiles)
    {
        var normalized = NormalizePath(path);
        return protectedFiles.Any(file =>
            string.Equals(file.Path, normalized, StringComparison.OrdinalIgnoreCase)
            && (string.IsNullOrWhiteSpace(hash)
                || string.Equals(file.Hash, hash, StringComparison.OrdinalIgnoreCase)));
    }

    private static bool IsProtectedClientPlugin(
        ClientPluginReport plugin,
        Dictionary<string, ClientFileReport> fileByPath,
        List<ServerFileInventoryItem> protectedFiles)
    {
        var normalized = NormalizePath(plugin.Location);
        return fileByPath.TryGetValue(normalized, out var file)
               && IsProtectedClientFile(normalized, file.Hash, protectedFiles);
    }

    private static bool MatchesPluginRule(PluginRule rule, ClientPluginReport plugin)
    {
        if (!string.IsNullOrWhiteSpace(rule.Guid)
            && string.Equals(rule.Guid, plugin.Guid, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(rule.DisplayName)
            && (string.Equals(rule.DisplayName, plugin.Name, StringComparison.OrdinalIgnoreCase)
                || string.Equals(rule.DisplayName, Path.GetFileNameWithoutExtension(plugin.Location), StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(rule.Name)
               && string.Equals(rule.Name, plugin.Name, StringComparison.OrdinalIgnoreCase);
    }

    private static bool GlobMatches(string glob, string path)
    {
        var normalizedGlob = NormalizePath(glob);
        var regex = Regex.Escape(normalizedGlob)
            .Replace("\\*\\*", ".*")
            .Replace("\\*", "[^/]*")
            .Replace("\\?", "[^/]");

        return Regex.IsMatch(path, $"^{regex}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private static bool ConfigValuePasses(ConfigRule rule, string? actualValue)
    {
        var expected = ConfigScalar(rule.AllowedValue);
        var actual = actualValue ?? "";
        var allowedValues = ConfigAllowedValues(rule);
        var blockedValues = ConfigBlockedValues(rule);

        if (rule.AllowedValues.Count > 0)
        {
            return allowedValues.Any(value => ConfigValuesEqual(actual, value));
        }

        if (rule.BlockedValues.Count > 0 && blockedValues.Any(value => ConfigValuesEqual(actual, value)))
        {
            return false;
        }

        return rule.Operator.ToLowerInvariant() switch
        {
            "equals" => allowedValues.Any(value => ConfigValuesEqual(actual, value)),
            "notequals" => blockedValues.All(value => !ConfigValuesEqual(actual, value)),
            "in" => allowedValues.Any(value => ConfigValuesEqual(actual, value)),
            "notin" => blockedValues.All(value => !ConfigValuesEqual(actual, value)),
            "contains" => actual.Contains(expected, StringComparison.OrdinalIgnoreCase),
            "notcontains" => !actual.Contains(expected, StringComparison.OrdinalIgnoreCase),
            "lessthanorequal" => TryCompareNumber(actual, expected, (a, e) => a <= e),
            "greaterthanorequal" => TryCompareNumber(actual, expected, (a, e) => a >= e),
            "range" => TryCompareRange(actual, rule.MinValue, rule.MaxValue, inRange: true),
            "notrange" => TryCompareRange(actual, rule.MinValue, rule.MaxValue, inRange: false),
            _ => true
        };
    }

    private static bool ConfigValuesEqual(string actual, string expected)
    {
        return string.Equals(NormalizeConfigScalar(actual), NormalizeConfigScalar(expected), StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeConfigScalar(string value)
    {
        var normalized = value.Trim().Trim('"');
        return normalized.Equals("<blank>", StringComparison.OrdinalIgnoreCase)
            || normalized.Equals("(blank)", StringComparison.OrdinalIgnoreCase)
            || normalized.Equals("unbound", StringComparison.OrdinalIgnoreCase)
            ? ""
            : normalized;
    }

    private static string BuildConfigViolationReason(ConfigRule rule, string? actualValue)
    {
        var actual = actualValue ?? "(missing)";
        return $"Config setting '{DisplayConfigKey(rule)}' is set to '{actual}', but the server allows {DescribeConfigExpectation(rule)}.";
    }

    private static Violation BuildMissingConfigViolation(ConfigRule rule, ClientConfigValue? value)
    {
        var setting = DisplayConfigKey(rule);
        var actual = value is { FileExists: false } ? "config file not installed" : "missing";
        var expected = DescribeConfigExpectation(rule);

        return new Violation
        {
            Severity = rule.Severity,
            Reason = value is { FileExists: false }
                ? $"Required config file '{rule.Path}' was not found. Expected setting '{setting}' to be {expected}."
                : $"Config setting '{setting}' was not found. Expected {expected}.",
            Path = rule.Path,
            RuleId = rule.Id,
            Category = "config",
            Setting = setting,
            ActualValue = actual,
            ExpectedValue = expected
        };
    }

    private static string DescribeConfigExpectation(ConfigRule rule)
    {
        return rule.Operator switch
        {
            "range" => $"a value from {rule.MinValue?.ToString() ?? "-infinity"} to {rule.MaxValue?.ToString() ?? "infinity"}",
            "notrange" => $"a value outside {rule.MinValue?.ToString() ?? "-infinity"} to {rule.MaxValue?.ToString() ?? "infinity"}",
            "in" or "equals" => ConfigAllowedValues(rule).Count == 1
                ? DescribeConfigValue(ConfigAllowedValues(rule)[0])
                : $"one of: {string.Join(", ", ConfigAllowedValues(rule).Select(DescribeConfigValue))}",
            "notin" or "notequals" => ConfigBlockedValues(rule).Count == 1
                ? $"anything except {DescribeConfigValue(ConfigBlockedValues(rule)[0])}"
                : $"none of: {string.Join(", ", ConfigBlockedValues(rule).Select(DescribeConfigValue))}",
            _ => $"{rule.Operator} {DescribeConfigValue(ConfigScalar(rule.AllowedValue))}"
        };
    }

    private static List<string> ConfigAllowedValues(ConfigRule rule)
    {
        return rule.AllowedValues.Count > 0
            ? rule.AllowedValues.Select(ConfigScalar).ToList()
            : new List<string> { ConfigScalar(rule.AllowedValue) };
    }

    private static List<string> ConfigBlockedValues(ConfigRule rule)
    {
        return rule.BlockedValues.Count > 0
            ? rule.BlockedValues.Select(ConfigScalar).ToList()
            : new List<string> { ConfigScalar(rule.AllowedValue) };
    }

    private static string DescribeConfigValue(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? "blank / unbound" : $"'{value}'";
    }

    private static string ConfigScalar(object? value)
    {
        return value switch
        {
            null => "",
            JsonElement element => element.ValueKind switch
            {
                JsonValueKind.String => element.GetString() ?? "",
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Number => element.ToString(),
                _ => element.ToString()
            },
            _ => value.ToString() ?? ""
        };
    }

    private static bool ConfigReportValueMatchesRule(ConfigRule rule, ClientConfigValue value)
    {
        if (!string.Equals(NormalizePath(value.Path), NormalizePath(rule.Path), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(rule.Section)
            && !string.Equals(value.Section, rule.Section, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !string.IsNullOrWhiteSpace(rule.Key)
                   && string.Equals(value.Key, rule.Key, StringComparison.OrdinalIgnoreCase)
               || !string.IsNullOrWhiteSpace(rule.JsonPath)
                   && string.Equals(value.JsonPath, rule.JsonPath, StringComparison.OrdinalIgnoreCase);
    }

    private static ClientConfigValue? FindConfigReportValue(ConfigRule rule, List<ClientConfigValue> values)
    {
        return values.FirstOrDefault(value => string.Equals(value.RuleId, rule.Id, StringComparison.OrdinalIgnoreCase))
               ?? values.FirstOrDefault(value => ConfigReportValueMatchesRule(rule, value));
    }

    private static bool TryCompareNumber(string actual, string expected, Func<double, double, bool> compare)
    {
        return double.TryParse(actual, out var actualNumber)
               && double.TryParse(expected, out var expectedNumber)
               && compare(actualNumber, expectedNumber);
    }

    private static bool TryCompareRange(string actual, double? minValue, double? maxValue, bool inRange)
    {
        if (!double.TryParse(actual, out var actualNumber))
        {
            return false;
        }

        var passes = (minValue == null || actualNumber >= minValue)
                     && (maxValue == null || actualNumber <= maxValue);
        return inRange ? passes : !passes;
    }

    private static string DisplayConfigKey(ConfigRule rule)
    {
        var key = string.IsNullOrWhiteSpace(rule.Key) ? rule.JsonPath : rule.Key;
        return string.IsNullOrWhiteSpace(rule.Section) ? key : $"{rule.Section}/{key}";
    }

    private static bool IsStrikeSeverity(string severity)
    {
        return severity.Equals("strike", StringComparison.OrdinalIgnoreCase)
               || severity.Equals("block", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsBlockSeverity(string severity)
    {
        return severity.Equals("block", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ModeAllowsStrikes(string mode)
    {
        return mode.Equals("BlockRaid", StringComparison.OrdinalIgnoreCase)
               || mode.Equals("StrikeThenBlock", StringComparison.OrdinalIgnoreCase);
    }

    private static int GetRiskDelta(Violation violation)
    {
        return violation.Severity.ToLowerInvariant() switch
        {
            "block" => 40,
            "strike" => 25,
            "warn" => 10,
            _ => 5
        };
    }

    private static int GetNextInterval(ModSecConfig config, PlayerState state)
    {
        var baseline = Math.Clamp(
            config.BackgroundIntervalSeconds,
            config.MinimumIntervalSeconds,
            config.MaximumIntervalSeconds);
        var effectiveRisk = Math.Clamp(state.RiskScore + (state.Strikes * 10), 0, 100);
        var riskRatio = effectiveRisk / 100d;
        var interval = baseline - ((baseline - config.MinimumIntervalSeconds) * riskRatio);

        return Math.Clamp((int)Math.Round(interval), config.MinimumIntervalSeconds, baseline);
    }

    private static void DecayStrikes(PlayerState state, ModSecConfig config)
    {
        if (state.Strikes <= 0 || state.LastViolationAtUtc == null)
        {
            return;
        }

        if (state.LastViolationAtUtc.Value.AddMinutes(config.StrikeDecayMinutes) <= DateTime.UtcNow)
        {
            state.Strikes = 0;
            state.CooldownUntilUtc = null;
        }
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('\\', '/').Trim().TrimStart('/');
    }

    private static async Task<T> ReadJson<T>(HttpContext context) where T : new()
    {
        var value = await JsonSerializer.DeserializeAsync<T>(context.Request.Body, JsonOptions);
        return value ?? new T();
    }

    private static async Task WriteJson(HttpContext context, object value, int statusCode = StatusCodes.Status200OK)
    {
        var json = JsonSerializer.Serialize(value, JsonOptions);
        context.Response.ContentType = "application/json";
        context.Response.StatusCode = statusCode;
        await context.Response.WriteAsync(json);
    }

    private class AdminFailureState
    {
        public DateTime WindowStartedUtc { get; set; }
        public int Count { get; set; }
        public DateTime? LockedUntilUtc { get; set; }
    }

    private class QueuedBroadcastPopup(AdminPopup popup)
    {
        public AdminPopup Popup { get; } = popup;
        public HashSet<string> DeliveredTo { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private class QueuedRaidCommand(RaidCommand command, IEnumerable<string> excludedProfileIds)
    {
        public RaidCommand Command { get; } = command;
        public HashSet<string> ExcludedProfileIds { get; } = excludedProfileIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> DeliveredTo { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private const string DashboardHtml = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ModSec Admin</title>
  <style>
    :root { color-scheme: dark; font-family: Segoe UI, Arial, sans-serif; background: #101316; color: #f2f4f7; }
    body { margin: 0; padding: 26px; }
    main { max-width: 1280px; margin: 0 auto; }
    h1 { margin: 0 0 18px; font-size: 28px; }
    h2 { margin: 0 0 14px; font-size: 18px; }
    section { margin-top: 18px; padding: 16px; border: 1px solid #2a3038; border-radius: 6px; background: #171b20; overflow: hidden; }
    label { display: block; margin: 8px 0 4px; color: #b8c0cc; font-size: 13px; }
    input, textarea, select { width: 100%; box-sizing: border-box; border: 1px solid #3a4350; border-radius: 4px; background: #101317; color: #f2f4f7; padding: 9px; }
    textarea { min-height: 80px; resize: vertical; }
    button { border: 1px solid #4d8cff; border-radius: 4px; background: #2367d1; color: white; padding: 9px 12px; cursor: pointer; white-space: nowrap; }
    button.secondary { border-color: #4a5667; background: #252c35; }
    button.danger { border-color: #d94c4c; background: #9f2f2f; }
    .row { display: grid; grid-template-columns: repeat(12, 1fr); gap: 12px; align-items: end; }
    .span-3 { grid-column: span 3; }
    .span-4 { grid-column: span 4; }
    .span-6 { grid-column: span 6; }
    .span-12 { grid-column: span 12; }
    .table-wrap { width: 100%; overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: 13px; }
    th, td { border-bottom: 1px solid #2a3038; padding: 10px 8px; text-align: left; vertical-align: top; }
    th { color: #b8c0cc; font-weight: 600; white-space: nowrap; }
    .players col:nth-child(1) { width: 110px; }
    .players col:nth-child(2) { width: 270px; }
    .players col:nth-child(3) { width: 90px; }
    .players col:nth-child(4) { width: 150px; }
    .players col:nth-child(5) { width: 62px; }
    .players col:nth-child(6) { width: 150px; }
    .players col:nth-child(7) { width: auto; }
    .players col:nth-child(8) { width: 250px; }
    .events col:nth-child(1) { width: 165px; }
    .events col:nth-child(2) { width: 130px; }
    .events col:nth-child(3) { width: 255px; }
    .events col:nth-child(4) { width: auto; }
    .events col:nth-child(5) { width: 340px; }
    .files col:nth-child(1) { width: auto; }
    .files col:nth-child(2) { width: 540px; }
    .files col:nth-child(3) { width: 95px; }
    .files col:nth-child(4) { width: 120px; }
    .status { margin-top: 12px; color: #93c5fd; min-height: 20px; }
    .muted { color: #8d98a8; }
    .pill { display: inline-flex; align-items: center; max-width: 100%; padding: 2px 7px; border: 1px solid #3f4956; border-radius: 999px; color: #cbd5e1; background: #202630; font-size: 12px; line-height: 1.35; }
    .pill.bad { border-color: #884545; color: #fecaca; background: #351b1f; }
    .pill.warn { border-color: #7a612a; color: #fde68a; background: #302715; }
    .detail { color: #aeb7c5; font-size: 12px; line-height: 1.45; white-space: normal; overflow-wrap: anywhere; }
    .subtle { color: #8993a2; font-size: 12px; margin-top: 3px; }
    .mono { font-family: Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }
    .cell-stack { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
    .violation-list { display: flex; flex-direction: column; gap: 7px; min-width: 0; }
    .violation-item { padding-left: 8px; border-left: 2px solid #5b4630; }
    .actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px; }
    .actions button { padding: 8px 10px; }
    .modal .actions { grid-template-columns: repeat(3, minmax(0, 1fr)); min-width: 260px; }
    .toolbar { display: flex; gap: 8px; align-items: end; }
    .token-row { display: grid; grid-template-columns: 1fr auto; gap: 8px; align-items: end; }
    .filters { display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 10px; align-items: end; margin: 10px 0 14px; }
    .filters.two { grid-template-columns: 2fr 1fr; }
    .result-count { color: #8993a2; font-size: 12px; margin: -4px 0 10px; }
    .config-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; align-items: end; }
    .diag-card { border: 1px solid #29313b; background: #11161b; border-radius: 5px; padding: 10px; min-height: 62px; min-width: 0; }
    .diag-card label { margin-top: 0; }
    .diag-detail { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .page-tabs { display: flex; gap: 8px; flex-wrap: wrap; margin: 18px 0 0; border-bottom: 1px solid #2a3038; padding-bottom: 10px; }
    .page-tabs button { border-color: #4a5667; background: #252c35; }
    .page-tabs button.active { border-color: #4d8cff; background: #2367d1; }
    .dashboard-page { display: none; }
    .dashboard-page.active { display: block; }
    .policy-actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
    .pending-tray { display: none; margin-top: 12px; border: 1px solid #526070; background: #10151a; padding: 12px; border-radius: 6px; }
    .pending-head { display: flex; justify-content: space-between; gap: 12px; align-items: center; margin-bottom: 8px; }
    .pending-list { display: grid; gap: 8px; }
    .pending-item { display: grid; grid-template-columns: 100px 1fr auto; gap: 10px; align-items: center; border-top: 1px solid #252d35; padding-top: 8px; }
    .pending-item:first-child { border-top: 0; padding-top: 0; }
    .rule-builder { border: 1px solid #33404c; background: #10151a; border-radius: 6px; padding: 12px; margin: 12px 0; }
    .rule-builder h3 { margin: 0 0 10px; font-size: 16px; }
    .drop-zone { border: 1px dashed #697586; background: #0b1015; border-radius: 6px; padding: 18px; text-align: center; color: #cbd5e1; transition: border-color .12s, background .12s; }
    .drop-zone.dragging { border-color: #93c5fd; background: #101c28; }
    .drop-zone strong { display: block; font-size: 15px; margin-bottom: 4px; }
    .builder-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: end; margin-top: 10px; }
    .json-only { display: none; }
    #policyEditor.show-advanced-json .json-only { display: block; }
    .friendly-note { border: 1px solid #33404c; background: #111820; color: #cbd5e1; border-radius: 6px; padding: 10px 12px; line-height: 1.45; margin-bottom: 12px; }
    .policy-json { min-height: 150px; font-family: Consolas, monospace; font-size: 12px; line-height: 1.45; }
    .policy-json.tall { min-height: 220px; }
    .rule-review { display: grid; gap: 14px; margin: 14px 0; }
    .rule-review-card { border: 1px solid #33404c; background: #10151a; border-radius: 6px; overflow: hidden; }
    .rule-review-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 10px 12px; border-bottom: 1px solid #25303a; }
    .rule-review-head h3 { margin: 0; font-size: 15px; }
    .rule-review-head .hint { margin: 0; }
    .rule-review-table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    .rule-review-table th, .rule-review-table td { padding: 8px; border-bottom: 1px solid #252d35; vertical-align: top; }
    .rule-review-table th { color: #cbd5e1; font-size: 12px; background: #121920; }
    .rule-review-table input, .rule-review-table select { width: 100%; min-width: 0; }
    .rule-review-table .mini { font-size: 11px; color: #8f9aaa; margin-top: 4px; overflow-wrap: anywhere; }
    .rule-review-actions { display: flex; gap: 6px; flex-wrap: wrap; }
    .hint { color: #8993a2; font-size: 12px; line-height: 1.45; margin-top: 8px; }
    .modal-backdrop { display: none; position: fixed; inset: 0; z-index: 10; background: rgba(0,0,0,.72); padding: 28px; box-sizing: border-box; }
    .modal { max-width: 1180px; max-height: calc(100vh - 56px); margin: 0 auto; background: #171b20; border: 1px solid #44505f; border-radius: 6px; overflow: hidden; box-shadow: 0 18px 70px rgba(0,0,0,.55); }
    .modal-head { display: flex; justify-content: space-between; gap: 12px; align-items: center; padding: 14px 16px; border-bottom: 1px solid #2a3038; }
    .modal-body { padding: 16px; overflow: auto; max-height: calc(100vh - 130px); }
    .modal-foot { display: flex; justify-content: flex-end; gap: 8px; padding: 12px 16px; border-top: 1px solid #2a3038; background: #12171c; }
    .modal-form { display: grid; gap: 12px; }
    .modal-pre { white-space: pre-wrap; color: #cbd5e1; background: #101317; border: 1px solid #29313b; border-radius: 4px; padding: 12px; max-height: 46vh; overflow: auto; }
    .policy-preview { display: grid; gap: 14px; }
    .preview-warning { border: 1px solid #7f3d3d; background: #211415; color: #fecaca; padding: 12px; border-radius: 5px; line-height: 1.45; }
    .preview-note { border: 1px solid #3d4957; background: #111820; color: #cbd5e1; padding: 12px; border-radius: 5px; line-height: 1.45; }
    .preview-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
    .preview-card { border: 1px solid #29313b; background: #10151a; border-radius: 5px; padding: 10px; min-width: 0; }
    .preview-card label { display: block; color: #8993a2; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; margin: 0 0 6px; }
    .preview-card strong { display: block; color: #e5e7eb; font-size: 20px; line-height: 1.1; overflow-wrap: anywhere; }
    .preview-meta { display: grid; grid-template-columns: 140px 1fr; gap: 8px 12px; border: 1px solid #29313b; background: #101317; border-radius: 5px; padding: 12px; }
    .preview-meta dt { color: #8993a2; }
    .preview-meta dd { margin: 0; color: #dbeafe; overflow-wrap: anywhere; }
    .preview-private { color: #fde68a; }
    .tabs { display: flex; gap: 8px; margin: 0 0 12px; }
    .tabs button { background: #252c35; border-color: #4a5667; }
    .tabs button.active { background: #2367d1; border-color: #4d8cff; }
    .auth-only { display: none; }
    body.authenticated .auth-only { display: inline-block; }
    body:not(.authenticated) .page-tabs,
    body:not(.authenticated) .dashboard-page { display: none !important; }
    @media (max-width: 900px) {
      body { padding: 14px; }
      .row, .config-grid, .filters, .filters.two { grid-template-columns: 1fr; }
      .preview-grid, .preview-meta { grid-template-columns: 1fr; }
      .page-tabs { position: static; }
      .span-3, .span-4, .span-6, .span-12 { grid-column: auto; }
    }
  </style>
</head>
<body>
  <main>
    <h1>ModSec Admin</h1>
    <section>
      <h2>Dashboard Login</h2>
      <div class="row">
        <div class="span-6">
          <label for="token">Admin token</label>
          <div class="token-row">
            <input id="token" value="" autocomplete="off" type="password">
            <button id="tokenToggle" class="secondary" onclick="toggleTokenVisibility()" type="button">Show</button>
          </div>
        </div>
        <div class="span-3">
          <button id="loginButton" onclick="login()">Login</button>
        </div>
        <div class="span-3">
          <button class="secondary auth-only" onclick="loadAll()">Refresh</button>
          <button class="secondary auth-only" onclick="reloadConfig()">Reload Config</button>
        </div>
      </div>
      <div id="status" class="status"></div>
    </section>

    <nav class="page-tabs" aria-label="Dashboard pages">
      <button id="tab-overview" class="active" onclick="showDashboardPage('overview')">Overview</button>
      <button id="tab-players" onclick="showDashboardPage('players')">Players</button>
      <button id="tab-events" onclick="showDashboardPage('events')">Events</button>
      <button id="tab-policy" onclick="showDashboardPage('policy')">Policy</button>
      <button id="tab-files" onclick="showDashboardPage('files')">Files</button>
      <button id="tab-popups" onclick="showDashboardPage('popups')">Popups</button>
    </nav>

    <section id="page-overview" class="dashboard-page active">
      <h2>Diagnostics</h2>
      <div id="diagnosticsSummary" class="config-grid">
        <div class="muted">Diagnostics not loaded yet.</div>
      </div>
    </section>

    <section id="page-players" class="dashboard-page">
      <h2>Players</h2>
      <div class="filters two">
        <div>
          <label for="playerSearch">Search players</label>
          <input id="playerSearch" placeholder="name, profile, endpoint, violation" oninput="renderPlayers()">
        </div>
        <div>
          <label for="playerStatusFilter">Status</label>
          <select id="playerStatusFilter" onchange="renderPlayers()">
            <option value="all">All players</option>
            <option value="client-seen">Client seen</option>
            <option value="pending-client">Pending client</option>
            <option value="missing-client">Missing client</option>
            <option value="stale-client">Stale client</option>
            <option value="banned">Locked out</option>
            <option value="strikes">Has strikes</option>
            <option value="risk">Risk 20+</option>
          </select>
        </div>
      </div>
      <div id="playerCount" class="result-count"></div>
      <div class="table-wrap">
        <table class="players">
          <colgroup><col><col><col><col><col><col><col><col></colgroup>
          <thead>
            <tr>
              <th>Player</th>
              <th>Profile ID</th>
              <th>Endpoint</th>
              <th>Status</th>
              <th>Risk</th>
              <th>Last Seen</th>
              <th>Recent Violations</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="players">
            <tr><td colspan="8" class="muted">No players loaded yet.</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <section id="page-events" class="dashboard-page">
      <h2>Event History</h2>
      <div class="filters">
        <div>
          <label for="eventSearch">Search events</label>
          <input id="eventSearch" placeholder="type, player, profile, message, violation" oninput="renderEvents()">
        </div>
        <div>
          <label for="eventTypeFilter">Type</label>
          <select id="eventTypeFilter" onchange="renderEvents()">
            <option value="all">All types</option>
          </select>
        </div>
        <div>
          <label for="eventSeverityFilter">Severity</label>
          <select id="eventSeverityFilter" onchange="renderEvents()">
            <option value="all">All severities</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="block">Block</option>
          </select>
        </div>
      </div>
      <div id="eventCount" class="result-count"></div>
      <div class="table-wrap">
      <table class="events">
        <colgroup><col><col><col><col><col></colgroup>
        <thead>
          <tr>
            <th>Time</th>
            <th>Type</th>
            <th>Player</th>
            <th>Message</th>
            <th>Violations</th>
          </tr>
        </thead>
        <tbody id="events">
          <tr><td colspan="5" class="muted">No events loaded yet.</td></tr>
        </tbody>
      </table>
      </div>
    </section>

    <section id="page-policy" class="dashboard-page">
      <h2>Policy</h2>
      <div id="policySummary" class="config-grid">
        <div class="muted">Policy not loaded yet.</div>
      </div>
      <div class="policy-actions">
        <button class="secondary" onclick="togglePolicyEditor()">Edit Policy</button>
        <button class="secondary" onclick="loadEditablePolicy()">Reset Editor</button>
        <button class="secondary" onclick="exportPolicy()">Export Policy</button>
        <button class="secondary" onclick="selectPolicyFile(false)">Import Policy</button>
        <button class="secondary" onclick="selectPolicyFile(true)">Merge Policy</button>
        <button class="secondary" onclick="toggleAdvancedPolicyJson()" type="button">Advanced JSON</button>
        <button onclick="savePolicy()">Save Policy</button>
        <input id="policyFileInput" type="file" accept=".json,application/json" style="display:none" onchange="handlePolicyFileSelected(event)">
      </div>
      <div id="pendingTray" class="pending-tray">
        <div class="pending-head">
          <div>
            <strong>Pending Policy Changes</strong>
            <div class="hint" style="margin: 2px 0 0;">Review staged client snapshot actions before applying them to the policy editor.</div>
          </div>
          <div class="policy-actions" style="margin:0;">
            <button onclick="applyPendingPolicyChanges()">Apply Staged</button>
            <button class="secondary" onclick="discardPendingPolicyChanges()">Discard</button>
          </div>
        </div>
        <div id="pendingPolicyChanges" class="pending-list"></div>
      </div>
      <div id="policyEditor" style="display:none; margin-top: 14px;">
        <div class="friendly-note">
          Use the plain controls and builders for normal setup. The JSON boxes are hidden under Advanced JSON for edge cases and shared community policies.
        </div>
        <div class="row">
          <div class="span-3">
            <label for="policyEnabled">Enabled</label>
            <select id="policyEnabled">
              <option value="true">Enabled</option>
              <option value="false">Disabled</option>
            </select>
          </div>
          <div class="span-3">
            <label for="policyMode">Mode</label>
            <select id="policyMode">
              <option value="Disabled">Disabled</option>
              <option value="WarnOnly">Warn Only</option>
              <option value="BlockRaid">Block Raid</option>
              <option value="StrikeThenBlock">Strike Then Block</option>
            </select>
          </div>
          <div class="span-3">
            <label for="policyStrictWhitelist">Allow-list mode</label>
            <select id="policyStrictWhitelist">
              <option value="false">Disabled - block-list rules only</option>
              <option value="true">Enabled - only allowed file hashes may pass</option>
            </select>
          </div>
          <div class="span-3">
            <label for="policyTimezone">Server timezone</label>
            <input id="policyTimezone" value="UTC">
          </div>
          <div class="span-3">
            <label for="policyBackgroundInterval">Background seconds</label>
            <input id="policyBackgroundInterval" type="number" min="10" max="3600">
          </div>
          <div class="span-3">
            <label for="policyMinimumInterval">Minimum seconds</label>
            <input id="policyMinimumInterval" type="number" min="5" max="3600">
          </div>
          <div class="span-3">
            <label for="policyMaximumInterval">Maximum seconds</label>
            <input id="policyMaximumInterval" type="number" min="5" max="7200">
          </div>
          <div class="span-3">
            <label for="policyStrikeLimit">Strike limit</label>
            <input id="policyStrikeLimit" type="number" min="1" max="20">
          </div>
          <div class="span-3">
            <label for="policyStrikeDecay">Strike decay minutes</label>
            <input id="policyStrikeDecay" type="number" min="1" max="43200">
          </div>
          <div class="span-3">
            <label for="policyCooldown">Strike protection minutes</label>
            <input id="policyCooldown" type="number" min="0" max="10080">
          </div>
          <div class="span-6">
            <label for="policyAutoBlockDurations">Lockout hours (comma separated, 0 = permanent)</label>
            <input id="policyAutoBlockDurations" value="24,72,168,0">
          </div>
          <div class="span-6">
            <label for="policyScanPaths">Scan paths (one per line)</label>
            <textarea id="policyScanPaths"></textarea>
          </div>
          <div class="span-6 json-only">
            <label for="policyAutoWhitelist">Auto allow/block list options JSON</label>
            <textarea id="policyAutoWhitelist" class="policy-json"></textarea>
          </div>
          <div class="span-6 json-only">
            <label for="policyReportSanity">Report sanity options JSON</label>
            <textarea id="policyReportSanity" class="policy-json"></textarea>
          </div>
          <div class="span-6 json-only">
            <label for="policyClientPresence">Client presence options JSON</label>
            <textarea id="policyClientPresence" class="policy-json"></textarea>
          </div>
          <div class="span-6 json-only">
            <label for="policyPrivacy">Privacy options JSON</label>
            <textarea id="policyPrivacy" class="policy-json"></textarea>
          </div>
          <div class="span-12 json-only">
            <label for="policyIncidentMail">Incident mail options JSON</label>
            <textarea id="policyIncidentMail" class="policy-json tall"></textarea>
          </div>
          <div class="span-12">
            <div class="rule-builder">
              <h3>Mod File Rule Builder</h3>
              <div class="row">
                <div class="span-3">
                  <label for="dropRuleTarget">Target list</label>
                  <select id="dropRuleTarget">
                    <option value="blocked">Block dragged files</option>
                    <option value="allowed">Allow dragged files</option>
                  </select>
                </div>
                <div class="span-3">
                  <label for="dropRuleSeverity">Severity</label>
                  <select id="dropRuleSeverity">
                    <option value="block">Block</option>
                    <option value="warn">Warn</option>
                    <option value="audit">Audit</option>
                  </select>
                </div>
                <div class="span-3">
                  <label for="dropRuleExtensions">Extensions / managed assemblies</label>
                  <input id="dropRuleExtensions" value=".dll">
                </div>
                <div class="span-3">
                  <label for="dropRuleReason">Reason</label>
                  <input id="dropRuleReason" value="Managed by ModSec dashboard.">
                </div>
              </div>
              <div id="modDropZone" class="drop-zone" ondragover="handleRuleDropOver(event)" ondragleave="handleRuleDropLeave(event)" ondrop="handleRuleDrop(event)" onclick="document.getElementById('modFilePicker').click()">
                <strong>Drop mod folders or assembly files here</strong>
                Hashes are calculated locally in this browser. DLLs and renamed .NET assemblies are staged automatically.
              </div>
              <input id="modFilePicker" type="file" multiple webkitdirectory directory style="display:none" onchange="handleRuleFilePick(event)">
              <div class="builder-actions">
                <button class="secondary" onclick="document.getElementById('modFilePicker').click()" type="button">Choose Folder/Files</button>
                <span id="dropRuleStatus" class="hint">Selected extensions plus renamed .NET assemblies are staged.</span>
              </div>
            </div>
          </div>
          <div class="span-12">
            <div class="rule-builder">
              <h3>Config Rule Builder</h3>
              <div class="row">
                <div class="span-3">
                  <label for="configRuleFile">Config path</label>
                  <input id="configRuleFile" placeholder="BepInEx/config/com.example.cfg">
                </div>
                <div class="span-3">
                  <label for="configRuleSection">Section (optional)</label>
                  <input id="configRuleSection" placeholder="2- Debug Mods">
                </div>
                <div class="span-3">
                  <label for="configRuleKey">Key / JSON path</label>
                  <input id="configRuleKey" placeholder="GodMode - On/Off">
                </div>
                <div class="span-3">
                  <label for="configRuleName">Display name (optional)</label>
                  <input id="configRuleName" placeholder="auto: megamod.GodMode">
                </div>
                <div class="span-3">
                  <label for="configRuleFormat">Format</label>
                  <select id="configRuleFormat">
                    <option value="bepinex">BepInEx cfg</option>
                    <option value="json">JSON</option>
                  </select>
                </div>
                <div class="span-3">
                  <label for="configRuleOperator">Operator</label>
                  <select id="configRuleOperator">
                    <option value="in">Allowed values</option>
                    <option value="notin">Blocked values</option>
                    <option value="range">Allowed numeric range</option>
                    <option value="notrange">Blocked numeric range</option>
                    <option value="exists">Must exist</option>
                    <option value="missing">Must be missing</option>
                  </select>
                </div>
                <div class="span-3">
                  <label for="configRuleValues">Values</label>
                  <input id="configRuleValues" placeholder="false or true,false">
                </div>
                <div class="span-3">
                  <label for="configRuleRange">Range</label>
                  <input id="configRuleRange" placeholder="30-50">
                </div>
                <div class="span-12">
                  <label for="configRuleSeverity">Severity</label>
                  <select id="configRuleSeverity">
                    <option value="block">Block</option>
                    <option value="warn">Warn</option>
                    <option value="audit">Audit</option>
                  </select>
                </div>
              </div>
              <div class="builder-actions">
                <button class="secondary" onclick="stageConfigRuleFromBuilder()" type="button">Stage Config Rule</button>
                <span class="hint">Section is only needed for BepInEx cfg files when the same key appears under multiple headers. Rules are staged first. Click Apply Staged, then Save Policy.</span>
              </div>
            </div>
          </div>
          <div class="span-12">
            <div class="rule-review" id="policyRuleReview">
              <div class="rule-review-card">
                <div class="rule-review-head">
                  <h3>Allowed File Hashes</h3>
                  <div class="hint">Files allowed when allow-list mode is enabled.</div>
                </div>
                <div id="allowedFilesReview"></div>
              </div>
              <div class="rule-review-card">
                <div class="rule-review-head">
                  <h3>Blocked Files</h3>
                  <div class="hint">Denied by hash, exact path, or glob. Hash rules survive renames.</div>
                </div>
                <div id="blockedFilesReview"></div>
              </div>
              <div class="rule-review-card">
                <div class="rule-review-head">
                  <h3>Blocked Plugin GUIDs</h3>
                  <div class="hint">BepInEx metadata rules. Prefer GUIDs when known.</div>
                </div>
                <div id="blockedPluginsReview"></div>
              </div>
              <div class="rule-review-card">
                <div class="rule-review-head">
                  <h3>Config Rules</h3>
                  <div class="hint">Allowed/blocked values for BepInEx cfg or JSON settings.</div>
                </div>
                <div id="configRulesReview"></div>
              </div>
            </div>
          </div>
          <div class="span-6 json-only">
            <label for="policyBlockedPlugins">Blocked plugins JSON</label>
            <textarea id="policyBlockedPlugins" class="policy-json tall"></textarea>
          </div>
          <div class="span-6 json-only">
            <label for="policyBlockedFiles">Blocked files JSON</label>
            <textarea id="policyBlockedFiles" class="policy-json tall"></textarea>
          </div>
          <div class="span-6 json-only">
            <label for="policyAllowedFiles">Allowed files JSON</label>
            <textarea id="policyAllowedFiles" class="policy-json tall"></textarea>
          </div>
          <div class="span-12 json-only">
            <label for="policyConfigRules">Config rules JSON</label>
            <textarea id="policyConfigRules" class="policy-json tall"></textarea>
          </div>
        </div>
        <div class="hint">Save writes to config/modsec.json and reloads the live policy. Generated auto allow/block list rules are not baked into this editor unless they already exist in the human config file.</div>
      </div>
    </section>

    <section id="page-files" class="dashboard-page">
      <h2>Server File Hashes</h2>
      <div class="hint">Review hashes from configured server scan paths. Use the Policy page to add, edit, or remove allow/block rules.</div>
      <div class="table-wrap">
        <table class="files">
          <colgroup><col><col><col><col></colgroup>
          <thead>
            <tr>
              <th>Path</th>
              <th>SHA-256</th>
              <th>Size</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="serverFiles">
            <tr><td colspan="4" class="muted">No server files loaded yet.</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <section id="page-popups" class="dashboard-page">
      <h2>Send Popup</h2>
      <div class="hint">Live popups are shown by the ModSec client in-game/menu. Hall of Shame inbox messages are configured separately under Incident Mail.</div>
      <div class="row">
        <div class="span-6">
          <label for="popupTarget">Target</label>
          <select id="popupTarget">
            <option value="">Everyone (broadcast)</option>
          </select>
        </div>
        <div class="span-3">
          <label for="kind">Popup style</label>
          <select id="kind" onchange="applyTemplateDefaults()">
            <option value="dialog">Dialog - centered message</option>
            <option value="toast">Toast - quick corner notice</option>
            <option value="information">Information - tan notice</option>
            <option value="warning">Warning - amber notice</option>
            <option value="kick">Kick - red action notice</option>
            <option value="ban">Lockout - red action notice</option>
          </select>
        </div>
        <div class="span-3">
          <label for="severity">Severity</label>
          <select id="severity">
            <option>info</option>
            <option>warning</option>
            <option>block</option>
          </select>
        </div>
        <div class="span-3">
          <label for="duration">Toast seconds</label>
          <input id="duration" type="number" min="2" max="60" value="6">
        </div>
        <div class="span-3">
          <label for="requiresQuit">Requires quit</label>
          <select id="requiresQuit">
            <option value="false">No</option>
            <option value="true">Yes</option>
          </select>
        </div>
        <div class="span-6">
          <label for="title">Popup title</label>
          <input id="title" value="Server Notice">
        </div>
        <div class="span-12">
          <label for="message">Message</label>
          <textarea id="message">Placeholder ModSec dashboard popup.</textarea>
        </div>
        <div class="span-3">
          <button onclick="sendPopup()">Send Popup</button>
        </div>
      </div>
    </section>
  </main>

  <div id="inventoryModal" class="modal-backdrop">
    <div class="modal">
      <div class="modal-head">
        <div>
          <h2 id="inventoryTitle" style="margin:0;">Client Snapshot</h2>
          <div id="inventoryMeta" class="detail"></div>
        </div>
        <button class="secondary" onclick="closeInventory()">Close</button>
      </div>
      <div class="modal-body">
        <div class="tabs">
          <button id="tabPlugins" class="active" onclick="renderInventoryTab('plugins')">Plugins</button>
          <button id="tabFiles" onclick="renderInventoryTab('files')">Files</button>
          <button id="tabConfigs" onclick="renderInventoryTab('configs')">Config Values</button>
        </div>
        <div id="inventoryBody" class="table-wrap"></div>
      </div>
    </div>
  </div>

  <div id="dashboardModal" class="modal-backdrop">
    <div class="modal" style="max-width: 720px;">
      <div class="modal-head">
        <h2 id="dashboardModalTitle" style="margin:0;">Confirm</h2>
        <button class="secondary" onclick="closeDashboardModal()">Close</button>
      </div>
      <div id="dashboardModalBody" class="modal-body"></div>
      <div id="dashboardModalFoot" class="modal-foot"></div>
    </div>
  </div>

  <script>
    let adminSession = sessionStorage.getItem('modsecAdminSession') || '';
    let adminSessionExpiresAt = sessionStorage.getItem('modsecAdminSessionExpiresAt') || '';
    function token() {
      const input = document.getElementById('token');
      return input.dataset.hidden === 'true' ? (input.dataset.actualValue || '') : input.value;
    }
    function initializeTokenMask() {
      const input = document.getElementById('token');
      input.dataset.actualValue = '';
      input.dataset.hidden = 'false';
      document.getElementById('tokenToggle').textContent = 'Show';
    }
    function toggleTokenVisibility() {
      const input = document.getElementById('token');
      const toggle = document.getElementById('tokenToggle');
      if (input.dataset.hidden === 'true') {
        input.value = input.dataset.actualValue || '';
        input.type = 'text';
        input.dataset.hidden = 'false';
        input.readOnly = false;
        toggle.textContent = 'Hide';
        input.focus();
        return;
      }

      input.dataset.actualValue = input.value;
      input.dataset.hidden = 'true';
      input.type = 'text';
      input.value = '****';
      input.readOnly = true;
      toggle.textContent = 'Show';
    }
    function setStatus(text) { document.getElementById('status').textContent = text; }
    function markPolicyDirty(message) {
      policyDirty = true;
      setStatus(message || 'Unsaved policy changes. Click Save Policy to write them.');
    }
    function clearPolicyDirty() {
      policyDirty = false;
    }
    function hasUnsavedPolicyWork() {
      return policyDirty || pendingPolicyChanges.length > 0;
    }
    function setAuthenticated(value) {
      document.body.classList.toggle('authenticated', Boolean(value));
      document.getElementById('loginButton').textContent = value ? 'Login Again' : 'Login';
    }
    async function login() {
      try {
        const response = await fetch('/modsec/admin/login', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ token: token() })
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || !payload.success) {
          const detail = payload.lockedUntilUtc ? ` Locked until ${formatDate(payload.lockedUntilUtc)}.` : '';
          throw new Error(`Dashboard login failed.${detail}`);
        }

        adminSession = payload.sessionToken || '';
        adminSessionExpiresAt = payload.expiresAtUtc || '';
        sessionStorage.setItem('modsecAdminSession', adminSession);
        sessionStorage.setItem('modsecAdminSessionExpiresAt', adminSessionExpiresAt);
        setAuthenticated(true);
        if (token()) {
          const input = document.getElementById('token');
          input.dataset.actualValue = token();
          input.dataset.hidden = 'true';
          input.type = 'text';
          input.value = '****';
          input.readOnly = true;
          document.getElementById('tokenToggle').textContent = 'Show';
        }
        setStatus(`Logged in. Session expires ${formatDate(adminSessionExpiresAt)}.`);
        await loadAll();
      } catch (error) { setStatus(error.message); }
    }
    async function api(path, options = {}) {
      if (!adminSession) throw new Error('Login required.');
      options.headers = Object.assign({ 'modsec-admin-session': adminSession }, options.headers || {});
      const response = await fetch(path, options);
      if (response.status === 403) {
        setAuthenticated(false);
        throw new Error('Dashboard session expired or access denied. Log in again.');
      }
      if (!response.ok) throw new Error(await response.text());
      return response.json();
    }
    let editablePolicy = null;
    let activeInventory = null;
    let activeInventoryTab = 'plugins';
    let playerCache = [];
    let eventCache = [];
    let pendingPolicyChanges = [];
    let activeDashboardPage = 'overview';
    let policyDirty = false;
    async function loadAll() {
      await Promise.all([loadDiagnostics(), loadPlayers(), loadEvents(), loadPolicy(), loadEditablePolicy(), loadServerFiles()]);
    }
    function showDashboardPage(page, force = false) {
      if (!force && page !== activeDashboardPage && hasUnsavedPolicyWork()) {
        openDashboardModal({
          title: 'Unsaved Policy Changes',
          bodyHtml: `<div class="preview-warning"><strong>Save Policy before leaving?</strong><br>You have staged or edited policy changes that have not been saved to config/modsec.json yet.</div><div class="preview-note">Choose Stay to return to Policy and save, or Leave Anyway to keep the edits in the browser while switching pages.</div>`,
          cancelText: 'Stay',
          confirmText: 'Leave Anyway',
          danger: true,
          onConfirm: async () => {
            await discardUnsavedPolicyChanges();
            showDashboardPage(page, true);
          }
        });
        return;
      }
      activeDashboardPage = page;
      for (const name of ['overview', 'players', 'events', 'policy', 'files', 'popups']) {
        document.getElementById(`page-${name}`).classList.toggle('active', name === page);
        document.getElementById(`tab-${name}`).classList.toggle('active', name === page);
      }
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    async function discardUnsavedPolicyChanges() {
      pendingPolicyChanges = [];
      renderPendingPolicyChanges();
      clearPolicyDirty();
      await loadEditablePolicy();
      setStatus('Discarded unsaved policy changes.');
    }
    async function loadDiagnostics() {
      try {
        const diagnostics = await api('/modsec/admin/diagnostics');
        renderDiagnostics(diagnostics);
      } catch (error) { setStatus(error.message); }
    }
    function renderDiagnostics(diagnostics) {
      const el = document.getElementById('diagnosticsSummary');
      const policy = diagnostics.policy || {};
      const players = diagnostics.players || {};
      const events = diagnostics.events || {};
      const counts = policy.ruleCounts || {};
      const compactConfigPath = compactPath(diagnostics.configPath || '');
      el.innerHTML = `
        ${diagnosticCard('Server', `v${diagnostics.serverVersion || 'unknown'}`, `Config: ${diagnostics.configFileExists ? 'found' : 'missing'}`)}
        ${diagnosticCard('Config Last Saved', formatDate(diagnostics.configLastWriteUtc) || 'never', compactConfigPath, '', diagnostics.configPath || '')}
        ${diagnosticCard('Policy Mode', policy.mode || 'unknown', `${policy.enabled ? 'enabled' : 'disabled'} | dashboard ${policy.dashboardEnabled ? 'on' : 'off'}`, policy.mode === 'BlockRaid' || policy.mode === 'StrikeThenBlock' ? 'bad' : policy.mode === 'WarnOnly' ? 'warn' : '')}
        ${diagnosticCard('Client Presence', policy.missingClientAction || 'audit', `${policy.clientPresenceEnabled ? 'enabled' : 'disabled'} | heartbeat ${policy.heartbeatIntervalSeconds || '?'}s/${policy.heartbeatTimeoutSeconds || '?'}s`, policy.missingClientAction === 'block' ? 'bad' : policy.missingClientAction === 'warn' ? 'warn' : '')}
        ${diagnosticCard('Players', `${players.visible || 0} visible`, `${players.tracked || 0} tracked | ${players.clientSeen || 0} client seen`)}
        ${diagnosticCard('Missing Client', `${players.missingClient || 0} missing`, `${players.pendingClient || 0} pending | ${players.staleClient || 0} stale`, (players.missingClient || players.staleClient) ? 'warn' : '')}
        ${diagnosticCard('Risk', `${players.withStrikes || 0} with strikes`, `${players.banned || 0} locked out | ${players.withMissingClientAttempts || 0} missing-client attempts`, (players.banned || players.withStrikes) ? 'bad' : '')}
        ${diagnosticCard('Policy Rules', `${counts.blockedPlugins || 0} plugins / ${counts.blockedFiles || 0} files`, `${counts.effectiveConfigRules || 0} config | ${counts.allowedFiles || 0} allowed`)}
        ${diagnosticCard('Auto Allow/Block List', policy.autoWhitelistEnabled ? 'enabled' : 'disabled', policy.autoWhitelistTargetList || 'allowedFiles')}
        ${diagnosticCard('Events', `${events.stored || 0} stored`, `${events.blocks || 0} blocks | ${events.warnings || 0} warnings`)}
      `;
    }
    function diagnosticCard(label, value, detail, tone, title) {
      return `<div class="diag-card" title="${escapeAttr(title || detail || '')}"><label>${escapeHtml(label)}</label><span class="pill ${tone || ''}">${escapeHtml(value)}</span><div class="detail diag-detail">${escapeHtml(detail || '')}</div></div>`;
    }
    function compactPath(value) {
      const path = String(value || '').replace(/\\/g, '/');
      if (path.length <= 46) return path;
      const parts = path.split('/').filter(Boolean);
      if (parts.length <= 3) return `...${path.slice(-43)}`;
      return `${parts[0]}/.../${parts.slice(-3).join('/')}`;
    }
    async function loadPlayers() {
      try {
        playerCache = await api('/modsec/admin/players');
        renderPlayers();
        populatePopupTargets();
        setStatus(`Loaded ${playerCache.length} player(s).`);
      } catch (error) { setStatus(error.message); }
    }
    function populatePopupTargets() {
      const select = document.getElementById('popupTarget');
      if (!select) return;

      const current = select.value || '';
      const players = [...playerCache]
        .filter(player => player.profileId)
        .sort((a, b) => String(a.playerName || a.profileId).localeCompare(String(b.playerName || b.profileId)));

      select.innerHTML = '<option value="">Everyone (broadcast)</option>' + players.map(player => {
        const name = player.playerName || '(unknown profile)';
        const install = player.installId ? ` | Install: ${String(player.installId).slice(0, 12)}` : '';
        return `<option value="${escapeAttr(player.profileId)}">${escapeHtml(name)} - ${escapeHtml(player.profileId)}${escapeHtml(install)}</option>`;
      }).join('');

      select.value = players.some(player => player.profileId === current) ? current : '';
    }
    function renderPlayers() {
      const tbody = document.getElementById('players');
      const count = document.getElementById('playerCount');
      const filtered = filterPlayers(playerCache);
      count.textContent = `${filtered.length} of ${playerCache.length} player(s) shown.`;
      if (!playerCache.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="muted">No clients have reported yet.</td></tr>';
        return;
      }
      if (!filtered.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="muted">No players match the current filters.</td></tr>';
        return;
      }
      tbody.innerHTML = filtered.map(p => `
        <tr>
          <td title="${escapeAttr(playerIdentityTooltip(p))}"><div class="cell-stack"><strong>${escapeHtml(p.playerName || '(unknown)')}</strong><span class="subtle">${escapeHtml(p.timeZoneId || 'timezone unknown')}</span></div></td>
          <td><div class="mono">${escapeHtml(p.profileId)}</div></td>
          <td>${escapeHtml(p.lastKnownIp || '')}</td>
          <td>${playerStatus(p)}</td>
          <td><span class="pill ${p.riskScore >= 60 ? 'bad' : p.riskScore >= 20 ? 'warn' : ''}">${p.riskScore}</span></td>
          <td><div class="detail">${escapeHtml(formatDate(p.lastSeenUtc))}</div></td>
          <td>${renderViolations(p.recentViolations || [])}</td>
          <td class="actions">
            <button class="secondary" onclick="openInventory('${escapeAttr(p.profileId)}')">Client Snapshot</button>
            <button class="secondary" onclick="pardon('${escapeAttr(p.profileId)}')">Pardon</button>
            <button class="danger" onclick="ban('${escapeAttr(p.profileId)}')">Lockout</button>
            <button class="secondary" onclick="unban('${escapeAttr(p.profileId)}')">Clear Lockout</button>
          </td>
        </tr>`).join('');
    }
    async function loadServerFiles() {
      try {
        const files = await api('/modsec/admin/server-files');
        const tbody = document.getElementById('serverFiles');
        if (!files.length) {
          tbody.innerHTML = '<tr><td colspan="4" class="muted">No files found in configured server scan paths.</td></tr>';
          return;
        }
        tbody.innerHTML = files.slice(0, 250).map(file => `
          <tr>
            <td><div class="mono">${escapeHtml(file.path)}</div></td>
            <td><div class="mono">${escapeHtml(file.hash)}</div></td>
            <td><span class="detail">${formatBytes(file.size || 0)}</span></td>
            <td><button class="secondary" onclick="addHashBlock('${escapeAttr(file.path)}','${escapeAttr(file.hash)}')">Block Hash</button></td>
          </tr>`).join('');
      } catch (error) { setStatus(error.message); }
    }
    async function openInventory(profileId) {
      try {
        activeInventory = await api(`/modsec/admin/player-inventory?profileId=${encodeURIComponent(profileId)}`);
        if (activeInventory.success === false) throw new Error(activeInventory.error || 'Client snapshot not found.');
        activeInventoryTab = 'plugins';
        document.getElementById('inventoryTitle').textContent = `Client Snapshot: ${activeInventory.playerName || activeInventory.profileId}`;
        document.getElementById('inventoryMeta').textContent = `${activeInventory.profileId}${activeInventory.installId ? ` | Install ID: ${activeInventory.installId}` : ''} | last ${activeInventory.lastReportKind || 'report'}: ${formatDate(activeInventory.lastReportAtUtc) || 'never'}`;
        document.getElementById('inventoryModal').style.display = 'block';
        renderInventoryTab('plugins');
      } catch (error) { setStatus(error.message); }
    }
    function closeInventory() {
      document.getElementById('inventoryModal').style.display = 'none';
    }
    function renderInventoryTab(tab) {
      activeInventoryTab = tab;
      for (const name of ['Plugins', 'Files', 'Configs']) {
        document.getElementById(`tab${name}`).classList.toggle('active', tab === name.toLowerCase());
      }
      const body = document.getElementById('inventoryBody');
      if (!activeInventory) {
        body.innerHTML = '<div class="muted">No client snapshot loaded.</div>';
        return;
      }
      if (tab === 'plugins') {
        body.innerHTML = `<table><thead><tr><th>Name</th><th>GUID</th><th>Version</th><th>Location</th><th>Actions</th></tr></thead><tbody>${(activeInventory.plugins || []).map(p => {
          const file = findInventoryFile(p.location);
          const hashButtons = file ? `<button class="secondary" onclick="stageInventoryHashRule('blocked','${escapeAttr(file.path)}','${escapeAttr(file.hash)}')">Block Hash</button><button class="secondary" onclick="stageInventoryHashRule('allowed','${escapeAttr(file.path)}','${escapeAttr(file.hash)}')">Allow Hash</button>` : '<span class="muted">No hash</span>';
          return `<tr><td>${escapeHtml(p.name)}</td><td class="mono">${escapeHtml(p.guid)}</td><td>${escapeHtml(p.version)}</td><td class="mono">${escapeHtml(p.location)}</td><td class="actions"><button class="secondary" onclick="stagePluginBlock('${escapeAttr(p.guid)}','${escapeAttr(p.name)}')">Block GUID</button>${hashButtons}</td></tr>`;
        }).join('') || '<tr><td colspan="5" class="muted">No plugins reported.</td></tr>'}</tbody></table>`;
        return;
      }
      if (tab === 'files') {
        body.innerHTML = `<table><thead><tr><th>Path</th><th>SHA-256</th><th>Size</th><th>Actions</th></tr></thead><tbody>${(activeInventory.files || []).map(f => `<tr><td class="mono">${escapeHtml(f.path)}</td><td class="mono">${escapeHtml(f.hash)}</td><td>${formatBytes(f.size || 0)}</td><td class="actions"><button class="secondary" onclick="stageInventoryHashRule('blocked','${escapeAttr(f.path)}','${escapeAttr(f.hash)}')">Block Hash</button><button class="secondary" onclick="stageInventoryHashRule('allowed','${escapeAttr(f.path)}','${escapeAttr(f.hash)}')">Allow Hash</button></td></tr>`).join('') || '<tr><td colspan="4" class="muted">No files reported.</td></tr>'}</tbody></table>`;
        return;
      }
      body.innerHTML = `<table><thead><tr><th>Rule</th><th>Path</th><th>Section</th><th>Key</th><th>Value</th><th>File</th><th>Found</th></tr></thead><tbody>${(activeInventory.configValues || []).map(c => `<tr><td class="mono">${escapeHtml(c.ruleId)}</td><td class="mono">${escapeHtml(c.path)}</td><td>${escapeHtml(c.section || '')}</td><td>${escapeHtml(c.key || c.jsonPath || '')}</td><td class="mono">${escapeHtml(c.value || '')}</td><td>${c.fileExists ? 'yes' : 'no'}</td><td>${c.found ? 'yes' : 'no'}</td></tr>`).join('') || '<tr><td colspan="7" class="muted">No config values reported.</td></tr>'}</tbody></table>`;
    }
    async function loadEvents() {
      try {
        eventCache = await api('/modsec/admin/events');
        populateEventTypeFilter(eventCache);
        renderEvents();
      } catch (error) { setStatus(error.message); }
    }
    function renderEvents() {
      const tbody = document.getElementById('events');
      const count = document.getElementById('eventCount');
      const filtered = filterEvents(eventCache);
      count.textContent = `${Math.min(filtered.length, 120)} of ${eventCache.length} event(s) shown${filtered.length > 120 ? ' (limited to newest 120)' : ''}.`;
      if (!eventCache.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="muted">No events yet.</td></tr>';
        return;
      }
      if (!filtered.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="muted">No events match the current filters.</td></tr>';
        return;
      }
      tbody.innerHTML = filtered.slice(0, 120).map(e => `
        <tr>
          <td class="detail">${escapeHtml(formatDate(e.createdAtUtc))}</td>
          <td>${eventPill(e)}</td>
          <td><div class="cell-stack"><span>${escapeHtml(e.playerName || '(system)')}</span><span class="mono">${escapeHtml(e.profileId || '')}</span></div></td>
          <td class="detail">${escapeHtml(e.message || '')}</td>
          <td>${renderViolations(e.violations || [])}</td>
        </tr>`).join('');
    }
    async function loadPolicy() {
      try {
        const policy = await api('/modsec/admin/config');
        const el = document.getElementById('policySummary');
        el.innerHTML = `
          <div><label>Mode</label><span class="pill ${policy.mode === 'BlockRaid' || policy.mode === 'StrikeThenBlock' ? 'bad' : policy.mode === 'WarnOnly' ? 'warn' : ''}">${escapeHtml(policy.mode)}</span></div>
          <div><label>Allow-list mode</label><span class="pill">${policy.strictWhitelist ? 'enabled' : 'disabled'}</span></div>
          <div><label>Server timezone</label><div class="mono">${escapeHtml(policy.serverTimeZoneId || 'UTC')}</div></div>
          <div><label>Scan paths</label><div class="detail">${escapeHtml((policy.scanPaths || []).join(', ') || 'none')}</div></div>
          <div><label>Blocked plugins</label><span class="pill">${(policy.blockedPlugins || []).length}</span></div>
          <div><label>Blocked files</label><span class="pill">${(policy.blockedFiles || []).length}</span></div>
          <div><label>Allowed files</label><span class="pill">${(policy.allowedFiles || []).length}</span></div>
          <div><label>Config rules</label><span class="pill">${countConfigRules(policy)}</span></div>
          <div><label>Report sanity</label><span class="pill ${policy.reportSanity?.enabled ? '' : 'warn'}">${policy.reportSanity?.enabled ? 'enabled' : 'disabled'}</span></div>
          <div><label>Client presence</label><span class="pill ${policy.clientPresence?.missingClientAction === 'block' ? 'bad' : policy.clientPresence?.missingClientAction === 'warn' ? 'warn' : ''}">${escapeHtml(policy.clientPresence?.missingClientAction || 'audit')}</span></div>`;
      } catch (error) { setStatus(error.message); }
    }
    async function loadEditablePolicy() {
      try {
        editablePolicy = await api('/modsec/admin/config/editable');
        fillPolicyEditor(editablePolicy);
      } catch (error) { setStatus(error.message); }
    }
    function togglePolicyEditor() {
      const editor = document.getElementById('policyEditor');
      editor.style.display = editor.style.display === 'none' ? 'block' : 'none';
      if (!editablePolicy) loadEditablePolicy();
    }
    function toggleAdvancedPolicyJson() {
      const editor = document.getElementById('policyEditor');
      if (editor.style.display === 'none') editor.style.display = 'block';
      editor.classList.toggle('show-advanced-json');
    }
    function fillPolicyEditor(policy) {
      document.getElementById('policyEnabled').value = String(Boolean(policy.enabled));
      document.getElementById('policyMode').value = policy.mode || 'WarnOnly';
      document.getElementById('policyStrictWhitelist').value = String(Boolean(policy.strictWhitelist));
      document.getElementById('policyTimezone').value = policy.serverTimeZoneId || 'UTC';
      document.getElementById('policyBackgroundInterval').value = policy.backgroundIntervalSeconds || 60;
      document.getElementById('policyMinimumInterval').value = policy.minimumIntervalSeconds || 15;
      document.getElementById('policyMaximumInterval').value = policy.maximumIntervalSeconds || 300;
      document.getElementById('policyStrikeLimit').value = policy.strikeLimit || 3;
      document.getElementById('policyStrikeDecay').value = policy.strikeDecayMinutes || 1440;
      document.getElementById('policyCooldown').value = policy.cooldownMinutes || 1;
      document.getElementById('policyAutoBlockDurations').value = (policy.autoBlockDurationsHours || policy.autoBanDurationsHours || [24,72,168,0]).join(',');
      document.getElementById('policyScanPaths').value = (policy.scanPaths || []).join('\n');
      setJsonField('policyAutoWhitelist', policy.autoWhitelist || {});
      setJsonField('policyPrivacy', policy.privacy || {});
      setJsonField('policyReportSanity', policy.reportSanity || {});
      setJsonField('policyClientPresence', policy.clientPresence || {});
      setJsonField('policyIncidentMail', policy.incidentMail || {});
      setJsonField('policyBlockedPlugins', policy.blockedPlugins || []);
      setJsonField('policyBlockedFiles', policy.blockedFiles || []);
      setJsonField('policyAllowedFiles', policy.allowedFiles || []);
      setJsonField('policyConfigRules', policy.configFiles && policy.configFiles.length ? policy.configFiles : (policy.configRules || []));
      renderPolicyRuleReview();
      clearPolicyDirty();
    }
    async function savePolicy() {
      try {
        if (!editablePolicy) await loadEditablePolicy();
        const payload = Object.assign({}, editablePolicy || {});
        payload.enabled = document.getElementById('policyEnabled').value === 'true';
        payload.mode = document.getElementById('policyMode').value;
        payload.strictWhitelist = document.getElementById('policyStrictWhitelist').value === 'true';
        payload.serverTimeZoneId = document.getElementById('policyTimezone').value || 'UTC';
        payload.backgroundIntervalSeconds = readInt('policyBackgroundInterval', 60);
        payload.minimumIntervalSeconds = readInt('policyMinimumInterval', 15);
        payload.maximumIntervalSeconds = readInt('policyMaximumInterval', 300);
        payload.strikeLimit = readInt('policyStrikeLimit', 3);
        payload.strikeDecayMinutes = readInt('policyStrikeDecay', 1440);
        payload.cooldownMinutes = readInt('policyCooldown', 1);
        payload.autoBlockDurationsHours = document.getElementById('policyAutoBlockDurations').value
          .split(',')
          .map(value => Number(value.trim()))
          .filter(value => Number.isFinite(value));
        delete payload.autoBanDurationsHours;
        payload.scanPaths = document.getElementById('policyScanPaths').value
          .split(/\r?\n/)
          .map(value => value.trim())
          .filter(Boolean);
        payload.autoWhitelist = readJsonField('policyAutoWhitelist', {});
        payload.privacy = readJsonField('policyPrivacy', {});
        payload.reportSanity = readJsonField('policyReportSanity', {});
        payload.clientPresence = readJsonField('policyClientPresence', {});
        payload.incidentMail = readJsonField('policyIncidentMail', {});
        payload.blockedPlugins = readJsonField('policyBlockedPlugins', []);
        payload.blockedFiles = readJsonField('policyBlockedFiles', []);
        payload.allowedFiles = readJsonField('policyAllowedFiles', []);
        const configRuleEditorValue = readJsonField('policyConfigRules', []);
        payload.configFiles = [];
        payload.configRules = [];
        for (const item of configRuleEditorValue) {
          if (Array.isArray(item.rules)) {
            payload.configFiles.push(item);
          } else {
            payload.configRules.push(item);
          }
        }

        await api('/modsec/admin/config', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
        clearPolicyDirty();
        setStatus('Policy saved and reloaded.');
        await Promise.all([loadDiagnostics(), loadPolicy(), loadEditablePolicy(), loadEvents()]);
      } catch (error) { setStatus(error.message); }
    }
    function openDashboardModal(options) {
      const modal = document.getElementById('dashboardModal');
      const title = document.getElementById('dashboardModalTitle');
      const body = document.getElementById('dashboardModalBody');
      const foot = document.getElementById('dashboardModalFoot');
      title.textContent = options.title || 'Confirm';
      body.innerHTML = options.bodyHtml || '';
      foot.innerHTML = '';
      const cancel = document.createElement('button');
      cancel.className = 'secondary';
      cancel.textContent = options.cancelText || 'Cancel';
      cancel.onclick = closeDashboardModal;
      foot.appendChild(cancel);
      const confirm = document.createElement('button');
      confirm.className = options.danger ? 'danger' : '';
      confirm.textContent = options.confirmText || 'Confirm';
      confirm.onclick = async () => {
        confirm.disabled = true;
        try {
          if (options.onConfirm) await options.onConfirm();
          closeDashboardModal();
        } catch (error) {
          setStatus(error.message);
          confirm.disabled = false;
        }
      };
      foot.appendChild(confirm);
      modal.style.display = 'block';
    }
    function closeDashboardModal() {
      document.getElementById('dashboardModal').style.display = 'none';
    }
    function modalInput(id, label, value, attrs = '') {
      return `<label for="${escapeAttr(id)}">${escapeHtml(label)}</label><input id="${escapeAttr(id)}" value="${escapeAttr(value || '')}" ${attrs}>`;
    }
    function modalTextarea(id, label, value) {
      return `<label for="${escapeAttr(id)}">${escapeHtml(label)}</label><textarea id="${escapeAttr(id)}">${escapeHtml(value || '')}</textarea>`;
    }
    async function exportPolicy() {
      openDashboardModal({
        title: 'Export Policy',
        bodyHtml: `<div class="modal-form">${modalInput('exportName', 'Policy name', 'ModSec Community Policy')}${modalTextarea('exportNotes', 'Notes', '')}<div class="hint">Exports are sanitized. Dashboard tokens and timezone are not included.</div></div>`,
        confirmText: 'Export',
        onConfirm: async () => {
        const name = document.getElementById('exportName').value || 'ModSec Community Policy';
        const notes = document.getElementById('exportNotes').value || '';
        const packageData = await api(`/modsec/admin/policy/export?name=${encodeURIComponent(name)}&notes=${encodeURIComponent(notes)}`);
        const json = JSON.stringify(packageData, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `${slugify(packageData.name || 'modsec-policy')}.json`;
        document.body.appendChild(link);
        link.click();
        URL.revokeObjectURL(link.href);
        link.remove();
        setStatus('Exported sanitized policy package. Dashboard token and timezone are not included.');
        }
      });
    }
    function selectPolicyFile(merge) {
      const input = document.getElementById('policyFileInput');
      input.dataset.merge = merge ? 'true' : 'false';
      input.value = '';
      input.click();
    }
    async function handlePolicyFileSelected(event) {
      const input = event.target;
      const file = input.files && input.files[0];
      if (!file) return;
      await importPolicyFile(file, input.dataset.merge === 'true');
    }
    async function importPolicyFile(file, merge) {
      try {
        const raw = await file.text();
        const packageData = normalizePolicyPackage(JSON.parse(raw));
        const preview = buildPolicyImportPreview(packageData, merge);
        openDashboardModal({
          title: `${merge ? 'Merge' : 'Import'} Policy`,
          bodyHtml: preview.html,
          confirmText: merge ? 'Merge Policy' : 'Import Policy',
          danger: !merge,
          onConfirm: async () => {
            const route = merge ? '/modsec/admin/policy/merge' : '/modsec/admin/policy/import';
            await api(route, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(packageData) });
            clearPolicyDirty();
            setStatus(`${merge ? 'Merged' : 'Imported'} ${file.name}. Local dashboard token and timezone were preserved.`);
            await Promise.all([loadDiagnostics(), loadPolicy(), loadEditablePolicy(), loadEvents()]);
          }
        });
      } catch (error) { setStatus(error.message); }
    }
    function normalizePolicyPackage(parsed) {
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Policy JSON must be an object.');
      }

      const hasPolicyWrapper = parsed.policy && typeof parsed.policy === 'object' && !Array.isArray(parsed.policy);
      const packageData = hasPolicyWrapper
        ? Object.assign({}, parsed, { policy: Object.assign({}, parsed.policy) })
        : {
            packageType: 'modsec-policy',
            name: parsed.name || 'Imported Policy',
            notes: 'Imported from raw ModSec config/policy JSON.',
            modSecVersion: parsed.modSecVersion || '',
            exportedAtUtc: parsed.exportedAtUtc || new Date().toISOString(),
            policy: Object.assign({}, parsed)
          };

      if (!packageData.policy || typeof packageData.policy !== 'object' || Array.isArray(packageData.policy)) {
        throw new Error('Policy package is missing a policy object.');
      }

      const privateFields = findPrivatePolicyFields(parsed, packageData);
      delete packageData.dashboard;
      delete packageData.adminToken;
      delete packageData.serverTimeZoneId;
      delete packageData.policy.dashboard;
      delete packageData.policy.adminToken;
      delete packageData.policy.serverTimeZoneId;
      packageData.packageType = packageData.packageType || 'modsec-policy';
      packageData.name = packageData.name || 'Imported Policy';
      packageData.notes = packageData.notes || '';
      packageData.modSecVersion = packageData.modSecVersion || '';
      packageData.exportedAtUtc = packageData.exportedAtUtc || new Date().toISOString();
      packageData.__privateFields = privateFields;
      validatePolicyShape(packageData.policy);
      return packageData;
    }
    function validatePolicyShape(policy) {
      const knownFields = ['enabled','mode','strictWhitelist','startupCheck','backgroundChecks','backgroundIntervalSeconds','minimumIntervalSeconds','maximumIntervalSeconds','strikeLimit','strikeDecayMinutes','cooldownMinutes','autoBlockDurationsHours','autoBanDurationsHours','autoWhitelist','privacy','reportSanity','clientPresence','incidentMail','scanPaths','requiredFiles','allowedFiles','blockedFiles','blockedPlugins','configFiles','configRules'];
      if (!knownFields.some(field => Object.prototype.hasOwnProperty.call(policy, field))) {
        throw new Error('Policy JSON does not look like a ModSec policy. Nothing was imported.');
      }

      for (const field of ['scanPaths','requiredFiles','allowedFiles','blockedFiles','blockedPlugins','configFiles','configRules']) {
        if (policy[field] != null && !Array.isArray(policy[field])) {
          throw new Error(`${field} must be an array.`);
        }
      }
    }
    function findPrivatePolicyFields(parsed, packageData) {
      const fields = [];
      if (parsed.dashboard) fields.push('dashboard');
      if (parsed.adminToken) fields.push('adminToken');
      if (parsed.serverTimeZoneId) fields.push('serverTimeZoneId');
      if (packageData.policy?.dashboard) fields.push('policy.dashboard');
      if (packageData.policy?.adminToken) fields.push('policy.adminToken');
      if (packageData.policy?.serverTimeZoneId) fields.push('policy.serverTimeZoneId');
      return [...new Set(fields)];
    }
    function buildPolicyImportPreview(packageData, merge) {
      const counts = countPolicyPackageRules(packageData.policy);
      const privateFields = packageData.__privateFields || [];
      delete packageData.__privateFields;
      const warning = merge
        ? 'This will merge rules into your current policy. Export a backup first if you may want to undo it.'
        : 'WARNING: This will overwrite your current shareable config/policy. Export a backup first if needed.';
      const countCards = [
        ['Mode', packageData.policy.mode || '(default)'],
        ['Scan paths', counts.scanPaths],
        ['Blocked plugins', counts.blockedPlugins],
        ['Blocked files', counts.blockedFiles],
        ['Allowed files', counts.allowedFiles],
        ['Required files', counts.requiredFiles],
        ['Config files', counts.configFiles],
        ['Config rules', counts.configRules],
        ['Gate routes', counts.gateRoutes]
      ].map(([label, value]) => `<div class="preview-card"><label>${escapeHtml(label)}</label><strong>${escapeHtml(value)}</strong></div>`).join('');
      const ignored = privateFields.length
        ? `<div class="preview-note preview-private"><strong>Ignored private/local fields</strong><br>${escapeHtml(privateFields.join(', '))}</div>`
        : '';
      return {
        html: `<div class="policy-preview">
          <div class="preview-warning"><strong>${escapeHtml(merge ? 'Merge policy' : 'Import policy')}</strong><br>${escapeHtml(warning)}</div>
          <dl class="preview-meta">
            <dt>Package</dt><dd>${escapeHtml(packageData.name || 'Imported Policy')}</dd>
            <dt>Created for</dt><dd>${escapeHtml(packageData.modSecVersion || 'Unknown ModSec version')}</dd>
            <dt>Notes</dt><dd>${escapeHtml(packageData.notes || 'No notes included.')}</dd>
          </dl>
          <div class="preview-grid">${countCards}</div>
          <div class="preview-note">Dashboard admin tokens and server timezone are never imported, merged, or overwritten.</div>
          ${ignored}
          <div class="preview-note">Continue with ${escapeHtml(merge ? 'merge' : 'import')}?</div>
        </div>`
      };
    }
    function countPolicyPackageRules(policy) {
      return {
        scanPaths: (policy.scanPaths || []).length,
        requiredFiles: (policy.requiredFiles || []).length,
        allowedFiles: (policy.allowedFiles || []).length,
        blockedFiles: (policy.blockedFiles || []).length,
        blockedPlugins: (policy.blockedPlugins || []).length,
        configFiles: (policy.configFiles || []).length,
        configRules: countConfigRules(policy),
        gateRoutes: (policy.clientPresence?.gateRoutes || []).length
      };
    }
    function setJsonField(id, value) {
      document.getElementById(id).value = JSON.stringify(value, null, 2);
    }
    function readJsonField(id, fallback) {
      const raw = document.getElementById(id).value.trim();
      if (!raw) return fallback;
      try {
        return JSON.parse(raw);
      } catch (error) {
        throw new Error(`${id} has invalid JSON: ${error.message}`);
      }
    }
    function safeJsonField(id, fallback) {
      try { return readJsonField(id, fallback); } catch { return fallback; }
    }
    function renderPolicyRuleReview() {
      renderFileRuleReview('allowedFilesReview', 'policyAllowedFiles', 'allowed');
      renderFileRuleReview('blockedFilesReview', 'policyBlockedFiles', 'blocked');
      renderPluginRuleReview();
      renderConfigRuleReview();
    }
    function renderFileRuleReview(targetId, fieldId, type) {
      const rules = safeJsonField(fieldId, []);
      const title = type === 'allowed' ? 'Allowed file hash' : 'Blocked file';
      const empty = type === 'allowed'
        ? 'No allowed file hashes yet.'
        : 'No blocked file rules yet.';
      const body = !rules.length
        ? `<div class="friendly-note" style="margin:12px;">${escapeHtml(empty)}</div>`
        : `<table class="rule-review-table">
            <colgroup><col style="width:24%"><col style="width:31%"><col style="width:21%"><col style="width:12%"><col style="width:12%"></colgroup>
            <thead><tr><th>Name</th><th>Match</th><th>Reason</th><th>Severity</th><th>Actions</th></tr></thead>
            <tbody>${rules.map((rule, index) => `
              <tr>
                <td>
                  <input value="${escapeAttr(rule.name || rule.id || title)}" onchange="updateRuleField('${fieldId}', ${index}, 'name', this.value)">
                  <div class="mini">${escapeHtml(rule.id || '(no id)')}</div>
                </td>
                <td>
                  <div class="mono">${escapeHtml(rule.hash ? `sha256:${shortHash(rule.hash)}` : rule.path || rule.glob || rule.name || '(metadata only)')}</div>
                  <div class="mini">${escapeHtml([rule.path ? `path ${rule.path}` : '', rule.glob ? `glob ${rule.glob}` : '', rule.hash ? rule.hash : ''].filter(Boolean).join(' | '))}</div>
                </td>
                <td><input value="${escapeAttr(rule.reason || '')}" onchange="updateRuleField('${fieldId}', ${index}, 'reason', this.value)"></td>
                <td>${severitySelect(rule.severity || (type === 'allowed' ? 'allow' : 'block'), `updateRuleField('${fieldId}', ${index}, 'severity', this.value)`, type === 'allowed')}</td>
                <td><div class="rule-review-actions"><button class="danger" onclick="removeRule('${fieldId}', ${index})">Remove</button></div></td>
              </tr>`).join('')}</tbody>
          </table>`;
      document.getElementById(targetId).innerHTML = body;
    }
    function renderPluginRuleReview() {
      const fieldId = 'policyBlockedPlugins';
      const rules = safeJsonField(fieldId, []);
      const body = !rules.length
        ? '<div class="friendly-note" style="margin:12px;">No blocked plugin GUID rules yet.</div>'
        : `<table class="rule-review-table">
            <colgroup><col style="width:22%"><col style="width:25%"><col style="width:25%"><col style="width:14%"><col style="width:14%"></colgroup>
            <thead><tr><th>Name</th><th>GUID</th><th>Reason</th><th>Severity</th><th>Actions</th></tr></thead>
            <tbody>${rules.map((rule, index) => `
              <tr>
                <td><input value="${escapeAttr(rule.name || rule.displayName || rule.guid || 'Blocked plugin')}" onchange="updateRuleField('${fieldId}', ${index}, 'name', this.value)"><div class="mini">${escapeHtml(rule.id || '(no id)')}</div></td>
                <td><input class="mono" value="${escapeAttr(rule.guid || '')}" onchange="updateRuleField('${fieldId}', ${index}, 'guid', this.value)"><div class="mini">Display: ${escapeHtml(rule.displayName || '(any)')}</div></td>
                <td><input value="${escapeAttr(rule.reason || '')}" onchange="updateRuleField('${fieldId}', ${index}, 'reason', this.value)"></td>
                <td>${severitySelect(rule.severity || 'block', `updateRuleField('${fieldId}', ${index}, 'severity', this.value)`)}</td>
                <td><div class="rule-review-actions"><button class="danger" onclick="removeRule('${fieldId}', ${index})">Remove</button></div></td>
              </tr>`).join('')}</tbody>
          </table>`;
      document.getElementById('blockedPluginsReview').innerHTML = body;
    }
    function renderConfigRuleReview() {
      const fieldId = 'policyConfigRules';
      const value = safeJsonField(fieldId, []);
      const rows = flattenConfigRuleEditorValue(value);
      const body = !rows.length
        ? '<div class="friendly-note" style="margin:12px;">No config rules yet.</div>'
        : `<table class="rule-review-table">
            <colgroup><col style="width:25%"><col style="width:25%"><col style="width:18%"><col style="width:18%"><col style="width:14%"></colgroup>
            <thead><tr><th>Setting</th><th>File</th><th>Allowed / Blocked</th><th>Severity</th><th>Actions</th></tr></thead>
            <tbody>${rows.map(row => {
              const rule = row.rule;
              return `<tr>
                <td>
                  <input value="${escapeAttr(rule.name || rule.id || rule.key || rule.jsonPath || 'Config rule')}" onchange="updateConfigRuleField('${row.key}', 'name', this.value)">
                  <div class="mini">${escapeHtml([rule.section ? `[${rule.section}]` : '', rule.key || rule.jsonPath || '', rule.operator || 'equals'].filter(Boolean).join(' '))}</div>
                </td>
                <td><div class="mono">${escapeHtml(row.path || rule.path || '(no path)')}</div><div class="mini">${escapeHtml(rule.format || row.format || 'bepinex')}</div></td>
                <td>
                  <input value="${escapeAttr(configRuleValuesText(rule))}" onchange="updateConfigRuleValues('${row.key}', this.value)">
                  <div class="mini">${escapeHtml(configRuleExpectationLabel(rule))}</div>
                </td>
                <td>${severitySelect(rule.severity || 'block', `updateConfigRuleField('${row.key}', 'severity', this.value)`)}</td>
                <td><div class="rule-review-actions"><button class="danger" onclick="removeConfigRule('${row.key}')">Remove</button></div></td>
              </tr>`;
            }).join('')}</tbody>
          </table>`;
      document.getElementById('configRulesReview').innerHTML = body;
    }
    function severitySelect(value, onchange, allowMode = false) {
      const options = allowMode ? ['allow', 'audit', 'warn', 'block'] : ['block', 'warn', 'audit', 'strike'];
      return `<select onchange="${escapeAttr(onchange)}">${options.map(option => `<option value="${option}" ${String(value).toLowerCase() === option ? 'selected' : ''}>${option}</option>`).join('')}</select>`;
    }
    function shortHash(hash) {
      const text = String(hash || '');
      return text.length > 18 ? `${text.slice(0, 12)}...${text.slice(-6)}` : text;
    }
    function updateRuleField(fieldId, index, key, value) {
      const rules = safeJsonField(fieldId, []);
      if (!rules[index]) return;
      rules[index][key] = value;
      setJsonField(fieldId, rules);
      renderPolicyRuleReview();
      markPolicyDirty();
    }
    function removeRule(fieldId, index) {
      const rules = safeJsonField(fieldId, []);
      rules.splice(index, 1);
      setJsonField(fieldId, rules);
      renderPolicyRuleReview();
      markPolicyDirty('Removed rule from editor. Click Save Policy to persist.');
    }
    function flattenConfigRuleEditorValue(value) {
      const rows = [];
      (value || []).forEach((item, fileIndex) => {
        if (Array.isArray(item.rules)) {
          (item.rules || []).forEach((rule, ruleIndex) => rows.push({
            key: `group:${fileIndex}:${ruleIndex}`,
            path: item.path || rule.path || '',
            format: item.format || rule.format || 'bepinex',
            rule
          }));
        } else {
          rows.push({ key: `flat:${fileIndex}`, path: item.path || '', format: item.format || 'bepinex', rule: item });
        }
      });
      return rows;
    }
    function mutateConfigRule(rowKey, mutator) {
      const value = safeJsonField('policyConfigRules', []);
      const [kind, first, second] = rowKey.split(':');
      if (kind === 'group') {
        const file = value[Number(first)];
        const rule = file?.rules?.[Number(second)];
        if (!rule) return;
        mutator(rule, file, value);
      } else {
        const rule = value[Number(first)];
        if (!rule) return;
        mutator(rule, null, value);
      }
      setJsonField('policyConfigRules', value);
      renderPolicyRuleReview();
      markPolicyDirty();
    }
    function updateConfigRuleField(rowKey, key, value) {
      mutateConfigRule(rowKey, rule => { rule[key] = value; });
    }
    function updateConfigRuleValues(rowKey, text) {
      mutateConfigRule(rowKey, rule => {
        const values = String(text || '').split(',').map(value => value.trim()).filter(value => value.length || value === '');
        if ((rule.operator || '').toLowerCase().includes('range')) {
          const match = String(text || '').match(/(-?\d+(?:\.\d+)?)\s*(?:-|to|,)\s*(-?\d+(?:\.\d+)?)/i);
          rule.minValue = match ? Number(match[1]) : rule.minValue ?? null;
          rule.maxValue = match ? Number(match[2]) : rule.maxValue ?? null;
          return;
        }

        if ((rule.operator || '').toLowerCase() === 'notin') {
          rule.blockedValues = values;
        } else {
          rule.allowedValues = values;
        }
      });
    }
    function removeConfigRule(rowKey) {
      const value = safeJsonField('policyConfigRules', []);
      const [kind, first, second] = rowKey.split(':');
      if (kind === 'group') {
        const file = value[Number(first)];
        if (file?.rules) {
          file.rules.splice(Number(second), 1);
          if (!file.rules.length) value.splice(Number(first), 1);
        }
      } else {
        value.splice(Number(first), 1);
      }
      setJsonField('policyConfigRules', value);
      renderPolicyRuleReview();
      markPolicyDirty('Removed config rule from editor. Click Save Policy to persist.');
    }
    function configRuleValuesText(rule) {
      const op = String(rule.operator || '').toLowerCase();
      if (op.includes('range')) return [rule.minValue, rule.maxValue].filter(value => value !== null && value !== undefined).join('-');
      if (op === 'notin') return (rule.blockedValues || []).join(',');
      return (rule.allowedValues || (rule.allowedValue !== undefined && rule.allowedValue !== null ? [rule.allowedValue] : [])).join(',');
    }
    function configRuleExpectationLabel(rule) {
      const op = rule.operator || 'equals';
      if (String(op).toLowerCase().includes('range')) return `${op}: ${rule.minValue ?? '?'}-${rule.maxValue ?? '?'}`;
      if (String(op).toLowerCase() === 'notin') return `blocked: ${(rule.blockedValues || []).join(', ') || '(empty)'}`;
      return `allowed: ${(rule.allowedValues || []).join(', ') || rule.allowedValue || '(empty)'}`;
    }
    function readInt(id, fallback) {
      const value = Number(document.getElementById(id).value);
      return Number.isFinite(value) ? value : fallback;
    }
    async function addHashBlock(path, hash) {
      stageInventoryHashRule('blocked', path, hash);
    }
    function findInventoryFile(path) {
      const normalized = normalizePath(path);
      return (activeInventory?.files || []).find(file => normalizePath(file.path) === normalized);
    }
    function normalizePath(path) {
      return String(path || '').replace(/\\/g, '/').replace(/^\/+/, '');
    }
    function stagePluginBlock(guid, name) {
      queuePendingPolicyChange({
        type: 'blockedPlugin',
        label: 'Block GUID',
        summary: `${name || guid} (${guid})`,
        key: `blockedPlugin:${String(guid || '').toLowerCase()}`,
        rule: {
          id: `block-plugin-${slugify(guid || name)}`,
          name: name || guid || 'Blocked plugin',
          guid,
          displayName: name || '',
          reason: `${name || guid} is not allowed on this server.`,
          severity: 'block'
        }
      });
    }
    function stageInventoryHashRule(target, path, hash) {
      const allowed = target === 'allowed';
      queuePendingPolicyChange({
        type: allowed ? 'allowedFile' : 'blockedFile',
        label: allowed ? 'Allow Hash' : 'Block Hash',
        summary: `${path} (${String(hash || '').slice(0, 12)})`,
        key: `${allowed ? 'allowedFile' : 'blockedFile'}:${String(hash || '').toLowerCase()}`,
        rule: {
          id: `${allowed ? 'allow-hash' : 'block-hash'}-${String(hash || '').slice(0, 12)}`,
          name: path.split('/').pop() || `${target} hash`,
          path: '',
          glob: '',
          hash,
          reason: allowed
            ? `${path} hash is allowed on this server.`
            : `${path} hash is not allowed on this server.`,
          severity: allowed ? 'audit' : 'block'
        }
      });
    }
    function queuePendingPolicyChange(change) {
      if (pendingPolicyChanges.some(existing => existing.key === change.key)) {
        setStatus(`${change.label} is already staged.`);
        return;
      }

      pendingPolicyChanges.push(change);
      renderPendingPolicyChanges();
      setStatus(`Staged ${change.label}: ${change.summary}`);
    }
    function renderPendingPolicyChanges() {
      const tray = document.getElementById('pendingTray');
      const list = document.getElementById('pendingPolicyChanges');
      tray.style.display = pendingPolicyChanges.length ? 'block' : 'none';
      if (!pendingPolicyChanges.length) {
        list.innerHTML = '';
        return;
      }

      list.innerHTML = pendingPolicyChanges.map((change, index) => `
        <div class="pending-item">
          <span class="pill ${change.type === 'blockedPlugin' || change.type === 'blockedFile' ? 'bad' : ''}">${escapeHtml(change.label)}</span>
          <div class="detail">${escapeHtml(change.summary)}</div>
          <button class="secondary" onclick="removePendingPolicyChange(${index})">Remove</button>
        </div>`).join('');
    }
    function removePendingPolicyChange(index) {
      pendingPolicyChanges.splice(index, 1);
      renderPendingPolicyChanges();
    }
    function discardPendingPolicyChanges() {
      pendingPolicyChanges = [];
      renderPendingPolicyChanges();
      setStatus('Discarded staged policy changes.');
    }
    async function applyPendingPolicyChanges() {
      try {
        if (!pendingPolicyChanges.length) {
          setStatus('No staged policy changes to apply.');
          return;
        }

        if (!editablePolicy) await loadEditablePolicy();
        const blockedPlugins = readJsonField('policyBlockedPlugins', []);
        const blockedFiles = readJsonField('policyBlockedFiles', []);
        const allowedFiles = readJsonField('policyAllowedFiles', []);
        const configRules = readJsonField('policyConfigRules', []);

        for (const change of pendingPolicyChanges) {
          if (change.type === 'blockedPlugin' && !blockedPlugins.some(rule => String(rule.guid || '').toLowerCase() === String(change.rule.guid || '').toLowerCase())) {
            blockedPlugins.push(change.rule);
          } else if (change.type === 'blockedFile' && !blockedFiles.some(rule => String(rule.hash || '').toLowerCase() === String(change.rule.hash || '').toLowerCase())) {
            blockedFiles.push(normalizeHashRule(change.rule));
          } else if (change.type === 'allowedFile' && !allowedFiles.some(rule => String(rule.hash || '').toLowerCase() === String(change.rule.hash || '').toLowerCase())) {
            allowedFiles.push(normalizeHashRule(change.rule));
          } else if (change.type === 'configRule') {
            mergeConfigRule(configRules, change.rule);
          }
        }

        setJsonField('policyBlockedPlugins', blockedPlugins);
        setJsonField('policyBlockedFiles', blockedFiles);
        setJsonField('policyAllowedFiles', allowedFiles);
        setJsonField('policyConfigRules', configRules);
        renderPolicyRuleReview();
        document.getElementById('policyEditor').style.display = 'block';
        const count = pendingPolicyChanges.length;
        pendingPolicyChanges = [];
        renderPendingPolicyChanges();
        markPolicyDirty(`Applied ${count} staged change(s) to the policy editor. Click Save Policy to write them.`);
      } catch (error) { setStatus(error.message); }
    }
    function slugify(value) {
      return String(value || 'rule').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48) || 'rule';
    }
    function normalizeHashRule(rule) {
      if (!rule || !rule.hash) return rule;
      return Object.assign({}, rule, { path: '', glob: '' });
    }
    function handleRuleDropOver(event) {
      event.preventDefault();
      document.getElementById('modDropZone')?.classList.add('dragging');
    }
    function handleRuleDropLeave(event) {
      event.preventDefault();
      document.getElementById('modDropZone')?.classList.remove('dragging');
    }
    async function handleRuleDrop(event) {
      event.preventDefault();
      document.getElementById('modDropZone')?.classList.remove('dragging');
      try {
        const files = await getDroppedFiles(event.dataTransfer);
        await stageDraggedFiles(files);
      } catch (error) { setStatus(error.message); }
    }
    async function handleRuleFilePick(event) {
      try {
        await stageDraggedFiles(Array.from(event.target.files || []));
        event.target.value = '';
      } catch (error) { setStatus(error.message); }
    }
    async function getDroppedFiles(dataTransfer) {
      const items = Array.from(dataTransfer?.items || []);
      if (!items.length) return Array.from(dataTransfer?.files || []);
      const files = [];
      for (const item of items) {
        const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
        if (entry) {
          files.push(...await readEntryFiles(entry));
        } else if (item.kind === 'file') {
          const file = item.getAsFile();
          if (file) files.push(file);
        }
      }
      return files;
    }
    async function readEntryFiles(entry, prefix) {
      if (!entry) return [];
      if (entry.isFile) {
        return [await new Promise((resolve, reject) => entry.file(file => {
          file.modSecRelativePath = `${prefix || ''}${file.name}`;
          resolve(file);
        }, reject))];
      }
      if (!entry.isDirectory) return [];
      const reader = entry.createReader();
      const files = [];
      let batch = [];
      do {
        batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
        for (const child of batch) {
          files.push(...await readEntryFiles(child, `${prefix || ''}${entry.name}/`));
        }
      } while (batch.length);
      return files;
    }
    async function stageDraggedFiles(files) {
      if (!files.length) {
        setStatus('No files were found in that drop.');
        return;
      }
      const extensions = document.getElementById('dropRuleExtensions').value
        .split(',')
        .map(value => value.trim().toLowerCase())
        .filter(Boolean);
      const target = document.getElementById('dropRuleTarget').value;
      const severity = document.getElementById('dropRuleSeverity').value || 'block';
      const reason = document.getElementById('dropRuleReason').value || 'Managed by ModSec dashboard.';
      let staged = 0;
      for (const file of files) {
        const buffer = await file.arrayBuffer();
        if (!shouldStageDroppedFile(file, buffer, extensions)) {
          continue;
        }

        const hash = await sha256Buffer(buffer);
        const rawPath = file.modSecRelativePath || file.webkitRelativePath || file.name;
        const path = normalizePolicyPath(rawPath);
        const name = file.name || path.split('/').pop() || 'mod-file';
        const rule = {
          id: `${target}-${slugify(name)}-${hash.slice(0, 8)}`,
          name,
          path: '',
          glob: '',
          hash,
          reason: `${reason} Observed path: ${path}`,
          severity: target === 'allowed' ? 'allow' : severity
        };
        queuePendingPolicyChange({
          type: target === 'allowed' ? 'allowedFile' : 'blockedFile',
          key: `${target}:${hash}`,
          label: target === 'allowed' ? 'Allow Hash' : 'Block Hash',
          summary: `${name} (${hash.slice(0, 12)}...)`,
          rule
        });
        staged++;
      }
      document.getElementById('dropRuleStatus').textContent = `Staged ${staged} of ${files.length} file(s).`;
    }
    function shouldStageDroppedFile(file, buffer, extensions) {
      const name = String(file.name || '').toLowerCase();
      const extensionMatch = !extensions.length || extensions.some(ext => name.endsWith(ext.startsWith('.') ? ext : `.${ext}`));
      return extensionMatch || isManagedAssemblyBuffer(buffer);
    }
    function isManagedAssemblyBuffer(buffer) {
      try {
        const view = new DataView(buffer);
        if (view.byteLength < 0x100 || view.getUint16(0, true) !== 0x5A4D) return false;
        const peOffset = view.getInt32(0x3C, true);
        if (peOffset <= 0 || peOffset > view.byteLength - 0x108) return false;
        if (view.getUint32(peOffset, true) !== 0x00004550) return false;
        const optionalHeaderStart = peOffset + 24;
        const magic = view.getUint16(optionalHeaderStart, true);
        const dataDirectoryStart = magic === 0x10B
          ? optionalHeaderStart + 96
          : magic === 0x20B
            ? optionalHeaderStart + 112
            : -1;
        if (dataDirectoryStart < 0 || dataDirectoryStart + 14 * 8 + 8 > view.byteLength) return false;
        const cliHeaderRva = view.getUint32(dataDirectoryStart + 14 * 8, true);
        const cliHeaderSize = view.getUint32(dataDirectoryStart + 14 * 8 + 4, true);
        return cliHeaderRva !== 0 && cliHeaderSize !== 0;
      } catch {
        return false;
      }
    }
    async function sha256Buffer(buffer) {
      const hash = await crypto.subtle.digest('SHA-256', buffer);
      return Array.from(new Uint8Array(hash)).map(byte => byte.toString(16).padStart(2, '0')).join('');
    }
    function normalizePolicyPath(path) {
      return String(path || '').replace(/\\/g, '/').replace(/^\/+/, '');
    }
    function stageConfigRuleFromBuilder() {
      try {
        const path = normalizePolicyPath(document.getElementById('configRuleFile').value);
        const format = document.getElementById('configRuleFormat').value || 'bepinex';
        const section = document.getElementById('configRuleSection').value.trim();
        const keyOrJson = document.getElementById('configRuleKey').value.trim();
        const operator = document.getElementById('configRuleOperator').value || 'in';
        if (!path || !keyOrJson) throw new Error('Config path and key/json path are required.');
        const name = document.getElementById('configRuleName').value.trim() || defaultConfigRuleName(path, keyOrJson);
        const rule = {
          id: configRuleId(path, section, keyOrJson, operator),
          name,
          path,
          format,
          section: format === 'json' ? '' : section,
          key: format === 'json' ? '' : keyOrJson,
          jsonPath: format === 'json' ? keyOrJson : '',
          operator,
          required: false,
          severity: document.getElementById('configRuleSeverity').value || 'block'
        };
        if (operator === 'in') {
          rule.allowedValues = parseRuleValues(document.getElementById('configRuleValues').value);
        } else if (operator === 'notin') {
          rule.blockedValues = parseRuleValues(document.getElementById('configRuleValues').value);
        } else if (operator === 'range' || operator === 'notrange') {
          const range = parseRuleRange(document.getElementById('configRuleRange').value);
          rule.minValue = range.min;
          rule.maxValue = range.max;
        } else if (operator === 'exists') {
          rule.required = true;
        }
        queuePendingPolicyChange({
          type: 'configRule',
          key: `config:${rule.id}:${Date.now()}:${pendingPolicyChanges.length}`,
          label: 'Config Rule',
          summary: `${name} (${operator})`,
          rule
        });
      } catch (error) { setStatus(error.message); }
    }
    function defaultConfigRuleName(path, keyOrJson) {
      const fileName = normalizePolicyPath(path).split('/').pop() || 'config';
      const stem = fileName.replace(/\.(cfg|json)$/i, '');
      const modName = (stem.split('.').filter(Boolean).pop() || stem || 'config')
        .replace(/[^a-z0-9]+/gi, '');
      const settingName = String(keyOrJson || 'setting')
        .split(' - ')[0]
        .split('.')[0]
        .replace(/[^a-z0-9]+/gi, '');
      return `${modName || 'config'}.${settingName || 'setting'}`;
    }
    function configRuleId(path, section, keyOrJson, operator) {
      const readable = slugify(`${defaultConfigRuleName(path, keyOrJson)}-${section}-${operator}`);
      return `${readable}-${shortTextHash([path, section, keyOrJson, operator].join('|'))}`;
    }
    function shortTextHash(value) {
      let hash = 2166136261;
      for (let index = 0; index < value.length; index++) {
        hash ^= value.charCodeAt(index);
        hash = Math.imul(hash, 16777619);
      }
      return (hash >>> 0).toString(16).padStart(8, '0');
    }
    function parseRuleValues(value) {
      return String(value || '')
        .split(',')
        .map(item => parseRuleScalar(item.trim()))
        .filter(item => item !== '');
    }
    function parseRuleScalar(value) {
      if (value === '') return '';
      if (value.toLowerCase() === 'true') return true;
      if (value.toLowerCase() === 'false') return false;
      if (value.toLowerCase() === 'null') return null;
      if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value);
      return value;
    }
    function parseRuleRange(value) {
      const match = String(value || '').match(/^\s*(-?\d+(?:\.\d+)?)\s*(?:-|,|to)\s*(-?\d+(?:\.\d+)?)\s*$/i);
      if (!match) throw new Error('Range must look like 30-50.');
      return { min: Number(match[1]), max: Number(match[2]) };
    }
    function mergeConfigRule(configRules, rule) {
      const existingFile = configRules.find(item => Array.isArray(item.rules) && String(item.path || '').toLowerCase() === String(rule.path || '').toLowerCase());
      if (existingFile) {
        if (!existingFile.rules.some(existing => sameConfigRuleTarget(existing, rule, existingFile.path))) {
          existingFile.rules.push(rule);
        }
        return;
      }
      if (configRules.some(existing => !Array.isArray(existing.rules) && sameConfigRuleTarget(existing, rule, ''))) return;
      configRules.push(rule);
    }
    function sameConfigRuleTarget(existing, incoming, fallbackPath) {
      return configRuleTargetKey(existing, fallbackPath) === configRuleTargetKey(incoming, '');
    }
    function configRuleTargetKey(rule, fallbackPath) {
      return [
        normalizePolicyPath(rule.path || fallbackPath).toLowerCase(),
        String(rule.format || 'bepinex').toLowerCase(),
        String(rule.section || '').trim().toLowerCase(),
        String(rule.key || '').trim().toLowerCase(),
        String(rule.jsonPath || '').trim().toLowerCase(),
        String(rule.operator || 'in').trim().toLowerCase()
      ].join('|');
    }
    async function reloadConfig() {
      try {
        await api('/modsec/admin/reload', { method: 'POST', body: '{}' });
        setStatus('Config reloaded.');
        await Promise.all([loadDiagnostics(), loadPolicy(), loadEditablePolicy(), loadEvents()]);
      } catch (error) { setStatus(error.message); }
    }
    async function sendPopup() {
      try {
        const payload = {
          targetProfileId: document.getElementById('popupTarget').value,
          title: document.getElementById('title').value,
          message: document.getElementById('message').value,
          kind: document.getElementById('kind').value,
          position: 'topRight',
          severity: document.getElementById('severity').value,
          durationSeconds: Number(document.getElementById('duration').value || 6),
          blocking: document.getElementById('requiresQuit').value === 'true',
          requiresQuit: document.getElementById('requiresQuit').value === 'true'
        };
        await api('/modsec/admin/popup', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
        setStatus('Popup queued.');
      } catch (error) { setStatus(error.message); }
    }
    async function ban(profileId) {
      const player = playerCache.find(p => p.profileId === profileId);
      openDashboardModal({
        title: 'Apply Server Lockout',
        bodyHtml: `<div class="modal-form"><div class="hint">Restricts raid access for ${escapeHtml(player?.playerName || profileId)} on this host only.</div>${modalTextarea('banReason', 'Reason', 'Restricted by ModSec admin dashboard.')}${modalInput('banMinutes', 'Minutes (0 = permanent)', '1440', 'type="number" min="0"')}</div>`,
        confirmText: 'Apply Lockout',
        danger: true,
        onConfirm: async () => {
          const reason = document.getElementById('banReason').value || 'Restricted by ModSec admin dashboard.';
          const minutes = Number(document.getElementById('banMinutes').value || '0');
          await api('/modsec/admin/ban', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ profileId, reason, minutes }) });
          await loadAll();
        }
      });
    }
    async function unban(profileId) {
      const player = playerCache.find(p => p.profileId === profileId);
      openDashboardModal({
        title: 'Clear Server Lockout',
        bodyHtml: `<div class="modal-pre">Clear the current server lockout for ${escapeHtml(player?.playerName || profileId)}?</div>`,
        confirmText: 'Clear Lockout',
        onConfirm: async () => {
          await api('/modsec/admin/unban', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ profileId }) });
          await loadAll();
        }
      });
    }
    async function pardon(profileId) {
      const player = playerCache.find(p => p.profileId === profileId);
      openDashboardModal({
        title: 'Clear Local Strikes',
        bodyHtml: `<div class="modal-pre">Clear strikes, risk, and strike protection cooldown for ${escapeHtml(player?.playerName || profileId)}?</div>`,
        confirmText: 'Pardon',
        onConfirm: async () => {
          await api('/modsec/admin/pardon', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ profileId }) });
          await loadAll();
        }
      });
    }
    function filterPlayers(players) {
      const search = document.getElementById('playerSearch')?.value.trim().toLowerCase() || '';
      const status = document.getElementById('playerStatusFilter')?.value || 'all';
      return players.filter(p => {
        if (status !== 'all' && !matchesPlayerStatus(p, status)) return false;
        if (!search) return true;
        return getPlayerSearchText(p).includes(search);
      });
    }
    function matchesPlayerStatus(p, status) {
      const banned = p.bannedUntilUtc && new Date(p.bannedUntilUtc) > new Date();
      if (status === 'banned') return Boolean(banned);
      if (status === 'strikes') return (p.strikes || 0) > 0;
      if (status === 'risk') return (p.riskScore || 0) >= 20;
      return String(p.complianceStatus || '').toLowerCase() === status;
    }
    function getPlayerSearchText(p) {
      return [
        p.playerName, p.installId, p.profileId, p.lastKnownIp, p.complianceStatus, p.timeZoneId,
        ...(p.recentViolations || []).flatMap(v => [v.ruleId, v.reason, v.path, v.severity])
      ].filter(Boolean).join(' ').toLowerCase();
    }
    function playerIdentityTooltip(p) {
      return [`SPT profile: ${p.playerName || '(unknown)'}`, `Profile ID: ${p.profileId || ''}`, p.installId ? `ModSec Install ID: ${p.installId}` : '']
        .filter(Boolean)
        .join('\n');
    }
    function populateEventTypeFilter(events) {
      const select = document.getElementById('eventTypeFilter');
      const current = select.value || 'all';
      const types = [...new Set(events.map(e => e.type).filter(Boolean).sort())];
      select.innerHTML = '<option value="all">All types</option>' + types.map(type => `<option value="${escapeAttr(type)}">${escapeHtml(type)}</option>`).join('');
      select.value = types.includes(current) ? current : 'all';
    }
    function filterEvents(events) {
      const search = document.getElementById('eventSearch')?.value.trim().toLowerCase() || '';
      const type = document.getElementById('eventTypeFilter')?.value || 'all';
      const severity = document.getElementById('eventSeverityFilter')?.value || 'all';
      return events.filter(e => {
        if (type !== 'all' && String(e.type || '') !== type) return false;
        if (severity !== 'all' && String(e.severity || '').toLowerCase() !== severity) return false;
        if (!search) return true;
        return getEventSearchText(e).includes(search);
      });
    }
    function getEventSearchText(e) {
      return [
        e.type, e.severity, e.playerName, e.profileId, e.message,
        ...(e.violations || []).flatMap(v => [v.ruleId, v.reason, v.path, v.severity])
      ].filter(Boolean).join(' ').toLowerCase();
    }
    function applyTemplateDefaults() {
      const kind = document.getElementById('kind').value;
      const severity = document.getElementById('severity');
      const requiresQuit = document.getElementById('requiresQuit');
      const duration = document.getElementById('duration');
      if (kind === 'toast') {
        severity.value = 'info';
        requiresQuit.value = 'false';
        duration.value = '6';
        document.getElementById('title').value = 'Server Notification';
      } else if (kind === 'information' || kind === 'dialog') {
        severity.value = 'info';
        requiresQuit.value = 'false';
        document.getElementById('title').value = kind === 'information' ? 'Server Notice' : 'Server Message';
      } else if (kind === 'warning') {
        severity.value = 'warning';
        requiresQuit.value = 'false';
        document.getElementById('title').value = 'Server Warning';
      } else if (kind === 'kick' || kind === 'ban') {
        severity.value = 'block';
        requiresQuit.value = 'true';
        document.getElementById('title').value = kind === 'ban' ? 'Server Lockout' : 'Raid Access Notice';
      }
    }
    function escapeHtml(value) {
      return String(value).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
    }
    function escapeAttr(value) { return escapeHtml(value).replace(/`/g, '&#96;'); }
    function formatDate(value) {
      if (!value) return '';
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
    }
    function formatBytes(value) {
      if (value < 1024) return `${value} B`;
      if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
      return `${(value / 1024 / 1024).toFixed(1)} MB`;
    }
    function countConfigRules(policy) {
      const flat = (policy.configRules || []).length;
      const grouped = (policy.configFiles || []).reduce((total, file) => total + (file.rules || []).length, 0);
      return flat + grouped;
    }
    function playerStatus(p) {
      const banned = p.bannedUntilUtc && new Date(p.bannedUntilUtc) > new Date();
      const protectedUntil = p.cooldownUntilUtc && new Date(p.cooldownUntilUtc) > new Date();
      const lines = [];
      lines.push(`<span class="pill ${banned ? 'bad' : p.strikes > 0 ? 'warn' : ''}">${banned ? 'LOCKED OUT' : `${p.strikes || 0} strike(s)`}</span>`);
      if (p.complianceStatus) lines.push(`<span class="subtle">Client: ${escapeHtml(p.complianceStatus)}</span>`);
      if (p.missingClientAttempts) lines.push(`<span class="subtle">Missing-client attempts: ${p.missingClientAttempts}</span>`);
      if (banned) lines.push(`<span class="subtle">Until ${escapeHtml(formatDate(p.bannedUntilUtc))}</span>`);
      if (protectedUntil) lines.push(`<span class="subtle">Protected until ${escapeHtml(formatDate(p.cooldownUntilUtc))}</span>`);
      if (p.banCount) lines.push(`<span class="subtle">Lockouts: ${p.banCount}</span>`);
      return `<div class="cell-stack">${lines.join('')}</div>`;
    }
    function renderViolations(violations) {
      if (!violations.length) return '<span class="muted">None</span>';
      return `<div class="violation-list">${violations.slice(0, 4).map(v => `<div class="violation-item"><span class="pill ${String(v.severity || '').toLowerCase() === 'block' ? 'bad' : 'warn'}">${escapeHtml(v.severity || '')}</span><div class="detail">${escapeHtml(v.reason || '')}</div><div class="mono">${escapeHtml(v.path || v.ruleId || '')}</div></div>`).join('')}</div>`;
    }
    function eventPill(e) {
      const sev = (e.severity || '').toLowerCase();
      return `<span class="pill ${sev === 'block' ? 'bad' : sev === 'warning' ? 'warn' : ''}">${escapeHtml(e.type || 'event')}</span>`;
    }
    function initializePolicyJsonSync() {
      ['policyBlockedPlugins', 'policyBlockedFiles', 'policyAllowedFiles', 'policyConfigRules'].forEach(id => {
        const field = document.getElementById(id);
        if (field) field.addEventListener('change', renderPolicyRuleReview);
      });
    }
    function initializePolicyDirtyTracking() {
      const editor = document.getElementById('policyEditor');
      if (!editor) return;
      editor.addEventListener('input', event => {
        if (event.target?.matches?.('input, textarea, select')) markPolicyDirty();
      });
      editor.addEventListener('change', event => {
        if (event.target?.matches?.('input, textarea, select')) markPolicyDirty();
      });
    }
    initializeTokenMask();
    initializePolicyJsonSync();
    initializePolicyDirtyTracking();
    if (adminSession && (!adminSessionExpiresAt || new Date(adminSessionExpiresAt) > new Date())) {
      setAuthenticated(true);
      loadAll();
    } else {
      sessionStorage.removeItem('modsecAdminSession');
      sessionStorage.removeItem('modsecAdminSessionExpiresAt');
      setStatus('Enter the dashboard token to view ModSec data.');
    }
  </script>
</body>
</html>
""";
}
