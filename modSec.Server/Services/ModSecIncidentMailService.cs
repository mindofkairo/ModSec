using System.Text;
using ModSec.Server.Models;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Models.Eft.Profile;
using SPTarkov.Server.Core.Models.Enums;
using SPTarkov.Server.Core.Servers;
using SPTarkov.Server.Core.Utils;

namespace ModSec.Server.Services;

[Injectable(InjectionType.Singleton)]
public class ModSecIncidentMailService(SaveServer saveServer, TimeUtil timeUtil)
{
    private static readonly MongoId SenderId = new("66f0000000000000000d5ec1");
    private readonly Dictionary<string, DateTime> _lastSentBySignature = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public void BroadcastPolicyIncident(PlayerState state, string status, bool strikeApplied, ModSecConfig config, List<Violation> violations)
    {
        if (!config.IncidentMail.Enabled || !config.IncidentMail.IncludePolicyViolations || violations.Count == 0)
        {
            return;
        }

        var signature = $"policy:{state.ProfileId}:{GetViolationSignature(violations)}:{status}";
        if (!ShouldSend(signature, config.IncidentMail.CooldownSeconds))
        {
            return;
        }

        var message = BuildPolicyIncidentMessage(state, status, strikeApplied, config, violations);
        Broadcast(config, message);
    }

    public void BroadcastAutomaticBan(PlayerState state, ModSecConfig config, List<Violation> violations)
    {
        if (!config.IncidentMail.Enabled || !config.IncidentMail.IncludeAutomaticBans)
        {
            return;
        }

        var signature = $"ban:{state.ProfileId}:{state.BanCount}";
        if (!ShouldSend(signature, config.IncidentMail.CooldownSeconds))
        {
            return;
        }

        var message = BuildAutomaticBanMessage(state, config, violations);
        Broadcast(config, message);
    }

    public void BroadcastMissingClientBlock(PlayerState state, string route, ModSecConfig config)
    {
        if (!config.IncidentMail.Enabled || !config.IncidentMail.IncludeMissingClientBlocks)
        {
            return;
        }

        var signature = $"missing-client:{state.ProfileId}:{route}";
        if (!ShouldSend(signature, config.IncidentMail.CooldownSeconds))
        {
            return;
        }

        var message = RenderTemplate(
            ResolveTemplate(
                config.IncidentMail.Templates.MissingClientLines,
                config.IncidentMail.Templates.MissingClient,
                DefaultMissingClientLines()),
            BuildTemplateValues(state, config, route: route));

        Broadcast(config, message);
    }

    private static string BuildPolicyIncidentMessage(PlayerState state, string status, bool strikeApplied, ModSecConfig config, List<Violation> violations)
    {
        return RenderTemplate(
            ResolveTemplate(
                config.IncidentMail.Templates.PolicyViolationLines,
                config.IncidentMail.Templates.PolicyViolation,
                DefaultPolicyViolationLines()),
            BuildTemplateValues(state, config, status, strikeApplied, violations));
    }

    private static string BuildAutomaticBanMessage(PlayerState state, ModSecConfig config, List<Violation> violations)
    {
        return RenderTemplate(
            ResolveTemplate(
                config.IncidentMail.Templates.AutomaticBanLines,
                config.IncidentMail.Templates.AutomaticBan,
                DefaultAutomaticBanLines()),
            BuildTemplateValues(state, config, "banned", true, violations));
    }

    private static IEnumerable<string> DescribeViolations(List<Violation> violations, int maxViolations)
    {
        var listed = violations.Take(Math.Max(1, maxViolations)).ToList();
        foreach (var violation in listed)
        {
            if (!string.IsNullOrWhiteSpace(violation.Setting))
            {
                yield return $"- {violation.Setting}: current {QuoteOrUnknown(violation.ActualValue)}, allowed {QuoteOrUnknown(violation.ExpectedValue)}";
                if (!string.IsNullOrWhiteSpace(violation.Path))
                {
                    yield return $"  {violation.Path}";
                }

                continue;
            }

            yield return $"- {violation.Reason}";
            if (!string.IsNullOrWhiteSpace(violation.Path))
            {
                yield return $"  {violation.Path}";
            }
        }

        if (violations.Count > listed.Count)
        {
            yield return $"- plus {violations.Count - listed.Count} more item(s)";
        }
    }

    private void Broadcast(ModSecConfig config, string message)
    {
        var recipients = GetRecipients(config);
        var sender = BuildSender(config);
        var sent = 0;

        foreach (var recipient in recipients)
        {
            try
            {
                SendDialogueMessage(recipient, sender, message);
                sent++;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ModSec] Could not send incident mail to {recipient}: {ex.Message}");
            }
        }

        if (sent > 0)
        {
            Console.WriteLine($"[ModSec] Sent incident mail to {sent} profile(s).");
        }
    }

    private void SendDialogueMessage(MongoId recipientId, UserDialogInfo sender, string messageText)
    {
        if (!saveServer.ProfileExists(recipientId))
        {
            return;
        }

        var recipientProfile = saveServer.GetProfile(recipientId);
        if (recipientProfile?.ProfileInfo?.ProfileId == null)
        {
            return;
        }

        var recipientDetails = BuildRecipientDetails(recipientProfile);
        recipientProfile.DialogueRecords ??= [];

        if (!recipientProfile.DialogueRecords.ContainsKey(sender.Id))
        {
            recipientProfile.DialogueRecords.Add(sender.Id, new()
            {
                AttachmentsNew = 0,
                New = 0,
                Pinned = false,
                Type = MessageType.UserMessage,
                Messages = [],
                Users = [],
                Id = sender.Id
            });
        }

        var dialog = recipientProfile.DialogueRecords[sender.Id];
        dialog.New++;
        dialog.Type = MessageType.UserMessage;
        dialog.Users =
        [
            sender,
            recipientDetails
        ];

        dialog.Messages ??= [];
        dialog.Messages.Add(new Message
        {
            Id = new MongoId(),
            UserId = sender.Id,
            MessageType = MessageType.UserMessage,
            Member = new()
            {
                Nickname = sender.Info?.Nickname ?? "Hall of Shame",
                Side = sender.Info?.Side ?? "Usec",
                Level = sender.Info?.Level.HasValue == true ? Convert.ToInt32(sender.Info.Level.Value) : 1,
                MemberCategory = sender.Info?.MemberCategory ?? MemberCategory.Default,
                IsIgnored = false,
                IsBanned = false
            },
            DateTime = timeUtil.GetTimeStamp(),
            Text = messageText,
            RewardCollected = false
        });

        saveServer.SaveProfileAsync(recipientId).GetAwaiter().GetResult();
    }

    private static UserDialogInfo BuildRecipientDetails(SptProfile profile)
    {
        var profileId = profile.ProfileInfo?.ProfileId.GetValueOrDefault() ?? new MongoId();
        var info = profile.CharacterData?.PmcData?.Info;
        return new UserDialogInfo
        {
            Id = profileId,
            Aid = profile.ProfileInfo?.Aid ?? 0,
            Info = new()
            {
                Nickname = info?.Nickname ?? profileId.ToString(),
                Side = info?.Side ?? "Usec",
                Level = info?.Level ?? 1,
                MemberCategory = info?.MemberCategory ?? MemberCategory.Default,
                SelectedMemberCategory = info?.SelectedMemberCategory ?? MemberCategory.Default
            }
        };
    }

    private List<MongoId> GetRecipients(ModSecConfig config)
    {
        if (!config.IncidentMail.SendToAllProfiles)
        {
            return [];
        }

        try
        {
            return saveServer.GetProfiles()
                .Select(pair => pair.Key)
                .Distinct()
                .ToList();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ModSec] Could not enumerate profiles for incident mail: {ex.Message}");
            return [];
        }
    }

    private bool ShouldSend(string signature, int cooldownSeconds)
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            if (_lastSentBySignature.TryGetValue(signature, out var lastSent)
                && lastSent.AddSeconds(Math.Max(0, cooldownSeconds)) > now)
            {
                return false;
            }

            _lastSentBySignature[signature] = now;
            if (_lastSentBySignature.Count > 500)
            {
                foreach (var key in _lastSentBySignature
                             .Where(pair => pair.Value.AddHours(2) < now)
                             .Select(pair => pair.Key)
                             .ToList())
                {
                    _lastSentBySignature.Remove(key);
                }
            }

            return true;
        }
    }

    private static UserDialogInfo BuildSender(ModSecConfig config)
    {
        var senderName = string.IsNullOrWhiteSpace(config.IncidentMail.SenderName)
            ? "Hall of Shame"
            : config.IncidentMail.SenderName.Trim();

        return new UserDialogInfo
        {
            Id = SenderId,
            Aid = 56001337,
            Info = new()
            {
                Level = 1,
                MemberCategory = MemberCategory.Emissary,
                SelectedMemberCategory = MemberCategory.Emissary,
                Nickname = senderName,
                Side = "Usec"
            }
        };
    }

    private static string DisplayPlayerName(PlayerState state)
    {
        if (!string.IsNullOrWhiteSpace(state.PlayerName))
        {
            return $"{state.PlayerName} ({state.ProfileId})";
        }

        return state.ProfileId;
    }

    private static string QuoteOrUnknown(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? "unknown" : $"'{value}'";
    }

    private static string GetViolationSignature(List<Violation> violations)
    {
        return string.Join("|", violations
            .Select(violation => $"{violation.RuleId}:{violation.Path}:{violation.Setting}:{violation.ActualValue}")
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase));
    }

    private static Dictionary<string, string> BuildTemplateValues(
        PlayerState state,
        ModSecConfig config,
        string status = "",
        bool strikeApplied = false,
        List<Violation>? violations = null,
        string route = "")
    {
        violations ??= [];
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["player"] = DisplayPlayerName(state),
            ["playerName"] = string.IsNullOrWhiteSpace(state.PlayerName) ? state.ProfileId : state.PlayerName,
            ["profileId"] = state.ProfileId,
            ["installId"] = state.InstallId,
            ["status"] = status,
            ["action"] = status,
            ["strikeApplied"] = strikeApplied ? "yes" : "no",
            ["strikes"] = state.Strikes.ToString(),
            ["strikeLimit"] = config.StrikeLimit.ToString(),
            ["risk"] = state.RiskScore.ToString(),
            ["route"] = route,
            ["banReason"] = state.BanReason,
            ["unlockUtc"] = FormatUnlockUtc(state.BannedUntilUtc),
            ["violations"] = string.Join(Environment.NewLine, DescribeViolations(violations, config.IncidentMail.MaxViolationsListed)),
            ["violationsCompact"] = string.Join("; ", DescribeViolations(violations, config.IncidentMail.MaxViolationsListed).Select(line => line.TrimStart('-', ' '))),
            ["violationCount"] = violations.Count.ToString()
        };
    }

    private static string RenderTemplate(string template, Dictionary<string, string> values)
    {
        var rendered = template.Replace("\\n", Environment.NewLine, StringComparison.Ordinal);
        foreach (var pair in values)
        {
            rendered = rendered.Replace($"{{{pair.Key}}}", pair.Value ?? "", StringComparison.OrdinalIgnoreCase);
        }

        return rendered.Trim();
    }

    public static string ResolveTemplate(List<string> configuredLines, string configuredTemplate, List<string> defaultLines)
    {
        if (configuredLines.Count > 0)
        {
            return string.Join(Environment.NewLine, configuredLines);
        }

        return string.IsNullOrWhiteSpace(configuredTemplate)
            ? string.Join(Environment.NewLine, defaultLines)
            : configuredTemplate;
    }

    private static string FormatUnlockUtc(DateTime? bannedUntilUtc)
    {
        if (bannedUntilUtc == null)
        {
            return "";
        }

        return bannedUntilUtc == DateTime.MaxValue
            ? "permanent"
            : $"{bannedUntilUtc:yyyy-MM-dd HH:mm:ss} UTC";
    }

    public static string DefaultMissingClientTemplate()
    {
        return string.Join(Environment.NewLine, DefaultMissingClientLines());
    }

    public static string DefaultPolicyViolationTemplate()
    {
        return string.Join(Environment.NewLine, DefaultPolicyViolationLines());
    }

    public static string DefaultAutomaticBanTemplate()
    {
        return string.Join(Environment.NewLine, DefaultAutomaticBanLines());
    }

    public static List<string> DefaultMissingClientLines()
    {
        return
        [
            "MODSEC HOST RULE NOTICE",
            "",
            "Player: {player}",
            "Action: raid access blocked",
            "Reason: ModSec client did not report for this game launch.",
            "Route: {route}",
            "",
            "This attempt was blocked for this player only. Other players can continue normally."
        ];
    }

    public static List<string> DefaultPolicyViolationLines()
    {
        return
        [
            "MODSEC HOST RULE NOTICE",
            "",
            "Player: {player}",
            "Action: {status}",
            "Local strike applied: {strikeApplied}",
            "Strikes: {strikes}/{strikeLimit}",
            "",
            "Detected:",
            "{violations}"
        ];
    }

    public static List<string> DefaultAutomaticBanLines()
    {
        return
        [
            "MODSEC SERVER LOCKOUT",
            "",
            "Player: {player}",
            "Reason: {banReason}",
            "Unlock: {unlockUtc}",
            "",
            "Detected:",
            "{violations}"
        ];
    }
}
