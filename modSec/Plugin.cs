using System.Collections;
using BepInEx;
using BepInEx.Bootstrap;
using BepInEx.Logging;
using ModSec.Models;
using ModSec.Services;
using ModSec.UI;
using SPT.Reflection.Utils;
using UnityEngine;

namespace ModSec;

[BepInPlugin(ModSecConstants.ClientGuid, "ModSec", ModSecConstants.Version)]
public class Plugin : BaseUnityPlugin
{
    public static ManualLogSource LogSource = null!;

    private ModSecServerModule _server = null!;
    private ModSecScanner _scanner = null!;
    private ModSecConsentService _consent = null!;
    private RaidRemovalService _raidRemoval = null!;
    private PopupOverlay _overlay = null!;
    private PolicyResponse? _policy;
    private string _clientId = "";
    private float _nextCheckAt;
    private float _nextHeartbeatAt;
    private float _nextPopupPollAt;
    private bool _checkRunning;
    private bool _heartbeatRunning;
    private bool _popupPollRunning;
    private bool _blocked;
    private bool _allowChecksWhileBlocked;
    private bool _consentAcceptedForCurrentPolicy;
    private bool _consentInvalidatedThisLaunch;
    private float _nextConsentWatchAt;
    private string _lastReportedProfileId = "";
    private string _lastKnownSptProfileId = "";
    private string _lastRaidRemovalSignature = "";
    private float _nextRaidRemovalAttemptAt;
    private bool _hostPeerExtractionAttempted;
    private bool _wasInRaid;
    private readonly HashSet<string> _processedRaidCommands = new(StringComparer.OrdinalIgnoreCase);

    private void Awake()
    {
        LogSource = Logger;
        _server = new ModSecServerModule();
        _scanner = new ModSecScanner(LogSource);
        _consent = new ModSecConsentService();
        _raidRemoval = new RaidRemovalService();
        _overlay = new PopupOverlay();
        _clientId = LoadClientId();

        LogSource.LogInfo("ModSec loaded.");
    }

    private void Start()
    {
        LogSource.LogInfo("Starting ModSec startup check.");
        StartCoroutine(RunStartupCheck());
    }

    private void Update()
    {
        if (_policy != null && _consentAcceptedForCurrentPolicy && Time.realtimeSinceStartup >= _nextConsentWatchAt)
        {
            _nextConsentWatchAt = Time.realtimeSinceStartup + 2f;
            if (!_consent.HasAccepted(_policy))
            {
                LogSource.LogWarning("ModSec consent was revoked or no longer matches the host disclosure during this session.");
                _consentAcceptedForCurrentPolicy = false;
                _consentInvalidatedThisLaunch = true;
                _blocked = true;
                _overlay.ShowConsentRestartRequired();
                return;
            }
        }

        if (_policy != null
            && _consentAcceptedForCurrentPolicy
            && !_consentInvalidatedThisLaunch
            && !_popupPollRunning
            && Time.realtimeSinceStartup >= _nextPopupPollAt)
        {
            StartCoroutine(RunPopupPoll());
        }

        if ((_blocked && !_allowChecksWhileBlocked) || _checkRunning || _policy is not { BackgroundChecks: true })
        {
            return;
        }

        TightenPollingWhileInRaid();

        if (_blocked && _allowChecksWhileBlocked)
        {
            if (Time.realtimeSinceStartup >= _nextCheckAt)
            {
                StartCoroutine(RunBackgroundCheck());
            }

            return;
        }

        var profileId = GetProfileId();
        if (!_heartbeatRunning
            && !string.Equals(profileId, _clientId, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(profileId, _lastReportedProfileId, StringComparison.OrdinalIgnoreCase))
        {
            StartCoroutine(RunHeartbeat());
            return;
        }

        if (Time.realtimeSinceStartup >= _nextCheckAt)
        {
            StartCoroutine(RunBackgroundCheck());
        }

        if (!_heartbeatRunning && Time.realtimeSinceStartup >= _nextHeartbeatAt)
        {
            StartCoroutine(RunHeartbeat());
        }
    }

    private void OnGUI()
    {
        _overlay.Draw();
    }

    private IEnumerator RunStartupCheck()
    {
        var timeoutAt = Time.realtimeSinceStartup + 5f;
        while (Chainloader.PluginInfos.Count == 0 && Time.realtimeSinceStartup < timeoutAt)
        {
            yield return null;
        }

        yield return new WaitForSeconds(1f);
        yield return RunCheck("startup");
    }

    private IEnumerator RunBackgroundCheck()
    {
        yield return RunCheck("background");
    }

    private IEnumerator RunHeartbeat()
    {
        if (_policy == null)
        {
            yield break;
        }

        if (_consentInvalidatedThisLaunch)
        {
            yield break;
        }

        if (!_consent.HasAccepted(_policy))
        {
            _consentAcceptedForCurrentPolicy = false;
            yield break;
        }

        _heartbeatRunning = true;
        var profileId = GetProfileId();
        var heartbeat = new ClientHeartbeat
        {
            ProfileId = profileId,
            PlayerName = GetProfileName(),
            InstallId = _clientId,
            TimeZoneId = TimeZoneInfo.Local.Id,
            ClientVersion = ModSecConstants.Version,
            InRaid = _raidRemoval.IsInRaid(),
            IsFikaHost = _raidRemoval.IsFikaHost(),
            HumanPlayerCount = _raidRemoval.GetHumanPlayerCount()
        };
        var heartbeatTask = _server.SendHeartbeat(heartbeat);
        yield return new WaitUntil(() => heartbeatTask.IsCompleted);

        if (heartbeatTask.IsFaulted)
        {
            LogSource.LogWarning($"ModSec heartbeat failed: {heartbeatTask.Exception?.GetBaseException().Message}");
            ScheduleNextHeartbeat(_policy.HeartbeatIntervalSeconds);
            _heartbeatRunning = false;
            yield break;
        }

        if (heartbeatTask.Result != null)
        {
            _lastReportedProfileId = profileId;
            ApplyServerResponse(heartbeatTask.Result);
        }

        ScheduleNextHeartbeat(_policy.HeartbeatIntervalSeconds);
        _heartbeatRunning = false;
    }

    private IEnumerator RunPopupPoll()
    {
        if (_policy == null || _consentInvalidatedThisLaunch || !_consent.HasAccepted(_policy))
        {
            ScheduleNextPopupPoll();
            yield break;
        }

        _popupPollRunning = true;
        var poll = new ClientPopupPoll
        {
            ProfileId = GetProfileId(),
            PlayerName = GetProfileName(),
            InstallId = _clientId,
            ClientVersion = ModSecConstants.Version
        };

        var pollTask = _server.PollPopups(poll);
        yield return new WaitUntil(() => pollTask.IsCompleted);

        if (pollTask.IsFaulted)
        {
            LogSource.LogWarning($"ModSec popup poll failed: {pollTask.Exception?.GetBaseException().Message}");
        }
        else if (pollTask.Result != null)
        {
            foreach (var popup in pollTask.Result.Popups)
            {
                _overlay.Enqueue(popup);
            }
        }

        ScheduleNextPopupPoll();
        _popupPollRunning = false;
    }

    private IEnumerator RunCheck(string checkKind)
    {
        _checkRunning = true;

        Task<PolicyResponse?> policyTask = _server.GetPolicy();

        yield return new WaitUntil(() => policyTask.IsCompleted);

        if (policyTask.IsFaulted || policyTask.Result == null)
        {
            LogSource.LogWarning($"Could not reach ModSec server: {policyTask.Exception?.GetBaseException().Message}");
            _overlay.ShowBlocking(
                "ModSec Server Required",
                "ModSec could not contact this host's policy endpoint. Raid access protection cannot continue until the host server is reachable.",
                false);
            _blocked = true;
            _allowChecksWhileBlocked = false;
            _checkRunning = false;
            yield break;
        }

        _policy = policyTask.Result;
        _policy.Privacy ??= new PrivacyOptions();
        _policy.Disclosure ??= new PolicyDisclosure();
        if (_consentInvalidatedThisLaunch)
        {
            _overlay.ShowConsentRestartRequired();
            _blocked = true;
            _allowChecksWhileBlocked = false;
            _checkRunning = false;
            yield break;
        }

        if (!_policy.Enabled)
        {
            _checkRunning = false;
            ScheduleNextCheck(_policy.BackgroundIntervalSeconds);
            ScheduleNextHeartbeat(_policy.HeartbeatIntervalSeconds);
            yield break;
        }

        if (!_consent.HasAccepted(_policy))
        {
            if (_consent.HasDeclined(_policy))
            {
                ShowConsentRequiredPrompt(_policy);
                _blocked = true;
                _allowChecksWhileBlocked = false;
                _checkRunning = false;
                yield break;
            }

            bool? accepted = null;
            _overlay.ShowConsent(ModSecConsentService.BuildDisclosureText(_policy), () => accepted = true, () => accepted = false);
            yield return new WaitUntil(() => accepted.HasValue);
            if (accepted == true)
            {
                _consent.Accept(_policy);
                MarkConsentAccepted();
            }
            else
            {
                _consent.Decline(_policy);
                ShowConsentRequiredPrompt(_policy);
                _blocked = true;
                _allowChecksWhileBlocked = false;
                _checkRunning = false;
                yield break;
            }
        }

        MarkConsentAccepted();

        var profileId = GetProfileId();
        if (string.Equals(profileId, _clientId, StringComparison.OrdinalIgnoreCase))
        {
            var waitUntil = Time.realtimeSinceStartup + 10f;
            while (Time.realtimeSinceStartup < waitUntil)
            {
                profileId = GetProfileId();
                if (!string.Equals(profileId, _clientId, StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                yield return new WaitForSeconds(0.25f);
            }
        }

        ClientReport report;
        try
        {
            report = _scanner.BuildReport(_policy, profileId, GetProfileName(), _clientId, checkKind);
            report.InRaid = _raidRemoval.IsInRaid();
            report.IsFikaHost = _raidRemoval.IsFikaHost();
            report.HumanPlayerCount = _raidRemoval.GetHumanPlayerCount();
            _lastReportedProfileId = profileId;
        }
        catch (Exception ex)
        {
            LogSource.LogError($"Failed to build ModSec report: {ex}");
            _overlay.ShowBlocking("ModSec Scan Failed", "ModSec could not scan the configured SPT files. Check BepInEx logs or contact the host admin.", false);
            _blocked = true;
            _allowChecksWhileBlocked = false;
            _checkRunning = false;
            yield break;
        }

        var reportTask = _server.SendReport(report);
        yield return new WaitUntil(() => reportTask.IsCompleted);

        if (reportTask.IsFaulted || reportTask.Result == null)
        {
            LogSource.LogWarning($"Could not submit ModSec report: {reportTask.Exception?.GetBaseException().Message}");
            _overlay.ShowBlocking("ModSec Report Failed", "ModSec could not submit the host rule enforcement report to the server.", false);
            _blocked = true;
            _allowChecksWhileBlocked = false;
            _checkRunning = false;
            yield break;
        }

        ApplyServerResponse(reportTask.Result);
        ScheduleNextHeartbeat(_policy.HeartbeatIntervalSeconds);
        _checkRunning = false;
    }

    private void ApplyServerResponse(EnforcementResponse response)
    {
        foreach (var popup in response.Popups)
        {
            _overlay.Enqueue(popup);
        }

        foreach (var command in response.RaidCommands)
        {
            HandleRaidCommand(response, command);
        }

        if (response.Status is "blocked" or "cooldown" or "banned")
        {
            _blocked = true;
            _allowChecksWhileBlocked = response.Status == "banned" || CanManualRecheck(response);
            _overlay.ShowEnforcement(response, true, _allowChecksWhileBlocked ? StartManualRecheck : null);
            if (response.Status == "banned")
            {
                HandleInRaidRestriction(response);
            }
            if (_allowChecksWhileBlocked)
            {
                ScheduleNextCheck(response.Status == "banned"
                    ? Math.Min(response.NextCheckSeconds, 30)
                    : Math.Min(response.NextCheckSeconds, 10));
            }

            return;
        }

        _blocked = false;
        _allowChecksWhileBlocked = false;
        _lastRaidRemovalSignature = "";
        _hostPeerExtractionAttempted = false;
        if (response.Status == "warn")
        {
            _overlay.ShowEnforcement(response, false);
        }
        else
        {
            _overlay.ClearEnforcement();
        }

        ScheduleNextCheck(response.NextCheckSeconds);
    }

    private void HandleRaidCommand(EnforcementResponse response, RaidCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.Id) || !_processedRaidCommands.Add(command.Id))
        {
            return;
        }

        LogSource.LogWarning($"ModSec received raid command: id={command.Id}, action={command.Action}, delay={command.DelaySeconds}, reason={command.Reason}");

        switch (command.Action)
        {
            case "extract-local-safe":
                if (_raidRemoval.TryExtractLocalPlayerSafe(response, out var extractMessage))
                {
                    LogSource.LogWarning($"ModSec safely extracted the local player from raid. {extractMessage}");
                    ShowRaidCommandPopup(command);
                }
                else
                {
                    LogSource.LogWarning($"ModSec could not safely extract the local player from raid: {extractMessage}");
                }
                break;
            case "remove-local-loss-delayed":
                StartCoroutine(RemoveLocalPlayerAfterDelay(response, command.DelaySeconds));
                break;
            case "remove-local-loss":
                RemoveFlaggedLocalPlayer(response);
                break;
        }
    }

    private void ShowRaidCommandPopup(RaidCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.PopupTitle) && string.IsNullOrWhiteSpace(command.PopupMessage))
        {
            return;
        }

        _overlay.Enqueue(new AdminPopup
        {
            Id = string.IsNullOrWhiteSpace(command.Id) ? Guid.NewGuid().ToString("N") : $"{command.Id}-popup",
            Title = string.IsNullOrWhiteSpace(command.PopupTitle) ? "Raid Notice" : command.PopupTitle,
            Message = command.PopupMessage,
            Kind = string.IsNullOrWhiteSpace(command.PopupKind) ? "dialog" : command.PopupKind,
            Severity = string.IsNullOrWhiteSpace(command.PopupSeverity) ? "info" : command.PopupSeverity,
            DurationSeconds = command.PopupDurationSeconds <= 0 ? 8 : command.PopupDurationSeconds,
            Blocking = false,
            RequiresQuit = false,
            CreatedAtUtc = DateTime.UtcNow
        });
    }

    private IEnumerator RemoveLocalPlayerAfterDelay(EnforcementResponse response, int delaySeconds)
    {
        var safeDelay = Mathf.Clamp(delaySeconds, 0, 180);
        LogSource.LogWarning($"ModSec scheduled flagged local player raid removal in {safeDelay} seconds.");
        if (safeDelay > 0)
        {
            yield return new WaitForSecondsRealtime(safeDelay);
        }

        RemoveFlaggedLocalPlayer(response);
    }

    private void RemoveFlaggedLocalPlayer(EnforcementResponse response)
    {
        if (_raidRemoval.TryRemoveFlaggedLocalPlayer(response, out var message))
        {
            LogSource.LogWarning($"ModSec removed the flagged local player from the active raid as a loss. {message}");
        }
        else
        {
            LogSource.LogWarning($"ModSec could not remove the flagged local player from the active raid: {message}");
        }
    }

    private void HandleInRaidRestriction(EnforcementResponse response)
    {
        if (!_raidRemoval.IsInRaid())
        {
            _lastRaidRemovalSignature = "";
            _hostPeerExtractionAttempted = false;
            return;
        }

        var signature = BuildEnforcementSignature(response);
        if (string.Equals(_lastRaidRemovalSignature, signature, StringComparison.Ordinal)
            && Time.realtimeSinceStartup < _nextRaidRemovalAttemptAt)
        {
            return;
        }

        _lastRaidRemovalSignature = signature;
        _nextRaidRemovalAttemptAt = Time.realtimeSinceStartup + 30f;

        if (_raidRemoval.IsFikaHost() && _raidRemoval.GetHumanPlayerCount() > 1)
        {
            if (!_hostPeerExtractionAttempted)
            {
                _hostPeerExtractionAttempted = true;
                if (_raidRemoval.TryExtractOtherHumanPlayersSafe(out var extractOthersMessage))
                {
                    LogSource.LogWarning($"ModSec asked Fika to safely extract other human players before removing the restricted host. {extractOthersMessage}");
                }
                else
                {
                    LogSource.LogWarning($"ModSec could not safely extract other human players before host removal: {extractOthersMessage}");
                }
            }

            StartCoroutine(RemoveLocalPlayerAfterDelay(response, 8));
            return;
        }

        RemoveFlaggedLocalPlayer(response);
    }

    private static string BuildEnforcementSignature(EnforcementResponse response)
    {
        var violations = string.Join("|", response.Violations
            .OrderBy(violation => violation.RuleId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(violation => violation.Path, StringComparer.OrdinalIgnoreCase)
            .Select(violation => $"{violation.RuleId}:{violation.Path}:{violation.Setting}:{violation.ActualValue}:{violation.ExpectedValue}"));

        return $"{response.Status}:{response.Strikes}:{response.CooldownUntilUtc:O}:{violations}";
    }

    private void ShowConsentRequiredPrompt(PolicyResponse policy)
    {
        _overlay.ShowConsentRequired(() =>
        {
            _overlay.ShowConsent(
                ModSecConsentService.BuildDisclosureText(policy),
                () =>
                {
                    _consent.Accept(policy);
                    MarkConsentAccepted();
                    _blocked = false;
                    _allowChecksWhileBlocked = false;
                    StartManualRecheck();
                },
                () =>
                {
                    _consent.Decline(policy);
                    ShowConsentRequiredPrompt(policy);
                });
        });
    }

    private void MarkConsentAccepted()
    {
        _consentAcceptedForCurrentPolicy = true;
        _nextConsentWatchAt = Time.realtimeSinceStartup + 2f;
    }

    private void ScheduleNextCheck(int seconds)
    {
        var safeSeconds = Mathf.Clamp(seconds, 15, 3600);
        _nextCheckAt = Time.realtimeSinceStartup + safeSeconds;
    }

    private void ScheduleNextHeartbeat(int seconds)
    {
        var safeSeconds = Mathf.Clamp(seconds, 30, 900);
        _nextHeartbeatAt = Time.realtimeSinceStartup + safeSeconds;
    }

    private void ScheduleNextPopupPoll()
    {
        _nextPopupPollAt = Time.realtimeSinceStartup + 5f;
    }

    private void TightenPollingWhileInRaid()
    {
        var inRaid = _raidRemoval.IsInRaid();
        if (inRaid && !_wasInRaid)
        {
            _nextCheckAt = Mathf.Min(_nextCheckAt, Time.realtimeSinceStartup + 5f);
        }

        _wasInRaid = inRaid;

        if (!inRaid)
        {
            return;
        }

        var maxInRaidDelay = Mathf.Clamp(_policy?.BackgroundIntervalSeconds ?? 60, 10, 300);
        _nextCheckAt = Mathf.Min(_nextCheckAt, Time.realtimeSinceStartup + maxInRaidDelay);
    }

    private void StartManualRecheck()
    {
        if (_checkRunning || _consentInvalidatedThisLaunch)
        {
            if (_consentInvalidatedThisLaunch)
            {
                _overlay.ShowConsentRestartRequired();
                _blocked = true;
                _allowChecksWhileBlocked = false;
            }

            return;
        }

        _blocked = false;
        _allowChecksWhileBlocked = false;
        StartCoroutine(RunCheck("manual"));
    }

    private static bool CanManualRecheck(EnforcementResponse response)
    {
        return response.Status == "banned"
               || response.Violations.Any(violation =>
                   violation.Path.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase)
                   || violation.Path.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                   || violation.RuleId.StartsWith("megamod-", StringComparison.OrdinalIgnoreCase));
    }

    private static string LoadClientId()
    {
        var dataDir = Path.Combine(ModSecScanner.GetGameRoot(), "ModSec_Data");
        var idPath = Path.Combine(dataDir, "client-id.txt");
        Directory.CreateDirectory(dataDir);

        if (File.Exists(idPath))
        {
            var existing = File.ReadAllText(idPath).Trim();
            if (!string.IsNullOrWhiteSpace(existing))
            {
                return existing;
            }
        }

        var id = Guid.NewGuid().ToString("N");
        File.WriteAllText(idPath, id);
        return id;
    }

    private string GetProfileId()
    {
        try
        {
            var profileId = ClientAppUtils.GetClientApp()?.GetClientBackEndSession()?.Profile?.ProfileId;
            if (!string.IsNullOrWhiteSpace(profileId))
            {
                if (!profileId.Equals(_clientId, StringComparison.OrdinalIgnoreCase))
                {
                    _lastKnownSptProfileId = profileId;
                }

                return profileId;
            }
        }
        catch
        {
            // The profile is not available during very early startup; the generated ID keeps ModSec functional.
        }

        if (!string.IsNullOrWhiteSpace(_lastKnownSptProfileId))
        {
            return _lastKnownSptProfileId;
        }

        return _clientId;
    }

    private static string GetProfileName()
    {
        try
        {
            var profile = ClientAppUtils.GetClientApp()?.GetClientBackEndSession()?.Profile;
            return ReadStringProperty(profile, "Nickname")
                   ?? ReadStringProperty(ReadProperty(profile, "Info"), "Nickname")
                   ?? ReadStringProperty(ReadProperty(profile, "ProfileInfo"), "Nickname")
                   ?? "";
        }
        catch
        {
            return "";
        }
    }

    private static object? ReadProperty(object? target, string name)
    {
        return target?.GetType().GetProperty(name)?.GetValue(target);
    }

    private static string? ReadStringProperty(object? target, string name)
    {
        return ReadProperty(target, name) as string;
    }
}
