using System.Reflection;
using ModSec.Models;

namespace ModSec.Services;

internal sealed class RaidRemovalService
{
    private const string AssemblyCSharpName = "Assembly-CSharp";
    private const string FikaAssemblyName = "Fika.Core";
    private const BindingFlags InstanceFlags = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
    private const BindingFlags StaticFlags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;

    public bool IsInRaid()
    {
        if (TryReadStaticBool("Fika.Core.Main.Utils.FikaGlobals", "IsInRaid"))
        {
            return true;
        }

        if (TryGetSingletonInstance(FindType("Fika.Core.Main.GameMode.IFikaGame", FikaAssemblyName), out var fikaGame)
            && fikaGame != null)
        {
            return true;
        }

        return TryGetMainPlayer(out _);
    }

    public bool IsFikaHost()
    {
        return TryReadStaticBool("Fika.Core.Main.Utils.FikaBackendUtils", "IsServer");
    }

    public int GetHumanPlayerCount()
    {
        if (!TryGetSingletonInstance(FindType("Fika.Core.Main.GameMode.IFikaGame", FikaAssemblyName), out var fikaGame)
            || fikaGame == null)
        {
            return IsInRaid() ? 1 : 0;
        }

        var coopHandler = GetCoopHandler(fikaGame);
        var amount = ReadProperty(coopHandler, "AmountOfHumans");
        if (amount is int humanCount)
        {
            return humanCount;
        }

        return IsInRaid() ? 1 : 0;
    }

    public bool TryRemoveFlaggedLocalPlayer(EnforcementResponse response, out string message)
    {
        return TryStopLocalPlayer(response, "MissingInAction", out message);
    }

    public bool TryExtractOtherHumanPlayersSafe(out string message)
    {
        message = "";
        if (!TryGetSingletonInstance(FindType("Fika.Core.Main.GameMode.IFikaGame", FikaAssemblyName), out var fikaGame)
            || fikaGame == null)
        {
            message = "Fika raid interface is not available.";
            return false;
        }

        var coopHandler = GetCoopHandler(fikaGame);
        var humanPlayers = ReadProperty(coopHandler, "HumanPlayers") as System.Collections.IEnumerable;
        if (humanPlayers == null)
        {
            message = "Fika human player list is not available.";
            return false;
        }

        var extractMethod = fikaGame.GetType()
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .FirstOrDefault(method =>
                method.Name == "Extract"
                && method.GetParameters().Length == 3);

        if (extractMethod == null)
        {
            message = "Fika extract method was not found.";
            return false;
        }

        var extracted = 0;
        var errors = new List<string>();
        foreach (var player in humanPlayers)
        {
            if (player == null || IsLocalPlayer(player))
            {
                continue;
            }

            try
            {
                extractMethod.Invoke(fikaGame, [player, null, null]);
                extracted++;
            }
            catch (TargetInvocationException ex)
            {
                errors.Add(ex.InnerException?.ToString() ?? ex.ToString());
            }
            catch (Exception ex)
            {
                errors.Add(ex.ToString());
            }
        }

        if (extracted > 0)
        {
            message = errors.Count == 0
                ? $"Safely extracted {extracted} other human player(s)."
                : $"Safely extracted {extracted} other human player(s); {errors.Count} extraction error(s): {string.Join("; ", errors.Take(3))}";
            return true;
        }

        message = errors.Count == 0
            ? "No other human players were available to extract."
            : $"Could not extract other human players: {string.Join("; ", errors.Take(3))}";
        return false;
    }

    public bool TryExtractLocalPlayerSafe(EnforcementResponse response, out string message)
    {
        return TryStopLocalPlayer(response, "Survived", out message);
    }

    private bool TryStopLocalPlayer(EnforcementResponse response, string exitStatus, out string message)
    {
        message = "";

        if (!TryGetLocalPlayer(out var mainPlayer) || mainPlayer == null)
        {
            message = "No local raid player is active.";
            return false;
        }

        if (!TryGetSingletonInstance(FindType("Fika.Core.Main.GameMode.IFikaGame", FikaAssemblyName), out var fikaGame)
            || fikaGame == null)
        {
            message = "Fika raid interface is not available.";
            return false;
        }

        var stopMethod = fikaGame.GetType()
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .FirstOrDefault(method =>
                method.Name == "Stop"
                && method.GetParameters().Length >= 3);

        if (stopMethod == null)
        {
            message = "Fika stop method was not found.";
            return false;
        }

        var profileId = ReadProperty(mainPlayer, "ProfileId") as string
                        ?? ReadFikaProfileId();
        if (string.IsNullOrWhiteSpace(profileId))
        {
            message = "Local player profile ID was not available.";
            return false;
        }

        var exitStatusValue = ParseExitStatus(exitStatus);
        if (exitStatusValue == null)
        {
            message = "ExitStatus type was not found.";
            return false;
        }

        try
        {
            var parameters = stopMethod.GetParameters().Length == 3
                ? new[] { profileId, exitStatusValue, null }
                : new[] { profileId, exitStatusValue, null, 0f };
            stopMethod.Invoke(fikaGame, parameters);
            message = BuildReason(response);
            return true;
        }
        catch (TargetInvocationException ex)
        {
            message = ex.InnerException?.Message ?? ex.Message;
            return false;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return false;
        }
    }

    private static string BuildReason(EnforcementResponse response)
    {
        var first = response.Violations.FirstOrDefault();
        if (first == null)
        {
            return "Host rule enforcement restricted raid access.";
        }

        var item = !string.IsNullOrWhiteSpace(first.Setting)
            ? first.Setting
            : !string.IsNullOrWhiteSpace(first.Path)
                ? first.Path
                : first.RuleId;

        return $"Host rule enforcement restricted raid access: {item}";
    }

    private static object? ParseExitStatus(string statusName)
    {
        var exitStatusType = FindType("EFT.ExitStatus", AssemblyCSharpName);
        if (exitStatusType == null)
        {
            return null;
        }

        try
        {
            return Enum.Parse(exitStatusType, statusName);
        }
        catch
        {
            return null;
        }
    }

    private static bool TryReadStaticBool(string fullName, string propertyName)
    {
        var type = FindType(fullName, FikaAssemblyName);
        if (type == null)
        {
            return false;
        }

        try
        {
            return type.GetProperty(propertyName, StaticFlags)?.GetValue(null) as bool? == true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsLocalPlayer(object player)
    {
        var value = ReadProperty(player, "IsYourPlayer");
        return value is bool isLocal && isLocal;
    }

    private static bool TryGetLocalPlayer(out object? localPlayer)
    {
        localPlayer = null;

        if (TryGetSingletonInstance(FindType("Fika.Core.Main.GameMode.IFikaGame", FikaAssemblyName), out var fikaGame)
            && fikaGame != null)
        {
            var coopHandler = GetCoopHandler(fikaGame);
            localPlayer = ReadProperty(coopHandler, "MyPlayer");
            if (localPlayer != null)
            {
                return true;
            }
        }

        if (TryGetMainPlayer(out localPlayer) && localPlayer != null)
        {
            return true;
        }

        if (TryFindYourPlayerFromGameWorld(out localPlayer) && localPlayer != null)
        {
            return true;
        }

        return false;
    }

    private static bool TryGetMainPlayer(out object? mainPlayer)
    {
        mainPlayer = null;
        if (!TryGetSingletonInstance(FindType("EFT.GameWorld", AssemblyCSharpName), out var gameWorld)
            || gameWorld == null)
        {
            return false;
        }

        mainPlayer = ReadProperty(gameWorld, "MainPlayer");
        return mainPlayer != null;
    }

    private static bool TryFindYourPlayerFromGameWorld(out object? localPlayer)
    {
        localPlayer = null;
        if (!TryGetSingletonInstance(FindType("EFT.GameWorld", AssemblyCSharpName), out var gameWorld)
            || gameWorld == null)
        {
            return false;
        }

        foreach (var sourceName in new[] { "RegisteredPlayers", "AllPlayers", "Players" })
        {
            if (ReadProperty(gameWorld, sourceName) is not System.Collections.IEnumerable players)
            {
                continue;
            }

            foreach (var player in players)
            {
                if (player != null && IsLocalPlayer(player))
                {
                    localPlayer = player;
                    return true;
                }
            }
        }

        return false;
    }

    private static bool TryGetSingletonInstance(Type? targetType, out object? instance)
    {
        instance = null;
        if (targetType == null)
        {
            return false;
        }

        var singletonType = FindType("Comfort.Common.Singleton`1", AssemblyCSharpName);
        if (singletonType == null)
        {
            return false;
        }

        var typedSingleton = singletonType.MakeGenericType(targetType);
        var instantiated = typedSingleton.GetProperty("Instantiated", StaticFlags)?.GetValue(null) as bool?;
        if (instantiated == false)
        {
            return false;
        }

        instance = typedSingleton.GetProperty("Instance", StaticFlags)?.GetValue(null);
        return instance != null;
    }

    private static object? GetCoopHandler(object fikaGame)
    {
        var gameController = ReadProperty(fikaGame, "GameController");
        return ReadProperty(gameController, "CoopHandler");
    }

    private static object? ReadProperty(object? target, string name)
    {
        if (target == null)
        {
            return null;
        }

        var type = target.GetType();
        return type.GetProperty(name, InstanceFlags)?.GetValue(target)
               ?? type.GetField(name, InstanceFlags)?.GetValue(target);
    }

    private static string? ReadFikaProfileId()
    {
        var backendUtils = FindType("Fika.Core.Main.Utils.FikaBackendUtils", FikaAssemblyName);
        var profile = backendUtils?.GetProperty("Profile", StaticFlags)?.GetValue(null)
                      ?? backendUtils?.GetField("Profile", StaticFlags)?.GetValue(null);
        return ReadProperty(profile, "ProfileId") as string
               ?? ReadProperty(profile, "Id") as string;
    }

    private static Type? FindType(string fullName, string? preferredAssemblyName = null)
    {
        if (!string.IsNullOrWhiteSpace(preferredAssemblyName))
        {
            var qualified = Type.GetType($"{fullName}, {preferredAssemblyName}", false);
            if (qualified != null)
            {
                return qualified;
            }
        }

        foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
        {
            Type? type;
            try
            {
                type = assembly.GetType(fullName, false);
            }
            catch
            {
                continue;
            }

            if (type != null)
            {
                return type;
            }
        }

        return null;
    }
}
