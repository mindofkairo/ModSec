using System.Security.Cryptography;
using BepInEx.Bootstrap;
using BepInEx.Configuration;
using BepInEx.Logging;
using ModSec.Models;
using Newtonsoft.Json.Linq;

namespace ModSec.Services;

public class ModSecScanner(ManualLogSource logger)
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

    public ClientReport BuildReport(PolicyResponse policy, string clientId, string playerName, string installId, string checkKind)
    {
        var gameRoot = GetGameRoot();
        return new ClientReport
        {
            ProfileId = clientId,
            PlayerName = playerName,
            InstallId = installId,
            TimeZoneId = TimeZoneInfo.Local.Id,
            ClientVersion = ModSecConstants.Version,
            CheckKind = checkKind,
            MainPluginPresent = true,
            CompanionPresent = File.Exists(Path.Combine(gameRoot, "BepInEx", "plugins", "modSec", "modSec.Companion.dll")),
            Plugins = policy.Privacy.SendFullSnapshotsAfterConsent ? ScanPlugins(gameRoot) : [],
            Files = policy.Privacy.SendFullSnapshotsAfterConsent ? ScanFiles(gameRoot, policy.ScanPaths, policy.Privacy.AllowOutsideSptScanPaths) : [],
            ConfigValues = ReadConfigValues(policy.ConfigRules)
        };
    }

    private List<ClientPluginReport> ScanPlugins(string gameRoot)
    {
        return Chainloader.PluginInfos.Values
            .Select(plugin => new ClientPluginReport
            {
                Guid = plugin.Metadata.GUID,
                Name = plugin.Metadata.Name,
                Version = plugin.Metadata.Version?.ToString() ?? "",
                Location = ToRelativePath(gameRoot, plugin.Location ?? "")
            })
            .OrderBy(plugin => plugin.Guid, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private List<ClientFileReport> ScanFiles(string gameRoot, List<string> scanPaths, bool allowOutsideSptScanPaths)
    {
        var reports = new List<ClientFileReport>();

        foreach (var scanPath in scanPaths)
        {
            var normalizedScanPath = NormalizePath(scanPath);
            if (!allowOutsideSptScanPaths && !IsAllowedSptPath(normalizedScanPath))
            {
                logger.LogWarning($"ModSec ignored non-SPT scan path from host policy: {normalizedScanPath}");
                continue;
            }

            var fullPath = Path.GetFullPath(Path.Combine(gameRoot, normalizedScanPath));
            if (!allowOutsideSptScanPaths && !IsInsideRoot(gameRoot, fullPath))
            {
                logger.LogWarning($"ModSec ignored scan path outside SPT root: {normalizedScanPath}");
                continue;
            }

            if (File.Exists(fullPath))
            {
                TryAddFileReport(gameRoot, fullPath, reports);
                continue;
            }

            if (!Directory.Exists(fullPath))
            {
                logger.LogWarning($"ModSec scan path does not exist: {normalizedScanPath}");
                continue;
            }

            foreach (var file in Directory.EnumerateFiles(fullPath, "*", SearchOption.AllDirectories))
            {
                TryAddFileReport(gameRoot, file, reports);
            }
        }

        if (reports.Count == 0)
        {
            var fallbackPath = Path.Combine(gameRoot, "BepInEx", "plugins");
            logger.LogWarning($"ModSec file report is empty. Falling back to direct plugin scan: {fallbackPath}");
            if (Directory.Exists(fallbackPath))
            {
                foreach (var file in Directory.EnumerateFiles(fallbackPath, "*", SearchOption.AllDirectories))
                {
                    TryAddFileReport(gameRoot, file, reports);
                }
            }
        }

        return reports;
    }

    private void TryAddFileReport(string gameRoot, string filePath, List<ClientFileReport> reports)
    {
        try
        {
            var relativePath = NormalizePath(Path.GetRelativePath(gameRoot, filePath));
            if (IsPluginFolderPath(relativePath) && !IsPluginCandidateFile(filePath))
            {
                return;
            }

            var info = new FileInfo(filePath);
            reports.Add(new ClientFileReport
            {
                Path = relativePath,
                Hash = HashFile(filePath),
                Size = info.Length,
                LastWriteUtc = info.LastWriteTimeUtc
            });
        }
        catch (Exception ex)
        {
            logger.LogWarning($"ModSec could not hash '{filePath}': {ex.Message}");
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

    private List<ClientConfigValue> ReadConfigValues(List<ConfigRule> rules)
    {
        return rules.Select(ReadConfigValue).ToList();
    }

    private ClientConfigValue ReadConfigValue(ConfigRule rule)
    {
        var configValue = new ClientConfigValue
        {
            RuleId = rule.Id,
            Path = NormalizePath(rule.Path),
            Section = rule.Section,
            Key = rule.Key,
            JsonPath = rule.JsonPath
        };

        var fullPath = Path.GetFullPath(Path.Combine(GetGameRoot(), configValue.Path));
        if (!IsAllowedSptPath(configValue.Path) || !IsInsideRoot(GetGameRoot(), fullPath))
        {
            logger.LogWarning($"ModSec ignored config rule outside allowed SPT folders: {configValue.Path}");
            configValue.FileExists = false;
            configValue.Found = false;
            return configValue;
        }

        if (!File.Exists(fullPath))
        {
            configValue.FileExists = false;
            configValue.Found = false;
            return configValue;
        }

        try
        {
            configValue.FileExists = true;
            if (!rule.Format.Equals("json", StringComparison.OrdinalIgnoreCase)
                && TryReadLiveBepInExConfigValue(gameRoot: GetGameRoot(), rule, configValue))
            {
                return configValue;
            }

            if (rule.Format.Equals("json", StringComparison.OrdinalIgnoreCase))
            {
                var token = JObject.Parse(File.ReadAllText(fullPath)).SelectToken(rule.JsonPath);
                configValue.Found = token != null;
                configValue.Value = token?.Type == JTokenType.String ? token.Value<string>() : token?.ToString(Newtonsoft.Json.Formatting.None);
                return configValue;
            }

            return ReadBepInExConfigValue(fullPath, rule, configValue);
        }
        catch (Exception ex)
        {
            logger.LogWarning($"ModSec could not read config rule '{rule.Id}' from '{rule.Path}': {ex.Message}");
            configValue.Found = false;
            return configValue;
        }
    }

    private static bool TryReadLiveBepInExConfigValue(string gameRoot, ConfigRule rule, ClientConfigValue configValue)
    {
        foreach (var plugin in Chainloader.PluginInfos.Values)
        {
            var config = plugin.Instance?.Config;
            if (config == null)
            {
                continue;
            }

            var configPath = ToRelativePath(gameRoot, config.ConfigFilePath);
            if (!configPath.Equals(configValue.Path, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var definition = new ConfigDefinition(rule.Section, rule.Key);
            if (!config.ContainsKey(definition))
            {
                configValue.FileExists = true;
                configValue.Found = false;
                return true;
            }

            var entry = config[definition];
            configValue.FileExists = true;
            configValue.Found = true;
            configValue.Section = definition.Section;
            configValue.Key = definition.Key;
            configValue.Value = entry.GetSerializedValue();
            return true;
        }

        return false;
    }

    private static ClientConfigValue ReadBepInExConfigValue(string fullPath, ConfigRule rule, ClientConfigValue configValue)
    {
        var currentSection = "";
        foreach (var line in File.ReadAllLines(fullPath))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith("#"))
            {
                continue;
            }

            if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
            {
                currentSection = trimmed.Substring(1, trimmed.Length - 2).Trim();
                continue;
            }

            var splitAt = trimmed.IndexOf('=');
            if (splitAt <= 0)
            {
                continue;
            }

            var key = trimmed.Substring(0, splitAt).Trim();
            if (!key.Equals(rule.Key, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(rule.Section)
                && !currentSection.Equals(rule.Section, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            configValue.Found = true;
            configValue.Section = currentSection;
            configValue.Value = trimmed.Substring(splitAt + 1).Trim();
            return configValue;
        }

        configValue.Found = false;
        return configValue;
    }

    private static string HashFile(string filePath)
    {
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var sha = SHA256.Create();
        return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('\\', '/').Trim().TrimStart('/');
    }

    private static bool IsAllowedSptPath(string path)
    {
        var normalized = NormalizePath(path);
        if (normalized.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        return AllowedScanRoots.Any(root =>
            normalized.Equals(root, StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(root.TrimEnd('/') + "/", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsInsideRoot(string gameRoot, string fullPath)
    {
        var root = Path.GetFullPath(gameRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var candidate = Path.GetFullPath(fullPath);
        return candidate.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

    public static string GetGameRoot()
    {
        var assemblyPath = typeof(ModSecScanner).Assembly.Location;
        if (!string.IsNullOrWhiteSpace(assemblyPath))
        {
            var directory = new FileInfo(assemblyPath).Directory;
            while (directory != null)
            {
                if (directory.Name.Equals("BepInEx", StringComparison.OrdinalIgnoreCase))
                {
                    return directory.Parent?.FullName ?? directory.FullName;
                }

                if (Directory.Exists(Path.Combine(directory.FullName, "BepInEx"))
                    && File.Exists(Path.Combine(directory.FullName, "EscapeFromTarkov.exe")))
                {
                    return directory.FullName;
                }

                directory = directory.Parent;
            }
        }

        return Directory.GetCurrentDirectory();
    }

    private static string ToRelativePath(string gameRoot, string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "";
        }

        try
        {
            var fullPath = Path.GetFullPath(path);
            return NormalizePath(Path.GetRelativePath(gameRoot, fullPath));
        }
        catch
        {
            return NormalizePath(path);
        }
    }
}
