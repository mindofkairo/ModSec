using System.Security.Cryptography;
using System.Text;
using ModSec.Models;
using Newtonsoft.Json;

namespace ModSec.Services;

public class ModSecConsentService
{
    private readonly string _statePath;

    public ModSecConsentService()
    {
        var dataDir = Path.Combine(ModSecScanner.GetGameRoot(), "ModSec_Data");
        Directory.CreateDirectory(dataDir);
        _statePath = Path.Combine(dataDir, "consent.json");
    }

    public ConsentState Load()
    {
        if (!File.Exists(_statePath))
        {
            return new ConsentState();
        }

        try
        {
            return JsonConvert.DeserializeObject<ConsentState>(File.ReadAllText(_statePath)) ?? new ConsentState();
        }
        catch
        {
            return new ConsentState();
        }
    }

    public bool HasAccepted(PolicyResponse policy)
    {
        if (!policy.Privacy.RequireClientConsent)
        {
            return true;
        }

        var state = Load();
        return state.Accepted
               && !state.Declined
               && state.ConsentVersion == policy.Privacy.ConsentVersion
               && state.DisclosureHash == GetDisclosureHash(policy);
    }

    public bool HasDeclined(PolicyResponse policy)
    {
        var state = Load();
        return state.Declined
               && state.ConsentVersion == policy.Privacy.ConsentVersion
               && state.DisclosureHash == GetDisclosureHash(policy);
    }

    public void Accept(PolicyResponse policy)
    {
        Save(new ConsentState
        {
            Accepted = true,
            Declined = false,
            ConsentVersion = policy.Privacy.ConsentVersion,
            DisclosureHash = GetDisclosureHash(policy),
            UpdatedAtUtc = DateTime.UtcNow
        });
    }

    public void Decline(PolicyResponse policy)
    {
        Save(new ConsentState
        {
            Accepted = false,
            Declined = true,
            ConsentVersion = policy.Privacy.ConsentVersion,
            DisclosureHash = GetDisclosureHash(policy),
            UpdatedAtUtc = DateTime.UtcNow
        });
    }

    public static string BuildDisclosureText(PolicyResponse policy)
    {
        var disclosure = policy.Disclosure;
        var scanned = disclosure.ScannedFolders.Count == 0
            ? string.Join("\n", policy.ScanPaths.Select(path => $"- {path}"))
            : string.Join("\n", disclosure.ScannedFolders.Select(path => $"- {path}"));
        var sent = disclosure.DataSent.Count == 0
            ? "- SPT profile ID\n- random ModSec Install ID\n- plugin metadata\n- relative file paths and hashes\n- selected config values"
            : string.Join("\n", disclosure.DataSent.Select(item => $"- {item}"));

        return string.Join("\n", new[]
        {
            "<b>HOST RULE ENFORCEMENT DISCLOSURE</b>",
            "This host requires ModSec checks for raid access.",
            "",
            "<b>Folders scanned</b>",
            scanned,
            "",
            "<b>Data sent to this host after acceptance</b>",
            sent,
            "",
            "<b>Storage and visibility</b>",
            disclosure.StoredWhere,
            disclosure.WhoCanView,
            "",
            "<b>Safety</b>",
            disclosure.ExternalTelemetry ? "- External telemetry is enabled by this host." : "- No data is sent to Forge, SPT, or third-party servers.",
            disclosure.FileModification ? "- This host allows file modification features." : "- ModSec does not delete, modify, or move third-party files.",
            "- Server admins control their own host, config, and installed server mods. ModSec's defaults are conservative, but only play on hosts you trust.",
            "",
            "<b>If you decline</b>",
            string.IsNullOrWhiteSpace(disclosure.DeclineEffect) ? "Declining prevents raid access on this host." : disclosure.DeclineEffect,
            "",
            "<b>Reset or revoke consent</b>",
            string.IsNullOrWhiteSpace(disclosure.ResetInstructions)
                ? "Consent can be reset or changed in SPT/ModSec_Data/consent.json. Consent changes require a game restart to take effect before joining raids."
                : disclosure.ResetInstructions
        });
    }

    private void Save(ConsentState state)
    {
        File.WriteAllText(_statePath, JsonConvert.SerializeObject(state, Formatting.Indented));
    }

    private static string GetDisclosureHash(PolicyResponse policy)
    {
        var material = JsonConvert.SerializeObject(new
        {
            policy.Privacy.RequireClientConsent,
            policy.Privacy.AllowOutsideSptScanPaths,
            policy.Privacy.SendFullSnapshotsAfterConsent,
            policy.Privacy.ConsentVersion,
            policy.Disclosure,
            policy.ScanPaths
        });
        using var sha = SHA256.Create();
        return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(material))).Replace("-", "").ToLowerInvariant();
    }
}

public class ConsentState
{
    public bool Accepted { get; set; }
    public bool Declined { get; set; }
    public int ConsentVersion { get; set; }
    public string DisclosureHash { get; set; } = "";
    public DateTime UpdatedAtUtc { get; set; }
}
