using System.Reflection;
using ModSec.Server.Models;
using ModSec.Server.Services;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.DI;
using SPTarkov.Server.Core.Helpers;
using SPTarkov.Server.Core.Models.Spt.Mod;
using Range = SemanticVersioning.Range;
using Version = SemanticVersioning.Version;

namespace ModSec.Server;

public record ModMetadata : AbstractModMetadata
{
    public override string ModGuid { get; init; } = ModSecConstants.ServerGuid;
    public override string Name { get; init; } = "ModSec (Server)";
    public override string Author { get; init; } = "kairo";
    public override Version Version { get; init; } = new(ModSecConstants.Version);
    public override Range SptVersion { get; init; } = new("~4.0.0");
    public override string License { get; init; } = "MIT";
    public override bool? IsBundleMod { get; init; } = false;
    public override Dictionary<string, Range>? ModDependencies { get; init; }
    public override string? Url { get; init; }
    public override List<string>? Contributors { get; init; }
    public override List<string>? Incompatibilities { get; init; }
}

[Injectable(TypePriority = OnLoadOrder.PostDBModLoader + 1)]
public class ModSecServer(
    ModHelper modHelper,
    ModSecConfigService configService,
    ModSecHttpListener httpListener) : IOnLoad
{
    public Task OnLoad()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var modPath = modHelper.GetAbsolutePathToModFolder(assembly);

        configService.Initialize(modPath);
        httpListener.Initialize(modPath);

        Console.WriteLine($"[ModSec] Server loaded v{ModSecConstants.Version}");
        return Task.CompletedTask;
    }
}
