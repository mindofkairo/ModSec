using ModSec.Server.Models;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.DI;
using SPTarkov.Server.Core.Helpers;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Models.Eft.Common;
using SPTarkov.Server.Core.Models.Eft.Match;
using SPTarkov.Server.Core.Utils;

namespace ModSec.Server.Services;

[Injectable]
public class ModSecPresenceRouter : StaticRouter
{
    public ModSecPresenceRouter(JsonUtil jsonUtil, ModSecHttpListener httpListener, ProfileHelper profileHelper)
        : base(jsonUtil, GetRoutes(httpListener, profileHelper))
    {
    }

    private static List<RouteAction> GetRoutes(ModSecHttpListener httpListener, ProfileHelper profileHelper)
    {
        return
        [
            new RouteAction<EmptyRequestData>(
                "/client/game/start",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/client/profile/status",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/client/raid/configuration",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/client/match/group/current",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<StartLocalRaidRequestData>(
                "/client/match/local/start",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/fika/presence/get",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/fika/client/check/version",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/fika/client/check/mods",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/fika/client/config",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/fika/natpunchserver/config",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/fika/raid/create",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/fika/raid/gethost",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/fika/raid/join",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/fika/update/addplayer",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/fika/raid/registerPlayer",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output)),
            new RouteAction<EmptyRequestData>(
                "/fika/update/playerspawn",
                (url, info, sessionId, output) => Observe(httpListener, profileHelper, sessionId, url, output))
        ];
    }

    private static ValueTask<string> Observe(ModSecHttpListener httpListener, ProfileHelper profileHelper, MongoId sessionId, string route, string? output)
    {
        return new ValueTask<string>(httpListener.ObserveSptRoute(sessionId, route, output ?? "", GetPlayerName(profileHelper, sessionId)));
    }

    private static string GetPlayerName(ProfileHelper profileHelper, MongoId sessionId)
    {
        try
        {
            return profileHelper.GetFullProfile(sessionId)?.CharacterData?.PmcData?.Info?.Nickname ?? "";
        }
        catch
        {
            return "";
        }
    }
}
