ModSec is a host rule enforcement mod for SPT/Fika servers when your friends are mostly trustworthy… you know, just in case. :)

It checks each client's SPT mod/config setup against rules chosen by the server host, then warns, blocks raid access, issues local strikes, or applies a local server lockout depending on your config. It is not an official SPT anti-cheat, it does not talk to Forge, and it does not pretend to be the police. It is more like a bouncer for your private server who reads hashes instead of vibes.

Go protect your raids, king.

![modsec-screenshot-security-alert](https://i.imgur.com/F5EQdXB.png)

### Overview

ModSec helps server hosts enforce private server rules for client mods and config values.

Stuff it can do:

- Require players to have the ModSec BepInEx client plugin installed before entering raid.
- Block or warn on specific BepInEx plugin GUIDs.
- Block/allow files by SHA-256 hash (renaming won’t save you, smart guy)
- Run allow list only mode so only approved client assemblies are allowed.
- Check selected `.cfg` or `.json` config values.
- Block raid start/join routes when the current profile is on timeout. :(
- Live checks without restarting the game.
- Apply local strikes with configurable cooldown/decay.
- Apply local server lockouts after too many strikes.
- Show in-game dialogs and toast notifications.
- Let admins send live popups/toasts to one player or everyone.
- Safely extract other Fika players when a restricted raid host is removed.
- Send configurable "Hall of Shame" in-game messages through the SPT dialogue system.
- Provide an admin dashboard for players, events, policy editing, file hashes, popups, imports, exports, and diagnostics.

The default setup is allow list mode; only approved client plugin assemblies are allowed, and anything else can block raid access until the host approves it.

---

#### What ModSec is
- Host rule enforcement
- Raid access protection
- Local server restrictions
- SPT folder integrity checks

#### What ModSec is **NOT**
- Global anti cheat
- SPT/Forge moderation
- A cheater database
- Whole computer scanning

## Support

If you have issues, bugs, weird behavior, policy ideas, or just need to tell me I named something stupid, contact me on Discord: **kairosmind**

