# iwant_bypass

Single-file iWantTFC capture / grab / mint / replay / player tool plus an offline
test + analysis suite. No user data is committed.

## Bring your own

Put your own account data in the working folder before use:

- bearer token: `token_template.json` -> `token.txt` (run `python iwant_bypass.py token`)
- identity: `identity_template.json` -> `identity.json` (run `python iwant_bypass.py ident`)
- start templates / captured sessions: `start_template.json`, `sessions/`

## How to get your own data

```
chrome
  -> login        (your Chrome profile, one login)
  -> token        (bearer -> token.txt)
  -> ident        (identity -> identity.json)
  -> grab / routes / capture <player-url>
        -> sessions/<asset>-<vod|live>-*.json + start_template.json
  -> mint <asset> --from-capture --http        (or replay from the session)
        -> mpd + licence + chain in the session
  -> play <session>   (local player)   OR   open the web tester with ?mpd=...&lic=...
```

## Commands

- `chrome`, `login`, `token`, `ident`, `grab`, `routes`, `capture`
- `mint`, `replay`, `plan`, `selftest --live`, `doctor`
- `play` -> local DASH / Widevine player

## Notes

- Entitled content only. Premium titles return EPS 401; not supported.
- Widevine needs a real CDM; attach your own Chrome over CDP.

## Web tester

The stream tester is published on GitHub Pages: https://fleurdeur.github.io/iwanttfc-premium-analysis/

The source lives in `dash_tester.html` in this repo (also at the repo root copy).

### One-time: Enable GitHub Pages

```powershell
# In the repo directory
git checkout main
# Then in GitHub browser:
#   Settings → Pages → Source: main / folder /docs
# Wait ~1 minute, then visit:
#   https://fleurdeur.github.io/iwanttfc-premium-analysis/
```

### Open the tester locally

```powershell
# Option 1: Open directly (uses live demo stream when no ?mpd param)
start https://fleurdeur.github.io/iwanttfc-premium-analysis/

# Option 2: Open with your own stream params
start "https://fleurdeur.github.io/iwanttfc-premium-analysis/?mpd=<your-mpd-url>&lic=<your-license-url>&kind=live"
```

### Auto quick-start behavior

The "Auto: play my stream" button (`bReal`) has three-tier logic:

| Scenario | Result |
|---|---|
| **URL has `?mpd=...&lic=...&kind=live`** | Plays your captured/minted stream (preserved) |
| **No `?mpd=` + Python Flask server running at `localhost:5000`** | XHR fetches `/api/session`, grabs real MPD + DRM license, auto-fills URL/license, starts playback |
| **No `?mpd=` + no Python server** | 🔄 Falls back to public live demo stream → auto-fills URL → starts playback |

#### Running the local Python Flask server (for the middle tier)

```powershell
# In the repo directory
python iwant_bypass.py play

# Then open the tester (the XHR will hit this server)
start https://fleurdeur.github.io/iwanttfc-premium-analysis/
```

The demo buttons work as before:
- **Auto demo: live** → `https://livesim.dashif.org/livesim/testpic_2s/Manifest.mpd`
- **Auto demo: VOD** → `https://dash.akamaized.net/akamai/bbb_30fps/bbb_30fps.mpd`
- **Auto: best quality** → `autoPick=true` mode

## Tests

- `python -m unittest test_iwant_bypass -v`
- `python iwant_bypass.py selftest`
- `python iwant_bypass.py selftest --live`
