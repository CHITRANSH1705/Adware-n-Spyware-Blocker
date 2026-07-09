# WARDEN — Adware & Spyware Blocker

A Chrome (Manifest V3) extension that blocks known ad/tracker requests at
the network level, safely removes ad/spyware DOM injections, and flags
third-party scripts that attach keystroke listeners.

## Why this is a rewrite, not a patch

The v1 version looked reasonable on the surface but had four bugs serious
enough that it either did nothing or actively broke the pages it ran on:

1. **The network blocker never worked.** `background.js` called
   `chrome.webRequest.onBeforeRequest.addListener(..., ["blocking"])`.
   Blocking `webRequest` was removed for regular extensions in Manifest V3
   — the README even says it uses `declarativeNetRequest`, but the actual
   code never did. In real Chrome this either silently fails to register
   or throws, so the entire "blocks 40+ ad/tracker domains" feature was
   not running at all.
2. **The DOM cleanup deleted real page content.** `[id*='ad']` and
   `[class*='ad']` match `id`/`class` as a raw substring — and "ad" is
   hiding inside `header`, `already`, `load`, `read`, `shadow`, `grade`,
   `upload`, `gradient`, and plenty of other completely ordinary words.
   Any site using conventional class names like `id="header"` or
   `class="load-more"` would have those elements silently deleted.
3. **`alert()` every 3 seconds.** `showAlert()` ran on a `setInterval`,
   so any page that tripped the (over-broad) selectors would nag with a
   blocking native dialog indefinitely — on top of the content it had
   already broken.
4. **The keylogger check matched the word "log."** It flagged any
   `onkeydown`/`onkeypress` attribute containing "log" — which also
   matches `login`, `dialog`, `catalog`, and `toggleLogin`. It would
   rarely, if ever, catch an actual keylogger, and would routinely misfire
   on ordinary form handlers.

Rather than patch around each symptom, this is a rewrite of the detection
and blocking engine, keeping the original's intent intact.

## What's new in v2

- **Real network-level blocking** via a `declarativeNetRequest` static
  ruleset (`rules/ads-trackers.json`), generated from a single
  `blocklist.json` source of truth — the MV3-correct replacement for the
  broken blocking `webRequest` call.
- **Precise DOM removal.** Two tiers:
  - *Precise signatures* (`ins.adsbygoogle`, `div[id^='div-gpt-ad']`,
    known ad-network iframe/script sources, etc.) — safe to remove
    anywhere in the document.
  - *Heuristic token match*, rewritten to require "ad"/"track"/etc. as its
    own word (bounded by start/end/hyphen/underscore/space, not a raw
    substring) **and** restricted to the tags that actually deliver
    ads/trackers (`script`, `img`, `iframe`, `ins`) — never applied to
    layout containers like `div`/`header`/`nav`, which is what broke page
    structure before.
  - A dimension-based tracking-pixel check (`1×1` images) instead of a
    `src` filename guess.
- **A real keylogger heuristic.** Inline `onkeydown`/`onkeypress`/
  `onkeyup`/`oninput` handlers are only flagged when they contain an
  actual exfiltration call (`fetch(`, `XMLHttpRequest`, `.send(`,
  `sendBeacon`, `new Image().src =`) — a real indicator instead of a
  coincidental word match.
- **Detection (not removal) of third-party keystroke listeners.** A
  MAIN-world script wraps `addEventListener` before any page script runs,
  and flags — without ever touching — third-party code that attaches
  `keydown`/`keyup`/`keypress`/`input` listeners to `document`, `window`,
  or form fields. This is reported as a signal in the popup, not auto-
  removed, because plenty of legitimate code (password managers, input
  masks, chat widgets) listens to keystrokes for reasons that have
  nothing to do with spying — a content script can't reliably tell intent
  from a stack trace alone, so WARDEN surfaces it instead of guessing.
- **No more `alert()` spam.** A cyberpunk-terminal popup shows live counts
  instead (network blocked / DOM removed / scripts flagged), plus a
  lifetime total.
- **Global on/off + per-site allowlist**, both enforced in two places at
  once: a `declarativeNetRequest` dynamic `allow` rule (network requests)
  and a `chrome.storage` flag the content script checks before touching
  the DOM (so "Trust this site" actually restores full functionality, not
  just network requests).
- **`MutationObserver` instead of a 3-second poll** — catches
  dynamically-injected ads/trackers as they appear instead of re-scanning
  the whole document on a timer.
- Proper multi-size icon set (16/32/48/128) instead of one oversized,
  unoptimized 372×372 PNG.

## Install (unpacked, for development/testing)

1. `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select this folder.
3. Requires Chrome 111+ (for the `"world": "MAIN"` content script field).

## Architecture

```
                    ┌─ page-hook.js (MAIN world, document_start)
                    │   wraps addEventListener, flags 3rd-party keystroke
                    │   listeners via postMessage — detection only
                    │
   popup.js ──msg──▶│  background.js
      ▲             │   - counts observed requests matching blocklist.json
      │             │     (webRequest, NON-blocking — just for the badge/
      │             │     stats; actual blocking is declarativeNetRequest)
      │             │   - manages ruleset on/off + per-site allow rules
      └─ live stats ┤   - relays content.js's DOM counts to the badge
                    │
                    └─ content.js (isolated world, document_start)
                        - tiered DOM cleanup (precise + heuristic)
                        - inline-handler exfiltration check
                        - relays page-hook.js flags to background.js
```

Network blocking (`declarativeNetRequest`) and DOM cleanup (`content.js`)
are independent layers — either can be disabled without touching the
other, and the popup's global toggle disables both together.

## Permissions

| Permission | Why |
|---|---|
| `declarativeNetRequest` | The actual network-level blocking mechanism |
| `webRequest` | Observation only (no `"blocking"`) — counts matches for the badge/popup |
| `storage` | Protection on/off, per-site allowlist, lifetime counter |
| `scripting`, `tabs`, `activeTab` | Popup ↔ tab messaging |
| `host_permissions: <all_urls>` | Content scripts need to run on any site |

## Known limitations

- The blocklist (`blocklist.json`) is a curated list of well-known
  ad/tracking domains, not an exhaustive filter list like EasyList — it
  won't catch everything a dedicated ad blocker would.
- The keystroke-listener flag is a **signal, not a verdict**. It reports
  third-party code that *can* observe keystrokes; it does not prove
  malicious intent, and it deliberately never removes the listener, since
  doing so could break legitimate site functionality.
- Modern keyloggers overwhelmingly use `addEventListener` rather than
  inline HTML attributes; the inline-handler check only catches the
  (now rare) latter case, which is why the MAIN-world detector above
  exists as the primary defense for the former.
- Blocking a domain that turns out to be load-bearing for a site can
  break that site — use "Trust this site" to disable both layers there.

## File structure

```
manifest.json           MV3 manifest — DNR ruleset registration, both content scripts
background.js           Badge/stats, DNR ruleset + allowlist management
content.js               Tiered DOM cleanup, inline-handler check (isolated world)
page-hook.js             addEventListener wrapper, keystroke-listener detector (MAIN world)
blocklist.json           Single source of truth for blocked domains
rules/ads-trackers.json  Generated declarativeNetRequest ruleset (do not hand-edit)
popup.html/.css/.js      Popup UI
icons/                   Generated toolbar icons (16/32/48/128)
tools/build_rules.py     Regenerates rules/ads-trackers.json from blocklist.json
tools/make_icons.py      Regenerates icons/ if you want to restyle them
```

After editing `blocklist.json`, regenerate the ruleset:

```
python3 tools/build_rules.py
```

## Disclaimer

This extension is for educational and ethical use. It does not guarantee
complete protection from all threats, and the keystroke-listener flag in
particular should be treated as a lead to investigate, not a confirmed
detection. Use alongside a trusted antivirus/anti-malware tool.
