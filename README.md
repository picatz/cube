# cube
> Chrome URL Blocking Extension

This is a custom [Google Chrome](https://www.google.com/chrome/) extension that blocks network requests matching a predefined set of URL patterns.

## Installation

1. Clone this repository, so it exists locally: `$ git clone https://github.com/picatz/cube.git`
2. In your browser, open the Extension Management page by navigating to `chrome://extensions` or by clicking on the Chrome menu, hovering over More Tools then selecting Extensions.
3. Enable Developer Mode by clicking the toggle switch next to Developer mode.
4. Click the LOAD UNPACKED button and select the extension directory (this repository, where it was cloned to).

## How does it work?

`cube` is a Manifest V3 extension that uses Chrome’s [declarativeNetRequest](https://developer.chrome.com/docs/extensions/reference/declarativeNetRequest/) API.

The block list lives in `rules.json`, which is loaded by `manifest.json` as a static ruleset. Chrome applies these rules to matching requests.

By default, `cube` is privacy-first:
- The block ruleset is enabled.
- Optional allow rulesets (compatibility exceptions / support widget allowlist) are disabled unless you explicitly enable them in the popup.

### Regenerating rulesets

The rulesets are generated from Adblock Plus-style filter lists (currently EasyList + EasyPrivacy) via a small Go program:

```bash
go run ./tools/rulegen
```

Useful flags:
- `-max-rules 30000` to cap the output size.
- `-blocks-shards 4` to write multiple block rulesets (`rules.json`, `rules.2.json`, ...).
- `-source name=url` (repeatable) to add/replace filter list sources.
- `-exceptions none|scoped|all` controls which upstream exception rules are emitted into `rules.exceptions.json` (the default is `scoped`).
- `-builtin-allowlist=false` disables generating the small support-widget allowlist ruleset.
- `-allow-domain example.com` (repeatable) adds domains to the generated allowlist ruleset.

Generated files:
- `rules.json` (blocks shard 1)
- `rules.2.json` (blocks shard 2)
- `rules.3.json` (blocks shard 3)
- `rules.4.json` (blocks shard 4)
- `rules.exceptions.json` (allow rules derived from upstream exceptions; disabled by default)
- `rules.allowlist.json` (allow rules for support widgets; disabled by default)

### Customizing without reload

Open the extension popup to:
- Enable/disable `cube`
- Toggle the optional allow rulesets
- Add/remove domains from a per-domain allowlist (implemented as dynamic DNR allow rules)
- Add/remove domains from a per-domain blocklist (implemented as dynamic DNR block rules)
- Optionally enable diagnostics logging to see recent rule matches (requires granting the optional `declarativeNetRequestFeedback` permission; per Chrome docs this is for debugging/unpacked extensions)

For example, to block requests to `microsoft.com`:

```javascript
[
  {
    "id": 1,
    "priority": 1,
    "action": { "type": "block" },
    "condition": {
      "urlFilter": "*://*.microsoft.com/*",
      "excludedResourceTypes": ["main_frame"]
    }
  }
]
```

Notes:
- Rule `id`s must be unique.
- `excludedResourceTypes: ["main_frame"]` avoids breaking navigation to these domains while still blocking subresource requests (ads, pixels, scripts, etc.).
