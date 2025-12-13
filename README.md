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
