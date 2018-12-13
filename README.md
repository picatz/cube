# cube
> Chrome URL Blocking Extension

This is a custom [Google Chrome](https://www.google.com/chrome/) extension that blocks pre-determined [URL](https://en.wikipedia.org/wiki/URL)s.

## Installation

1. Clone this repository, so it exists locally: `$ git clone https://github.com/picatz/cube.git`
2. In your browser, open the Extension Management page by navigating to `chrome://extensions` or by clicking on the Chrome menu, hovering over More Tools then selecting Extensions.
3. Enable Developer Mode by clicking the toggle switch next to Developer mode.
4. Click the LOAD UNPACKED button and select the extension directory (this repository, where it was cloned to).

## How does it work?

The chrome browser exposes a [webRequest](https://developer.chrome.com/extensions/webRequest) API that enables plugin developers to observe and analyze traffic and to intercept, block, or modify requests in-flight. This makes it almost trivial to develop a URL blocking extension, which is exactly what `cube` does.

For example, if we wanted to block requests to `microsoft.com`:

```javascript
chrome.webRequest.onBeforeRequest.addListener(
  function(details) { return {cancel: true}; },
  { urls: ["*://*.microsoft.com/*"] },
  ["blocking"]
);
```
