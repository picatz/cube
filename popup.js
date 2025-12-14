const STORAGE_DEFAULTS = {
  cubeEnabled: true,
  exceptionsEnabled: false,
  builtinAllowlistEnabled: false,
  logEnabled: false,

  allowDomains: [],
  blockDomains: [],
  bypassSites: [],
  scopedAllows: [],
  tempAllowDomains: [],
  tempBypassSites: [],
  tempBypassTabs: [],
  tempScopedAllows: [],

  // Internal bookkeeping used by the service worker for stable dynamic rule IDs.
  allowDomainIds: {},
  blockDomainIds: {},
  bypassSiteIds: {},
  scopedAllowIds: {},
  tempAllowDomainIds: {},
  tempBypassSiteIds: {},
  tempBypassTabIds: {},
  tempScopedAllowIds: {},

  // Diagnostics ring buffer (only populated when logging is enabled).
  recentMatches: [],

  // Last DNR API error message (best-effort; used for troubleshooting).
  lastDnrError: "",
};

document.addEventListener("DOMContentLoaded", () => {
  let statusCopyText = "";
  let statusCopyResetTimer = null;
  let toastTimer = null;
  const DEFAULT_TEMP_MINUTES = 15;
  const els = {
    brandMark: document.querySelector(".brandMark"),
    brandMarkCube: document.querySelector(".brandMarkCube"),
    toggleEnabled: document.getElementById("toggleEnabled"),
    toggleExceptions: document.getElementById("toggleExceptions"),
    toggleBuiltinAllowlist: document.getElementById("toggleBuiltinAllowlist"),
    toggleLogging: document.getElementById("toggleLogging"),
    resetDefaults: document.getElementById("resetDefaults"),

    allowForm: document.getElementById("allowForm"),
    allowInput: document.getElementById("allowInput"),
    allowList: document.getElementById("allowList"),

    blockForm: document.getElementById("blockForm"),
    blockInput: document.getElementById("blockInput"),
    blockList: document.getElementById("blockList"),

    bypassTab15m: document.getElementById("bypassTab15m"),
    bypassSite15m: document.getElementById("bypassSite15m"),
    bypassSiteAlways: document.getElementById("bypassSiteAlways"),
    reloadTab: document.getElementById("reloadTab"),
    bypassActive: document.getElementById("bypassActive"),
    bypassList: document.getElementById("bypassList"),
    scopedAllowList: document.getElementById("scopedAllowList"),

    clearActivity: document.getElementById("clearActivity"),
    activityScope: document.getElementById("activityScope"),
    activityFilter: document.getElementById("activityFilter"),
    activityHelp: document.getElementById("activityHelp"),
    activityNotice: document.getElementById("activityNotice"),
    activitySummary: document.getElementById("activitySummary"),
    activityList: document.getElementById("activityList"),

    runtimeStatus: document.getElementById("runtimeStatus"),
    statusInline: document.getElementById("statusInline"),
    copyStatus: document.getElementById("copyStatus"),
    status: document.getElementById("status"),
  };

  let brandMarkHoverAt = 0;
  let cubeRotX = -28;
  let cubeRotY = 45;
  let cubeRotZ = 0;

  function prefersReducedMotion() {
    try {
      return !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
    } catch {
      return false;
    }
  }

  function applyCubeTransform(durationMs) {
    if (!els.brandMark || !els.brandMarkCube) return;
    if (prefersReducedMotion()) return;
    if (Number.isFinite(durationMs)) els.brandMark.style.setProperty("--cubeDur", `${Math.max(0, durationMs)}ms`);
    els.brandMarkCube.style.transform = `rotateX(${cubeRotX}deg) rotateY(${cubeRotY}deg) rotateZ(${cubeRotZ}deg)`;
  }

  function turnCube(kind) {
    if (!els.brandMark || !els.brandMarkCube) return;
    if (prefersReducedMotion()) return;

    const baseJitter = () => (Math.random() * 2 - 1);
    const bump = (v, min, max) => Math.max(min, Math.min(max, v));

    let durationMs = 680;
    if (kind === "open") {
      cubeRotY += 18;
      cubeRotX += -2;
      cubeRotZ += baseJitter() * 1.5;
      durationMs = 760;
    } else if (kind === "hover") {
      cubeRotY += Math.random() < 0.5 ? 90 : -90;
      cubeRotX = bump(cubeRotX + baseJitter() * 4, -42, -16);
      cubeRotZ = bump(cubeRotZ + baseJitter() * 4, -14, 14);
      durationMs = 660;
    } else {
      cubeRotY += 180;
      cubeRotX = bump(cubeRotX + baseJitter() * 7, -46, -12);
      cubeRotZ = bump(cubeRotZ + baseJitter() * 10, -20, 20);
      durationMs = 840;
    }

    applyCubeTransform(durationMs);
  }

  function setStatus(text) {
    if (!els.status) return;
    const v = String(text || "").trim();
    if (toastTimer) {
      clearTimeout(toastTimer);
      toastTimer = null;
    }
    if (!v) {
      els.status.textContent = "";
      els.status.classList.remove("isVisible");
      return;
    }
    els.status.textContent = v;
    els.status.classList.add("isVisible");
    toastTimer = setTimeout(() => {
      els.status.classList.remove("isVisible");
      toastTimer = null;
    }, 2200);
  }

  function setRuntimeStatus(text) {
    statusCopyText = text || "";
  }

  function storageGet(cb) {
    chrome.storage.local.get(STORAGE_DEFAULTS, cb);
  }

  function storageSet(obj, cb) {
    chrome.storage.local.set(obj, cb);
  }

  function requestSync(cb) {
    chrome.runtime.sendMessage({ type: "sync" }, () => {
      void chrome.runtime.lastError;
      if (typeof cb === "function") cb();
    });
  }

  function dnrGetEnabledRulesets(cb) {
    const fn = chrome.declarativeNetRequest && chrome.declarativeNetRequest.getEnabledRulesets;
    if (!fn) return cb([]);
    try {
      const maybePromise = fn((ids) => cb(ids || []));
      if (maybePromise && typeof maybePromise.then === "function") {
        maybePromise.then((ids) => cb(ids || [])).catch(() => cb([]));
      }
    } catch {
      cb([]);
    }
  }

  function dnrGetDynamicRulesCount(cb) {
    const fn = chrome.declarativeNetRequest && chrome.declarativeNetRequest.getDynamicRules;
    if (!fn) return cb(0);
    try {
      const maybePromise = fn((rules) => cb((rules || []).length));
      if (maybePromise && typeof maybePromise.then === "function") {
        maybePromise.then((rules) => cb((rules || []).length)).catch(() => cb(0));
      }
    } catch {
      cb(0);
    }
  }

  function dnrGetSessionRulesCount(cb) {
    const fn = chrome.declarativeNetRequest && chrome.declarativeNetRequest.getSessionRules;
    if (!fn) return cb(0);
    try {
      const maybePromise = fn((rules) => cb((rules || []).length));
      if (maybePromise && typeof maybePromise.then === "function") {
        maybePromise.then((rules) => cb((rules || []).length)).catch(() => cb(0));
      }
    } catch {
      cb(0);
    }
  }

  function permissionsContains(name, cb) {
    if (!chrome.permissions || !chrome.permissions.contains) return cb(false);
    chrome.permissions.contains({ permissions: [name] }, (ok) => cb(!!ok));
  }

  function makeBadge(text, tone) {
    const badge = document.createElement("span");
    badge.className = ["badge", tone ? `badge${tone}` : ""].filter(Boolean).join(" ");

    const dot = document.createElement("span");
    dot.className = "badgeDot";

    const label = document.createElement("span");
    label.textContent = String(text || "");

    badge.appendChild(dot);
    badge.appendChild(label);
    return badge;
  }

  function renderInlineStatus(badges, metricsText) {
    els.statusInline.innerHTML = "";

    const row = document.createElement("div");
    row.className = "statusInlineRow";
    for (const b of Array.isArray(badges) ? badges : []) {
      if (b instanceof Node) row.appendChild(b);
    }
    els.statusInline.appendChild(row);

    const text = String(metricsText || "").trim();
    if (!text) return;
    const metrics = document.createElement("div");
    metrics.className = "statusInlineMetrics";
    metrics.textContent = text;
    els.statusInline.appendChild(metrics);
  }

  function refreshRuntimeStatus(settings) {
    dnrGetEnabledRulesets((ids) => {
      dnrGetDynamicRulesCount((dynCount) => {
        dnrGetSessionRulesCount((sessCount) => {
          permissionsContains("declarativeNetRequestFeedback", (hasFeedback) => {
          const enabled = settings.cubeEnabled ? "on" : "off";
          const enabledIds = Array.isArray(ids) ? ids : [];
          const rulesetsJoined = enabledIds.length ? enabledIds.join(", ") : "(none)";
          const fb = hasFeedback ? "on" : "off";

          const expectedBlocks = ["rules_block_1", "rules_block_2", "rules_block_3", "rules_block_4"];
          const blockEnabled = expectedBlocks.filter((x) => enabledIds.includes(x)).length;
          const missing = settings.cubeEnabled ? expectedBlocks.filter((x) => !enabledIds.includes(x)) : [];

          const health =
            settings.lastDnrError
              ? { label: "Error", tone: "Err" }
              : settings.cubeEnabled && missing.length
                ? { label: "Degraded", tone: "Warn" }
                : settings.cubeEnabled
                  ? { label: "Healthy", tone: "On" }
                  : { label: "Off", tone: "Off" };

          // Inline summary (always visible).
          const totalCustom = (dynCount || 0) + (sessCount || 0);
          const inlineBadges = [
            makeBadge(settings.cubeEnabled ? "On" : "Off", settings.cubeEnabled ? "On" : "Off"),
            makeBadge(health.label, health.tone),
          ];
          const inlineMetrics = [];
          if (settings.cubeEnabled) inlineMetrics.push(`Block ${blockEnabled}/${expectedBlocks.length}`);
          if (totalCustom) inlineMetrics.push(`Custom ${totalCustom}`);
          const bypassActive =
            (settings.bypassSites || []).length ||
            normalizeTempSites(settings.tempBypassSites).length ||
            normalizeTempTabs(settings.tempBypassTabs).length;
          if (bypassActive) inlineMetrics.push("Bypass active");
          if (fb === "off") inlineMetrics.push("Feedback off");
          renderInlineStatus(inlineBadges, inlineMetrics.join(" · "));

          // Expanded details.
          els.runtimeStatus.innerHTML = "";
          const grid = document.createElement("div");
          grid.className = "statusGrid";

          const addRow = (k, v, cls) => {
            const kk = document.createElement("div");
            kk.className = "statusKey";
            kk.textContent = k;
            const vv = document.createElement("div");
            vv.className = `statusVal${cls ? " " + cls : ""}`;
            if (v instanceof Node) vv.appendChild(v);
            else vv.textContent = String(v || "");
            grid.appendChild(kk);
            grid.appendChild(vv);
          };

          addRow("Health", makeBadge(health.label, health.tone));
          addRow("Cube", makeBadge(enabled, settings.cubeEnabled ? "On" : "Off"));

          if (settings.cubeEnabled) {
            const col = document.createElement("div");
            col.className = "statusValCol";
            col.appendChild(makeBadge(`${blockEnabled}/${expectedBlocks.length} enabled`, missing.length ? "Warn" : "On"));
            if (missing.length) {
              const sub = document.createElement("div");
              sub.className = "statusSubtext";
              sub.textContent = `Missing: ${missing.join(", ")}`;
              col.appendChild(sub);
            }
            addRow("Block shards", col);
          }

          addRow("Diagnostics logging", makeBadge(settings.logEnabled ? "on" : "off", settings.logEnabled ? "On" : "Off"));
          addRow("Compatibility exceptions", makeBadge(settings.exceptionsEnabled ? "on" : "off", settings.exceptionsEnabled ? "Warn" : "Off"));
          addRow("Support allowlist", makeBadge(settings.builtinAllowlistEnabled ? "on" : "off", settings.builtinAllowlistEnabled ? "Warn" : "Off"));

          const allowN = (settings.allowDomains || []).length || 0;
          const blockN = (settings.blockDomains || []).length || 0;
          const bypassN = (settings.bypassSites || []).length || 0;
          const scopedN = (settings.scopedAllows || []).length || 0;

          const tempAllowN = normalizeTempDomains(settings.tempAllowDomains).length;
          const tempBypassSiteN = normalizeTempSites(settings.tempBypassSites).length;
          const tempBypassTabN = normalizeTempTabs(settings.tempBypassTabs).length;
          const tempScopedN = normalizeTempScopedAllows(settings.tempScopedAllows).length;

          const permCounts = [`allow:${allowN}`, `block:${blockN}`, `bypass:${bypassN}`, `scoped:${scopedN}`].join(", ");
          let customCounts = `perm(${permCounts})`;
          if (tempAllowN || tempBypassSiteN || tempBypassTabN || tempScopedN) {
            const tempCounts = [`allow:${tempAllowN}`, `bypassSite:${tempBypassSiteN}`, `bypassTab:${tempBypassTabN}`, `scoped:${tempScopedN}`].join(", ");
            customCounts += ` temp(${tempCounts})`;
          }

          const customCol = document.createElement("div");
          customCol.className = "statusValCol";
          customCol.appendChild(
            makeBadge(
              `${totalCustom} ${totalCustom === 1 ? "rule" : "rules"}`,
              totalCustom ? (tempBypassTabN || tempBypassSiteN || tempAllowN ? "Warn" : "On") : "Off"
            )
          );

          const permLine = document.createElement("div");
          permLine.className = "statusSubtext";
          const permParts = [];
          if (allowN) permParts.push(`${allowN} allow`);
          if (blockN) permParts.push(`${blockN} block`);
          if (bypassN) permParts.push(`${bypassN} site bypass`);
          if (scopedN) permParts.push(`${scopedN} scoped allow`);
          permLine.textContent = permParts.length ? `Permanent: ${permParts.join(" · ")}` : "Permanent: none";
          customCol.appendChild(permLine);

          if (tempAllowN || tempBypassSiteN || tempBypassTabN || tempScopedN) {
            const tempLine = document.createElement("div");
            tempLine.className = "statusSubtext";
            const tempParts = [];
            if (tempAllowN) tempParts.push(`${tempAllowN} allow`);
            if (tempBypassSiteN) tempParts.push(`${tempBypassSiteN} site bypass`);
            if (tempBypassTabN) tempParts.push(`${tempBypassTabN} tab bypass`);
            if (tempScopedN) tempParts.push(`${tempScopedN} scoped allow`);
            tempLine.textContent = `Temporary: ${tempParts.join(" · ")}`;
            customCol.appendChild(tempLine);
          }

          if (sessCount) {
            const sessionLine = document.createElement("div");
            sessionLine.className = "statusSubtext";
            sessionLine.textContent = `Session rules: ${sessCount}`;
            customCol.appendChild(sessionLine);
          }

          addRow("Custom rules", customCol);

          addRow("Feedback permission", makeBadge(fb, hasFeedback ? "On" : "Off"));

          const chips = document.createElement("div");
          chips.className = "chips";
          if (!enabledIds.length) {
            const none = document.createElement("span");
            none.className = "statusSubtext";
            none.textContent = "(none)";
            chips.appendChild(none);
          } else {
            for (const id of enabledIds.slice(0, 12)) {
              const chip = document.createElement("span");
              chip.className = "chip";
              chip.textContent = id;
              chips.appendChild(chip);
            }
          }
          addRow("Enabled rulesets", chips);

          if (settings.lastDnrError) addRow("Last error", settings.lastDnrError, "warn wrap");

          els.runtimeStatus.appendChild(grid);

          // Copy-friendly plain text.
          const lines = [];
          lines.push(`health: ${health.label.toLowerCase()}`);
          lines.push(`cube: ${enabled}`);
          if (settings.cubeEnabled) lines.push(`block shards: ${blockEnabled}/${expectedBlocks.length}${missing.length ? ` (missing: ${missing.join(", ")})` : ""}`);
          lines.push(`diagnostics logging: ${settings.logEnabled ? "on" : "off"}`);
          lines.push(`compatibility exceptions: ${settings.exceptionsEnabled ? "on" : "off"}`);
          lines.push(`support allowlist: ${settings.builtinAllowlistEnabled ? "on" : "off"}`);
          lines.push(`custom rules: ${totalCustom} (dynamic:${dynCount}, session:${sessCount}) ${customCounts}`);
          lines.push(`feedback permission: ${fb}`);
          lines.push(`enabled rulesets: ${rulesetsJoined}`);
          if (settings.lastDnrError) lines.push(`last error: ${settings.lastDnrError}`);
          setRuntimeStatus(lines.join("\n"));
          });
        });
      });
    });
  }

  function getDiagnosticsStatus(cb) {
    chrome.runtime.sendMessage({ type: "diagnosticsStatus" }, (resp) => {
      const err = chrome.runtime.lastError;
      if (err || !resp || typeof resp !== "object") {
        cb({ ok: false, supported: false, hasFeedback: false });
        return;
      }
      cb(resp);
    });
  }

  function resetToDefaults() {
    const fresh = {
      cubeEnabled: true,
      exceptionsEnabled: false,
      builtinAllowlistEnabled: false,
      logEnabled: false,

      allowDomains: [],
      blockDomains: [],
      bypassSites: [],
      scopedAllows: [],
      tempAllowDomains: [],
      tempBypassSites: [],
      tempBypassTabs: [],
      tempScopedAllows: [],

      allowDomainIds: {},
      blockDomainIds: {},
      bypassSiteIds: {},
      scopedAllowIds: {},
      tempAllowDomainIds: {},
      tempBypassSiteIds: {},
      tempBypassTabIds: {},
      tempScopedAllowIds: {},
      recentMatches: [],
      lastDnrError: "",
    };
    storageSet(fresh, () => {
      requestSync();
      setStatus("Defaults restored");
      refresh();
    });
  }

  function normalizeDomain(input) {
    let v = (input || "").trim().toLowerCase();
    if (!v) return "";
    v = v.replace(/^\.+/, "").replace(/\.+$/, "");

    // Accept a full URL and extract hostname.
    if (v.includes("://")) {
      try {
        const u = new URL(v);
        v = u.hostname || "";
      } catch {
        return "";
      }
    }

    // Strip path/query/fragment if user pasted `example.com/path`.
    v = v.split("/")[0].split("?")[0].split("#")[0];
    // Strip port.
    v = v.split(":")[0];

    if (!v || v.includes(" ") || v.includes("\t")) return "";
    return v;
  }

  function hostMatchesDomain(hostRaw, domainRaw) {
    const host = normalizeDomain(hostRaw);
    const domain = normalizeDomain(domainRaw);
    if (!host || !domain) return false;
    return host === domain || host.endsWith(`.${domain}`);
  }

  function uniqSorted(list) {
    const out = Array.from(new Set(Array.isArray(list) ? list : [])).filter(Boolean);
    out.sort();
    return out;
  }

  function normalizeScopedAllows(list) {
    const out = [];
    const seen = new Set();
    for (const item of Array.isArray(list) ? list : []) {
      if (!item || typeof item !== "object") continue;
      const site = normalizeDomain(item.site);
      const domain = normalizeDomain(item.domain);
      if (!site || !domain) continue;
      const key = `${site}@@${domain}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ site, domain });
    }
    out.sort((a, b) => (a.site === b.site ? a.domain.localeCompare(b.domain) : a.site.localeCompare(b.site)));
    return out;
  }

  function tryParseHostname(raw) {
    if (!raw) return "";
    try {
      return new URL(raw).hostname || "";
    } catch {
      return "";
    }
  }

  function getCurrentSiteHostname(cb) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = (tabs || [])[0];
      const host = tab && typeof tab.url === "string" ? tryParseHostname(tab.url) : "";
      cb(host);
    });
  }

  function nowMs() {
    return Date.now();
  }

  function minutesFromNow(mins) {
    return nowMs() + Math.max(1, mins) * 60 * 1000;
  }

  function formatExpires(expiresAt) {
    if (!expiresAt) return "";
    const delta = expiresAt - nowMs();
    if (delta <= 0) return "expired";
    const mins = Math.round(delta / 60000);
    const hhmm = (() => {
      try {
        return new Date(expiresAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      } catch {
        return "";
      }
    })();
    return hhmm ? `until ${hhmm} (~${mins}m)` : `~${mins}m`;
  }

  function normalizeTempDomains(list) {
    const out = [];
    const seen = new Set();
    for (const item of Array.isArray(list) ? list : []) {
      if (!item || typeof item !== "object") continue;
      const domain = normalizeDomain(item.domain);
      const exp = typeof item.expiresAt === "number" ? item.expiresAt : 0;
      if (!domain || !exp || exp <= nowMs()) continue;
      const key = `${domain}@@${exp}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ domain, expiresAt: exp });
    }
    out.sort((a, b) => a.domain.localeCompare(b.domain) || a.expiresAt - b.expiresAt);
    return out;
  }

  function normalizeTempSites(list) {
    const out = [];
    const seen = new Set();
    for (const item of Array.isArray(list) ? list : []) {
      if (!item || typeof item !== "object") continue;
      const site = normalizeDomain(item.site);
      const exp = typeof item.expiresAt === "number" ? item.expiresAt : 0;
      if (!site || !exp || exp <= nowMs()) continue;
      const key = `${site}@@${exp}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ site, expiresAt: exp });
    }
    out.sort((a, b) => a.site.localeCompare(b.site) || a.expiresAt - b.expiresAt);
    return out;
  }

  function normalizeTempTabs(list) {
    const out = [];
    const seen = new Set();
    for (const item of Array.isArray(list) ? list : []) {
      if (!item || typeof item !== "object") continue;
      const tabId = typeof item.tabId === "number" ? item.tabId : -1;
      const exp = typeof item.expiresAt === "number" ? item.expiresAt : 0;
      const host = normalizeDomain(item.host);
      if (tabId < 0 || !exp || exp <= nowMs()) continue;
      const key = `${tabId}@@${exp}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ tabId, host, expiresAt: exp });
    }
    out.sort((a, b) => a.tabId - b.tabId || a.expiresAt - b.expiresAt);
    return out;
  }

  function normalizeTempScopedAllows(list) {
    const out = [];
    const seen = new Set();
    for (const item of Array.isArray(list) ? list : []) {
      if (!item || typeof item !== "object") continue;
      const site = normalizeDomain(item.site);
      const domain = normalizeDomain(item.domain);
      const exp = typeof item.expiresAt === "number" ? item.expiresAt : 0;
      if (!site || !domain || !exp || exp <= nowMs()) continue;
      const key = `${site}@@${domain}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ site, domain, expiresAt: exp });
    }
    out.sort((a, b) => (a.site === b.site ? a.domain.localeCompare(b.domain) : a.site.localeCompare(b.site)));
    return out;
  }

  function addTempBypassSite(siteRaw, mins) {
    const site = normalizeDomain(siteRaw);
    if (!site) {
      setStatus("No active site");
      return;
    }
    const expiresAt = minutesFromNow(mins);
    storageGet((cur) => {
      const next = normalizeTempSites([...(cur.tempBypassSites || []), { site, expiresAt }]);
      storageSet({ tempBypassSites: next }, () => {
        requestSync(() => {
          setStatus(`Bypass enabled for ${site} (${formatExpires(expiresAt)})`);
          refresh();
          reloadActiveTab({ quiet: true });
        });
      });
    });
  }

  function removeTempBypassSite(siteRaw) {
    const site = normalizeDomain(siteRaw);
    storageGet((cur) => {
      const next = normalizeTempSites((cur.tempBypassSites || []).filter((x) => !(x && normalizeDomain(x.site) === site)));
      storageSet({ tempBypassSites: next }, () => {
        requestSync(() => {
          setStatus(`Removed temp bypass for ${site}`);
          refresh();
          // If we're currently on that site, reloading applies re-blocking immediately.
          getActiveTab((tab) => {
            if (tab && hostMatchesDomain(tab.host, site)) reloadActiveTab({ quiet: true });
          });
        });
      });
    });
  }

  function addTempBypassTab(tab, mins) {
    if (!tab || typeof tab.id !== "number" || tab.id < 0) {
      setStatus("No active tab");
      return;
    }
    if (!tab.host) {
      setStatus("Tab bypass only works on normal webpages.");
      return;
    }
    const expiresAt = minutesFromNow(mins);
    storageGet((cur) => {
      const rest = (cur.tempBypassTabs || []).filter((x) => !(x && x.tabId === tab.id));
      const next = normalizeTempTabs([...rest, { tabId: tab.id, host: tab.host || "", expiresAt }]);
      storageSet({ tempBypassTabs: next }, () => {
        requestSync(() => {
          setStatus(`Bypass enabled for ${tab.host} in this tab (${formatExpires(expiresAt)})`);
          refresh();
          reloadActiveTab({ quiet: true });
        });
      });
    });
  }

  function removeTempBypassTab(tabId) {
    storageGet((cur) => {
      const next = normalizeTempTabs((cur.tempBypassTabs || []).filter((x) => !(x && x.tabId === tabId)));
      storageSet({ tempBypassTabs: next }, () => {
        requestSync(() => {
          setStatus("Removed tab bypass");
          refresh();
          getActiveTab((tab) => {
            if (tab && tab.id === tabId) reloadActiveTab({ quiet: true });
          });
        });
      });
    });
  }

  function addTempAllowDomain(raw, mins) {
    const domain = normalizeDomain(raw);
    if (!domain) {
      setStatus("Invalid domain");
      return;
    }
    const expiresAt = minutesFromNow(mins);
    storageGet((cur) => {
      const rest = (cur.tempAllowDomains || []).filter((x) => !(x && normalizeDomain(x.domain) === domain));
      const next = normalizeTempDomains([...rest, { domain, expiresAt }]);
      storageSet({ tempAllowDomains: next }, () => {
        requestSync();
        setStatus(`Temporarily allowed ${domain} (${formatExpires(expiresAt)})`);
      });
    });
  }

  function setButtonVariant(btn, variant) {
    if (!btn) return;
    btn.classList.remove("button", "remove", "danger");
    if (variant === "primary") btn.classList.add("button");
    else if (variant === "danger") btn.classList.add("danger");
    else if (variant === "remove") btn.classList.add("remove");
  }

  function toggleTempBypassTab(mins) {
    getActiveTab((tab) => {
      if (!tab || typeof tab.id !== "number") return;
      storageGet((cur) => {
        const entries = normalizeTempTabs(cur.tempBypassTabs);
        const existing = entries.find((x) => x.tabId === tab.id) || null;
        // Allow removing even if we're currently on a non-webpage where we can't read a hostname.
        if (existing) {
          removeTempBypassTab(tab.id);
          return;
        }
        addTempBypassTab(tab, mins);
      });
    });
  }

  function toggleTempBypassSite(mins) {
    getCurrentSiteHostname((host) => {
      const site = normalizeDomain(host);
      if (!site) {
        setStatus("No active site");
        return;
      }
      storageGet((cur) => {
        const entries = normalizeTempSites(cur.tempBypassSites);
        const matches = entries.filter((x) => x && hostMatchesDomain(site, x.site));
        if (matches.length) {
          removeTempBypassForHost(site);
          return;
        }
        addTempBypassSite(site, mins);
      });
    });
  }

  function togglePermanentBypassSite() {
    getCurrentSiteHostname((host) => {
      const site = normalizeDomain(host);
      if (!site) {
        setStatus("No active site");
        return;
      }
      storageGet((cur) => {
        const permanent = uniqSorted(cur.bypassSites);
        const on = permanent.some((d) => hostMatchesDomain(site, d));
        if (on) {
          removeBypassForHost(site, cur);
          return;
        }

        const nextTemp = normalizeTempSites((cur.tempBypassSites || []).filter((x) => !(x && hostMatchesDomain(site, x.site))));
        storageSet({ bypassSites: uniqSorted([...(cur.bypassSites || []), site]), tempBypassSites: nextTemp }, () => {
          requestSync(() => {
            setStatus(`Bypass enabled for ${site} (permanent)`);
            refresh();
            reloadActiveTab({ quiet: true });
          });
        });
      });
    });
  }

  function removeTempBypassForHost(hostRaw, curSettings) {
    const host = normalizeDomain(hostRaw);
    if (!host) return;
    const apply = (cur) => {
      const nextTemp = normalizeTempSites((cur.tempBypassSites || []).filter((x) => !(x && hostMatchesDomain(host, x.site))));
      storageSet({ tempBypassSites: nextTemp }, () => {
        requestSync(() => {
          setStatus(`Removed site bypass for ${host}`);
          refresh();
          getActiveTab((tab) => {
            if (tab && hostMatchesDomain(tab.host, host)) reloadActiveTab({ quiet: true });
          });
        });
      });
    };
    if (curSettings) apply(curSettings);
    else storageGet((cur) => apply(cur));
  }

  function removeBypassForHost(hostRaw, curSettings) {
    const host = normalizeDomain(hostRaw);
    if (!host) return;
    const apply = (cur) => {
      const permanent = uniqSorted(cur.bypassSites).filter((d) => !hostMatchesDomain(host, d));
      const nextTemp = normalizeTempSites((cur.tempBypassSites || []).filter((x) => !(x && hostMatchesDomain(host, x.site))));
      const nextTempTabs = normalizeTempTabs((cur.tempBypassTabs || []).filter((x) => !(x && hostMatchesDomain(host, x.host))));
      storageSet({ bypassSites: permanent, tempBypassSites: nextTemp, tempBypassTabs: nextTempTabs }, () => {
        requestSync(() => {
          setStatus(`Bypass removed for ${host}`);
          refresh();
          getActiveTab((tab) => {
            if (tab && hostMatchesDomain(tab.host, host)) reloadActiveTab({ quiet: true });
          });
        });
      });
    };
    if (curSettings) apply(curSettings);
    else storageGet((cur) => apply(cur));
  }

  function removeAllSiteBypass(siteRaw, curSettings) {
    const site = normalizeDomain(siteRaw);
    if (!site) return;
    const apply = (cur) => {
      const permanent = uniqSorted(cur.bypassSites).filter((d) => d !== site);
      const nextTemp = normalizeTempSites((cur.tempBypassSites || []).filter((x) => !(x && normalizeDomain(x.site) === site)));
      const nextTempTabs = normalizeTempTabs((cur.tempBypassTabs || []).filter((x) => !(x && normalizeDomain(x.host) === site)));
      storageSet({ bypassSites: permanent, tempBypassSites: nextTemp, tempBypassTabs: nextTempTabs }, () => {
        requestSync(() => {
          setStatus(`Bypass removed for ${site}`);
          refresh();
          getActiveTab((tab) => {
            if (tab && hostMatchesDomain(tab.host, site)) reloadActiveTab({ quiet: true });
          });
        });
      });
    };
    if (curSettings) apply(curSettings);
    else storageGet((cur) => apply(cur));
  }

  function renderDomainList(container, domains, onRemove) {
    container.innerHTML = "";
    for (const d of uniqSorted(domains)) {
      const li = document.createElement("li");
      li.className = "item";

      const label = document.createElement("span");
      label.className = "domain";
      label.textContent = d;

      const remove = document.createElement("button");
      remove.className = "remove";
      remove.textContent = "Remove";
      remove.addEventListener("click", () => onRemove(d));

      li.appendChild(label);
      li.appendChild(remove);
      container.appendChild(li);
    }
  }

  function renderScopedAllowList(settings) {
    const list = normalizeScopedAllows(settings.scopedAllows);
    els.scopedAllowList.innerHTML = "";
    for (const item of list) {
      const li = document.createElement("li");
      li.className = "item";

      const label = document.createElement("span");
      label.className = "domain";
      label.textContent = `${item.domain} @ ${item.site}`;

      const remove = document.createElement("button");
      remove.className = "remove";
      remove.textContent = "Remove";
      remove.addEventListener("click", () => removeScopedAllow(item.site, item.domain));

      li.appendChild(label);
      li.appendChild(remove);
      els.scopedAllowList.appendChild(li);
    }
  }

  function renderBypassList(settings, activeTab) {
    const now = nowMs();
    const tempSites = normalizeTempSites(settings.tempBypassSites);
    const tempTabs = normalizeTempTabs(settings.tempBypassTabs);
    const permanent = uniqSorted(settings.bypassSites);

    // Active status line for current site / tab.
    const host = activeTab && activeTab.host ? activeTab.host : "";
    const tabId = activeTab && typeof activeTab.id === "number" ? activeTab.id : -1;
    const tabEntry = tempTabs.find((x) => x.tabId === tabId) || null;
    const tabEntryActive = !!tabEntry && !!host && hostMatchesDomain(host, tabEntry.host);
    const matchingTempSites = host ? tempSites.filter((x) => x && hostMatchesDomain(host, x.site)) : [];
    matchingTempSites.sort((a, b) => (b.site || "").length - (a.site || "").length);
    const siteEntry = matchingTempSites[0] || null;
    const matchingPerm = host ? permanent.filter((d) => hostMatchesDomain(host, d)) : [];
    matchingPerm.sort((a, b) => (b || "").length - (a || "").length);
    const permOn = matchingPerm.length > 0;
    const permKey = matchingPerm[0] || "";

    const parts = [];
    if (tabEntry) {
      parts.push(
        tabEntryActive
          ? `Tab bypass active (${formatExpires(tabEntry.expiresAt)})`
          : `Tab bypass set for ${tabEntry.host || "?"} (${formatExpires(tabEntry.expiresAt)})`
      );
    }
    if (siteEntry) parts.push(`Site bypass ${formatExpires(siteEntry.expiresAt)}`);
    if (permOn) parts.push(`Site bypass permanent (${permKey || "active"})`);
    els.bypassActive.textContent = parts.length ? parts.join(" · ") : "No bypass active for this tab/site.";

    els.bypassList.innerHTML = "";

    const addItem = (labelText, badgeText, onRemove) => {
      const li = document.createElement("li");
      li.className = "item";

      const left = document.createElement("div");
      left.style.minWidth = "0";
      left.style.flex = "1";

      const label = document.createElement("div");
      label.className = "domain";
      label.textContent = labelText;

      const badge = document.createElement("div");
      badge.className = "help";
      badge.style.marginTop = "2px";
      badge.textContent = badgeText;

      left.appendChild(label);
      left.appendChild(badge);

      const remove = document.createElement("button");
      remove.className = "remove";
      remove.textContent = "Remove";
      remove.addEventListener("click", () => onRemove());

      li.appendChild(left);
      li.appendChild(remove);
      els.bypassList.appendChild(li);
    };

    for (const t of tempTabs) {
      const label = `tab #${t.tabId} @ ${t.host || "?"}`;
      addItem(label, `Temporary ${formatExpires(t.expiresAt)}`, () => removeTempBypassTab(t.tabId));
    }
    for (const t of tempSites) {
      addItem(t.site, `Temporary ${formatExpires(t.expiresAt)}`, () => removeTempBypassSite(t.site));
    }
    for (const s of permanent) {
      // Don't duplicate if also present as temp (user can still remove temp separately).
      addItem(s, "Permanent", () => removeAllSiteBypass(s));
    }
    if (!tempTabs.length && !tempSites.length && !permanent.length) {
      const li = document.createElement("li");
      li.className = "help";
      li.textContent = "No active bypasses.";
      els.bypassList.appendChild(li);
    }

    // Disable/enable buttons based on current state.
    if (els.bypassTab15m) {
      const active = !!tabEntry && tabEntry.expiresAt > now;
      els.bypassTab15m.disabled = tabId < 0 || (!host && !active);
      els.bypassTab15m.textContent = active ? "Remove Tab Bypass" : `Bypass This Site (Tab, ${DEFAULT_TEMP_MINUTES}m)`;
      setButtonVariant(els.bypassTab15m, active ? "danger" : null);
    }
    if (els.bypassSite15m) {
      const active = !!siteEntry && siteEntry.expiresAt > now;
      els.bypassSite15m.disabled = !host;
      els.bypassSite15m.textContent = active ? "Remove Site Bypass" : `Bypass Site (${DEFAULT_TEMP_MINUTES}m)`;
      setButtonVariant(els.bypassSite15m, active ? "danger" : null);
    }
    if (els.bypassSiteAlways) {
      els.bypassSiteAlways.disabled = !host;
      els.bypassSiteAlways.textContent = permOn ? "Remove Site Bypass (Always)" : "Bypass Site (Always)";
      setButtonVariant(els.bypassSiteAlways, permOn ? "remove" : "primary");
    }
  }

  function domainForMatch(m) {
    if (m && typeof m.domain === "string" && m.domain) return m.domain;
    if (m && typeof m.url === "string" && m.url) return tryParseHostname(m.url);
    return "";
  }

  function actionForMatch(m) {
    const a = m && typeof m.action === "string" ? m.action.toLowerCase() : "match";
    if (a === "block" || a === "allow" || a === "match") return a;
    return "match";
  }

  function addUniqueLimited(list, value, limit) {
    if (!value) return;
    if (!Array.isArray(list)) return;
    if (list.includes(value)) return;
    if (list.length >= limit) return;
    list.push(value);
  }

  function timeLabel(ts) {
    if (!ts) return "";
    try {
      return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    } catch {
      return "";
    }
  }

  function copyText(text) {
    const v = String(text || "");
    if (!v) return;
    const clipboard = navigator.clipboard && navigator.clipboard.writeText;
    if (clipboard) {
      clipboard(v).then(() => setStatus("Copied")).catch(() => void 0);
      return;
    }
    const ta = document.createElement("textarea");
    ta.value = v;
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      setStatus("Copied");
    } catch {
      // ignore
    } finally {
      ta.remove();
    }
  }

  const COPY_BUTTON_HTML = `
    <span class="srOnly"></span>
    <svg class="icon iconCopy" viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="currentColor"
        d="M16 1H6a2 2 0 0 0-2 2v12h2V3h10V1Zm3 4H10a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2Zm0 16H10V7h9v14Z"
      />
    </svg>
    <svg class="icon iconCheck" viewBox="0 0 24 24" aria-hidden="true">
      <path fill="currentColor" d="M9 16.2 4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4z" />
    </svg>
  `;

  function setCopiedState(btn, on) {
    if (!btn) return;
    if (on) btn.classList.add("isCopied");
    else btn.classList.remove("isCopied");
  }

  function setCopiedTemporarily(btn, ms) {
    setCopiedState(btn, true);
    btn.disabled = true;
    setTimeout(() => {
      setCopiedState(btn, false);
      btn.disabled = false;
    }, Math.max(200, ms || 900));
  }

  function makeCopyButton(label, onCopy) {
    const b = document.createElement("button");
    b.className = "mini iconButton";
    b.type = "button";
    b.setAttribute("aria-label", label);
    b.innerHTML = COPY_BUTTON_HTML;
    const sr = b.querySelector(".srOnly");
    if (sr) sr.textContent = label;
    b.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      onCopy && onCopy();
      setCopiedTemporarily(b, 900);
    });
    return b;
  }

  function buildActivityGroups(matches, opts) {
    const out = new Map();
    const scope = opts && opts.scope === "tab" ? "tab" : "all";
    const activeSite = opts && typeof opts.activeSite === "string" ? opts.activeSite : "";

    for (const m of Array.isArray(matches) ? matches : []) {
      if (!m || typeof m !== "object") continue;
      const domain = domainForMatch(m);
      if (!domain) continue;
      const action = actionForMatch(m);

      const site = scope === "tab" ? activeSite || (typeof m.site === "string" ? m.site : "") : typeof m.site === "string" ? m.site : "";
      const key = [action, site || "?", domain].join("|");

      const cur =
        out.get(key) ||
        ({
          key,
          action,
          domain,
          site,
          count: 0,
          firstTs: 0,
          lastTs: 0,
          types: new Set(),
          urls: [],
          initiators: new Set(),
          tabIds: new Set(),
          rules: new Map(), // rulesetId -> Set(ruleId)
        });

      const inc = typeof m.count === "number" && m.count > 0 ? m.count : 1;
      cur.count += inc;

      const firstTs = typeof m.firstTs === "number" ? m.firstTs : typeof m.lastTs === "number" ? m.lastTs : 0;
      const lastTs = typeof m.lastTs === "number" ? m.lastTs : 0;
      if (!cur.firstTs || (firstTs && firstTs < cur.firstTs)) cur.firstTs = firstTs;
      if (!cur.lastTs || (lastTs && lastTs > cur.lastTs)) cur.lastTs = lastTs;

      if (typeof m.type === "string" && m.type) cur.types.add(m.type);
      if (typeof m.initiator === "string" && m.initiator) cur.initiators.add(m.initiator);
      if (typeof m.tabId === "number" && m.tabId >= 0) cur.tabIds.add(m.tabId);

      if (Array.isArray(m.urls)) {
        for (const u of m.urls) addUniqueLimited(cur.urls, u, 3);
      } else if (typeof m.url === "string") {
        addUniqueLimited(cur.urls, m.url, 3);
      }

      const rs = typeof m.rulesetId === "string" ? m.rulesetId : "";
      if (rs) {
        const set = cur.rules.get(rs) || new Set();
        if (typeof m.ruleId === "number") set.add(m.ruleId);
        cur.rules.set(rs, set);
      }

      out.set(key, cur);
    }

    return Array.from(out.values()).sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0));
  }

  function renderActivitySummary(groups) {
    if (!Array.isArray(groups) || groups.length === 0) {
      els.activitySummary.textContent = "";
      return;
    }

    let blocked = 0;
    let allowed = 0;
    let matched = 0;
    const topBlocked = new Map();

    for (const g of groups) {
      const n = typeof g.count === "number" && g.count > 0 ? g.count : 1;
      if (g.action === "block") {
        blocked += n;
        topBlocked.set(g.domain, (topBlocked.get(g.domain) || 0) + n);
      } else if (g.action === "allow") {
        allowed += n;
      } else {
        matched += n;
      }
    }

    const top = Array.from(topBlocked.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([d, n]) => ({ domain: d, count: n }));

    const total = blocked + allowed + matched;
    const toneFor = (kind, n) => {
      if (!n) return "Off";
      if (kind === "blocked") return "Err";
      // Allows usually mean a user opted into reduced blocking (bypass/allow).
      if (kind === "allowed") return "Warn";
      return "Warn";
    };

    els.activitySummary.innerHTML = "";
    const wrap = document.createElement("div");
    wrap.className = "activitySummary";

    const counts = document.createElement("div");
    counts.className = "activitySummaryCounts";
    counts.appendChild(makeBadge(`${blocked} blocked`, toneFor("blocked", blocked)));

    const addZero = (text) => {
      const el = document.createElement("span");
      el.className = "activitySummaryZero";
      el.textContent = text;
      counts.appendChild(el);
    };

    if (allowed) counts.appendChild(makeBadge(`${allowed} allowed`, toneFor("allowed", allowed)));
    else addZero("0 allowed");

    if (matched) counts.appendChild(makeBadge(`${matched} matched`, toneFor("matched", matched)));
    else addZero("0 matched");
    wrap.appendChild(counts);

    if (total > 0) {
      const bar = document.createElement("div");
      bar.className = "activityBar";

      const seg = (cls, n) => {
        if (!n) return null;
        const el = document.createElement("span");
        el.className = `activityBarSeg ${cls}`;
        const pct = Math.max(2, Math.round((n / total) * 100));
        el.style.width = `${pct}%`;
        return el;
      };

      const b = seg("block", blocked);
      const a = seg("allow", allowed);
      const m = seg("match", matched);
      if (b) bar.appendChild(b);
      if (a) bar.appendChild(a);
      if (m) bar.appendChild(m);
      wrap.appendChild(bar);
    }

    if (top.length) {
      const topRow = document.createElement("div");
      topRow.className = "activitySummaryTop";

      const label = document.createElement("div");
      label.className = "activitySummaryLabel";
      label.textContent = "Top blocked";
      topRow.appendChild(label);

      const chips = document.createElement("div");
      chips.className = "activitySummaryChips";

      for (const item of top) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "chip chipButton activityChip";
        btn.title = `Copy ${item.domain}`;

        const inner = document.createElement("span");
        inner.className = "activityChipInner";

        const dom = document.createElement("span");
        dom.className = "activityChipDomain";
        dom.textContent = item.domain;

        const cnt = document.createElement("span");
        cnt.className = "chipCount";
        cnt.textContent = `×${item.count}`;

        inner.appendChild(dom);
        inner.appendChild(cnt);
        btn.appendChild(inner);

        btn.addEventListener("click", () => {
          copyText(item.domain);
        });

        chips.appendChild(btn);
      }

      topRow.appendChild(chips);
      wrap.appendChild(topRow);
    }

    els.activitySummary.appendChild(wrap);
  }

  function renderActivityList(groups, opts) {
    const list = Array.isArray(groups) ? groups.slice(0, 30) : [];
    const scope = opts && opts.scope === "tab" ? "tab" : "all";
    const activeSite = opts && typeof opts.activeSite === "string" ? opts.activeSite : "";

    els.activityList.innerHTML = "";

    for (const g of list) {
      const li = document.createElement("li");
      li.className = "item activityItem";

      const details = document.createElement("details");
      details.className = "activityDetails";

      const summary = document.createElement("summary");
      summary.className = "activitySummaryRow";

      const left = document.createElement("div");
      left.className = "activitySummaryLeft";

      const pill = document.createElement("span");
      pill.className = `pill ${g.action === "block" ? "pillBlock" : g.action === "allow" ? "pillAllow" : ""}`;
      pill.textContent = g.action;

      const domain = document.createElement("span");
      domain.className = "domain";
      domain.textContent = g.domain;

      const meta = document.createElement("span");
      meta.className = "activityMeta";
      const types = Array.from(g.types || []).slice(0, 2).join(", ");
      const site = scope === "tab" ? activeSite : g.site;
      const when = timeLabel(g.lastTs);
      const bits = [];
      if (types) bits.push(types);
      if (site) bits.push(`site:${site}`);
      if (when) bits.push(`last:${when}`);
      meta.textContent = bits.join(" · ");

      const top = document.createElement("div");
      top.className = "activityTopRow";
      top.appendChild(pill);
      top.appendChild(domain);

      left.appendChild(top);
      left.appendChild(meta);

      const right = document.createElement("div");
      right.className = "activitySummaryRight";

      const count = document.createElement("span");
      count.className = "count";
      count.textContent = `×${g.count}`;

      right.appendChild(count);

      summary.appendChild(left);
      summary.appendChild(right);

      const body = document.createElement("div");
      body.className = "activityBody";

      const siteLine = document.createElement("div");
      siteLine.className = "activityLine";
      siteLine.textContent = site ? `Site: ${site}` : "Site: (unknown)";

      const typesLine = document.createElement("div");
      typesLine.className = "activityLine";
      const allTypes = Array.from(g.types || []).sort().join(", ");
      typesLine.textContent = allTypes ? `Types: ${allTypes}` : "Types: (unknown)";

      const rulesLine = document.createElement("div");
      rulesLine.className = "activityLine";
      const rules = [];
      for (const [rs, ids] of (g.rules || new Map()).entries()) {
        const shown = Array.from(ids || []).slice(0, 3);
        const suffix = shown.length ? `#${shown.join(",#")}` : "";
        rules.push(`${rs}${suffix}${ids && ids.size > shown.length ? ` (+${ids.size - shown.length})` : ""}`);
      }
      rules.sort();
      rulesLine.textContent = rules.length ? `Rules: ${rules.join(" · ")}` : "Rules: (unknown)";

      const urlBox = document.createElement("div");
      urlBox.className = "urlBox";

      const urlTitle = document.createElement("div");
      urlTitle.className = "urlTitle";
      urlTitle.textContent = "Sample URLs";

      urlBox.appendChild(urlTitle);

      const urls = Array.isArray(g.urls) ? g.urls : [];
      if (!urls.length) {
        const none = document.createElement("div");
        none.className = "urlItem";
        none.textContent = "(URL unavailable)";
        urlBox.appendChild(none);
      } else {
        for (const u of urls) {
          const row = document.createElement("div");
          row.className = "urlRow";

          const code = document.createElement("code");
          code.className = "urlCode";
          code.textContent = u;

          const copy = makeCopyButton("Copy URL", () => copyText(u));

          row.appendChild(code);
          row.appendChild(copy);
          urlBox.appendChild(row);
        }
      }

      const buttons = document.createElement("div");
      buttons.className = "activityButtons";

      const allowSiteTemp = document.createElement("button");
      allowSiteTemp.className = "mini";
      allowSiteTemp.type = "button";
      allowSiteTemp.textContent = `Allow site (${DEFAULT_TEMP_MINUTES}m)`;
      allowSiteTemp.disabled = !site;
      allowSiteTemp.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!site) return;
        addTempBypassSite(site, DEFAULT_TEMP_MINUTES);
      });

      const allowSite = document.createElement("button");
      allowSite.className = "mini";
      allowSite.type = "button";
      allowSite.textContent = "Allow on this site";
      allowSite.disabled = !site;
      allowSite.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!site) return;
        addScopedAllow(site, g.domain);
      });

      const allowGlobalTemp = document.createElement("button");
      allowGlobalTemp.className = "mini";
      allowGlobalTemp.type = "button";
      allowGlobalTemp.textContent = `Allow (${DEFAULT_TEMP_MINUTES}m)`;
      allowGlobalTemp.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        addTempAllowDomain(g.domain, DEFAULT_TEMP_MINUTES);
      });

      const allowGlobal = document.createElement("button");
      allowGlobal.className = "mini";
      allowGlobal.type = "button";
      allowGlobal.textContent = "Allow everywhere";
      allowGlobal.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        addAllowDomain(g.domain);
      });

      const blockGlobal = document.createElement("button");
      blockGlobal.className = "mini danger";
      blockGlobal.type = "button";
      blockGlobal.textContent = "Block everywhere";
      blockGlobal.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        addBlockDomain(g.domain);
      });

      buttons.appendChild(allowSiteTemp);
      buttons.appendChild(allowSite);
      buttons.appendChild(allowGlobalTemp);
      buttons.appendChild(allowGlobal);
      buttons.appendChild(blockGlobal);

      body.appendChild(siteLine);
      body.appendChild(typesLine);
      body.appendChild(rulesLine);
      body.appendChild(urlBox);
      body.appendChild(buttons);

      details.appendChild(summary);
      details.appendChild(body);
      li.appendChild(details);
      els.activityList.appendChild(li);
    }
  }

  function addAllowDomain(raw) {
    const domain = normalizeDomain(raw);
    if (!domain) {
      setStatus("Invalid domain");
      return;
    }
    storageGet((cur) => {
      const next = uniqSorted([...(cur.allowDomains || []), domain]);
      storageSet({ allowDomains: next }, () => {
        requestSync();
        setStatus(`Allowed ${domain}`);
      });
    });
  }

  function addScopedAllow(siteRaw, domainRaw) {
    const site = normalizeDomain(siteRaw);
    const domain = normalizeDomain(domainRaw);
    if (!site || !domain) {
      setStatus("Missing site/domain");
      return;
    }
    storageGet((cur) => {
      const next = normalizeScopedAllows([...(cur.scopedAllows || []), { site, domain }]);
      storageSet({ scopedAllows: next }, () => {
        requestSync();
        setStatus(`Allowed ${domain} on ${site}`);
      });
    });
  }

  function removeScopedAllow(siteRaw, domainRaw) {
    const site = normalizeDomain(siteRaw);
    const domain = normalizeDomain(domainRaw);
    storageGet((cur) => {
      const next = normalizeScopedAllows((cur.scopedAllows || []).filter((x) => !(x && x.site === site && x.domain === domain)));
      storageSet({ scopedAllows: next }, () => {
        requestSync();
        setStatus(`Removed ${domain} on ${site}`);
      });
    });
  }

  function removeAllowDomain(domain) {
    storageGet((cur) => {
      const next = uniqSorted((cur.allowDomains || []).filter((d) => d !== domain));
      storageSet({ allowDomains: next }, () => {
        requestSync();
        setStatus(`Removed ${domain}`);
      });
    });
  }

  function addBlockDomain(raw) {
    const domain = normalizeDomain(raw);
    if (!domain) {
      setStatus("Invalid domain");
      return;
    }
    storageGet((cur) => {
      const next = uniqSorted([...(cur.blockDomains || []), domain]);
      storageSet({ blockDomains: next }, () => {
        requestSync();
        setStatus(`Blocked ${domain}`);
      });
    });
  }

  function removeBlockDomain(domain) {
    storageGet((cur) => {
      const next = uniqSorted((cur.blockDomains || []).filter((d) => d !== domain));
      storageSet({ blockDomains: next }, () => {
        requestSync();
        setStatus(`Removed ${domain}`);
      });
    });
  }

  function addBypassSite(site) {
    const domain = normalizeDomain(site);
    if (!domain) {
      setStatus("No active site");
      return;
    }
    storageGet((cur) => {
      const next = uniqSorted([...(cur.bypassSites || []), domain]);
      storageSet({ bypassSites: next }, () => {
        requestSync();
        setStatus(`Bypass enabled for ${domain} (permanent)`);
        refresh();
      });
    });
  }

  function removeBypassSite(site) {
    const domain = normalizeDomain(site);
    if (!domain) {
      setStatus("No active site");
      return;
    }
    storageGet((cur) => {
      const next = uniqSorted((cur.bypassSites || []).filter((d) => d !== domain));
      storageSet({ bypassSites: next }, () => {
        requestSync();
        setStatus(`Bypass removed for ${domain}`);
        refresh();
      });
    });
  }

  function refresh() {
    storageGet((settings) => {
      els.toggleEnabled.checked = !!settings.cubeEnabled;
      els.toggleExceptions.checked = !!settings.exceptionsEnabled;
      els.toggleBuiltinAllowlist.checked = !!settings.builtinAllowlistEnabled;
      els.toggleLogging.checked = !!settings.logEnabled;

      renderDomainList(els.allowList, settings.allowDomains, removeAllowDomain);
      renderDomainList(els.blockList, settings.blockDomains, removeBlockDomain);
      renderScopedAllowList(settings);

      getActiveTab((tab) => {
        renderBypassList(settings, tab);
      });

      const scope = els.activityScope.value || "tab";
      const filter = els.activityFilter.value || "all";
      const matches = Array.isArray(settings.recentMatches) ? settings.recentMatches : [];

      getDiagnosticsStatus((diag) => {
        const canEnable = !!diag.supported && !!diag.hasFeedback;
        els.toggleLogging.disabled = !canEnable && !settings.logEnabled;

        els.activityNotice.textContent = "";
        if (!canEnable) {
          els.activityNotice.textContent = diag.supported
            ? "Diagnostics logging requires an unpacked extension with declarativeNetRequestFeedback."
            : "Diagnostics logging isn't available in this Chrome build.";
        }

        const hasMatches = matches.length > 0;
        els.activityHelp.textContent = settings.logEnabled
          ? hasMatches
            ? "Showing recent rule matches captured locally."
            : "No matches captured yet. Browse a site and reload once."
          : "Enable diagnostics logging to see which requests are being allowed/blocked.";

        if (scope === "tab") {
          getActiveTab((tab) => {
            const filtered = matches.filter((m) => m && typeof m.tabId === "number" && m.tabId === tab.id);
            const groups = buildActivityGroups(filtered, { scope, activeSite: tab.host });
            const shown = filter === "all" ? groups : groups.filter((g) => g.action === filter);
            renderActivitySummary(shown);
            renderActivityList(shown, { scope, activeSite: tab.host });
          });
        } else {
          const groups = buildActivityGroups(matches, { scope, activeSite: "" });
          const shown = filter === "all" ? groups : groups.filter((g) => g.action === filter);
          renderActivitySummary(shown);
          renderActivityList(shown, { scope, activeSite: "" });
        }
      });

      refreshRuntimeStatus(settings);
    });
  }

  function getActiveTab(cb) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = (tabs || [])[0];
      const id = tab && typeof tab.id === "number" ? tab.id : -1;
      const url = tab && typeof tab.url === "string" ? tab.url : "";
      const host = url ? tryParseHostname(url) : "";
      cb({ id, url, host });
    });
  }

  function reloadActiveTab(opts) {
    getActiveTab((tab) => {
      if (!tab || typeof tab.id !== "number" || tab.id < 0) return;
      chrome.tabs.reload(tab.id, { bypassCache: true }, () => void chrome.runtime.lastError);
      const quiet = !!(opts && opts.quiet);
      if (!quiet) setStatus((opts && typeof opts.status === "string" && opts.status) || "Reloading…");
    });
  }

  els.toggleEnabled.addEventListener("change", () => {
    storageSet({ cubeEnabled: els.toggleEnabled.checked }, () => {
      requestSync();
      setStatus(els.toggleEnabled.checked ? "Enabled" : "Disabled");
    });
  });

  els.toggleExceptions.addEventListener("change", () => {
    storageSet({ exceptionsEnabled: els.toggleExceptions.checked }, () => {
      requestSync();
      setStatus(els.toggleExceptions.checked ? "Compatibility exceptions enabled" : "Compatibility exceptions disabled");
    });
  });

  els.toggleBuiltinAllowlist.addEventListener("change", () => {
    storageSet({ builtinAllowlistEnabled: els.toggleBuiltinAllowlist.checked }, () => {
      requestSync();
      setStatus(els.toggleBuiltinAllowlist.checked ? "Support widget allowlist enabled" : "Support widget allowlist disabled");
    });
  });

  els.toggleLogging.addEventListener("change", () => {
    const want = els.toggleLogging.checked;
    if (!want) {
      storageSet({ logEnabled: false }, () => {
        requestSync();
        setStatus("Diagnostics logging disabled");
      });
      return;
    }
    getDiagnosticsStatus((diag) => {
      if (!diag.supported) {
        els.toggleLogging.checked = false;
        setStatus("Diagnostics logging isn't available in this Chrome build.");
        return;
      }
      if (!diag.hasFeedback) {
        els.toggleLogging.checked = false;
        setStatus("Diagnostics logging requires an unpacked extension with declarativeNetRequestFeedback.");
        return;
      }
      storageSet({ logEnabled: true }, () => {
        requestSync();
        setStatus("Diagnostics logging enabled");
      });
    });
  });

  els.allowForm.addEventListener("submit", (e) => {
    e.preventDefault();
    addAllowDomain(els.allowInput.value);
    els.allowInput.value = "";
  });

  els.blockForm.addEventListener("submit", (e) => {
    e.preventDefault();
    addBlockDomain(els.blockInput.value);
    els.blockInput.value = "";
  });

  els.bypassTab15m.addEventListener("click", () => toggleTempBypassTab(DEFAULT_TEMP_MINUTES));
  els.bypassSite15m.addEventListener("click", () => toggleTempBypassSite(DEFAULT_TEMP_MINUTES));
  els.bypassSiteAlways.addEventListener("click", () => togglePermanentBypassSite());
  if (els.reloadTab) els.reloadTab.addEventListener("click", () => reloadActiveTab());

  els.clearActivity.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "clearRecentMatches" }, () => void chrome.runtime.lastError);
    setStatus("Cleared activity");
  });

  els.resetDefaults.addEventListener("click", () => resetToDefaults());

  if (els.status) {
    els.status.addEventListener("click", () => setStatus(""));
  }

  if (els.brandMark) {
    if (els.brandMarkCube) {
      // Let the initial CSS transform apply, then do a tiny "turn" on open.
      setTimeout(() => turnCube("open"), 60);
    }

    els.brandMark.addEventListener("mouseenter", () => {
      const now = Date.now();
      if (now - brandMarkHoverAt < 650) return;
      brandMarkHoverAt = now;
      if (els.brandMarkCube) turnCube("hover");
    });

    els.brandMark.addEventListener("click", (e) => {
      e.preventDefault();
      if (els.brandMarkCube) turnCube("click");
      els.brandMark.classList.remove("isSpinning");
      // Trigger reflow so the animation restarts.
      void els.brandMark.offsetWidth;
      els.brandMark.classList.add("isSpinning");
      setTimeout(() => els.brandMark && els.brandMark.classList.remove("isSpinning"), 650);
    });
  }
  els.copyStatus.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    copyText(statusCopyText || "");
    setCopiedState(els.copyStatus, true);
    els.copyStatus.disabled = true;
    if (statusCopyResetTimer) clearTimeout(statusCopyResetTimer);
    statusCopyResetTimer = setTimeout(() => {
      setCopiedState(els.copyStatus, false);
      els.copyStatus.disabled = false;
      statusCopyResetTimer = null;
    }, 900);
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (!changes) return;
    const keys = Object.keys(changes);
    if (
      keys.includes("recentMatches") ||
      keys.includes("cubeEnabled") ||
      keys.includes("exceptionsEnabled") ||
      keys.includes("builtinAllowlistEnabled") ||
      keys.includes("logEnabled") ||
      keys.includes("allowDomains") ||
      keys.includes("blockDomains") ||
      keys.includes("bypassSites") ||
      keys.includes("scopedAllows") ||
      keys.includes("tempBypassSites") ||
      keys.includes("tempBypassTabs") ||
      keys.includes("lastDnrError")
    ) {
      refresh();
    }
  });

  els.activityScope.addEventListener("change", () => refresh());
  els.activityFilter.addEventListener("change", () => refresh());

  refresh();
  requestSync();
});
