// Service worker for the cube extension.
//
// cube is privacy-first by default: only the block ruleset is enabled. Users can
// opt into additional allow rulesets (compatibility exceptions / support widget
// allowlist), and manage per-domain allow/block lists without reloading the
// extension.

const RULESETS = {
  blocks: ["rules_block_1", "rules_block_2", "rules_block_3", "rules_block_4"],
  exceptions: "rules_exceptions",
  builtinAllowlist: "rules_allowlist",
};

const STORAGE_DEFAULTS = {
  cubeEnabled: true,
  exceptionsEnabled: false,
  builtinAllowlistEnabled: false,
  logEnabled: false,

  allowDomains: [],
  blockDomains: [],
  bypassSites: [],
  scopedAllows: [],

  // Temporary (expiring) rules.
  // Each entry includes an absolute expiration timestamp in ms since epoch.
  tempAllowDomains: [],
  tempBypassSites: [],
  tempBypassTabs: [],
  tempScopedAllows: [],

  // Internal bookkeeping for stable dynamic rule IDs.
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

const INTERNAL_STORAGE_KEYS = new Set([
  "allowDomainIds",
  "blockDomainIds",
  "bypassSiteIds",
  "scopedAllowIds",
  "tempAllowDomainIds",
  "tempBypassSiteIds",
  "tempBypassTabIds",
  "tempScopedAllowIds",
  "recentMatches",
  "lastDnrError",
]);

const DYNAMIC_RULE_BASES = {
  allowDomain: 1_000_000,
  blockDomain: 2_000_000,
  bypassSite: 3_000_000,
  scopedAllow: 4_000_000,
  tempAllowDomain: 5_000_000,
  tempBypassSite: 6_000_000,
  tempScopedAllow: 8_000_000,
};

const DYNAMIC_PRIORITIES = {
  bypassSiteAllow: 110,
  allowDomainAllow: 100,
  scopedAllow: 95,
  blockDomainBlock: 90,
  tempAllowDomainAllow: 98,
  tempBypassSiteAllow: 108,
  tempScopedAllow: 94,
};

const SESSION_RULE_BASES = {
  tempBypassTab: 7_000_000,
};

const SESSION_PRIORITIES = {
  bypassTabAllow: 125,
};

const RECENT_MATCHES_LIMIT = 200;
const FLUSH_INTERVAL_MS = 1_500;
const PRUNE_ALARM = "cube_prune_expired";

let syncing = false;
let resyncRequested = false;
let currentSettings = { ...STORAGE_DEFAULTS };
let debugListenerAttached = false;
let flushTimer = null;
let pendingMatches = [];
let syncWaiters = [];

const RULE_ID_SPACE = 900_000;

function storageGet(cb) {
  chrome.storage.local.get(STORAGE_DEFAULTS, cb);
}

function storageSet(obj, cb) {
  chrome.storage.local.set(obj, cb);
}

function setLastDnrError(err) {
  const msg = err && err.message ? String(err.message) : err ? String(err) : "";
  storageSet({ lastDnrError: msg }, () => void chrome.runtime.lastError);
}

function normalizeDomain(input) {
  let v = (input || "").trim().toLowerCase();
  if (!v) return "";
  v = v.replace(/^\.+/, "").replace(/\.+$/, "");
  v = v.split("/")[0].split("?")[0].split("#")[0];
  v = v.split(":")[0];
  if (!v || v.includes(" ") || v.includes("\t")) return "";
  return v;
}

function uniqSorted(list) {
  const out = Array.from(new Set(Array.isArray(list) ? list : []))
    .map(normalizeDomain)
    .filter(Boolean);
  out.sort();
  return out;
}

function fnv1a32(str) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function stableRuleId(base, key, usedIds) {
  let id = base + (fnv1a32(String(key)) % RULE_ID_SPACE);
  while (usedIds.has(id)) id++;
  usedIds.add(id);
  return id;
}

function makeAllowDomainRule(id, domain) {
  return {
    id,
    priority: DYNAMIC_PRIORITIES.allowDomainAllow,
    action: { type: "allow" },
    condition: {
      requestDomains: [domain],
      excludedResourceTypes: ["main_frame"],
    },
  };
}

function makeTempAllowDomainRule(id, domain) {
  return {
    id,
    priority: DYNAMIC_PRIORITIES.tempAllowDomainAllow,
    action: { type: "allow" },
    condition: {
      requestDomains: [domain],
      excludedResourceTypes: ["main_frame"],
    },
  };
}

function makeBlockDomainRule(id, domain) {
  return {
    id,
    priority: DYNAMIC_PRIORITIES.blockDomainBlock,
    action: { type: "block" },
    condition: {
      requestDomains: [domain],
      excludedResourceTypes: ["main_frame"],
    },
  };
}

function makeBypassSiteRule(id, siteDomain) {
  return {
    id,
    priority: DYNAMIC_PRIORITIES.bypassSiteAllow,
    action: { type: "allow" },
    condition: {
      urlFilter: "*",
      topDomains: [siteDomain],
      excludedResourceTypes: ["main_frame"],
    },
  };
}

function makeBypassTabRule(id, tabId, siteDomain) {
  const site = normalizeDomain(siteDomain);
  return {
    id,
    priority: SESSION_PRIORITIES.bypassTabAllow,
    action: { type: "allow" },
    condition: {
      urlFilter: "*",
      tabIds: [tabId],
      ...(site ? { topDomains: [site] } : {}),
      excludedResourceTypes: ["main_frame"],
    },
  };
}

function makeScopedAllowRule(id, pairKey) {
  const [siteDomain, requestDomain] = String(pairKey).split("@@");
  return {
    id,
    priority: DYNAMIC_PRIORITIES.scopedAllow,
    action: { type: "allow" },
    condition: {
      topDomains: [siteDomain],
      requestDomains: [requestDomain],
      excludedResourceTypes: ["main_frame"],
    },
  };
}

function pruneExpiredSettings(settings) {
  const now = Date.now();
  const out = { ...settings };
  let changed = false;

  const pruneList = (list) => {
    const next = [];
    for (const item of Array.isArray(list) ? list : []) {
      if (!item || typeof item !== "object") continue;
      const exp = typeof item.expiresAt === "number" ? item.expiresAt : 0;
      if (!exp || exp <= now) {
        changed = true;
        continue;
      }
      next.push(item);
    }
    return next;
  };

  const nextTempAllow = pruneList(settings.tempAllowDomains);
  if (JSON.stringify(nextTempAllow) !== JSON.stringify(settings.tempAllowDomains || [])) {
    out.tempAllowDomains = nextTempAllow;
    changed = true;
  }
  const nextTempBypassSites = pruneList(settings.tempBypassSites);
  if (JSON.stringify(nextTempBypassSites) !== JSON.stringify(settings.tempBypassSites || [])) {
    out.tempBypassSites = nextTempBypassSites;
    changed = true;
  }
  const nextTempBypassTabs = [];
  for (const item of Array.isArray(settings.tempBypassTabs) ? settings.tempBypassTabs : []) {
    if (!item || typeof item !== "object") continue;
    const exp = typeof item.expiresAt === "number" ? item.expiresAt : 0;
    const tabId = typeof item.tabId === "number" ? item.tabId : -1;
    const host = normalizeDomain(item.host);
    if (!exp || exp <= now || tabId < 0 || !host) {
      changed = true;
      continue;
    }
    nextTempBypassTabs.push({ tabId, host, expiresAt: exp });
  }
  nextTempBypassTabs.sort((a, b) => a.tabId - b.tabId || a.expiresAt - b.expiresAt);
  if (JSON.stringify(nextTempBypassTabs) !== JSON.stringify(settings.tempBypassTabs || [])) {
    out.tempBypassTabs = nextTempBypassTabs;
    changed = true;
  }
  const nextTempScopedAllows = pruneList(settings.tempScopedAllows);
  if (JSON.stringify(nextTempScopedAllows) !== JSON.stringify(settings.tempScopedAllows || [])) {
    out.tempScopedAllows = nextTempScopedAllows;
    changed = true;
  }

  return { settings: out, changed };
}

function setEnabledRulesets(settings, cb) {
  const enable = [];
  const disable = [];

  if (settings.cubeEnabled) {
    enable.push(...RULESETS.blocks);

    if (settings.exceptionsEnabled) enable.push(RULESETS.exceptions);
    else disable.push(RULESETS.exceptions);

    if (settings.builtinAllowlistEnabled) enable.push(RULESETS.builtinAllowlist);
    else disable.push(RULESETS.builtinAllowlist);
  } else {
    disable.push(...RULESETS.blocks, RULESETS.exceptions, RULESETS.builtinAllowlist);
  }

  chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds: enable, disableRulesetIds: disable }, () => {
    const err = chrome.runtime.lastError;
    if (!err) {
      setLastDnrError("");
      cb && cb();
      return;
    }

    // If enabling all block shards fails (quota constraints), fall back to the first shard.
    if (settings.cubeEnabled) {
      chrome.declarativeNetRequest.updateEnabledRulesets(
        {
          enableRulesetIds: [RULESETS.blocks[0]],
          disableRulesetIds: RULESETS.blocks.slice(1),
        },
        () => {
          setLastDnrError(err);
          cb && cb();
        }
      );
      return;
    }

    setLastDnrError(err);
    cb && cb();
  });
}

function reconcileDynamicRules(settings, cb) {
  chrome.declarativeNetRequest.getDynamicRules((existingRules) => {
    const allowDomains = uniqSorted(settings.allowDomains);
    const blockDomains = uniqSorted(settings.blockDomains);
    const bypassSites = uniqSorted(settings.bypassSites);
    const scopedAllows = normalizeScopedPairs(settings.scopedAllows);

    const tempAllowDomains = normalizeExpiringDomains(settings.tempAllowDomains);
    const tempBypassSites = normalizeExpiringSites(settings.tempBypassSites);
    const tempScopedAllows = normalizeExpiringScopedPairs(settings.tempScopedAllows);

    const removeRuleIds = Array.from(new Set((existingRules || []).map((r) => r && typeof r.id === "number" ? r.id : null).filter((x) => x !== null)));
    const addRules = [];

    if (settings.cubeEnabled) {
      const usedIds = new Set();
      for (const d of allowDomains) addRules.push(makeAllowDomainRule(stableRuleId(DYNAMIC_RULE_BASES.allowDomain, d, usedIds), d));
      for (const d of blockDomains) addRules.push(makeBlockDomainRule(stableRuleId(DYNAMIC_RULE_BASES.blockDomain, d, usedIds), d));
      for (const s of bypassSites) addRules.push(makeBypassSiteRule(stableRuleId(DYNAMIC_RULE_BASES.bypassSite, s, usedIds), s));
      for (const key of scopedAllows) addRules.push(makeScopedAllowRule(stableRuleId(DYNAMIC_RULE_BASES.scopedAllow, key, usedIds), key));
      for (const d of tempAllowDomains) addRules.push(makeTempAllowDomainRule(stableRuleId(DYNAMIC_RULE_BASES.tempAllowDomain, d, usedIds), d));
      for (const s of tempBypassSites) addRules.push(makeBypassSiteRule(stableRuleId(DYNAMIC_RULE_BASES.tempBypassSite, s, usedIds), s));
      for (const key of tempScopedAllows)
        addRules.push(makeScopedAllowRule(stableRuleId(DYNAMIC_RULE_BASES.tempScopedAllow, key, usedIds), key));
    }

    chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules }, () => {
      const err = chrome.runtime.lastError;
      if (err) setLastDnrError(err);
      cb && cb();
    });
  });
}

function reconcileSessionRules(settings, cb) {
  const api = chrome.declarativeNetRequest;
  if (!api || !api.updateSessionRules || !api.getSessionRules) {
    cb && cb();
    return;
  }

  api.getSessionRules((existingRules) => {
    const tempBypassTabs = normalizeExpiringTabs(settings.tempBypassTabs);
    const removeRuleIds = Array.from(new Set((existingRules || []).map((r) => r && typeof r.id === "number" ? r.id : null).filter((x) => x !== null)));
    const addRules = [];

    if (settings.cubeEnabled) {
      const usedIds = new Set();
      for (const ent of tempBypassTabs) {
        const site = ent && typeof ent.host === "string" ? ent.host : "";
        if (!site || typeof ent.tabId !== "number") continue;
        addRules.push(makeBypassTabRule(stableRuleId(SESSION_RULE_BASES.tempBypassTab, String(ent.tabId), usedIds), ent.tabId, site));
      }
    }

    api.updateSessionRules({ removeRuleIds, addRules }, () => {
      const err = chrome.runtime.lastError;
      if (err) setLastDnrError(err);
      cb && cb();
    });
  });
}

function normalizeScopedPairs(list) {
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
    out.push(key);
  }
  out.sort();
  return out;
}

function normalizeExpiringDomains(list) {
  const out = [];
  const seen = new Set();
  const now = Date.now();
  for (const item of Array.isArray(list) ? list : []) {
    if (!item || typeof item !== "object") continue;
    const domain = normalizeDomain(item.domain);
    const exp = typeof item.expiresAt === "number" ? item.expiresAt : 0;
    if (!domain || !exp || exp <= now) continue;
    if (seen.has(domain)) continue;
    seen.add(domain);
    out.push(domain);
  }
  out.sort();
  return out;
}

function normalizeExpiringSites(list) {
  const out = [];
  const seen = new Set();
  const now = Date.now();
  for (const item of Array.isArray(list) ? list : []) {
    if (!item || typeof item !== "object") continue;
    const site = normalizeDomain(item.site);
    const exp = typeof item.expiresAt === "number" ? item.expiresAt : 0;
    if (!site || !exp || exp <= now) continue;
    if (seen.has(site)) continue;
    seen.add(site);
    out.push(site);
  }
  out.sort();
  return out;
}

function normalizeExpiringTabs(list) {
  const out = [];
  const byTabId = new Map();
  const now = Date.now();

  for (const item of Array.isArray(list) ? list : []) {
    if (!item || typeof item !== "object") continue;
    const tabId = typeof item.tabId === "number" ? item.tabId : -1;
    const exp = typeof item.expiresAt === "number" ? item.expiresAt : 0;
    const host = normalizeDomain(item.host);
    if (tabId < 0 || !exp || exp <= now) continue;
    // Keep the entry with the latest expiration for a given tabId.
    const prev = byTabId.get(tabId);
    if (!prev || exp > prev.expiresAt) byTabId.set(tabId, { tabId, host, expiresAt: exp });
  }

  for (const v of byTabId.values()) out.push(v);
  out.sort((a, b) => a.tabId - b.tabId);
  return out;
}

function normalizeExpiringScopedPairs(list) {
  const out = [];
  const seen = new Set();
  const now = Date.now();
  for (const item of Array.isArray(list) ? list : []) {
    if (!item || typeof item !== "object") continue;
    const site = normalizeDomain(item.site);
    const domain = normalizeDomain(item.domain);
    const exp = typeof item.expiresAt === "number" ? item.expiresAt : 0;
    if (!site || !domain || !exp || exp <= now) continue;
    const key = `${site}@@${domain}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(key);
  }
  out.sort();
  return out;
}

function hasFeedbackPermission(cb) {
  if (!chrome.permissions || !chrome.permissions.contains) return cb(false);
  chrome.permissions.contains({ permissions: ["declarativeNetRequestFeedback"] }, (ok) => cb(!!ok));
}

function attachOrDetachDebugListener(settings) {
  const debugEvent = chrome.declarativeNetRequest && chrome.declarativeNetRequest.onRuleMatchedDebug;
  if (!debugEvent) return;

  if (!settings.cubeEnabled || !settings.logEnabled) {
    if (debugListenerAttached) {
      debugEvent.removeListener(onRuleMatchedDebug);
      debugListenerAttached = false;
    }
    return;
  }

  hasFeedbackPermission((ok) => {
    if (!ok) {
      if (debugListenerAttached) {
        debugEvent.removeListener(onRuleMatchedDebug);
        debugListenerAttached = false;
      }
      return;
    }
    if (debugListenerAttached) return;
    debugEvent.addListener(onRuleMatchedDebug);
    debugListenerAttached = true;
  });
}

function onRuleMatchedDebug(info) {
  if (!currentSettings.cubeEnabled || !currentSettings.logEnabled) return;
  if (!info || !info.request || !info.rule) return;

  const url = typeof info.request.url === "string" ? info.request.url : "";
  const domain = safeHostname(url);

  const rulesetId = typeof info.rule.rulesetId === "string" ? info.rule.rulesetId : "";
  const ruleId = typeof info.rule.ruleId === "number" ? info.rule.ruleId : null;
  const requestType = typeof info.request.type === "string" ? info.request.type : "";
  const initiator = typeof info.request.initiator === "string" ? info.request.initiator : "";
  const site = safeHostname(initiator);
  const tabId = typeof info.request.tabId === "number" ? info.request.tabId : null;
  const frameId = typeof info.request.frameId === "number" ? info.request.frameId : null;
  const parentFrameId = typeof info.request.parentFrameId === "number" ? info.request.parentFrameId : null;

  let action = "";
  if (info.rule.action && typeof info.rule.action.type === "string") action = info.rule.action.type;
  // Fallback inference by ruleset.
  if (!action) {
    if (rulesetId.startsWith("rules_block_")) action = "block";
    else if (rulesetId === RULESETS.exceptions || rulesetId === RULESETS.builtinAllowlist) action = "allow";
    else action = "match";
  }

  const key = [tabId ?? "?", site || "?", domain || "?", requestType || "?", action, rulesetId || "?", ruleId ?? "?"].join("|");
  pendingMatches.push({
    key,
    ts: Date.now(),
    action,
    url,
    domain,
    site,
    initiator,
    tabId,
    frameId,
    parentFrameId,
    type: requestType,
    ruleId,
    rulesetId,
  });

  scheduleFlushMatches();
}

function safeHostname(rawURL) {
  if (!rawURL) return "";
  try {
    return new URL(rawURL).hostname || "";
  } catch {
    return "";
  }
}

function scheduleFlushMatches() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    flushMatches();
  }, FLUSH_INTERVAL_MS);
}

function flushMatches() {
  if (pendingMatches.length === 0) return;
  const toMerge = pendingMatches;
  pendingMatches = [];

  chrome.storage.local.get({ recentMatches: [] }, (cur) => {
    const existing = Array.isArray(cur.recentMatches) ? cur.recentMatches : [];
    const byKey = new Map();

    for (const e of existing) {
      if (!e || typeof e !== "object") continue;
      const k = typeof e.key === "string" ? e.key : "";
      if (!k) continue;
      byKey.set(k, { ...e });
    }

    for (const ev of toMerge) {
      if (!ev || typeof ev !== "object") continue;
      const k = ev.key;
      if (!k) continue;
      const curEnt = byKey.get(k);
      if (!curEnt) {
        const urls = [];
        if (ev.url) urls.push(ev.url);
        byKey.set(k, {
          key: k,
          action: ev.action,
          domain: ev.domain,
          site: ev.site,
          initiator: ev.initiator,
          url: ev.url,
          urls,
          type: ev.type,
          tabId: ev.tabId,
          frameId: ev.frameId,
          parentFrameId: ev.parentFrameId,
          ruleId: ev.ruleId,
          rulesetId: ev.rulesetId,
          firstTs: ev.ts,
          lastTs: ev.ts,
          count: 1,
        });
        continue;
      }
      curEnt.count = (typeof curEnt.count === "number" ? curEnt.count : 1) + 1;
      curEnt.lastTs = ev.ts;
      curEnt.url = ev.url || curEnt.url;
      if (!Array.isArray(curEnt.urls)) curEnt.urls = curEnt.url ? [curEnt.url] : [];
      if (ev.url && curEnt.urls.length < 3 && !curEnt.urls.includes(ev.url)) curEnt.urls.push(ev.url);
      curEnt.type = ev.type || curEnt.type;
      curEnt.site = ev.site || curEnt.site;
      curEnt.domain = ev.domain || curEnt.domain;
      curEnt.initiator = ev.initiator || curEnt.initiator;
      curEnt.frameId = typeof ev.frameId === "number" ? ev.frameId : curEnt.frameId;
      curEnt.parentFrameId = typeof ev.parentFrameId === "number" ? ev.parentFrameId : curEnt.parentFrameId;
      byKey.set(k, curEnt);
    }

    const next = Array.from(byKey.values())
      .sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0))
      .slice(0, RECENT_MATCHES_LIMIT);
    storageSet({ recentMatches: next }, () => void chrome.runtime.lastError);
  });
}

function syncAll(cb) {
  if (typeof cb === "function") syncWaiters.push(cb);
  if (syncing) {
    resyncRequested = true;
    return;
  }
  syncing = true;
  setLastDnrError("");

  storageGet((settings) => {
    const pruned = pruneExpiredSettings(settings);
    currentSettings = pruned.settings;
    if (pruned.changed) {
      storageSet(
        {
          tempAllowDomains: pruned.settings.tempAllowDomains,
          tempBypassSites: pruned.settings.tempBypassSites,
          tempBypassTabs: pruned.settings.tempBypassTabs,
          tempScopedAllows: pruned.settings.tempScopedAllows,
        },
        () => void chrome.runtime.lastError
      );
    }
    setEnabledRulesets(pruned.settings, () => {
      let remaining = 2;
      const done = () => {
        remaining--;
        if (remaining > 0) return;
        attachOrDetachDebugListener(pruned.settings);
        syncing = false;
        if (resyncRequested) {
          resyncRequested = false;
          syncAll();
          return;
        }
        const waiters = syncWaiters;
        syncWaiters = [];
        for (const w of waiters) {
          try {
            w();
          } catch {
            // ignore
          }
        }
      };

      reconcileDynamicRules(pruned.settings, done);
      reconcileSessionRules(pruned.settings, done);
    });
  });
}

function ensurePruneAlarm() {
  if (!chrome.alarms || !chrome.alarms.create) return;
  chrome.alarms.create(PRUNE_ALARM, { periodInMinutes: 1 });
}

chrome.runtime.onInstalled.addListener(() => {
  storageGet((settings) => {
    storageSet(settings, () => syncAll());
  });
  ensurePruneAlarm();
});

chrome.runtime.onStartup.addListener(() => syncAll());
chrome.runtime.onStartup.addListener(() => ensurePruneAlarm());
if (chrome.alarms && chrome.alarms.onAlarm) {
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (!alarm || alarm.name !== PRUNE_ALARM) return;
    syncAll();
  });
}
if (chrome.tabs && chrome.tabs.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    if (typeof tabId !== "number" || tabId < 0) return;
    chrome.storage.local.get({ tempBypassTabs: [] }, (cur) => {
      const list = Array.isArray(cur.tempBypassTabs) ? cur.tempBypassTabs : [];
      const next = list.filter((x) => !(x && typeof x === "object" && typeof x.tabId === "number" && x.tabId === tabId));
      if (next.length === list.length) return;
      storageSet({ tempBypassTabs: next }, () => void chrome.runtime.lastError);
    });
  });
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || typeof msg.type !== "string") return;
  if (msg.type === "sync") {
    syncAll(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.type === "diagnosticsStatus") {
    const debugEvent = chrome.declarativeNetRequest && chrome.declarativeNetRequest.onRuleMatchedDebug;
    hasFeedbackPermission((hasFeedback) => {
      sendResponse({
        ok: true,
        supported: !!debugEvent,
        hasFeedback,
        cubeEnabled: !!currentSettings.cubeEnabled,
        logEnabled: !!currentSettings.logEnabled,
      });
    });
    return true;
  }
  if (msg.type === "clearRecentMatches") {
    pendingMatches = [];
    storageSet({ recentMatches: [] }, () => sendResponse({ ok: true }));
    return true;
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  const keys = Object.keys(changes || {});
  if (keys.length === 0) return;
  if (keys.every((k) => INTERNAL_STORAGE_KEYS.has(k))) return;
  syncAll();
});
