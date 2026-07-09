// WARDEN background.js
// Actual network-level blocking is done by the declarativeNetRequest static
// ruleset (rules/ads-trackers.json) — that's the MV3-correct replacement for
// the old chrome.webRequest.onBeforeRequest(..., ["blocking"]) call, which
// was removed for regular extensions in Manifest V3 and would never have
// worked here. This file only OBSERVES requests (no "blocking" option, which
// is still permitted) so it can count matches for the badge/popup, and
// manages the DNR ruleset's on/off + per-site allowlist state.

const RULESET_ID = "ads_trackers";
const DYNAMIC_ALLOW_RULE_BASE_ID = 100000;

let blockedHostnames = [];
const tabStats = new Map(); // tabId -> { network, adware, spyware, suspiciousListeners }

function emptyStats() {
  return { network: 0, adware: 0, spyware: 0, suspiciousListeners: 0 };
}

function getStats(tabId) {
  if (!tabStats.has(tabId)) tabStats.set(tabId, emptyStats());
  return tabStats.get(tabId);
}

async function loadBlocklist() {
  try {
    const res = await fetch(chrome.runtime.getURL("blocklist.json"));
    blockedHostnames = await res.json();
  } catch (e) {
    blockedHostnames = [];
  }
}
loadBlocklist();

function hostMatchesBlocklist(hostname) {
  return blockedHostnames.some((d) => hostname === d || hostname.endsWith("." + d));
}

function updateBadge(tabId) {
  const s = getStats(tabId);
  const total = s.network + s.adware + s.spyware;
  chrome.action.setBadgeText({ text: total > 0 ? String(total) : "", tabId });
  chrome.action.setBadgeBackgroundColor({ color: "#00e5b0", tabId });
}

async function bumpLifetimeTotal(by) {
  const { wardenLifetimeBlocked = 0 } = await chrome.storage.local.get("wardenLifetimeBlocked");
  await chrome.storage.local.set({ wardenLifetimeBlocked: wardenLifetimeBlocked + by });
}

// ---- Observation-only request counting (no "blocking" — MV3 doesn't allow
// it for regular extensions; actual blocking is the DNR ruleset above). -----
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (typeof details.tabId !== "number" || details.tabId < 0) return;
    try {
      const hostname = new URL(details.url).hostname;
      if (hostMatchesBlocklist(hostname)) {
        const s = getStats(details.tabId);
        s.network++;
        updateBadge(details.tabId);
        bumpLifetimeTotal(1);
      }
    } catch (e) {
      /* malformed URL; ignore */
    }
  },
  { urls: ["<all_urls>"] }
);

// ---- DOM-side counts reported by content.js -------------------------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "warden:counts" && sender.tab && typeof sender.tab.id === "number") {
    const s = getStats(sender.tab.id);
    // content.js sends its own running total for the page, so set rather
    // than increment (avoids double counting across repeated reports).
    const prevTotal = s.adware + s.spyware;
    s.adware = msg.counts.adware || 0;
    s.spyware = msg.counts.spyware || 0;
    s.suspiciousListeners = msg.counts.suspiciousListeners || 0;
    const newTotal = s.adware + s.spyware;
    if (newTotal > prevTotal) bumpLifetimeTotal(newTotal - prevTotal);
    updateBadge(sender.tab.id);
    return false;
  }

  if (msg?.type === "warden:getStats") {
    (async () => {
      const tabId = msg.tabId;
      const s = getStats(tabId);
      const { wardenProtectionEnabled = true, wardenAllowlist = [], wardenLifetimeBlocked = 0 } =
        await chrome.storage.local.get([
          "wardenProtectionEnabled",
          "wardenAllowlist",
          "wardenLifetimeBlocked",
        ]);
      sendResponse({
        ok: true,
        stats: s,
        protectionEnabled: wardenProtectionEnabled,
        allowlist: wardenAllowlist,
        lifetimeBlocked: wardenLifetimeBlocked,
      });
    })();
    return true; // async sendResponse
  }

  if (msg?.type === "warden:toggleProtection") {
    (async () => {
      const { wardenProtectionEnabled = true } = await chrome.storage.local.get(
        "wardenProtectionEnabled"
      );
      const next = !wardenProtectionEnabled;
      await chrome.storage.local.set({ wardenProtectionEnabled: next });
      if (next) {
        await chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds: [RULESET_ID] });
      } else {
        await chrome.declarativeNetRequest.updateEnabledRulesets({ disableRulesetIds: [RULESET_ID] });
      }
      sendResponse({ ok: true, protectionEnabled: next });
    })();
    return true;
  }

  if (msg?.type === "warden:toggleAllowlist") {
    (async () => {
      const hostname = msg.hostname;
      const { wardenAllowlist = [] } = await chrome.storage.local.get("wardenAllowlist");
      const isAllowed = wardenAllowlist.includes(hostname);
      const next = isAllowed
        ? wardenAllowlist.filter((h) => h !== hostname)
        : [...wardenAllowlist, hostname];
      await chrome.storage.local.set({ wardenAllowlist: next });
      await syncAllowlistRules(next);
      sendResponse({ ok: true, allowlist: next, isAllowed: !isAllowed });
    })();
    return true;
  }

  return false;
});

// Per-site allowlist bypasses the DNR block rules for requests whose
// initiator is that site, by installing a higher-priority "allow" rule.
async function syncAllowlistRules(allowlist) {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.map((r) => r.id);
  const addRules = allowlist.map((hostname, i) => ({
    id: DYNAMIC_ALLOW_RULE_BASE_ID + i,
    priority: 2,
    action: { type: "allow" },
    condition: {
      initiatorDomains: [hostname],
      urlFilter: "*",
      resourceTypes: [
        "script",
        "image",
        "xmlhttprequest",
        "sub_frame",
        "ping",
        "media",
        "websocket",
        "other",
      ],
    },
  }));
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    tabStats.set(tabId, emptyStats());
    chrome.action.setBadgeText({ text: "", tabId });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabStats.delete(tabId);
});

chrome.runtime.onInstalled.addListener(async () => {
  const { wardenAllowlist = [] } = await chrome.storage.local.get("wardenAllowlist");
  syncAllowlistRules(wardenAllowlist);
});
