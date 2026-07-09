const els = {
  protectionToggle: document.getElementById("protection-toggle"),
  protectionDot: document.getElementById("protection-state"),
  protectionText: document.getElementById("protection-text"),
  siteName: document.getElementById("site-name"),
  trustBtn: document.getElementById("trust-btn"),
  statNetwork: document.getElementById("stat-network"),
  statDom: document.getElementById("stat-dom"),
  statScripts: document.getElementById("stat-scripts"),
  scriptsNote: document.getElementById("scripts-note"),
  lifetimeCount: document.getElementById("lifetime-count"),
};

let currentTabId = null;
let currentHostname = null;

function isRestrictedUrl(url) {
  if (!url) return true;
  return (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith("https://chrome.google.com/webstore") ||
    url.startsWith("https://chromewebstore.google.com")
  );
}

function renderProtection(enabled) {
  els.protectionToggle.checked = enabled;
  els.protectionDot.classList.toggle("off", !enabled);
  els.protectionText.textContent = enabled ? "PROTECTION ON" : "PROTECTION OFF";
}

function renderTrust(isTrusted, controllable) {
  els.trustBtn.disabled = !controllable;
  els.trustBtn.classList.toggle("trusted", isTrusted);
  els.trustBtn.textContent = isTrusted ? "TRUSTED ✓" : "TRUST SITE";
}

function renderStats(stats) {
  els.statNetwork.textContent = stats.network;
  els.statDom.textContent = stats.adware + stats.spyware;
  els.statScripts.textContent = stats.suspiciousListeners;
  els.scriptsNote.textContent =
    stats.suspiciousListeners > 0
      ? "// third-party script(s) observed attaching keystroke listeners — not necessarily malicious, worth a look_"
      : "";
}

async function refresh() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  currentTabId = tab.id;

  if (isRestrictedUrl(tab.url)) {
    currentHostname = null;
    els.siteName.textContent = "// restricted page_";
    renderTrust(false, false);
  } else {
    try {
      currentHostname = new URL(tab.url).hostname;
      els.siteName.textContent = currentHostname;
    } catch (e) {
      currentHostname = null;
      els.siteName.textContent = "// unknown site_";
    }
  }

  chrome.runtime.sendMessage({ type: "warden:getStats", tabId: currentTabId }, (res) => {
    if (!res?.ok) return;
    renderProtection(res.protectionEnabled);
    renderStats(res.stats);
    els.lifetimeCount.textContent = res.lifetimeBlocked;
    if (currentHostname) {
      renderTrust(res.allowlist.includes(currentHostname), true);
    }
  });
}

els.protectionToggle.addEventListener("change", () => {
  chrome.runtime.sendMessage({ type: "warden:toggleProtection" }, (res) => {
    if (res?.ok) renderProtection(res.protectionEnabled);
  });
});

els.trustBtn.addEventListener("click", () => {
  if (!currentHostname) return;
  chrome.runtime.sendMessage(
    { type: "warden:toggleAllowlist", hostname: currentHostname },
    (res) => {
      if (res?.ok) renderTrust(res.isAllowed, true);
    }
  );
});

refresh();
const liveRefresh = setInterval(refresh, 1500);
window.addEventListener("unload", () => clearInterval(liveRefresh));
