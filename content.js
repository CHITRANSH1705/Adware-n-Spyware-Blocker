// WARDEN content.js (isolated world)
// Runs the actual DOM cleanup and reports counts to background.js for the
// badge/popup. Network-level blocking is handled separately by the
// declarativeNetRequest ruleset — this script only ever touches the DOM.
(() => {
  if (window.__wardenContentActive) return;
  window.__wardenContentActive = true;

  const counts = { adware: 0, spyware: 0, suspiciousListeners: 0 };
  let enabled = true; // master + per-site toggle, resolved from storage below

  // ---- Tier 1: precise, well-known ad/tracker DOM signatures. -------------
  // Safe to remove anywhere in the document — these patterns don't occur
  // in ordinary page layout markup.
  const PRECISE_SELECTORS = [
    "ins.adsbygoogle",
    "iframe[id^='google_ads_iframe']",
    "iframe[src*='doubleclick.net']",
    "iframe[src*='googlesyndication.com']",
    "div[id^='div-gpt-ad']",
    "[data-ad-slot]",
    "[data-google-query-id]",
    "script[src*='beacon']",
    "script[src*='google-analytics.com']",
  ];

  // ---- Tier 2: heuristic token match. -------------------------------------
  // The original version matched `[id*='ad']` / `[class*='ad']` against the
  // WHOLE document, which deletes anything whose id/class merely CONTAINS
  // "ad" as a substring — "header", "gradient", "already", "load", "read",
  // "shadow" all contain it, so real pages lost their nav bars and sidebars.
  // Two changes fix that:
  //   1. Token-boundary regex, so "ad" must be its own word/segment
  //      (delimited by start/end/hyphen/underscore/space), not a substring.
  //   2. Restricted to the tags that actually deliver ads/trackers
  //      (script/img/iframe/ins) — never applied to layout containers like
  //      <div>/<header>/<nav>/<section>, which is what broke page structure
  //      before.
  const HEURISTIC_TAGS = "script, img, iframe, ins";
  const HEURISTIC_TOKEN = /(^|[\s_-])(ad|ads|advert|spyware|tracker|tracking|fingerprint)([\s_-]|$)/i;

  function matchesHeuristic(el) {
    const haystack = `${el.id || ""} ${el.className || ""} ${el.getAttribute("src") || ""}`;
    return HEURISTIC_TOKEN.test(haystack);
  }

  function isTrackingPixel(img) {
    // Classic 1x1 tracking pixel — dimension-based, not filename-based, so
    // it doesn't false-positive on things like "pixel-art.png".
    const w = img.naturalWidth || parseInt(img.getAttribute("width") || "0", 10);
    const h = img.naturalHeight || parseInt(img.getAttribute("height") || "0", 10);
    return w > 0 && w <= 2 && h > 0 && h <= 2;
  }

  function collect(root, selector) {
    if (root.nodeType !== 1) return [];
    const out = [];
    if (root.matches?.(selector)) out.push(root);
    root.querySelectorAll?.(selector).forEach((el) => out.push(el));
    return out;
  }

  function scan(root) {
    if (!enabled) return;

    PRECISE_SELECTORS.forEach((selector) => {
      collect(root, selector).forEach((el) => {
        el.remove();
        counts.adware++;
      });
    });

    collect(root, HEURISTIC_TAGS).forEach((el) => {
      if (el.isConnected && matchesHeuristic(el)) {
        el.remove();
        counts.spyware++;
      }
    });

    collect(root, "img").forEach((img) => {
      if (img.isConnected && isTrackingPixel(img)) {
        img.remove();
        counts.spyware++;
      }
    });

    report();
  }

  // ---- Inline-handler keylogger heuristic. --------------------------------
  // The original check flagged any onkeydown/onkeypress attribute whose text
  // contained "log" — which also matches "login", "dialog", "catalog", and
  // "toggleLogin", i.e. common, harmless handler names. This version instead
  // looks for an actual data-exfiltration call (fetch/XHR/sendBeacon/Image
  // ping) inside the handler, which is a real indicator rather than a
  // coincidental word match.
  const EXFIL_PATTERN = /(fetch\s*\(|xmlhttprequest|\.send\s*\(|sendbeacon|new\s+image\s*\(\s*\)\.src\s*=)/i;

  function scanInlineHandlers(root) {
    if (!enabled || root.nodeType !== 1) return;
    const fields = collect(root, "input, textarea");
    fields.forEach((field) => {
      ["onkeydown", "onkeypress", "onkeyup", "oninput"].forEach((attr) => {
        const handler = field.getAttribute(attr);
        if (handler && EXFIL_PATTERN.test(handler)) {
          field.removeAttribute(attr);
          counts.spyware++;
        }
      });
    });
    report();
  }

  function report() {
    try {
      chrome.runtime.sendMessage({ type: "warden:counts", counts });
    } catch (e) {
      /* background may not be ready yet; next report() call will catch up */
    }
  }

  // Relay flags from the MAIN-world hook (page-hook.js) — third-party
  // scripts attaching keystroke listeners to sensitive targets.
  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    if (event.data?.source === "warden-hook" && event.data.type === "suspicious-listener") {
      counts.suspiciousListeners++;
      report();
    }
  });

  const observer = new MutationObserver((mutations) => {
    if (!enabled) return;
    mutations.forEach((m) => {
      m.addedNodes.forEach((node) => {
        scan(node);
        scanInlineHandlers(node);
      });
    });
  });

  function start() {
    scan(document.documentElement);
    scanInlineHandlers(document.documentElement);
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  function resolveEnabledAndStart() {
    chrome.storage.local.get(["wardenProtectionEnabled", "wardenAllowlist"], (res) => {
      const globalOn = res.wardenProtectionEnabled !== false; // default ON
      const allowlist = res.wardenAllowlist || [];
      const siteAllowed = allowlist.includes(location.hostname);
      enabled = globalOn && !siteAllowed;
      if (document.documentElement) start();
      else document.addEventListener("DOMContentLoaded", start, { once: true });
    });
  }

  resolveEnabledAndStart();

  // React live if the user flips the toggle or allowlist while this page is open
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.wardenProtectionEnabled || changes.wardenAllowlist) {
      resolveEnabledAndStart();
    }
  });

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg?.type === "warden:getCounts") {
      sendResponse({ ok: true, counts, enabled });
      return true;
    }
    return false;
  });
})();
