// WARDEN page-hook.js — runs in the page's own (MAIN) JS world, not the
// isolated content-script world, because addEventListener must be wrapped
// before any other script on the page gets a chance to call it.
//
// This module only DETECTS and REPORTS. It never removes or blocks a
// listener — plenty of legitimate code (password managers, input masks,
// chat widgets, accessibility tools) listens for keystrokes for reasons
// that have nothing to do with spying, and content scripts have no
// reliable way to tell intent apart from a stack trace alone. Flagging
// instead of removing means WARDEN can surface a signal to the user
// without risking breaking a site's real functionality.
(() => {
  if (window.__wardenHookActive) return;
  window.__wardenHookActive = true;

  const KEY_EVENTS = new Set(["keydown", "keyup", "keypress", "input"]);
  const originalAddEventListener = EventTarget.prototype.addEventListener;

  function originHost(url) {
    try {
      return new URL(url, location.href).hostname;
    } catch (e) {
      return null;
    }
  }

  function isThirdPartyStack(stack) {
    const urls = stack.match(/https?:\/\/[^\s):]+/g) || [];
    return urls.some((u) => {
      const h = originHost(u);
      return h && h !== location.hostname;
    });
  }

  function isSensitiveTarget(target) {
    if (target === document || target === window) return true;
    const tag = target && target.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || (target && target.isContentEditable);
  }

  EventTarget.prototype.addEventListener = function (type, listener, options) {
    if (KEY_EVENTS.has(type) && isSensitiveTarget(this)) {
      const stack = new Error().stack || "";
      if (isThirdPartyStack(stack)) {
        window.postMessage(
          { source: "warden-hook", type: "suspicious-listener", eventType: type },
          "*"
        );
      }
    }
    return originalAddEventListener.call(this, type, listener, options);
  };
})();
