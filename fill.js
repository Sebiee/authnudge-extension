// Self-contained: chrome.scripting.executeScript serializes this function.
// Return status only — never field values.
export function fillLoginForm(identifier, secret, expectedOrigin) {
  const normalize = (tabUrl) => {
    let url;
    try {
      url = new URL(tabUrl);
    } catch {
      return null;
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    if (!url.hostname) return null;
    const path = url.pathname === "/" ? "" : url.pathname.replace(/\/+$/, "");
    return `${url.protocol}//${url.host.toLowerCase()}${path}`;
  };

  if (expectedOrigin && normalize(location.href) !== expectedOrigin) {
    return { ok: false, reason: "wrong_origin" };
  }

  const visible = (el) => {
    if (!el || el.disabled) return false;
    if (el.type === "hidden") return false;
    if (el.getAttribute("aria-hidden") === "true") return false;
    const style = getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") return false;
    const rect = el.getBoundingClientRect();
    return rect.width >= 2 && rect.height >= 2;
  };

  const write = (el, value) => {
    el.focus();
    const desc = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
    if (desc?.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const scoreIdentifier = (el) => {
    const type = (el.type || "text").toLowerCase();
    const auto = (el.autocomplete || "").toLowerCase();
    if (type === "email") return 3;
    if (auto.includes("username")) return 2;
    return 1;
  };

  const pickIdentifier = (scope, passwordEl) => {
    const nodes = [...scope.querySelectorAll("input")].filter((el) => {
      if (!visible(el) || el === passwordEl) return false;
      const type = (el.type || "text").toLowerCase();
      if (["password", "hidden", "submit", "button", "checkbox", "radio", "file", "reset", "image"].includes(type)) {
        return false;
      }
      return ["email", "text", "tel", "search", "url"].includes(type);
    });
    if (!nodes.length) return null;
    const before = nodes.filter((el) => passwordEl.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_PRECEDING);
    const pool = before.length ? before : nodes;
    let best = pool[0];
    for (const el of pool) {
      if (scoreIdentifier(el) >= scoreIdentifier(best)) best = el;
    }
    return best;
  };

  const passwords = [...document.querySelectorAll("input[type=password]")].filter(visible);
  const groups = new Map();
  for (const pwd of passwords) {
    const form = pwd.form;
    const key = form ?? pwd;
    const entry = groups.get(key) ?? { form, passwords: [] };
    entry.passwords.push(pwd);
    groups.set(key, entry);
  }

  const candidates = [];
  for (const entry of groups.values()) {
    if (entry.passwords.length !== 1) continue;
    const passwordEl = entry.passwords[0];
    const scope = entry.form ?? document;
    const userEl = pickIdentifier(scope, passwordEl);
    if (userEl) candidates.push({ form: entry.form, passwordEl, userEl });
  }

  if (candidates.length !== 1) return { ok: false, reason: "no_form" };

  const { form, passwordEl, userEl } = candidates[0];
  write(userEl, identifier);
  write(passwordEl, secret);

  if (form) {
    const submit =
      form.querySelector("button[type=submit], input[type=submit]") || form.querySelector("button:not([type])");
    if (submit && visible(submit) && !submit.disabled) submit.click();
    else if (typeof form.requestSubmit === "function") form.requestSubmit();
  }

  return { ok: true };
}
