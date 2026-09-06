// Self-contained: chrome.scripting.executeScript serializes this function.
// Return status only — never field values.
// ponytail: no shadow-DOM / cross-host iframe recipes; add a site list if real logins stay unfilled.
export async function fillLoginForm(identifier, secret, expectedOrigin, waitMs = 15000) {
  // Playwright page.evaluate only passes one argument.
  if (identifier !== null && typeof identifier === "object" && !Array.isArray(identifier)) {
    ({ identifier, secret, expectedOrigin, waitMs = 15000 } = identifier);
  }
  const hostOf = (tabUrl) => {
    let url;
    try {
      url = new URL(tabUrl);
    } catch {
      return null;
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    if (!url.hostname) return null;
    return `${url.protocol}//${url.host.toLowerCase()}`;
  };
  const sameHost = () => {
    if (!expectedOrigin) return true;
    const left = hostOf(location.href);
    const right = hostOf(expectedOrigin);
    return Boolean(left && right && left === right);
  };

  if (!sameHost()) return { ok: false, reason: "wrong_origin" };

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

  const hint = (el) =>
    `${el.autocomplete || ""} ${el.name || ""} ${el.id || ""} ${el.placeholder || ""} ${el.getAttribute("inputmode") || ""}`.toLowerCase();

  const scoreIdentifier = (el) => {
    const type = (el.type || "text").toLowerCase();
    const text = hint(el);
    if (type === "email" || text.includes("email")) return 4;
    if (text.includes("username") || text.includes("user")) return 3;
    if (/(^|[^a-z])(login|identifier|acct|account)([^a-z]|$)/.test(text)) return 2;
    return 1;
  };

  const identifiers = () =>
    [...document.querySelectorAll("input")].filter((el) => {
      if (!visible(el)) return false;
      const type = (el.type || "text").toLowerCase();
      if (["password", "hidden", "submit", "button", "checkbox", "radio", "file", "reset", "image"].includes(type)) {
        return false;
      }
      return ["email", "text", "tel", "search", "url"].includes(type);
    });

  const passwords = () =>
    [...document.querySelectorAll("input[type=password]")].filter((el) => {
      if (!visible(el)) return false;
      return !hint(el).includes("new-password");
    });

  const pickIdentifier = (scope, passwordEl) => {
    const nodes = identifiers().filter((el) => (!scope || scope.contains(el)) && el !== passwordEl);
    if (!nodes.length) return null;
    const before = passwordEl
      ? nodes.filter((el) => passwordEl.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_PRECEDING)
      : nodes;
    const pool = before.length ? before : nodes;
    let best = pool[0];
    for (const el of pool) {
      if (scoreIdentifier(el) >= scoreIdentifier(best)) best = el;
    }
    return best;
  };

  const wipePassword = (el) => {
    const desc = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
    if (desc?.set) desc.set.call(el, "");
    else el.value = "";
  };

  const submitForm = (form) => {
    if (form) {
      const submit =
        form.querySelector("button[type=submit], input[type=submit]") || form.querySelector("button:not([type])");
      if (submit && visible(submit) && !submit.disabled) {
        submit.click();
        return true;
      }
      if (typeof form.requestSubmit === "function") {
        form.requestSubmit();
        return true;
      }
    }
    const next = [...document.querySelectorAll("button, input[type=submit], [role=button]")].find((el) => {
      if (!visible(el) || el.disabled) return false;
      return /^(continue|next|log\s*in|sign\s*in|submit)$/i.test((el.textContent || el.value || "").trim());
    });
    if (next) {
      next.click();
      return true;
    }
    return false;
  };

  const submitThenWipe = (form, passwordEl) => {
    const formEl = form || passwordEl.form;
    const wipe = () => wipePassword(passwordEl);
    if (formEl) formEl.addEventListener("submit", () => queueMicrotask(wipe), { once: true });
    if (submitForm(formEl)) queueMicrotask(wipe);
  };

  const waitForPassword = (ms) =>
    new Promise((resolve) => {
      const finish = (value) => {
        observer.disconnect();
        clearTimeout(timer);
        resolve(value);
      };
      const check = () => {
        if (!sameHost()) return finish(null);
        const found = passwords();
        if (found.length === 1) return finish(found[0]);
        if (found.length > 1) return finish(null);
      };
      const observer = new MutationObserver(check);
      observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true });
      const timer = setTimeout(() => finish(passwords().length === 1 ? passwords()[0] : null), ms);
      check();
    });

  const pwdFields = passwords();
  if (pwdFields.length > 1) return { ok: false, reason: "no_form" };

  if (pwdFields.length === 1) {
    const passwordEl = pwdFields[0];
    const userEl = pickIdentifier(passwordEl.form ?? document, passwordEl);
    if (userEl) write(userEl, identifier);
    write(passwordEl, secret);
    submitThenWipe(passwordEl.form, passwordEl);
    return { ok: true };
  }

  const userEl = pickIdentifier(document, null);
  if (!userEl) return { ok: false, reason: "no_form" };

  write(userEl, identifier);
  submitForm(userEl.form);

  const passwordEl = await waitForPassword(waitMs);
  if (!sameHost()) return { ok: false, reason: "wrong_origin" };
  if (!passwordEl) return { ok: false, reason: "need_password" };

  write(passwordEl, secret);
  submitThenWipe(passwordEl.form, passwordEl);
  return { ok: true };
}
