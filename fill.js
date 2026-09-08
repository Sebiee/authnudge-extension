/** Popup status after a fill. "filled" (Signed in) only when that step left the page. */
export function fillResultStatus(fill, stillOnStep, kind = "password") {
  if (fill?.reason === "permission_denied") return "permission_denied";
  if (fill?.reason === "need_permission") return "need_permission";
  if (fill?.reason === "wrong_origin") return "page_changed";
  if (fill?.ok && stillOnStep) return kind === "otp" ? "otp" : "need_password";
  if (fill?.ok) return "filled";
  if (fill?.reason === "need_password") return "need_password";
  if (fill?.reason === "no_form" || fill?.reason === "no_otp") return "no_form";
  return "need_password";
}

// Self-contained: chrome.scripting.executeScript serializes this function.
// Return status only — never field values.
// ponytail: no shadow-DOM pierce; add a site list if real logins stay unfilled.
export async function fillLoginForm(identifier, secret, expectedOrigin, waitMs = 15000, mode = "password") {
  // Playwright page.evaluate only passes one argument.
  if (identifier !== null && typeof identifier === "object" && !Array.isArray(identifier)) {
    ({ identifier, secret, expectedOrigin, waitMs = 15000, mode = "password" } = identifier);
  }
  const hostOf = (tabUrl) => {
    try {
      const url = new URL(tabUrl);
      if ((url.protocol !== "https:" && url.protocol !== "http:") || !url.hostname) return null;
      return `${url.protocol}//${url.host.toLowerCase()}`;
    } catch {
      return null;
    }
  };
  const sameHost = () => {
    const want = hostOf(expectedOrigin);
    const here = hostOf(location.href);
    // Own frame host only: the parent page origin is not a fill license (evil iframe on a granted page).
    return Boolean(want && here && want === here);
  };

  if (!sameHost()) return { ok: false, reason: "wrong_origin" };

  const visible = (el) => {
    if (!el || el.disabled || el.readOnly || el.type === "hidden" || el.getAttribute("aria-hidden") === "true") {
      return false;
    }
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
    `${el.autocomplete || ""} ${el.name || ""} ${el.id || ""} ${el.placeholder || ""} ${el.getAttribute("inputmode") || ""} ${el.getAttribute("aria-label") || ""} ${[...(el.labels ?? [])].map((l) => l.textContent).join(" ")}`
      .replace(/\s+/g, " ")
      .toLowerCase();

  const NOT_TEXT = ["password", "hidden", "submit", "button", "checkbox", "radio", "file", "reset", "image", "search"];

  const looksLikeOtp = (el) => {
    const type = (el.type || "text").toLowerCase();
    const text = hint(el);
    const max = Number(el.maxLength);
    const numeric = (el.getAttribute("inputmode") || "").toLowerCase() === "numeric" || type === "tel" || type === "number";
    // One character per box (maxlength=1 or pattern like [0-9]{1}): only ever a code.
    if (max === 1 || /^(\[0-9\]|\\d)(\{1\})?$/.test(el.getAttribute("pattern") || "")) return true;
    if ((el.autocomplete || "").toLowerCase() === "one-time-code") return true;
    if (numeric && max >= 4 && max <= 8) return true;
    if (/(^|[^a-z])(otp|totp|2fa|mfa|code)([^a-z]|$)/.test(text)) return true;
    return /(verification code|one[- ]time|security code|login code|auth code|einmalcode)/.test(text);
  };

  const inputs = () => [...document.querySelectorAll("input")].filter(visible);

  // One code field, or 4–8 one-character boxes (Galaxus: six type=tel name="otp-code" boxes, no maxlength).
  const otpBoxes = () => {
    const list = inputs().filter((el) => !NOT_TEXT.includes((el.type || "text").toLowerCase()) && looksLikeOtp(el));
    return list.length === 1 || (list.length >= 4 && list.length <= 8) ? list : [];
  };

  const passwords = () => inputs().filter((el) => el.type === "password" && !hint(el).includes("new-password"));

  if (mode === "detect-otp") {
    return otpBoxes().length > 0 ? { ok: true, reason: "otp" } : { ok: false, reason: "no_otp" };
  }
  if (mode === "detect-password") {
    return passwords().length > 0 ? { ok: true, reason: "need_password" } : { ok: false, reason: "no_form" };
  }

  const scoreIdentifier = (el) => {
    const type = (el.type || "text").toLowerCase();
    const text = hint(el);
    const auto = (el.autocomplete || "").toLowerCase();
    if (auto === "username" || auto === "email") return 5;
    if (type === "email" || text.includes("email") || text.includes("e-mail")) return 4;
    if (text.includes("username") || text.includes("user")) return 3;
    if (/(^|[^a-z])(login|identifier|acct|account)([^a-z]|$)/.test(text)) return 2;
    return 1;
  };

  const pickIdentifier = (scope, passwordEl) => {
    const nodes = inputs().filter((el) => {
      const type = (el.type || "text").toLowerCase();
      if (NOT_TEXT.includes(type) || !["email", "text", "tel", "url"].includes(type)) return false;
      if (el === passwordEl || !scope.contains(el) || looksLikeOtp(el)) return false;
      return !/search|suche|recherch/.test(hint(el));
    });
    if (!nodes.length) return null;
    const before = passwordEl
      ? nodes.filter((el) => passwordEl.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_PRECEDING)
      : nodes;
    const pool = before.length ? before : nodes;
    let best = pool[0];
    for (const el of pool) {
      if (scoreIdentifier(el) > scoreIdentifier(best)) best = el;
    }
    return best;
  };

  const wipePassword = (el) => {
    const desc = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
    if (desc?.set) desc.set.call(el, "");
    else el.value = "";
  };

  const controls = (root) =>
    [...root.querySelectorAll("button, input[type=submit], input[type=button], [role=button]")].filter((el) =>
      visible(el),
    );
  const label = (el) => (el.textContent || el.value || el.getAttribute("aria-label") || "").replace(/\s+/g, " ").trim();
  const looksLikeSubmit = (el) => {
    const text = label(el);
    if (!text || text.length > 48) return false;
    if (/google|apple|facebook|microsoft|github|passkey|forgot|vergessen|oubli|register|registr|sign\s*up|resend|neuen? code|renvoyer|cancel|abbrechen/i.test(text)) {
      return false;
    }
    return /continue|next|log\s*in|sign\s*in|submit|verify|confirm|anmelden|weiter|best[äa]tigen|se connecter|connexion|continuer|accedi|avanti|entrar|siguiente/i.test(
      text,
    );
  };
  // Browser order first: the form's default button is what Enter would press. Never guess a lone
  // button (Galaxus's code form only has "Neuen Code senden").
  const findSubmit = (el) => {
    const form = el.form ?? el.closest("form");
    if (form) {
      const list = controls(form);
      return (
        list.find((b) => b.matches("button[type=submit], input[type=submit]")) ??
        list.find((b) => b.matches("button:not([type])")) ??
        list.find(looksLikeSubmit) ??
        null
      );
    }
    let root = el;
    for (let i = 0; i < 8 && root.parentElement && root !== document.body; i++) {
      root = root.parentElement;
      const hit = controls(root).find(looksLikeSubmit);
      if (hit) return hit;
    }
    return null;
  };

  const submitAround = (el) => {
    const button = findSubmit(el);
    if (button) {
      button.click();
      return true;
    }
    const form = el.form ?? el.closest("form");
    if (form && typeof form.requestSubmit === "function") {
      form.requestSubmit();
      return true;
    }
    return false;
  };

  if (mode === "otp") {
    const boxes = otpBoxes();
    if (!boxes.length) return { ok: false, reason: "no_otp" };
    const code = String(secret ?? "");
    // Single-char boxes get one digit each (maxlength=1 truncates a paste); many auto-submit on the last one.
    for (let i = 0; i < (boxes.length > 1 ? Math.min(code.length, boxes.length) : 1); i++) {
      write(boxes[i], boxes.length > 1 ? code[i] : code);
    }
    submitAround(boxes[0]);
    return { ok: true };
  }

  const submitThenWipe = (passwordEl) => {
    const wipe = () => wipePassword(passwordEl);
    const form = passwordEl.form ?? passwordEl.closest("form");
    if (form) form.addEventListener("submit", () => queueMicrotask(wipe), { once: true });
    if (submitAround(passwordEl)) queueMicrotask(wipe);
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
    submitThenWipe(passwordEl);
    return { ok: true };
  }

  const userEl = pickIdentifier(document, null);
  if (!userEl) return { ok: false, reason: "no_form" };

  write(userEl, identifier);
  submitAround(userEl);

  const passwordEl = await waitForPassword(waitMs);
  if (!sameHost()) return { ok: false, reason: "wrong_origin" };
  if (!passwordEl) return { ok: false, reason: "need_password" };

  write(passwordEl, secret);
  submitThenWipe(passwordEl);
  return { ok: true };
}
