import { DEFAULT_BASE, normalizeTo } from "./origin.js";

const $ = (id) => document.getElementById(id);

let tabId = null;
let expiresAt = null;
let currentStatus = null;

function send(msg) {
  return chrome.runtime.sendMessage(msg);
}

function remaining() {
  if (!expiresAt) return "";
  const sec = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
  return `${Math.floor(sec / 60)}:${String(sec % 60).padStart(2, "0")}`;
}

function statusCopy(status, extra = {}) {
  if (status === "waiting") return `Waiting for approval… ${remaining()}`;
  if (status === "filling") return "Signing you in…";
  if (status === "filled") return "Signed in";
  if (status === "no_form") return "Could not find a login form";
  if (status === "expired") return "Request timed out";
  if (status === "page_changed") return "The page changed, so sign-in was cancelled.";
  if (extra.code === "pairing") {
    return "Save this public key on the dashboard and confirm the origin and account.";
  }
  if (extra.code === "bad_tab") {
    return "Open an http(s) page. chrome:// and similar tabs cannot be used.";
  }
  return extra.message || "Something went wrong.";
}

function paintStatus(status, extra = {}) {
  currentStatus = status;
  if (extra.expiresAt) expiresAt = extra.expiresAt;
  const el = $("status");
  el.textContent = status ? statusCopy(status, extra) : "";
  el.classList.toggle("ok", status === "filled");
  el.classList.toggle("err", Boolean(status) && !["waiting", "filling", "filled"].includes(status));
  const busy = status === "waiting" || status === "filling";
  $("send").disabled = busy || $("send").dataset.blocked === "1";
}

function paintKey(publicKey) {
  const value = publicKey ?? "";
  $("public-key").textContent = value;
  $("public-key").title = value;
}

async function persistHandle() {
  const remember = $("remember").checked;
  const savedTo = remember ? normalizeTo($("to").value) : "";
  await chrome.storage.local.set({ rememberTo: remember, savedTo });
}

function render(state) {
  $("fingerprint").textContent = state.fingerprint
    ? `Encryption key ${state.fingerprint} — compare with the grant page`
    : "Pairing…";
  paintKey(state.publicKey);
  tabId = state.tabId ?? tabId;
  $("remember").checked = Boolean(state.rememberTo);
  if (state.rememberTo && state.savedTo) $("to").value = state.savedTo;
  const local = Boolean(state.baseUrl) && state.baseUrl !== DEFAULT_BASE;
  $("api-base").hidden = !local;
  $("api-base").textContent = local ? `Sending to ${state.baseUrl}` : "";

  if (state.origin) {
    $("origin").textContent = state.origin;
    $("send").dataset.blocked = "";
  } else {
    $("origin").textContent = "This tab is not an http(s) page.";
    $("send").dataset.blocked = "1";
  }

  if (state.live) paintStatus(state.live.status, { expiresAt: state.live.expiresAt });
  else if (!state.origin) paintStatus("error", { code: "bad_tab" });
  else $("send").disabled = $("send").dataset.blocked === "1";
}

$("request-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const to = normalizeTo($("to").value);
  if (!to) {
    paintStatus("error", { message: "Enter an email or handle." });
    return;
  }
  await persistHandle();
  paintStatus("waiting", { expiresAt: Date.now() + 5 * 60 * 1000 });
  try {
    const result = await send({ type: "request", to, tabId });
    paintStatus(result.status, result);
  } catch {
    if (currentStatus !== "waiting") {
      paintStatus("error", { message: "Could not reach the extension." });
    }
  }
});

$("remember").addEventListener("change", () => {
  void persistHandle();
});

$("to").addEventListener("change", () => {
  if ($("remember").checked) void persistHandle();
});

$("copy-key").addEventListener("click", async () => {
  const value = $("public-key").textContent;
  if (!value) return;
  await navigator.clipboard.writeText(value);
  $("copy-key").textContent = "Copied";
  setTimeout(() => {
    $("copy-key").textContent = "Copy";
  }, 1500);
});

$("regenerate").addEventListener("click", async () => {
  if (!confirm("This breaks pairing until you save the new public key. Continue?")) return;
  const next = await send({ type: "regenerateKey" });
  paintKey(next.publicKey);
  $("fingerprint").textContent = next.fingerprint
    ? `Encryption key ${next.fingerprint} — compare with the grant page`
    : "Pairing…";
  paintStatus(null);
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "status") paintStatus(msg.status, msg);
});

setInterval(() => {
  if (currentStatus === "waiting") paintStatus("waiting", { expiresAt });
}, 1000);

const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
tabId = tab?.id ?? null;
try {
  render(await send({ type: "getState", tabId }));
} catch {
  paintStatus("error", { message: "Could not start the extension. Open the popup again." });
}
