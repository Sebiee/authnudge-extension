import { decryptEnvelope, generateRequesterKeys, requesterFingerprint, signRequest } from "./e2e.js";
import { fillLoginForm } from "./fill.js";
import { resolveBaseUrl, normalizeOrigin, normalizeTo, sameLoginHost } from "./origin.js";

const ALARM = "authnudge-watch";

let devBaseRaw;

async function apiBase() {
  if (devBaseRaw === undefined) {
    try {
      const res = await fetch(chrome.runtime.getURL("dev.json"));
      const data = res.ok ? await res.json() : null;
      devBaseRaw = typeof data?.baseUrl === "string" ? data.baseUrl : "";
    } catch {
      devBaseRaw = "";
    }
  }
  return resolveBaseUrl(devBaseRaw);
}

let live = null;
let claim = null;
let socket = null;
let requestGen = 0;
let inFlight = false;
let settledGen = 0;

function pushStatus(status, extra = {}) {
  if (live) live.status = status;
  chrome.runtime.sendMessage({ type: "status", status, expiresAt: live?.expiresAt ?? null, ...extra }).catch(() => {});
}

async function readStore() {
  return chrome.storage.local.get(["publicKey", "privateKey", "rememberTo", "savedTo"]);
}

async function ensureKeys() {
  const store = await readStore();
  if (store.publicKey && store.privateKey) {
    return { publicKey: store.publicKey, privateKey: store.privateKey };
  }
  const keys = await generateRequesterKeys();
  await chrome.storage.local.set({ publicKey: keys.publicKey, privateKey: keys.privateKey });
  return keys;
}

async function getTab(tabId) {
  if (typeof tabId !== "number") return null;
  return chrome.tabs.get(tabId).catch(() => null);
}

async function loadClaim() {
  const stored = await chrome.storage.session.get("claim");
  return stored.claim ?? null;
}

async function saveClaim(meta) {
  await chrome.storage.session.set({ claim: meta });
}

async function dropClaim() {
  claim = null;
  await chrome.storage.session.remove("claim");
}

function stopSocket() {
  try {
    socket?.close();
  } catch {
    /* ignore */
  }
  socket = null;
}

async function getState(tabId) {
  if (!live) {
    const meta = claim ?? (await loadClaim());
    if (meta && Date.now() < meta.expiresAt) {
      live = { tabId: meta.tabId, origin: meta.origin, expiresAt: meta.expiresAt, status: "waiting" };
    }
  }
  const keys = await ensureKeys();
  const store = await readStore();
  const tab = await getTab(tabId);
  const origin = tab?.url ? normalizeOrigin(tab.url) : null;
  return {
    publicKey: keys.publicKey,
    fingerprint: await requesterFingerprint(keys.publicKey),
    rememberTo: Boolean(store.rememberTo),
    savedTo: typeof store.savedTo === "string" ? store.savedTo : "",
    baseUrl: await apiBase(),
    tabId: tab?.id ?? null,
    origin,
    live: live ? { status: live.status, expiresAt: live.expiresAt } : null,
  };
}

async function regenerateKey() {
  requestGen += 1;
  settledGen = requestGen;
  live = null;
  stopSocket();
  await chrome.alarms.clear(ALARM);
  await dropClaim();
  const keys = await generateRequesterKeys();
  await chrome.storage.local.set({
    publicKey: keys.publicKey,
    privateKey: keys.privateKey,
  });
  return {
    publicKey: keys.publicKey,
    fingerprint: await requesterFingerprint(keys.publicKey),
  };
}

function toWsUrl(baseUrl, path, claimToken) {
  const url = new URL(path, baseUrl);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.searchParams.set("claim", claimToken);
  return url.toString();
}

function foldFillResults(injections) {
  const results = (injections ?? []).map((item) => item?.result).filter(Boolean);
  if (results.some((item) => item.ok)) return { ok: true };
  if (results.some((item) => item.reason === "need_password")) return { ok: false, reason: "need_password" };
  if (results.some((item) => item.reason === "no_form")) return { ok: false, reason: "no_form" };
  if (results.some((item) => item.reason === "wrong_origin")) return { ok: false, reason: "wrong_origin" };
  return { ok: false, reason: "need_password" };
}

function waitForFillRetry(tabId, deadline) {
  return new Promise((resolve) => {
    const leftover = Math.min(2000, Math.max(0, deadline - Date.now()));
    const timer = setTimeout(finish, leftover);
    const onUpdated = (id, info) => {
      if (id === tabId && (info.status === "complete" || info.url)) finish();
    };
    function finish() {
      clearTimeout(timer);
      chrome.tabs.onUpdated.removeListener(onUpdated);
      resolve();
    }
    chrome.tabs.onUpdated.addListener(onUpdated);
  });
}

async function runFillOnce(tabId, origin, identifier, secret, waitMs, mode = "password") {
  const inject = (allFrames) =>
    chrome.scripting.executeScript({
      target: { tabId, allFrames },
      func: fillLoginForm,
      args: [identifier, secret, origin, waitMs, mode],
    });
  try {
    return foldFillResults(await inject(true));
  } catch {
    return foldFillResults(await inject(false));
  }
}

async function injectFill(tabId, origin, identifier, secret) {
  const deadline = Date.now() + 45_000;
  let waitMs = 15_000;

  while (Date.now() < deadline) {
    const tab = await getTab(tabId);
    if (!tab?.url || !sameLoginHost(tab.url, origin)) return { status: "page_changed" };

    let result;
    try {
      result = await runFillOnce(tabId, origin, identifier, secret, waitMs);
    } catch {
      result = { ok: false, reason: "need_password" };
    }

    if (result.ok) return { status: "filled" };
    if (result.reason === "wrong_origin") return { status: "page_changed" };
    if (result.reason === "no_form") return { status: "no_form" };

    waitMs = 4_000;
    await waitForFillRetry(tabId, deadline);
  }

  const tab = await getTab(tabId);
  if (!tab?.url || !sameLoginHost(tab.url, origin)) return { status: "page_changed" };
  return { status: "no_form" };
}

async function useEnvelope(tabId, origin, envelope, privateKey, requestId, requesterPublicKey, step) {
  let payload;
  try {
    payload = await decryptEnvelope(privateKey, envelope, { requestId, requesterPublicKey, step });
  } catch {
    return { status: "error", code: "generic" };
  } finally {
    envelope = null;
  }

  if (payload?.origin !== origin) {
    payload = null;
    return { status: "error", code: "generic" };
  }

  if (step === "otp") {
    const code = payload?.otp;
    payload = null;
    if (typeof code !== "string" || !code.trim()) return { status: "error", code: "generic" };
    pushStatus("filling");
    const result = await runFillOnce(tabId, origin, "", code.trim(), 0, "otp");
    if (result.ok) return { status: "filled" };
    if (result.reason === "wrong_origin") return { status: "page_changed" };
    return { status: "no_form" };
  }

  const identifier = payload?.username;
  const secret = payload?.password;
  payload = null;
  if (typeof identifier !== "string" || typeof secret !== "string") {
    return { status: "error", code: "generic" };
  }

  pushStatus("filling");
  return injectFill(tabId, origin, identifier, secret);
}

async function detectOtp(tabId, origin) {
  const result = await runFillOnce(tabId, origin, "", "", 0, "detect-otp");
  return result.ok;
}

async function askOtp(meta) {
  try {
    const res = await fetch(`${meta.baseUrl}/api/v1/requests/${meta.requestId}/continue`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${meta.claimToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ type: "otp" }),
    });
    return res.ok || res.status === 409;
  } catch {
    return false;
  }
}

async function watchForOtp(meta, waitClear = false) {
  const deadline = Date.now() + 110_000;
  let wait = waitClear;
  while (meta.gen !== settledGen && Date.now() < deadline) {
    const tab = await getTab(meta.tabId);
    if (!tab?.url || !sameLoginHost(tab.url, meta.origin)) return;
    const found = await detectOtp(meta.tabId, meta.origin);
    if (wait) {
      if (!found) wait = false;
    } else if (found) {
      await askOtp(meta);
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
}

async function finishExpired(meta) {
  if (meta.gen === settledGen) return;
  settledGen = meta.gen;
  stopSocket();
  await chrome.alarms.clear(ALARM);
  await dropClaim();
  live = { tabId: meta.tabId, origin: meta.origin, expiresAt: meta.expiresAt, status: "expired" };
  pushStatus("expired");
}

async function finishFilled(meta) {
  if (meta.gen === settledGen) return;
  settledGen = meta.gen;
  stopSocket();
  await chrome.alarms.clear(ALARM);
  await dropClaim();
  live = { tabId: meta.tabId, origin: meta.origin, expiresAt: meta.expiresAt, status: "filled" };
  pushStatus("filled");
}

async function finishWith(meta, result) {
  if (meta.gen === settledGen) return;
  settledGen = meta.gen;
  stopSocket();
  await chrome.alarms.clear(ALARM);
  await dropClaim();
  live = { tabId: meta.tabId, origin: meta.origin, expiresAt: meta.expiresAt, status: result.status };
  pushStatus(result.status, result.code ? { code: result.code } : {});
}

async function handleEnvelope(meta, envelope, kind) {
  if (!envelope || meta.gen === settledGen) return;
  const seen = `${kind}:${envelope.ciphertext?.slice(0, 24) || ""}`;
  if (meta.lastEnvelope === seen) return;
  meta.lastEnvelope = seen;
  const keys = await ensureKeys();
  const step = kind === "otp" ? "otp" : undefined;
  const result = await useEnvelope(
    meta.tabId,
    meta.origin,
    envelope,
    keys.privateKey,
    meta.requestId,
    keys.publicKey,
    step,
  );
  if (kind === "otp") {
    if (result.status !== "filled") return finishWith(meta, result);
    pushStatus("filling");
    void watchForOtp(meta, true);
    return;
  }
  if (result.status !== "filled") return finishWith(meta, result);
  meta.gotPassword = true;
  await saveClaim(meta);
  pushStatus("filling");
  void watchForOtp(meta);
}

async function pollOnce(meta) {
  if (meta.gen === settledGen) return true;
  try {
    const res = await fetch(`${meta.baseUrl}/api/v1/requests/${meta.requestId}`, {
      headers: { authorization: `Bearer ${meta.claimToken}` },
    });
    if (!res.ok) return false;
    const data = await res.json();
    if (data.expiresAt) meta.expiresAt = Date.parse(data.expiresAt) || meta.expiresAt;
    if (data.status === "holding" && data.envelope) {
      await handleEnvelope(meta, data.envelope, data.envelopeKind);
      return false;
    }
    if (data.status === "fulfilled") {
      await finishFilled(meta);
      return true;
    }
    if (data.status === "expired") {
      await finishExpired(meta);
      return true;
    }
  } catch {
    /* still waiting */
  }
  return false;
}

function connectSocket(meta) {
  if (meta.gen === settledGen) return;
  if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) return;
  stopSocket();
  try {
    socket = new WebSocket(toWsUrl(meta.baseUrl, `/api/v1/requests/${meta.requestId}/ws`, meta.claimToken));
  } catch {
    return;
  }
  socket.addEventListener("message", (event) => {
    if (event.data === "pong") return;
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch {
      return;
    }
    if (msg.type === "holding" && msg.envelope) void handleEnvelope(meta, msg.envelope, msg.envelopeKind);
    if (msg.type === "fulfilled") void finishFilled(meta);
    if (msg.type === "expired") void finishExpired(meta);
  });
  socket.addEventListener("close", () => {
    socket = null;
  });
}

async function armWatch(meta) {
  claim = meta;
  live = { tabId: meta.tabId, origin: meta.origin, expiresAt: meta.expiresAt, status: "waiting" };
  await saveClaim(meta);
  await chrome.alarms.create(ALARM, { delayInMinutes: 0.5, periodInMinutes: 0.5 });
  connectSocket(meta);
}

async function resumeWatch() {
  const meta = claim ?? (await loadClaim());
  if (!meta) return;
  if (Date.now() >= meta.expiresAt) {
    if (!meta.gen) meta.gen = ++requestGen;
    const done = await pollOnce(meta);
    if (!done && meta.gotPassword) await finishFilled(meta);
    else if (!done) await finishExpired({ ...meta, gen: meta.gen });
    return;
  }
  if (meta.gen === settledGen) return;
  if (!meta.gen) meta.gen = ++requestGen;
  await armWatch(meta);
  await pollOnce(meta);
}

async function tickWatch() {
  const meta = claim ?? (await loadClaim());
  if (!meta) {
    await chrome.alarms.clear(ALARM);
    return;
  }
  if (Date.now() >= meta.expiresAt) {
    const done = await pollOnce(meta);
    if (!done && meta.gotPassword) await finishFilled(meta);
    else if (!done) await finishExpired(meta);
    return;
  }
  if (socket?.readyState === WebSocket.OPEN) socket.send("ping");
  else connectSocket(meta);
  await pollOnce(meta);
}

async function startRequest({ to, tabId }) {
  const address = normalizeTo(to);
  if (!address) return { status: "error", code: "generic", message: "Enter an email or handle." };
  if (inFlight) return { status: live?.status ?? "waiting", expiresAt: live?.expiresAt ?? null };
  const existing = claim ?? (await loadClaim());
  if (existing && Date.now() < existing.expiresAt) {
    return { status: "waiting", expiresAt: existing.expiresAt };
  }

  inFlight = true;
  try {
    const tab = await getTab(tabId);
    const origin = tab?.url ? normalizeOrigin(tab.url) : null;
    if (!origin) return { status: "error", code: "bad_tab" };

    const keys = await ensureKeys();
    const signature = await signRequest(keys.privateKey, { to: address, origin, publicKey: keys.publicKey });
    const baseUrl = await apiBase();

    let created;
    try {
      const res = await fetch(`${baseUrl}/api/v1/requests`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          to: address,
          origin,
          requesterPublicKey: keys.publicKey,
          signature,
        }),
      });
      created = await res.json().catch(() => ({}));
      if (res.status === 401) return { status: "error", code: "pairing" };
      if (res.status === 429) return { status: "error", code: "generic", message: "Too many requests. Try again shortly." };
      if (res.status !== 201) return { status: "error", code: "generic" };
    } catch {
      return { status: "error", code: "generic", message: "Could not reach Authnudge." };
    }

    const expiresAt = Date.parse(created.expiresAt) || Date.now() + 5 * 60 * 1000;
    const meta = {
      gen: ++requestGen,
      requestId: created.requestId,
      claimToken: created.claimToken,
      baseUrl,
      tabId,
      origin,
      expiresAt,
    };
    await armWatch(meta);
    void pollOnce(meta);
    pushStatus("waiting");
    return { status: "waiting", expiresAt };
  } finally {
    inFlight = false;
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const run = async () => {
    if (msg?.type === "getState") return getState(msg.tabId);
    if (msg?.type === "regenerateKey") return regenerateKey();
    if (msg?.type === "request") return startRequest({ to: msg.to, tabId: msg.tabId });
    return { status: "error", code: "generic" };
  };
  run().then(sendResponse).catch(() => sendResponse({ status: "error", code: "generic" }));
  return true;
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM) void tickWatch();
});

void resumeWatch();
