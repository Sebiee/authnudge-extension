import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { decryptEnvelope, encryptForRequester, generateRequesterKeys, requesterFingerprint, signRequest } from "./e2e.js";
import { fillLoginForm } from "./fill.js";
import { DEFAULT_BASE, LOCAL_BASE, normalizeBaseUrl, normalizeOrigin, normalizeTo, resolveBaseUrl, sameLoginHost } from "./origin.js";

const here = dirname(fileURLToPath(import.meta.url));

assert.equal(normalizeOrigin("https://X.com/login?foo=1#bar"), "https://x.com/login");
assert.equal(normalizeOrigin("https://x.com/"), "https://x.com");
assert.equal(normalizeOrigin("https://x.com/login/"), "https://x.com/login");
assert.equal(sameLoginHost("https://x.com/password", "https://x.com/login"), true);
assert.equal(sameLoginHost("https://evil.com/login", "https://x.com/login"), false);
assert.equal(sameLoginHost("chrome://extensions", "https://x.com/login"), false);
assert.equal(normalizeOrigin("chrome://extensions"), null);
assert.equal(normalizeOrigin("about:blank"), null);
assert.equal(normalizeTo("@Alice"), "alice");
assert.equal(normalizeTo("  You@Example.com "), "you@example.com");
assert.equal(normalizeBaseUrl("http://127.0.0.1:5173/path"), "http://127.0.0.1:5173");
assert.equal(normalizeBaseUrl("https://authnudge.com/"), "https://authnudge.com");
assert.equal(resolveBaseUrl(""), DEFAULT_BASE);
assert.equal(resolveBaseUrl("http://127.0.0.1:5173"), LOCAL_BASE);
assert.equal(resolveBaseUrl("http://localhost:5173/path"), "http://localhost:5173");
assert.equal(resolveBaseUrl("https://evil.example"), DEFAULT_BASE);
assert.equal(resolveBaseUrl("not a url"), DEFAULT_BASE);
assert.match(readFileSync(join(here, "LICENSE"), "utf8"), /MIT License/);
assert.match(readFileSync(join(here, "background.js"), "utf8"), /resolveBaseUrl/);
const manifest = readFileSync(join(here, "manifest.json"), "utf8");
assert.match(JSON.parse(manifest).version, /^\d+\.\d+\.\d+$/);
assert.match(manifest, /https:\/\/authnudge\.com\/\*/);
assert.match(manifest, /http:\/\/127\.0\.0\.1:5173\/\*/);
assert.doesNotMatch(manifest, /"host_permissions": \["http:\/\/\*\/\*", "https:\/\/\*\/\*"\]/);

const keys = await generateRequesterKeys();
const fingerprint = await requesterFingerprint(keys.publicKey);
assert.match(fingerprint, /^[0-9a-f]{4}-[0-9a-f]{6}$/);

const to = normalizeTo("@holder@example.com");
const origin = normalizeOrigin("https://X.com/login?foo=1#bar");
const signature = await signRequest(keys.privateKey, { to, origin, publicKey: keys.publicKey });
const unb64 = (value) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
const verifyKey = await crypto.subtle.importKey(
  "spki",
  unb64(keys.publicKey),
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["verify"],
);
const message = new TextEncoder().encode(`authnudge-request-v1\n${to}\n${origin}\n${keys.publicKey}`);
assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, verifyKey, unb64(signature), message), true);

const requestId = "req-check";
const envelope = await encryptForRequester(
  keys.publicKey,
  { username: "u", password: "p", origin, extra: true },
  requestId,
);
const plain = await decryptEnvelope(keys.privateKey, envelope, {
  requestId,
  requesterPublicKey: keys.publicKey,
});
assert.equal(plain.username, "u");
assert.equal(plain.password, "p");
assert.equal(plain.origin, origin);
await assert.rejects(() =>
  decryptEnvelope(keys.privateKey, envelope, { requestId: "other", requesterPublicKey: keys.publicKey }),
);
const otpEnvelope = await encryptForRequester(keys.publicKey, { otp: "123456", origin }, requestId, "otp");
const otpPlain = await decryptEnvelope(keys.privateKey, otpEnvelope, {
  requestId,
  requesterPublicKey: keys.publicKey,
  step: "otp",
});
assert.equal(otpPlain.otp, "123456");
await assert.rejects(() =>
  decryptEnvelope(keys.privateKey, otpEnvelope, { requestId, requesterPublicKey: keys.publicKey }),
);

const background = readFileSync(join(here, "background.js"), "utf8");
assert.match(background, /payload\?\.origin !== origin/);
assert.match(background, /requestId, requesterPublicKey/);
assert.match(background, /\/continue/);
assert.match(background, /detect-otp/);
assert.doesNotMatch(background, /setBaseUrl|keys\.baseUrl|update_url|useLocal/);
assert.match(background, /dev\.json/);

const src = fillLoginForm.toString();
assert.match(src, /detect-otp/);
assert.match(src, /one-time-code/);
assert.match(src, /return \{ ok: true \}/);
assert.match(src, /need_password/);
assert.match(src, /MutationObserver/);
assert.match(src, /wipePassword/);
assert.match(src, /typeof identifier === "object"/);
assert.doesNotMatch(src, /return \{[^}]*identifier|return \{[^}]*secret/);

const ui = ["popup.html", "popup.js", "popup.css"].map((name) => readFileSync(join(here, name), "utf8")).join("\n");
assert.doesNotMatch(ui, /envelope|decryptEnvelope|claimToken|privateKey/);
assert.doesNotMatch(ui, /payload\.(username|password)/);
assert.doesNotMatch(ui, /id="base-url"|id="pairing"|Authnudge URL/);
assert.match(ui, /id="remember"/);
assert.match(ui, /id="copy-key"/);
assert.doesNotMatch(ui, /id="use-local"/);

console.log("extension check ok", fingerprint);
