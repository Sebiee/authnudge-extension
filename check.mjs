import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { decryptEnvelope, encryptForRequester, generateRequesterKeys, requesterFingerprint, signRequest } from "./e2e.js";
import { fillLoginForm, fillResultStatus } from "./fill.js";
import { DEFAULT_BASE, LOCAL_BASE, frameIdsMatchingHost, hostPermissionPattern, normalizeBaseUrl, normalizeOrigin, normalizeTo, resolveBaseUrl, sameLoginHost } from "./origin.js";
import { assertPackedManifest, packedManifestText } from "./pack.mjs";

const here = dirname(fileURLToPath(import.meta.url));

assert.equal(normalizeOrigin("https://X.com/login?foo=1#bar"), "https://x.com/login");
assert.equal(normalizeOrigin("https://x.com/"), "https://x.com");
assert.equal(normalizeOrigin("https://x.com/login/"), "https://x.com/login");
assert.equal(sameLoginHost("https://x.com/password", "https://x.com/login"), true);
assert.equal(sameLoginHost("https://evil.com/login", "https://x.com/login"), false);
assert.equal(sameLoginHost("chrome://extensions", "https://x.com/login"), false);
assert.equal(sameLoginHost("https://x.com/login", ""), false);
assert.equal(hostPermissionPattern("https://X.com/login?foo=1"), "https://x.com/*");
assert.equal(hostPermissionPattern("http://127.0.0.1:5173/a"), "http://127.0.0.1:5173/*");
assert.equal(hostPermissionPattern("chrome://extensions"), null);
assert.deepEqual(
  frameIdsMatchingHost(
    [
      { frameId: 0, result: "https://x.com" },
      { frameId: 2, result: "https://evil.example" },
      { frameId: 3, result: "https://x.com" },
    ],
    "https://x.com/login",
  ),
  [0, 3],
);
assert.deepEqual(frameIdsMatchingHost([{ frameId: 2, result: "https://evil.example" }], "https://x.com/login"), []);
assert.deepEqual(frameIdsMatchingHost([{ frameId: 0, result: "https://x.com" }], ""), []);
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
const sourceManifest = JSON.parse(manifest);
assert.match(sourceManifest.version, /^\d+\.\d+\.\d+$/);
assert.equal(sourceManifest.minimum_chrome_version, "120");
assert.deepEqual(
  sourceManifest.host_permissions.filter((h) => h.startsWith("https:")),
  ["https://authnudge.com/*"],
);
assert.ok(sourceManifest.host_permissions.includes("http://127.0.0.1:5173/*"));
assert.ok(sourceManifest.host_permissions.includes("http://localhost:5173/*"));
assert.ok(sourceManifest.optional_host_permissions.includes("https://*/*"));
assert.ok(sourceManifest.optional_host_permissions.includes("http://*/*"));
assert.doesNotMatch(manifest, /<all_urls>/);
assert.doesNotMatch(manifest, /"host_permissions": \["http:\/\/\*\/\*", "https:\/\/\*\/\*"\]/);
assertPackedManifest(packedManifestText(manifest));
assert.match(readFileSync(join(here, "pack.mjs"), "utf8"), /writeFileSync\(dest, packedManifestText\(\)\)/);
const readme = readFileSync(join(here, "README.md"), "utf8");
assert.match(readme, /chromewebstore\.google\.com\/detail\/authnudge\/blcpeglclodcfkmakeilegdknbdaglpa/);
assert.match(readme, /Add to Chrome/);
assert.match(readme, /Load unpacked/);
assert.doesNotMatch(readme, /not on the Chrome Web Store/i);
assert.match(readme, /chrome\.storage/);
const releaseYml = readFileSync(join(here, ".github/workflows/release.yml"), "utf8");
assert.match(releaseYml, /chromewebstore\.google\.com\/detail\/authnudge\/blcpeglclodcfkmakeilegdknbdaglpa/);
assert.doesNotMatch(releaseYml, /Not on the Chrome Web Store/i);
assert.doesNotMatch(releaseYml, /Sideload only/i);

const keys = await generateRequesterKeys();
const fingerprint = await requesterFingerprint(keys.publicKey);
assert.match(fingerprint, /^[0-9a-f]{4}-[0-9a-f]{6}$/);

const to = normalizeTo("@holder@example.com");
const origin = normalizeOrigin("https://X.com/login?foo=1#bar");
const { signature, issuedAt } = await signRequest(keys.privateKey, { to, origin, publicKey: keys.publicKey });
assert.equal(Number.isInteger(issuedAt) && issuedAt > 0, true);
const unb64 = (value) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
const verifyKey = await crypto.subtle.importKey(
  "spki",
  unb64(keys.publicKey),
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["verify"],
);
const message = new TextEncoder().encode(`authnudge-request-v2\n${to}\n${origin}\n${keys.publicKey}\n${issuedAt}`);
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
assert.match(background, /\/done/);
assert.match(background, /detect-otp/);
assert.match(background, /detect-password/);
assert.match(background, /fillResultStatus/);
assert.match(background, /permission_denied/);
assert.doesNotMatch(background, /if \(result\.ok\) return \{ status: "filled" \}/);
assert.doesNotMatch(background, /catch \{\s*result = \{ ok: false, reason: "need_password" \}/);
assert.match(background, /res\.status !== 201 && res\.status !== 200/);
assert.match(background, /res\.status === 404 \|\| res\.status === 410/);
assert.match(background, /RELAY_TTL_MS/);
assert.match(background, /frameIdsMatchingHost/);
assert.match(background, /issuedAt/);
assert.doesNotMatch(background, /authnudge-request-v1/);
assert.doesNotMatch(background, /setBaseUrl|keys\.baseUrl|update_url|useLocal/);
assert.match(background, /dev\.json/);
assert.match(background, /sender\.id !== chrome\.runtime\.id/);
assert.doesNotMatch(background, /searchParams\.set\("claim"/);
assert.doesNotMatch(background, /\?claim=/);
assert.match(background, /\[`claim\.\$\{meta\.claimToken\}`\]/);
assert.match(background, /authorization: `Bearer \$\{meta\.claimToken\}`/);

const src = fillLoginForm.toString();
assert.match(src, /detect-otp/);
assert.match(src, /detect-password/);
assert.match(src, /one-time-code/);
assert.match(src, /otpBoxes/);
assert.match(src, /einmalcode/);
assert.match(src, /Neuen Code/);
assert.match(src, /max === 1/);
assert.match(src, /boxes\.length > 1/);
assert.match(src, /return \{ ok: true \}/);
assert.match(src, /need_password/);
assert.match(src, /MutationObserver/);
assert.match(src, /wipePassword/);
assert.match(src, /typeof identifier === "object"/);
assert.doesNotMatch(src, /return \{[^}]*identifier|return \{[^}]*secret/);
assert.doesNotMatch(src, /window\.top/);
assert.doesNotMatch(src, /if \(!expectedOrigin\) return true/);

{
  const prevLocation = globalThis.location;
  const prevWindow = globalThis.window;
  globalThis.location = { href: "https://evil.example/ad" };
  globalThis.window = { top: { location: { href: "https://x.com/login" } } };
  assert.deepEqual(await fillLoginForm("u", "p", "https://x.com/login"), { ok: false, reason: "wrong_origin" });
  assert.deepEqual(await fillLoginForm("u", "p", ""), { ok: false, reason: "wrong_origin" });
  if (prevLocation === undefined) delete globalThis.location;
  else globalThis.location = prevLocation;
  if (prevWindow === undefined) delete globalThis.window;
  else globalThis.window = prevWindow;
}

assert.equal(fillResultStatus({ ok: true }, false), "filled");
assert.equal(fillResultStatus({ ok: true }, true), "need_password");
assert.equal(fillResultStatus({ ok: true }, true, "otp"), "otp");
assert.equal(fillResultStatus({ ok: false, reason: "permission_denied" }, false), "permission_denied");
assert.equal(fillResultStatus({ ok: false, reason: "need_permission" }, false), "need_permission");
assert.equal(fillResultStatus({ ok: false, reason: "need_password" }, false), "need_password");
assert.equal(fillResultStatus({ ok: false, reason: "no_form" }, false), "no_form");

const ui = ["popup.html", "popup.js", "popup.css"].map((name) => readFileSync(join(here, name), "utf8")).join("\n");
assert.doesNotMatch(ui, /envelope|decryptEnvelope|claimToken|privateKey/);
assert.doesNotMatch(ui, /payload\.(username|password)/);
assert.doesNotMatch(ui, /id="base-url"|id="pairing"|Authnudge URL/);
assert.match(ui, /id="remember"/);
assert.match(ui, /id="copy-key"/);
assert.match(ui, /one-time code/);
assert.match(ui, /if \(status === "filled"\) return "Signed in"/);
assert.match(ui, /permissions\.request/);
assert.match(ui, /hostPermissionPattern/);
assert.doesNotMatch(ui, /http:\/\/\*\/\*/);
assert.doesNotMatch(ui, /id="use-local"/);

console.log("extension check ok", fingerprint);
