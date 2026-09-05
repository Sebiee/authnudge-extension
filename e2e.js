// Vendored from public/e2e.js — keep algorithms in sync. Do not fetch at runtime.
const INFO = new TextEncoder().encode("authnudge-v1");
const EMPTY_SALT = new Uint8Array(32);

function b64(bytes) {
  let binary = "";
  const view = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function unb64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function importPublic(spkiB64) {
  return crypto.subtle.importKey("spki", unb64(spkiB64), { name: "ECDH", namedCurve: "P-256" }, false, []);
}

async function deriveAesKey(privateKey, publicKey, usage) {
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  const hkdf = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: EMPTY_SALT, info: INFO },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

export async function requesterFingerprint(spkiB64) {
  const raw = unb64(spkiB64);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
  const hex = [...digest.slice(0, 5)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 4)}-${hex.slice(4)}`;
}

export async function generateRequesterKeys() {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  return {
    publicKey: b64(await crypto.subtle.exportKey("spki", keyPair.publicKey)),
    privateKey: b64(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)),
  };
}

export async function signRequest(privateKeyB64, { to, handle, origin, publicKey }) {
  const address = (to ?? handle ?? "").trim().toLowerCase().replace(/^@+/, "");
  const key = await crypto.subtle.importKey(
    "pkcs8",
    unb64(privateKeyB64),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const message = new TextEncoder().encode(`authnudge-request-v1\n${address}\n${origin}\n${publicKey}`);
  return b64(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, message));
}

export async function encryptForRequester(requesterPublicKey, payload) {
  const requesterPub = await importPublic(requesterPublicKey);
  const ephemeral = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const aesKey = await deriveAesKey(ephemeral.privateKey, requesterPub, "encrypt");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  return {
    ephemeralPublicKey: b64(await crypto.subtle.exportKey("spki", ephemeral.publicKey)),
    iv: b64(iv),
    ciphertext: b64(ciphertext),
  };
}

export async function decryptEnvelope(privateKeyB64, envelope) {
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    unb64(privateKeyB64),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const ephemeralPub = await importPublic(envelope.ephemeralPublicKey);
  const aesKey = await deriveAesKey(privateKey, ephemeralPub, "decrypt");
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(envelope.iv) },
    aesKey,
    unb64(envelope.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}
