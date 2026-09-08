# Authnudge

Chrome extension that asks an Authnudge account holder to sign you in. The extension never shows the credentials.

Install from the [Chrome Web Store](https://chromewebstore.google.com/detail/authnudge/blcpeglclodcfkmakeilegdknbdaglpa): **Add to Chrome**. Public key pairing; the account holder sends an encrypted envelope.

Contributors: `chrome://extensions` → Developer mode → **Load unpacked** (this folder). Packed zips (`node pack.mjs`) are the Chrome Web Store upload; they strip localhost hosts.

Privacy: the requester keypair stays in `chrome.storage` in this Chrome profile (anyone with this profile can export it); credentials are not uploaded or shown; the page origin is sent to authnudge.com so the account holder can approve.
