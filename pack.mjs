import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = dirname(fileURLToPath(import.meta.url));

export const PACK_FILES = [
  "LICENSE",
  "manifest.json",
  "background.js",
  "popup.html",
  "popup.js",
  "popup.css",
  "fill.js",
  "origin.js",
  "e2e.js",
  "icons/icon16.png",
  "icons/icon32.png",
  "icons/icon48.png",
  "icons/icon128.png",
];

export const PACKED_HOST_PERMISSIONS = ["https://authnudge.com/*"];
export const PACKED_OPTIONAL_HOST_PERMISSIONS = ["https://*/*"];

export function packageVersion() {
  return JSON.parse(readFileSync(join(root, "manifest.json"), "utf8")).version;
}

/** CWS upload zip: no localhost required hosts, no optional HTTP-all-urls (CWS rejects both). */
export function packedManifestText(source = readFileSync(join(root, "manifest.json"), "utf8")) {
  const manifest = JSON.parse(source);
  manifest.host_permissions = PACKED_HOST_PERMISSIONS;
  manifest.optional_host_permissions = PACKED_OPTIONAL_HOST_PERMISSIONS;
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

export function assertPackedManifest(text = packedManifestText()) {
  assert.doesNotMatch(text, /localhost/i);
  assert.doesNotMatch(text, /127\.0\.0\.1/);
  assert.doesNotMatch(text, /http:\/\/\*\/\*/);
  const packed = JSON.parse(text);
  assert.deepEqual(packed.host_permissions, PACKED_HOST_PERMISSIONS);
  assert.deepEqual(packed.optional_host_permissions, PACKED_OPTIONAL_HOST_PERMISSIONS);
}

function pack() {
  const zipHelp = spawnSync("zip", ["-h"], { encoding: "utf8" });
  if ((zipHelp.status ?? 1) !== 0 && !`${zipHelp.stdout}${zipHelp.stderr}`.includes("Zip")) {
    console.error("zip is required to pack the extension");
    process.exit(1);
  }

  const version = packageVersion();
  const staging = join(root, `authnudge-extension-v${version}`);
  const zipPath = `${staging}.zip`;
  rmSync(staging, { recursive: true, force: true });
  rmSync(zipPath, { force: true });
  mkdirSync(join(staging, "icons"), { recursive: true });

  for (const file of PACK_FILES) {
    const dest = join(staging, file);
    if (file === "manifest.json") writeFileSync(dest, packedManifestText());
    else copyFileSync(join(root, file), dest);
  }

  const zipped = spawnSync("zip", ["-r", "-X", "-q", zipPath, "."], { cwd: staging, stdio: "inherit" });
  if (zipped.status !== 0) process.exit(zipped.status ?? 1);
  rmSync(staging, { recursive: true, force: true });
  console.log(zipPath);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain && process.argv.includes("--check")) {
  assert.ok(PACK_FILES.includes("LICENSE"));
  assert.ok(!PACK_FILES.includes("check.mjs"));
  assert.ok(!PACK_FILES.includes("pack.mjs"));
  assert.ok(!PACK_FILES.includes("dev.json"));
  assert.match(packageVersion(), /^\d+\.\d+\.\d+$/);
  assert.throws(() => assertPackedManifest(readFileSync(join(root, "manifest.json"), "utf8")));
  assertPackedManifest();
  console.log("extension pack check ok");
} else if (isMain) {
  pack();
}
