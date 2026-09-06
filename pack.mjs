import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, readFileSync, rmSync } from "node:fs";
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

export function packageVersion() {
  return JSON.parse(readFileSync(join(root, "manifest.json"), "utf8")).version;
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

  for (const file of PACK_FILES) copyFileSync(join(root, file), join(staging, file));

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
  assert.match(packageVersion(), /^\d+\.\d+\.\d+$/);
  console.log("extension pack check ok");
} else if (isMain) {
  pack();
}
