import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function loadVersion() {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 10; i++) {
    const candidate = join(dir, "VERSION");
    if (existsSync(candidate)) return readFileSync(candidate, "utf8").trim();
    const parent = resolve(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  return "0.0.0";
}

export const VERSION = loadVersion();
export const RUNTIME = "js";
