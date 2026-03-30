import { cpSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const src = join(__dirname, "..", "node_modules", "@excalidraw", "excalidraw", "dist", "prod", "fonts");
const dst = join(__dirname, "..", "public");

if (!existsSync(src)) {
  console.log("Excalidraw fonts not found (pre-install) — skipping copy.");
  process.exit(0);
}

cpSync(src, dst, { recursive: true, force: true });
console.log("Copied Excalidraw fonts to public/.");
