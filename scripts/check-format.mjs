import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";

const root = path.resolve(import.meta.dirname, "..");
const require = createRequire(path.join(root, ".standards", "package.json"));
const prettier = require("prettier");
const options = JSON.parse(fs.readFileSync(path.join(root, ".standards", "format.json"), "utf8"));
const files = [
  ...new Set(
    execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
      cwd: root,
      encoding: "utf8",
    })
      .split("\0")
      .filter(Boolean),
  ),
];
const write = process.argv.includes("--write");
const failed = [];
let checked = 0;
for (const name of files) {
  if (name.startsWith(".standards/") || name.endsWith("package-lock.json")) continue;
  const full = path.join(root, name);
  const info = await prettier.getFileInfo(full, { resolveConfig: false });
  if (!info.inferredParser) continue;
  const content = fs.readFileSync(full, "utf8");
  const formatted = await prettier.format(content, { ...options, filepath: full });
  checked++;
  if (content !== formatted) {
    if (write) fs.writeFileSync(full, formatted);
    else failed.push(name);
  }
}
if (failed.length) throw new Error("Formatting required: " + failed.join(", "));
console.log(
  `PASS: ${checked} supported project files ${write ? "formatted" : "checked"} with pinned Prettier`,
);
