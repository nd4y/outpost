// Verify the installed toolkit in a disposable, private fixture repository.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";

const root = path.resolve(import.meta.dirname, "..");
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "outpost-standard-test-"));
function guard() {
  assert.equal(path.dirname(path.resolve(fixture)), path.resolve(os.tmpdir()));
  assert(path.basename(fixture).startsWith("outpost-standard-test-"));
}
function git(...args) {
  guard();
  return execFileSync("git", args, {
    cwd: fixture,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}
function write(name, text) {
  const target = path.resolve(fixture, name);
  assert(target.startsWith(fixture + path.sep));
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, text);
}
const docs = [
  "README.md",
  "README.ru.md",
  "docs/en/development-standard.md",
  "docs/ru/development-standard.md",
];
const results = [];
try {
  fs.cpSync(path.join(root, ".standards"), path.join(fixture, ".standards"), { recursive: true });
  write(".gitignore", ".standards/node_modules/\n.standards/bin/\n");
  write(".repo-policy.json", fs.readFileSync(path.join(root, ".repo-policy.json")));
  for (const name of docs)
    write(
      name,
      "# Isolated fixture\n\nThis baseline describes the original reproducible example.\n",
    );
  git("init", "-q");
  git("config", "user.name", "Synthetic verification");
  git("config", "user.email", "fixture@example.invalid");
  // Only this newly created fixture bypasses hooks so invalid commits can be tested.
  fs.mkdirSync(path.join(fixture, ".git", "empty-hooks"));
  git("config", "core.hooksPath", path.join(fixture, ".git", "empty-hooks"));
  git("add", ".");
  git("commit", "-qm", "fixture baseline");
  const baseline = git("rev-parse", "HEAD");
  for (const name of [
    "valid",
    "bad-format",
    "missing-language",
    "whitespace-only",
    "deleted-docs",
    "synthetic-secret",
    "scanner-unavailable",
  ]) {
    guard();
    git("reset", "--hard", baseline);
    git("clean", "-fd");
    for (const page of docs)
      write(
        page,
        "# Isolated fixture\n\nThis change adds a bounded validation workflow and explains recovery.\n",
      );
    if (name === "bad-format") write("sample.js", "const value= {x:1};;\n");
    if (name === "missing-language") fs.unlinkSync(path.join(fixture, "README.ru.md"));
    if (name === "whitespace-only")
      write("README.ru.md", git("show", baseline + ":README.ru.md") + "\n\n");
    if (name === "deleted-docs")
      fs.unlinkSync(path.join(fixture, "docs/ru/development-standard.md"));
    if (name === "synthetic-secret")
      write("synthetic-secret.txt", "ghp_" + crypto.randomBytes(20).toString("hex") + "\n");
    git("add", ".");
    git("commit", "-qm", name);
    const scanner = path.join(
      fixture,
      ".standards",
      "bin",
      process.platform === "win32" ? "gitleaks.exe" : "gitleaks",
    );
    const held = scanner + ".held";
    if (name === "scanner-unavailable") fs.renameSync(scanner, held);
    let result;
    try {
      result = spawnSync(
        process.execPath,
        [".standards/check.mjs", "ci", baseline, git("rev-parse", "HEAD")],
        {
          cwd: fixture,
          encoding: "utf8",
          timeout: 30000,
          env: { ...process.env, GITLEAKS_BIN: scanner },
        },
      );
    } finally {
      if (name === "scanner-unavailable") fs.renameSync(held, scanner);
    }
    assert.equal(result.error, undefined, name + ": checker did not finish");
    assert.equal(
      result.status === 0,
      name === "valid",
      name + ": unexpected outcome\n" + result.stdout + "\n" + result.stderr,
    );
    results.push({ name, outcome: name === "valid" ? "accepted" : "rejected" });
  }
  console.log(
    JSON.stringify({ checks: results, scope: "installed pinned toolkit", externalServices: false }),
  );
} finally {
  guard();
  fs.rmSync(fixture, { recursive: true, force: true });
}
