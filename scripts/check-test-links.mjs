// Exercise the actual documentation checker in an owned disposable checkout.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

const root = path.resolve(import.meta.dirname, "..");
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "outpost-trace-test-"));
const guard = () => {
  assert.equal(path.dirname(fs.realpathSync(fixture)), fs.realpathSync(os.tmpdir()));
  assert(path.basename(fixture).startsWith("outpost-trace-test-"));
};
const cases = [];
try {
  guard();
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
  for (const name of files) {
    const source = path.resolve(root, name),
      target = path.resolve(fixture, name);
    assert(source.startsWith(root + path.sep) && target.startsWith(fixture + path.sep));
    assert(fs.lstatSync(source).isFile(), `Only regular repository files: ${name}`);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(source, target);
  }
  execFileSync("git", ["init", "--quiet"], { cwd: fixture });
  const file = path.join(fixture, "docs/product-status.json");
  const original = JSON.parse(fs.readFileSync(file, "utf8"));
  const browser = (value) =>
    value.requirements.flatMap((r) => r.checks).find((c) => c.path === "scripts/browser/check.mjs");
  const go = (value) =>
    value.requirements.flatMap((r) => r.checks).find((c) => c.path.endsWith("_test.go"));
  const artifact = (value) =>
    value.requirements.flatMap((r) => r.checks).find((c) => c.path === "scripts/check-release.py");
  const container = (value) =>
    value.requirements
      .flatMap((r) => r.checks)
      .find((c) => c.path === "scripts/check-container.py");
  const monitoring = (value) =>
    value.requirements
      .flatMap((r) => r.checks)
      .find((c) => c.path === "packaging/monitoring/rules.test.yml");
  assert(
    browser(original) &&
      go(original) &&
      artifact(original) &&
      container(original) &&
      monitoring(original),
  );
  for (const [name, accepted, mutate] of [
    ["valid", true, () => {}],
    [
      "missing-container-check",
      false,
      (v) => {
        container(v).name = "test_nonexistent_container_case";
      },
    ],
    [
      "unregistered-container-function",
      false,
      (v) => {
        container(v).name = "test_defined_but_unregistered";
        fs.appendFileSync(
          path.join(fixture, "scripts/check-container.py"),
          "\ndef test_defined_but_unregistered(suite):\n    pass\n",
        );
      },
    ],
    [
      "missing-artifact-check",
      false,
      (v) => {
        artifact(v).name = "test_nonexistent_artifact_case";
      },
    ],
    [
      "unapproved-artifact-path",
      false,
      (v) => {
        artifact(v).path = "scripts/build-release.py";
      },
    ],
    [
      "unregistered-artifact-function",
      false,
      (v) => {
        artifact(v).name = "test_defined_but_unregistered";
        fs.appendFileSync(
          path.join(fixture, "scripts/check-release.py"),
          "\ndef test_defined_but_unregistered(root, digest, work):\n    pass\n",
        );
      },
    ],
    [
      "unknown-browser-scenario",
      false,
      (v) => {
        browser(v).name = "nonexistent browser journey";
      },
    ],
    [
      "unapproved-browser-path",
      false,
      (v) => {
        browser(v).path = "scripts/check-docs.mjs";
      },
    ],
    [
      "missing-go-symbol",
      false,
      (v) => {
        go(v).name = "TestNonexistentTraceabilityScenario";
      },
    ],
    [
      "missing-monitoring-scenario",
      false,
      (v) => {
        monitoring(v).name = "Nonexistent watchdog scenario";
      },
    ],
    [
      "component-proof-is-not-full-acceptance",
      false,
      (v) => {
        v.acceptance[0].state = "PASS";
      },
    ],
  ]) {
    const value = structuredClone(original);
    mutate(value);
    fs.writeFileSync(file, JSON.stringify(value));
    const result = spawnSync(process.execPath, ["scripts/check-docs.mjs"], {
      cwd: fixture,
      encoding: "utf8",
      timeout: 15000,
    });
    assert.equal(result.error, undefined, `${name}: checker did not run`);
    assert.equal(result.status === 0, accepted, `${name}: unexpected checker result`);
    cases.push({ name, outcome: accepted ? "accepted" : "rejected" });
  }
  console.log(
    JSON.stringify({
      checks: cases,
      scope: "actual source traceability checker",
      externalServices: false,
    }),
  );
} finally {
  guard();
  fs.rmSync(fixture, { recursive: true, force: true });
}
