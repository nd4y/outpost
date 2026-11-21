import assert from "node:assert/strict";
import fs from "node:fs";
import { test } from "node:test";
import { validateG1Evidence } from "./g1-evidence.mjs";

const read = (name) =>
  JSON.parse(fs.readFileSync(new URL("../docs/" + name, import.meta.url), "utf8"));
const evidence = read("g1-scale-evidence.json");
const limits = read("g1-acceptance.json");
const gate = read("requirements.json").gates.G1;
const phase = (e, label) => e.phases.find((p) => p.label === label).measurements;
test("retained full-scale evidence satisfies its original bounds and keeps cgroup peak distinct", () => {
  assert(evidence.observedCgroups.maximumMemoryPeakBytes > limits.containerMemoryBytes);
  validateG1Evidence(evidence, limits, gate);
});
for (const [name, mutate] of [
  [
    "incomplete run",
    (e) => {
      e.status = "RUNNING";
    },
  ],
  [
    "missing phase",
    (e) => {
      e.phases.pop();
    },
  ],
  [
    "failed command",
    (e) => {
      e.phases[3].exitCode = 1;
    },
  ],
  [
    "substituted source",
    (e) => {
      e.testedSourceCommit = "0".repeat(40);
    },
  ],
  [
    "missing terminal success",
    (e) => {
      e.terminal.passMarkerVerified = false;
    },
  ],
  [
    "sparse source",
    (e) => {
      phase(e, "generate").allocatedBytes = 128;
    },
  ],
  [
    "incremental overflow",
    (e) => {
      phase(e, "backup-patched").counters.newPayloadBytes = limits.maximumIncrementalBytes + 1;
    },
  ],
  [
    "wrong old bytes",
    (e) => {
      phase(e, "independent-old-after-maintenance-oracle").sha256 = "0".repeat(64);
    },
  ],
  [
    "unverified attributes",
    (e) => {
      phase(e, "independent-new-after-maintenance-oracle").attributesVerified = false;
    },
  ],
  [
    "excess RSS",
    (e) => {
      phase(e, "repack").maxRSSKiB = limits.containerMemoryBytes;
    },
  ],
  [
    "observed OOM",
    (e) => {
      e.observedCgroups.maximumObservedOOMKills = 1;
    },
  ],
  [
    "negative read counter",
    (e) => {
      phase(e, "independent-new-after-maintenance").counters.io.verifiedReadBytes = -1;
    },
  ],
  [
    "new version for unchanged input",
    (e) => {
      e.versionReferences["backup-unchanged"].version = "0".repeat(64);
    },
  ],
  [
    "old bytes claimed as changed version",
    (e) => {
      phase(e, "independent-new-after-maintenance-oracle").sha256 = phase(e, "generate").sha256;
    },
  ],
])
  test("refuses " + name, () => {
    const changed = structuredClone(evidence);
    mutate(changed);
    assert.throws(() => validateG1Evidence(changed, limits, gate));
  });
test("refuses retroactively relaxed accepted limits", () => {
  const relaxed = { ...limits, maximumIncrementalBytes: limits.maximumIncrementalBytes * 2 };
  assert.throws(() => validateG1Evidence(evidence, relaxed, gate));
});
