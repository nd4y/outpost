import assert from "node:assert/strict";
import { createHash } from "node:crypto";

const phases = [
  "keygen",
  "recovery-key",
  "generate",
  "backup-base",
  "inspect-base",
  "patch",
  "backup-patched",
  "backup-unchanged",
  "backup-renamed",
  "scatter",
  "backup-scattered",
  "insert",
  "backup-inserted",
  "restore-inserted",
  "restore-inserted-oracle",
  "export-before-maintenance",
  "repack",
  "retire",
  "independent-old-after-maintenance",
  "independent-old-after-maintenance-oracle",
  "export-retained-new",
  "independent-new-after-maintenance",
  "independent-new-after-maintenance-oracle",
];
const sha = (text) => createHash("sha256").update(text).digest("hex");
const integer = (n) => Number.isSafeInteger(n) && n >= 0;
function checkCounters(values) {
  for (const [key, value] of Object.entries(values)) {
    if (key === "io") checkCounters(value);
    else assert(integer(value), "Invalid byte/object counter");
  }
}

// This validates the published, scoped metadata. It does not execute a backup
// or authenticate private runtime evidence; the maintainer reviews that proof.
export function validateG1Evidence(e, limits, gate) {
  assert.equal(gate.status, "PASS");
  assert.equal(limits.status, "PASS");
  assert.equal(e.format, "outpost-g1-scale-evidence-1");
  assert.equal(e.status, "PASS");
  assert.equal(e.fullScale, true);
  assert.equal(e.testedSourceCommit, "68bede552755edc0f37fba1060cebde0501a1861");
  assert.equal(e.testedSourceTree, "624b6115be2eefe61898adc5f49d4d4d82afd481");
  assert.equal(
    e.originalMetadataReceiptSha256,
    "fc0cf1baa150a1f9cf0f2a1c463f5a6bdffb744ecf281f438f8ad77c0c32bfd7",
  );
  assert.equal(
    e.testedLimitsSha256,
    "d6cbe6f169f9e0881342567b9ec0aa6a6a0a9a8c28ad6ecb736cb59746ef203e",
  );
  assert.equal(sha(e.testedLimitsDocument), e.testedLimitsSha256);
  const original = JSON.parse(e.testedLimitsDocument);
  assert.equal(original.status, "NOT_VERIFIED");
  const { status: oldStatus, ...oldLimits } = original;
  const { status: newStatus, ...currentLimits } = limits;
  assert.deepEqual(currentLimits, oldLimits, "Accepted numeric limits changed");
  assert.equal(e.baselineBytes, limits.sourceBytes);
  assert(
    Number.isFinite(Date.parse(e.started)) && Date.parse(e.observedAt) > Date.parse(e.started),
  );
  assert.equal(e.terminal.exitCode, 0);
  assert.equal(e.terminal.passMarkerVerified, true);
  assert.equal(e.terminal.sourceFilesVerified, 642);
  for (const value of [e.binarySha256.kit, e.binarySha256.fixture, e.terminal.wrapperSha256])
    assert(/^[0-9a-f]{64}$/.test(value));
  const env = e.environment;
  assert.equal(env.network, "none");
  assert.equal(env.cpus, 1);
  assert.equal(env.memoryBytes, limits.containerMemoryBytes);
  assert.equal(env.swapBytes, 0);
  assert.equal(env.pids, 128);
  assert.equal(env.nonRoot, true);
  assert.equal(env.rootFilesystem, "read-only");
  assert.equal(env.capabilities, "none");
  assert.equal(env.noNewPrivileges, true);
  assert.equal(env.phaseTimeoutSeconds, 21600);
  assert.deepEqual(
    e.phases.map((p) => p.label),
    phases,
  );
  for (const p of e.phases) {
    assert.equal(p.status, "PASS");
    assert.equal(p.exitCode, 0);
    assert(
      integer(p.measurements.maxRSSKiB) &&
        p.measurements.maxRSSKiB * 1024 <= limits.containerMemoryBytes,
    );
    assert(
      Number.isFinite(p.measurements.elapsedSeconds) &&
        p.measurements.elapsedSeconds >= 0 &&
        p.measurements.elapsedSeconds <= env.phaseTimeoutSeconds,
    );
    if (p.measurements.counters) checkCounters(p.measurements.counters);
  }
  const m = Object.fromEntries(e.phases.map((p) => [p.label, p.measurements]));
  const n = limits.sourceBytes;
  assert.equal(m.generate.fileBytes, n);
  assert.equal(m.generate.bytesProcessed, n);
  assert(
    m.generate.allocatedBytes >= n * 0.99 &&
      Number.isFinite(m.generate.compressionRatio) &&
      m.generate.compressionRatio >= 0.99,
  );
  const initial = m["inspect-base"].counters;
  assert(initial.storedBytes <= n * limits.maximumInitialKitRatio);
  assert(initial.objects > 0 && initial.objects <= limits.maximumSelectedKitObjects);
  assert.equal(m.patch.bytesProcessed, limits.contiguousChangeBytes);
  assert.equal(m.scatter.bytesProcessed, limits.contiguousChangeBytes);
  for (const name of phases.filter((name) => name.startsWith("backup-")))
    assert.equal(m[name].counters.sourceBytes, n + (name === "backup-inserted" ? 1 << 20 : 0));
  const changed = m["backup-patched"].counters;
  assert(integer(changed.newPayloadBytes) && integer(changed.newMetadataBytes));
  assert(changed.newPayloadBytes + changed.newMetadataBytes <= limits.maximumIncrementalBytes);
  for (const key of ["newPayloadBytes", "newMetadataBytes", "newObjects"])
    assert.equal(m["backup-unchanged"].counters[key], 0);
  assert.equal(m["backup-renamed"].counters.newPayloadBytes, 0);
  const refs = e.versionReferences;
  for (const name of phases.filter((name) => name.startsWith("backup-"))) {
    assert(/^[0-9a-f]{64}$/.test(refs[name].version));
    assert.equal(refs[name].file, refs["backup-base"].file);
  }
  assert(/^[0-9a-f]{64}$/.test(refs["backup-base"].file));
  assert.equal(refs["backup-unchanged"].version, refs["backup-patched"].version);
  assert.notEqual(refs["backup-renamed"].version, refs["backup-patched"].version);
  for (const label of [
    "restore-inserted",
    "independent-old-after-maintenance",
    "independent-new-after-maintenance",
  ]) {
    const size = n + (label === "restore-inserted" ? 1 << 20 : 0);
    const restore = m[label].counters;
    const oracle = m[label + "-oracle"];
    assert.equal(restore.size, size);
    assert.equal(restore.aliases, 2);
    assert(
      restore.io.verifiedReadBytes <=
        n * limits.maximumRestoreReadRatio + limits.restoreReadAllowanceBytes,
    );
    assert.equal(oracle.attributesVerified, true);
    assert.equal(oracle.fileBytes, size);
    assert.equal(oracle.bytesProcessed, size);
    assert(oracle.allocatedBytes >= size * 0.99);
    assert(/^[0-9a-f]{64}$/.test(oracle.sha256));
  }
  assert.equal(m["independent-old-after-maintenance-oracle"].sha256, m.generate.sha256);
  assert.equal(m["restore-inserted-oracle"].phase, "inserted");
  assert.equal(m["independent-old-after-maintenance-oracle"].phase, "base");
  assert.equal(m["independent-new-after-maintenance-oracle"].phase, "patched");
  assert.notEqual(m["independent-new-after-maintenance-oracle"].sha256, m.generate.sha256);
  assert(
    m.repack.counters.payloadObjectsReplaced > 0 && m.repack.counters.garbageObjectsRemoved > 0,
  );
  assert.equal(m.retire.counters.retiredVersions, 3);
  assert.equal(e.filesystemReserveMaintained, true);
  assert.equal(e.minimumRequiredFreeRatio, limits.minimumFilesystemFreeRatio);
  const cg = e.observedCgroups;
  assert(integer(cg.sampleCount) && cg.sampleCount > 0);
  assert.equal(cg.memoryMaxBytes, limits.containerMemoryBytes);
  assert.equal(cg.swapMaxBytes, 0);
  assert.equal(cg.cpuMax, "100000 100000");
  assert.equal(cg.pidsMax, 128);
  assert.equal(cg.maximumObservedSwapBytes, 0);
  assert.equal(cg.maximumObservedOOMKills, 0);
  assert.equal(cg.maximumObservedOOMEvents, 0);
  // memory.peak includes charged cache/kernel memory and permitted transients.
  // The process RSS assertion above uses each command's kernel RUSAGE instead.
  assert(integer(cg.maximumMemoryPeakBytes) && cg.maximumMemoryPeakBytes > 0);
}
