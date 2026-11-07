import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

const root = path.resolve(import.meta.dirname, "..");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");
const catalog = JSON.parse(read("docs/requirements.json"));
const languages = ["en", "ru"];
const ids = (text, pattern) => [...text.matchAll(pattern)].map((match) => match[1]).sort();
const requireIds = catalog.requirements.map((item) => item.id).sort();
const testIds = catalog.acceptance.map((item) => item.id).sort();
assert.equal(new Set(requireIds).size, requireIds.length, "Duplicate catalog requirement");
assert.equal(new Set(testIds).size, testIds.length, "Duplicate catalog acceptance");
for (const lang of languages) {
  const spec = read(`docs/${lang}/specification.md`);
  assert.deepEqual(ids(spec, /^\*\*(REQ-\d{2})\./gm), requireIds, `${lang}: requirements differ`);
  assert.deepEqual(ids(spec, /^\|\s*(AT-\d{2})\s*\|/gm), testIds, `${lang}: acceptance differs`);
  assert.equal([...spec.matchAll(/^# \d+ /gm)].length, 26, `${lang}: incomplete sections`);
  assert(spec.includes(catalog.specVersion), `${lang}: version missing`);
}
for (const requirement of catalog.requirements) {
  assert.equal(requirement.level, "MUST");
  assert(requirement.scope && requirement.stage && requirement.milestones.length);
  assert(requirement.acceptance.length || requirement.documentChecks?.length);
  for (const id of requirement.acceptance) assert(testIds.includes(id), `Unknown test ${id}`);
}
for (const id of testIds)
  assert(
    catalog.requirements.some((item) => item.acceptance.includes(id)),
    `Unmapped ${id}`,
  );
// The completion map must retain the entire contract, including unfinished work.
// Existing source symbols establish traceability, never runtime acceptance.
const product = JSON.parse(read("docs/product-status.json"));
assert.equal(product.schemaVersion, 1);
assert.equal(product.specVersion, catalog.specVersion);
assert.deepEqual(product.requirements.map((r) => r.id).sort(), requireIds);
assert.deepEqual(product.acceptance.map((a) => a.id).sort(), testIds);
for (const item of product.requirements) {
  const requirement = catalog.requirements.find((r) => r.id === item.id);
  assert(
    item.workstream &&
      item.remaining &&
      ["IN_DEVELOPMENT", "SEPARATE_PROFILE"].includes(item.state),
  );
  assert.deepEqual([...item.acceptance].sort(), [...requirement.acceptance].sort());
  for (const file of item.implementation) {
    assert(!path.isAbsolute(file) && !file.split("/").includes(".."));
    assert(fs.existsSync(path.join(root, file)), `Missing implementation: ${item.id} ${file}`);
  }
  for (const check of item.checks) {
    assert(/^internal\/[a-z_]+\/[a-z_]+_test\.go$/.test(check.path));
    assert(/^Test[A-Za-z0-9]+$/.test(check.name));
    assert(
      read(check.path).includes(`func ${check.name}(t *testing.T)`),
      `Stale product check: ${item.id} ${check.name}`,
    );
  }
}
for (const item of product.acceptance) {
  assert.equal(item.state, "NOT_VERIFIED");
  assert.deepEqual(
    [...item.requirements].sort(),
    catalog.requirements
      .filter((r) => r.acceptance.includes(item.id))
      .map((r) => r.id)
      .sort(),
  );
}
// Keep the G1 trace attached to existing checks. Existence is not execution.
const g1Trace = JSON.parse(read("docs/g1-trace.json"));
assert.equal(g1Trace.schemaVersion, 1);
assert.equal(g1Trace.gate, "G1");
assert.deepEqual(
  g1Trace.requirements.map((item) => item.id).sort(),
  [...catalog.gates.G1.requirements].sort(),
  "G1 trace must cover exactly its requirement set",
);
const fixtureSource = read("experiments/filekit/run.py");
for (const item of g1Trace.requirements) {
  const requirement = catalog.requirements.find((entry) => entry.id === item.id);
  assert(item.tests.length && item.fixturePhases.length && item.acceptanceSubset.length);
  for (const test of item.acceptanceSubset)
    assert(
      requirement.acceptance.includes(test),
      `G1 acceptance link absent: ${item.id} -> ${test}`,
    );
  for (const test of item.tests) {
    assert(/^internal\/filekit\/[a-z_]+_test\.go$/.test(test.path));
    assert(/^Test[A-Za-z0-9]+$/.test(test.name));
    assert(
      read(test.path).includes(`func ${test.name}(t *testing.T)`),
      `Missing G1 executable check: ${item.id} -> ${test.name}`,
    );
  }
  for (const phase of item.fixturePhases)
    assert(fixtureSource.includes(JSON.stringify(phase)), `Missing G1 fixture phase: ${phase}`);
}
const generationTrace = JSON.parse(read("docs/g2-trace.json"));
assert.equal(generationTrace.gate, "G2");
assert.deepEqual(
  generationTrace.requirements.map((item) => item.id).sort(),
  [...catalog.gates.G2.requirements].sort(),
);
for (const item of generationTrace.requirements) {
  const requirement = catalog.requirements.find((entry) => entry.id === item.id);
  assert(
    item.scope && item.remaining && item.tests.length,
    `Missing scoped G2 evidence: ${item.id}`,
  );
  for (const id of item.acceptanceSubset)
    assert(requirement.acceptance.includes(id), `Invalid G2 subset ${item.id} -> ${id}`);
  for (const test of item.tests) {
    assert(/^internal\/(?:generation|filekit)\/[a-z_]+_test\.go$/.test(test.path));
    assert(/^Test[A-Za-z0-9]+$/.test(test.name));
    assert(
      read(test.path).includes(`func ${test.name}(t *testing.T)`),
      `Missing G2 check: ${test.name}`,
    );
  }
}
const peerTrace = JSON.parse(read("docs/g3-trace.json"));
assert.equal(peerTrace.schemaVersion, 1);
assert.equal(peerTrace.gate, "G3");
assert.deepEqual(
  peerTrace.requirements.map((item) => item.id).sort(),
  [...catalog.gates.G3.requirements].sort(),
  "G3 trace must cover exactly its requirement set",
);
for (const item of [...peerTrace.requirements, ...peerTrace.supportingRequirements]) {
  const requirement = catalog.requirements.find((entry) => entry.id === item.id);
  assert(
    requirement &&
      item.scope &&
      item.remaining &&
      item.tests.length &&
      item.acceptanceSubset.length,
  );
  for (const id of item.acceptanceSubset)
    assert(requirement.acceptance.includes(id), `Invalid G3 subset ${item.id} -> ${id}`);
  for (const test of item.tests) {
    assert(/^internal\/(peer|storage|upload)\/[a-z_]+_test\.go$/.test(test.path));
    assert(/^Test[A-Za-z0-9]+$/.test(test.name));
    assert(
      read(test.path).includes(`func ${test.name}(t *testing.T)`),
      `Missing G3 check: ${test.name}`,
    );
  }
}
// These failure-mode links are part of the reviewed specification contract.
// Existence of a test elsewhere does not establish a scoped requirement's coverage.
for (const [id, required] of Object.entries({
  "REQ-19": ["AT-22"],
  "REQ-39": ["AT-22", "AT-25", "AT-30"],
  "REQ-44": ["AT-22", "AT-29", "AT-30"],
  "REQ-53": ["AT-22", "AT-25", "AT-29", "AT-30"],
})) {
  const requirement = catalog.requirements.find((item) => item.id === id);
  for (const test of required)
    assert(requirement?.acceptance.includes(test), `Missing failure-mode link ${id} -> ${test}`);
}
const ruleIds = ids(read(".standards/rules.en.md"), /^## ([A-Z]+-\d{3}) /gm);
const audit = JSON.parse(read("docs/standard-review.json"));
assert.equal(audit.specVersion, catalog.specVersion, "Audit/catalog version differs");
for (const lang of languages) {
  const digest = createHash("sha256")
    .update(read(`docs/${lang}/specification.md`))
    .digest("hex");
  assert.equal(audit.specSha256[lang], digest, `${lang}: audit source changed; review it again`);
}
assert.deepEqual(
  audit.rules.map((item) => item.id).sort(),
  ruleIds,
  "Audit must cover pinned rules",
);
for (const rule of audit.rules) {
  assert(rule.expected.en && rule.expected.ru && rule.observation.en && rule.observation.ru);
  assert(rule.references.length, `Evidence reference missing: ${rule.id}`);
  for (const reference of rule.references) {
    const lines = read(reference.path).split("\n");
    assert(reference.line > 0 && reference.line <= lines.length, `Invalid reference: ${rule.id}`);
    if (reference.requirement)
      assert(
        lines[reference.line - 1].startsWith(`**${reference.requirement}.`),
        `Stale requirement reference: ${rule.id}`,
      );
  }
  for (const id of rule.requirements) assert(requireIds.includes(id), `Unknown requirement ${id}`);
}
const pages = languages.map((lang) =>
  fs
    .readdirSync(path.join(root, "docs", lang))
    .filter((name) => name.endsWith(".md"))
    .sort(),
);
assert.deepEqual(pages[0], pages[1], "Documentation language pairs differ");
const files = execFileSync(
  "git",
  ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
  {
    cwd: root,
    encoding: "utf8",
  },
)
  .split("\0")
  .filter(Boolean);
const missing = [];
for (const name of [...new Set(files)]) {
  if (!name.endsWith(".md") || name.startsWith(".standards/")) continue;
  const text = read(name);
  for (const match of text.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g)) {
    const target = match[1].replace(/^<|>$/g, "").split(/[?#]/)[0];
    if (!target || /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(target)) continue;
    const resolved = path.resolve(root, path.dirname(name), decodeURIComponent(target));
    if (!resolved.startsWith(root + path.sep) || !fs.existsSync(resolved))
      missing.push(`${name}: ${target}`);
  }
}
assert.deepEqual(missing, [], "Broken local links");
console.log(
  `PASS: ${requireIds.length} requirements, ${testIds.length} acceptance scenarios, ${ruleIds.length} rules, language pairs and local links`,
);
