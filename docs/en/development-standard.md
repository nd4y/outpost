# Development standard adoption

[Русский](../ru/development-standard.md)

Outpost adopts Development Standard **0.4.0** through a checksum-pinned, public-safe local toolkit. Its [lock](../../.standards/lock.json), [English rules](../../.standards/rules.en.md) and [Russian rules](../../.standards/rules.ru.md) work without access to the private control repository. Only the distributable allowlist is included; no private inventory or operational profile is published.

Toolkit source commit (SHA-1): `75833a42311832d1de665d0e441adac2b5b701d2`.

The project is an experiment with adoption status **adopting**. This means repository mechanics can be verified while implementation, runtime and profile acceptance are still open. Read the [45-rule audit](standard-review.md).

## Profiles and exceptions

Applicable: web, cli, library, service, network, integration, infra, monitoring, data and docs. They cover browser/CLI UX, API consumers, container privileges, partial connectivity, external-provider compatibility, installation/diffs, telemetry and backup/restore. Mobile, ML and firmware are outside scope. No rule exception is approved.

Future exceptions must identify rule, scope, reason/risk, owner, compensation and review date. MUST failures block their relevant stage. Do not change strict documentation mode or required checks as a shortcut.

## Bootstrap and commands

```sh
npm ci --prefix .standards --ignore-scripts --no-audit --no-fund
node .standards/install-gitleaks.mjs
node .standards/install-hooks.mjs
node .standards/check.mjs structure
node scripts/check-docs.mjs
node scripts/check-format.mjs
node scripts/check-standard-adoption.mjs
```

Tools: Node.js 22+ locally, CI Node.js 24.18.0, Prettier 3.9.10 and checksum-verified Gitleaks 8.30.1. Git, npm, tar and a POSIX hook shell are required. The M0 prototype uses Go 1.27.3: native gofmt, go test and go vet run in the prototype workflow. Its synthetic integration fixture runs without network or private credentials; see the [G1 commands and limits](g1-prototype.md). The production worker is not implemented.

Format with `node scripts/check-format.mjs --write`, review the diff and stage only intended files. The pre-commit hook runs `node .standards/check.mjs staged` on index content; it preserves partial staging and chains any prior hook. Do not edit vendored toolkit files to reformat the project.

After staging, run the staged checker explicitly when checking outside a commit. Full-history publication scan on POSIX uses:

```sh
.standards/bin/gitleaks git . --log-opts=--all --redact --no-banner --config .standards/gitleaks.toml
```

On Windows use the same arguments with `.standards/bin/gitleaks.exe`. Scanner absence blocks publication. The adoption test uses a disposable local repository, accepts a valid change and rejects bad format, missing language, whitespace-only documentation, deleted docs, a synthetic secret and unavailable scanning. It changes no project history and contacts no external service.

## CI and merge policy

The isolated repository-standard workflow checks the complete PR diff, pinned bundle, meaningful bilingual docs, formatting and secrets. It also scans full history, covering the first root commit that an ordinary commit range could omit. The documentation workflow checks language/ID/link coherence, complete formatting and the seven toolkit cases.

Both use SHA-pinned actions, read-only permissions and hosted runners. Fork PRs require no secrets or private network. Required statuses must pass for the actual head. Main protection is configured only after a real successful run and verified separately from YAML existence.

After initial bootstrap, use branches/PRs; the owner merges. Do not bypass protection or silently loosen checks. The source policy intentionally does not predict future CI success: inspect the exact commit's Actions result. Product release/runtime fields remain NOT_VERIFIED until accepted.

## Evidence, updates and rollback

Record commit/digest, environment, commands, time, results and unverified paths. [requirements.json](../requirements.json) retains 53 requirements and 35 planned scenarios. The checker verifies structure; human review verifies bilingual meaning. Runtime tests belong to G1-G3 and M1-M5.

Update the toolkit with a versioned reviewed PR after checking checksums and rejection behavior. To undo local hook installation, restore the previous hooksPath recorded in the local Git directory's repository-standard-hook.json; a previous hook is preserved. Removing public adoption files requires a reviewed PR preserving product checks. Owner infrastructure and build policies remain private.
