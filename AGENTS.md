# Repository instructions

Read .repo-policy.json, docs/en/development-standard.md (or the Russian pair), the pinned rules and applicable profiles before a change. This is a design and bootstrap stage. Product implementation begins with G1-G3 in the specification. Documentation checks do not establish backup, restore, capacity or runtime acceptance.

Use branches and pull requests after the initial repository bootstrap. The owner merges unless they explicitly authorize otherwise. Keep README.md, README.ru.md and relevant docs/en and docs/ru pages meaningful and current together. Preserve strict documentation policy and required checks. Do not weaken scanners or trust rules to obtain a pass.

Run from the repository root:

```sh
npm ci --prefix .standards --ignore-scripts --no-audit --no-fund
node .standards/install-gitleaks.mjs
node .standards/install-hooks.mjs
node .standards/check.mjs structure
node scripts/check-docs.mjs
node scripts/check-format.mjs
node .standards/check.mjs staged
```

Format supported project files with the pinned Prettier configuration before staging. The hook installer preserves existing hooks. Add native formatters and behavioral checks with the first implementation in a language. Update the vendored toolkit only through a reviewed versioned change; never modify its lock to bypass a check.

Before publication, scan the entire published history with checksum-verified Gitleaks. Unavailable scanning blocks publication. Public commands are portable. Keep workstation paths, internal hosts, credentials, budgets, private inventories, backup payloads and owner journals outside this repository.

Private owner profiles govern build resources and external workers; this file grants no such access. Do not start background jobs or subagents without a direct request. Review executor results and preserve concurrent work.

Separate trusted nodes, untrusted nodes and external storage. An ordinary trusted worker has no decryption key. Placement and transit rules apply before packing. Prototypes must preserve independent file recovery and offline retention.

Legacy receivers belong to https://github.com/nd4y/outpost-legacy. This project has a separate history. Routine source work does not authorize data migration, legacy image-tag reuse, networking changes, deployment, releases or real notifications.

Before a task, record scope, acceptance, rollback and stop conditions. Report exact version, environment, commands, results and remaining stages. A passing repository checker does not certify the product.
