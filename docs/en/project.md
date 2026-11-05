# Project passport

[Русский](../ru/project.md)

Outpost is an experimental backup product for data owners who need complete copies on intermittently connected infrastructure. The repository contains the design and development bootstrap; no new runtime is delivered.

| Actor and workflow                  | Input                                                                | Expected result                                                      | Acceptance                |
| ----------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------- | ------------------------- |
| Owner creates a protected backup    | Stable source view, domain policy and permitted targets              | Encrypted, complete assigned replicas with truthful per-target state | AT-01, AT-06, AT-23       |
| Owner restores a selected version   | Recovery kit and one complete replica or independent file kit        | Exact content and mandatory attributes without source/control plane  | AT-04, AT-05, AT-24       |
| Operator returns an offline replica | Persisted state, permitted temporal route and surviving dependencies | Catch-up/repair with last-good preserved                             | AT-07-AT-13, AT-17, AT-22 |

## Boundaries and authority

The source agent may read assigned data and use its approved consistency provider. Ordinary workers store/transfer authorized ciphertext. A trusted maintenance component can read repository semantics; deletion is separately authorized. Node administrators do not automatically become data owners. Control-plane configuration cannot execute arbitrary shell commands.

Policies use trusted nodes, untrusted nodes and external storage. Category, explicit identity, domain scope and transit restrictions all apply. Complete copies cover assigned datasets, not every dataset everywhere. No distributed filesystem, independent multi-writer merge, billing or bare-metal recovery is included.

## Platforms and contracts

Planned workers: Linux amd64/arm64 containers. Planned operator surfaces: browser UI and recovery/management CLI. Exact OS/browser/runtime versions belong to a release compatibility matrix and are currently unverified. Restic 0.19.1 is a candidate, not a frozen engine decision. Sources use verified filesystem/application providers. External storage profiles cover S3-compatible APIs, WebDAV and separately delayed-access archive classes.

Published development tooling requires Git, Node.js 22+, npm, tar and a POSIX hook shell. No Go package, product binary or container is implied by that tooling bootstrap.

## Data and resource envelope

The initial acceptance profile is in specification section 20: over-5-TB design target, a dedicated 100 GiB change fixture, bounded source temporary space and a 180-generation offline simulation. These are test inputs/targets, not achieved capacity claims.

M0 owns the measurement plan for CPU/RAM/disk, object count, concurrency, API/egress cost and RPO/RTO. Each profile must have results before its release. Recovery and retention are explicit per dataset. Do not assume a single environment proves all limits.

Names and contents are source-encrypted; sizes/timing/reuse remain visible. Owner recovery secrets are stored separately. Supported export, retention/deletion and key-rotation behavior must be accepted before runtime release.

## Source of truth and history

Versioned specifications and docs/requirements.json define the contract. English and Russian pages are paired. The repository checker verifies IDs, traceability and local links; reviewers verify meaning. An external overview is a projection and must identify/reconcile its source version.

The previous Hyper Backup receiver has a separate history at [outpost-legacy](https://github.com/nd4y/outpost-legacy). Its images, data and operational acceptance are not new Outpost releases. Image-tag ownership and migration require a later explicit plan.

Support status: experiment. Original material is MIT; retain dependency notices. Read SECURITY.md and the [roadmap](roadmap.md) before any production use.
