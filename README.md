# Outpost

[Русский](README.ru.md)

[Bounded verification windows](docs/en/verification-windows.md) continue peer generation checks across HTTPS requests and cloud object hashing across physical parts. Receipts preserve original read time. Short tests exercise interrupted progress, fresh operations, legacy peers, corruption and independent recovery; this does not close the full product or large-scale gates.

![Outpost architecture preview: encrypted replicas and policy-controlled storage](docs/assets/architecture.svg)

Autonomous encrypted backups with complete assigned replicas, granular placement and recovery after long disconnections.

**Stage: M0, G1-G3 implementation candidates.** The [G1 format candidate](docs/en/file-kit-format.md) streams files into encrypted objects and restores a selected version without a global repository index. Typed kits also preserve directory attributes and symbolic links without following their targets; regular files retain the original format. There is no production backup service yet. Start with the [specification](docs/en/specification.md) and [G1-G3 feasibility gates](docs/en/roadmap.md). The previous receiver remains in [outpost-legacy](https://github.com/nd4y/outpost-legacy).

The [G1 acceptance plan](docs/en/g1-acceptance.md) covers encrypted names, old/new versions, attributes, multipart descriptors, tamper rejection, actual SIGKILL boundaries and concurrent maintenance. Its 100 GiB/8 MiB profile records reads, added ciphertext/metadata, objects, memory and storage. Full-scale acceptance is pending the recorded run; G2/G3 and production deployment remain separate.

The local CLI accepts regular source and owner-key files. It rejects symbolic links and named pipes without waiting for a pipe writer; recovery keys must have private filesystem permissions. Restored names must fit Linux byte limits (255 per component, 4095 per relative path), so unsupported names fail before capture.

The [G2 generation/replica candidate](docs/en/generation-replicas.md) adds signed complete catalogs, keyless reception, restart-safe progress, persistent pins and separately authorized cleanup. Its compact local history index has explicit migration and guarded rollback commands; wire catalogs and existing file kits remain compatible. Small HDD tests cover checkpoint catch-up, source repack, actual process termination and independent old/new restoration. Heavy scale/endurance tests remain deferred; this is not full G2 acceptance or a network service.

The [G3 peer candidate](docs/en/peer-transfer.md) adds mutually authenticated HTTPS push/pull, durable operation journals and complete publication through an asynchronous bridge. Bounded fault tests include false acknowledgments, lost replies, cancelled parallel reads and independent restoration after source/bridge loss. Push defaults to full target readback; an explicit [reuse policy](docs/en/readback-reuse.md) retains original evidence age while avoiding unchanged-object downloads. The [external-upload candidate](docs/en/external-upload.md) adds S3-compatible/WebDAV adapters, three independent workers, cached signed plans, resumable multipart planning, failover and independently recoverable target generations. A separate owner policy enables cloud readback reuse with exact descriptor binding and original evidence age. Real endpoint admission, full traffic accounting and heavy G3 acceptance remain open.

The [durable upload queue](docs/en/upload-queue.md) now admits signed plans, pins sources and runs independent targets with bounded concurrency, automatic delayed retries and process-crash recovery. Expired or permanently blocked jobs remain explicit and protected.

The [source and recovery components](docs/en/product-development.md) include bounded alias-aware scanning, a metadata-only streaming cache and whole-replica/directory recovery without the state index. [Authenticated source ingress](docs/en/source-ingress.md) adds current-policy admission, bounded verification and durable acknowledgement cleanup to workers. `restore-replica` validates an explicit checkpoint and publishes a complete selected result atomically. The [private source agent](docs/en/source-agent.md) now runs restartable best-effort capture over HTTPS and prepares the next signed generation. [Autonomous replication](docs/en/autonomous-replication.md) discovers new complete generations under explicit owner rules. [Signed copy observations](docs/en/copy-observations.md) support two-copy release through an outbound-only relay. Native consistency providers and the installable product remain in development.

Worker bootstrap now requires [runtime volume admission](docs/en/runtime-volume.md). Missing markers or replaced paths stop work, while opened descriptors keep writes on the admitted tree. Encrypted per-file progress reuses accepted packs after a crash; the source is still reread. The [source job lifecycle](docs/en/source-jobs.md) defines enforced checkpoint/release ordering and the remaining network copy-threshold integration.

## Planned workflows

- Back up a dataset once at the source and distribute complete encrypted replicas across permitted nodes.
- Restore one retained file version independently, including when other nodes and the control plane are unavailable.
- Reconcile and repair replicas after weeks or months offline, using authorized intermediate nodes when direct links are impossible.

## Storage and privacy

Policies distinguish **trusted nodes**, **untrusted nodes** and **external storage** using S3-compatible APIs or WebDAV. Each dataset selects permitted categories, concrete recipients and transit routes. Untrusted workers receive ciphertext without decryption keys. Trusted worker status alone grants no decryption rights. External storage is a backend, not an implicit worker.

Names and file metadata are encrypted at the source. Technical sizes, timing and block-reuse patterns are not hidden. A complete replica covers its assigned datasets and retained versions. Every cloud target must be independently complete for its assignments; eligible workers divide uploads.

## Read and check this repository

```sh
git clone https://github.com/nd4y/outpost.git
cd outpost
npm ci --prefix .standards --ignore-scripts --no-audit --no-fund
node .standards/install-gitleaks.mjs
node .standards/install-hooks.mjs
node .standards/check.mjs structure
node scripts/check-docs.mjs
node scripts/check-format.mjs
```

These commands validate documentation and the standard toolkit. They do not start a backup service. Development requires Git, Node.js 22+, npm, tar and a POSIX shell for hooks; CI pins its exact versions. The G1 CLI targets Linux and reuses the pinned restic chunker with standard Go cryptography. The older restic 0.19.1 experiment remains a comparison; planned workers target Linux amd64/arm64.

## Documentation

- [Project passport and workflows](docs/en/project.md)
- [Technical specification 1.4](docs/en/specification.md)
- [Milestones and open acceptance](docs/en/roadmap.md)
- [Product completion and signed configuration](docs/en/product-development.md)
- [Development standard and commands](docs/en/development-standard.md)
- [Audit against all 45 rules](docs/en/standard-review.md)
- [G1 executable experiment and limits](docs/en/g1-prototype.md)
- [Independent file-kit format and engine decision](docs/en/file-kit-format.md)
- [G1 acceptance, cost bounds and commands](docs/en/g1-acceptance.md)
- [Infrastructure profile contract](docs/en/infrastructure-profile.md)
- [Machine-readable requirement trace](docs/requirements.json)
- [G1 requirements linked to executable checks](docs/g1-trace.json)
- [G2 generation and replica contracts](docs/en/generation-replicas.md)
- [G2 scoped requirement-to-check trace](docs/g2-trace.json)
- [G3 peer protocol, evidence and limits](docs/en/peer-transfer.md)
- [Distributed external upload, recovery and limits](docs/en/external-upload.md)
- [Autonomous external planning](docs/en/delegated-upload.md)
- [Immutable-object readback reuse contract](docs/en/readback-reuse.md)
- [G3 scoped requirement-to-check trace](docs/g3-trace.json)

[Repository checks](https://github.com/nd4y/outpost/actions) assess source/documentation mechanics. Product builds, releases, installation, restore and runtime acceptance remain separate. The pinned toolkit is autonomous and needs no private-repository credentials.

## Support and licensing

Track design defects and scoped proposals in [Issues](https://github.com/nd4y/outpost/issues). Use [SECURITY.md](SECURITY.md) for sensitive reports. No runtime compatibility or response-time SLA is promised at this stage. [CONTRIBUTING.md](CONTRIBUTING.md) explains bilingual PRs and owner merges.

Original project material is [MIT licensed](LICENSE). The vendored toolkit retains its [MIT notice](.standards/LICENSE). Restic and other future runtime dependencies retain their own licenses; none is bundled as a product release here.

The private source agent supports a [durable interval schedule](docs/en/source-scheduling.md) with pause, restart and unchanged pending-operation recovery. Full product acceptance remains open.

The [management API candidate](docs/en/management-api.md) supports authenticated enrollment, owner-signed configuration and original-age reports. A separate worker reporting process persists its queue, schedule and retries; pause or revocation cancels active delivery. Unknown verification age, logical size and transfer progress remain explicit. Command execution, management service bootstrap and the operator UI are still in development.
