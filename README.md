# Outpost

[Русский](README.ru.md)

[Bounded verification windows](docs/en/verification-windows.md) continue peer generation checks across HTTPS requests and cloud object hashing across physical parts. Receipts preserve original read time. Short tests exercise interrupted progress, fresh operations, legacy peers, corruption and independent recovery; this does not close the full product or large-scale gates.

![Outpost architecture preview: encrypted replicas and policy-controlled storage](docs/assets/architecture.svg)

Autonomous encrypted backups with complete assigned replicas, granular placement and recovery after long disconnections.

**Stage: M0, G1-G3 implementation candidates.** The [G1 format candidate](docs/en/file-kit-format.md) streams files into encrypted objects and restores a selected version without a global repository index. Typed kits also preserve directory attributes and symbolic links without following their targets; regular files retain the original format. There is no production backup service yet. Start with the [specification](docs/en/specification.md) and [G1-G3 feasibility gates](docs/en/roadmap.md). The previous receiver remains in [outpost-legacy](https://github.com/nd4y/outpost-legacy).

The [G1 acceptance plan](docs/en/g1-acceptance.md) covers encrypted names, old/new versions, attributes, multipart descriptors, tamper rejection, actual SIGKILL boundaries and concurrent maintenance. Its 100 GiB/8 MiB profile records reads, added ciphertext/metadata, objects, memory and storage. Full-scale acceptance is pending the recorded run; G2/G3 and production deployment remain separate.

The local CLI accepts regular source and owner-key files. It rejects symbolic links and named pipes without waiting for a pipe writer; recovery keys must have private filesystem permissions. Restored names must fit Linux byte limits (255 per component, 4095 per relative path), so unsupported names fail before capture.

The [G2 generation/replica candidate](docs/en/generation-replicas.md) adds signed complete catalogs, keyless reception, restart-safe progress, persistent pins and separately authorized cleanup. Its compact local history index has explicit migration and guarded rollback commands; wire catalogs and existing file kits remain compatible. Small HDD tests cover checkpoint catch-up, source repack, actual process termination and independent old/new restoration. Heavy scale/endurance tests remain deferred; this is not full G2 acceptance or a network service.

The [specification 1.5](docs/en/specification.md) requires parallel capture across authorized receivers, forwarding before generation sealing and a policy-defined release threshold. The [two-holder source candidate](docs/en/source-agent.md#parallel-capture-to-two-required-holders) forwards accepted packs before seal, keeps the verified two-full-copy default and offers explicit early release when both holders each cover the whole catalog or their assigned share. Workers can finish publication with the source offline. The candidate renews both grants in one signed source update.

The [G3 peer candidate](docs/en/peer-transfer.md) adds mutually authenticated HTTPS push/pull, durable operation journals and complete publication through an asynchronous bridge. Bounded fault tests include false acknowledgments, lost replies, cancelled parallel reads and independent restoration after source/bridge loss. Push defaults to full target readback; an explicit [reuse policy](docs/en/readback-reuse.md) retains original evidence age while avoiding unchanged-object downloads. The [external-upload candidate](docs/en/external-upload.md) adds S3-compatible/WebDAV adapters, three independent workers, cached signed plans, resumable multipart planning, failover and independently recoverable target generations. A separate owner policy enables cloud readback reuse with exact descriptor binding and original evidence age. Real endpoint admission, full traffic accounting and heavy G3 acceptance remain open.

The [durable upload queue](docs/en/upload-queue.md) now admits signed plans, pins sources and runs independent targets with bounded concurrency, automatic delayed retries and process-crash recovery. Expired or permanently blocked jobs remain explicit and protected.

The [source and recovery components](docs/en/product-development.md) include bounded alias-aware scanning, a metadata-only streaming cache and whole-replica/directory recovery without the state index. [Authenticated source ingress](docs/en/source-ingress.md) adds current-policy admission, bounded verification and durable acknowledgement cleanup to workers. `restore-replica` validates an explicit checkpoint and publishes a complete selected result atomically. The [private source agent](docs/en/source-agent.md) now runs restartable best-effort capture over HTTPS and prepares the next signed generation. [Autonomous replication](docs/en/autonomous-replication.md) discovers new complete generations under explicit owner rules. [Signed copy observations](docs/en/copy-observations.md) support two-copy release through an outbound-only relay. The prepared provider accepts read-only Btrfs snapshots with native identity checks. Other filesystem providers and application-specific admission remain in development.

The `source-status` command reports the expiry of pending work and indicates whether the operator can resume it or needs owner action or receiver reconciliation. An expired operation prepared locally can be retired with owner approval until execution reaches the receiver fence.

[Automatic receiver replacement](docs/en/source-agent.md#automatic-replacement-after-active) supports a standby for one copy and a reserve for two. With a complete surviving closure, the pair replays the signed catalog and reclaims the old slot after catch-up. [Scoped recovery](docs/en/source-settlement.md) lets both holders finish staged publication after expiry and distinguishes an unadmitted source operation from retained receiver work.

Worker bootstrap now requires [runtime volume admission](docs/en/runtime-volume.md). Missing markers or replaced paths stop work, while opened descriptors keep writes on the admitted tree. Encrypted per-file progress reuses accepted packs after a crash; the source is still reread. The [source job lifecycle](docs/en/source-jobs.md) defines enforced checkpoint/release ordering and the remaining network copy-threshold integration.

[Trusted content verification](docs/en/trusted-verification.md) decrypts selected retained versions without plaintext output or a replica index. Private reports preserve per-version outcomes and original check times; partial checks return a failure status. Ordinary workers remain keyless.

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
- [Technical specification 1.5](docs/en/specification.md)
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
- [Distributed external upload, recovery and limits](docs/en/external-upload.md) - S3-compatible and WebDAV targets with bounded repeated capability checks.
- [Autonomous external planning](docs/en/delegated-upload.md)
- [Immutable-object readback reuse contract](docs/en/readback-reuse.md)
- [G3 scoped requirement-to-check trace](docs/g3-trace.json)

[Repository checks](https://github.com/nd4y/outpost/actions) assess source/documentation mechanics. Product builds, releases, installation, restore and runtime acceptance remain separate. The pinned toolkit is autonomous and needs no private-repository credentials. CI verifies the unchanged scanner checksum even when using the official release API download route.

## Support and licensing

Track design defects and scoped proposals in [Issues](https://github.com/nd4y/outpost/issues). Use [SECURITY.md](SECURITY.md) for sensitive reports. No runtime compatibility or response-time SLA is promised at this stage. [CONTRIBUTING.md](CONTRIBUTING.md) explains bilingual PRs and owner merges.

Original project material is [MIT licensed](LICENSE). The vendored toolkit retains its [MIT notice](.standards/LICENSE). Restic and other future runtime dependencies retain their own licenses; none is bundled as a product release here.

The private source agent supports a [durable interval schedule](docs/en/source-scheduling.md) with pause, restart and unchanged pending-operation recovery. Explicit source-authority renewal preserves that history and migrates the signed journal without expanding scope. Initial installation publishes only a complete runtime, keeps interrupted candidates and bounds retries. Full product acceptance remains open.

The [management API candidate](docs/en/management-api.md) supports signed configuration, durable original-age reports and a signed command queue. Workers persist pause/resume across restart and policy changes, join active transfers before acknowledging pause, and retry the same receipt after a lost reply. Blocked-job retries use a durable token across worker/upload journals and never repeat a completed upload. Foreground reporting and command polling remain independent of backup execution. Asynchronous ciphertext scrub and separately signed maintenance preserve original results across restart. Signed reports expose bounded command progress separately from backup jobs. [Authorized replica repair](docs/en/integrity-repair.md) preserves quarantine and repairs detected damage through existing push/pull routes. [Trusted recovery](docs/en/trusted-recovery.md) and the [private management service](docs/en/management-service.md) have short process checks; the [bilingual operator interface](docs/en/management-ui.md) now has isolated browser checks for coverage, signed-policy preview and exact recovery requests. The persistent browser journal preserves exact retries across closed tabs and browser restart, coordinates concurrent tabs and rejects unsafe storage failures. Unconfirmed-request resolution, external-target coverage, manual accessibility and full product acceptance remain open.

[Trusted recovery](docs/en/trusted-recovery.md) connects signed restore commands to a private local executor with separate output admission, atomic bundles, historical receipts and versioned reports. The normal worker remains keyless.

[Catalog repair](docs/en/integrity-repair.md#unreadable-catalogs) isolates damaged metadata without hiding healthy generations, preserves the original in quarantine and restores it through explicitly authorized peers.

[Management service commands](docs/en/management-service.md) provide private initialization, runtime status, profile revision, bounded reconciliation and TLS serving. Stop/join, volume-loss and real process-kill checks run on isolated fixtures; no live installation is implied.

Owners can now review and abandon an admitted request only while its effect remains unpublished. An independent resolution receipt and audit preserve the original request; replay cannot execute it. Published commands and durable configuration effects are refused. [The lifecycle contract](docs/en/management-service.md#resolving-unpublished-intents) describes the format fence, retained checkpoint and remaining recovery work.

The [private management snapshot](docs/en/management-snapshots.md) preserves administrative history and independently verifies a selected checkpoint without activating historical commands.

The interface now shows [external-copy observations](docs/en/external-copy-reporting.md) with their original verification time and explicit unknown state.

The [Linux distribution candidate](docs/en/distribution.md) builds source-bound amd64/arm64 archives and a shellless container input; installation and runtime acceptance remain explicit gates.

The [durable telemetry process](docs/en/telemetry.md) provides a signed bounded OTLP queue, retained source positions, explicit scope renewal and independent delivery. Short checks include a real collector and backup/restore during a slow sink; complete instrumentation and operational acceptance remain open.

The [owner recovery package](docs/en/owner-recovery-package.md) keeps read-only decryption material, original checkpoint age and selected offline tools in private owner storage. Export, digest-anchored inspection and atomic extraction leave signing authority out of the package. Selected-file and complete-replica recovery have separate small process checks; key lifecycle and full-scale acceptance remain open.

The [expired-operation settlement workflow](docs/en/source-settlement.md) retrieves only an already durable original receipt under fresh owner permission and current receiver policy. It preserves original verification age and the independent-copy threshold. Missing receipt or expired observation permission remains pending; an immutable write intent is never renewed by settlement.

The [receiver renewal workflow](docs/en/receiver-renewal.md) admits a fresh same-scope grant in the existing registry after explicit quiescent maintenance. It preserves historical receipts and generations, fences previous readers and uses the current receiver policy and disk budget.

[Missing receipt recovery](docs/en/receipt-recovery.md) uses separate fresh owner permission and current receiver policy to reconstruct a receipt only from an already complete generation and unchanged original publication proof. It preserves the original verification age and signed audit; ordinary settlement remains a separate step. Truly unpublished operations and lost journals remain pending.

[Prepared application exports](docs/en/prepared-exports.md) bind a native producer's signed closed inventory to an immutable source operation, preserving original age and file history. Current/previous CLI and actual SIGKILL checks include independent restoration and reopening of two native SQLite exports. Read-only Btrfs snapshot capture uses the same signed inventory. Snapshot production and retention belong to the native producer.

WebDAV targets without conditional `PUT` can use the explicit MOVE profile. Workers save each staging attempt, verify the ciphertext and publish with `Overwrite: F`. The process fixture restarts workers on both sides of MOVE and restores two retained generations independently. [External upload](docs/en/external-upload.md).

`restore-external` restores a selected file version, directory or generation directly from an S3-compatible or WebDAV copy with read-only credentials and the owner kit. It verifies the selected checkpoint and publishes the output atomically. [Independent external recovery](docs/en/external-upload.md#independent-external-recovery).
