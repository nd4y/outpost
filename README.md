# Outpost

[Русский](README.ru.md)

[Bounded verification windows](docs/en/verification-windows.md) continue peer generation checks across HTTPS requests and cloud object hashing across physical parts. Receipts preserve original read time. Short tests exercise interrupted progress, fresh operations, legacy peers, corruption and independent recovery; this does not close the full product or large-scale gates.

![Outpost architecture preview: encrypted replicas and policy-controlled storage](docs/assets/architecture.svg)

Autonomous encrypted backups with complete assigned replicas, granular placement and recovery after long disconnections.

**Stage: M0; G1 accepted, G2/G3 implementation candidates.** The [G1 file-kit format](docs/en/file-kit-format.md) streams files into encrypted objects and restores a selected version without a global repository index. Typed kits also preserve directory attributes and symbolic links without following their targets; regular files retain the original format. There is no production backup service yet. Start with the [specification](docs/en/specification.md) and [G1-G3 feasibility gates](docs/en/roadmap.md). The previous receiver remains in [outpost-legacy](https://github.com/nd4y/outpost-legacy).

The [G1 acceptance record](docs/en/g1-acceptance.md) covers encrypted names, old/new versions, attributes, multipart descriptors, tamper rejection, actual SIGKILL boundaries and concurrent maintenance. Its physical 100 GiB/8 MiB run passed all 23 phases, including independent old/new recovery after repack and retirement. Added ciphertext and metadata for the contiguous change total 31,103,218 bytes, below 128 MiB. The [scoped receipt](docs/g1-scale-evidence.json) identifies the tested source and costs; G2/G3, whole-product acceptance and production deployment remain separate.

The local CLI accepts regular source and owner-key files. It rejects symbolic links and named pipes without waiting for a pipe writer; recovery keys must have private filesystem permissions. Restored names must fit Linux byte limits (255 per component, 4095 per relative path), so unsupported names fail before capture.

The [G2 generation/replica candidate](docs/en/generation-replicas.md) adds signed complete catalogs, keyless reception, restart-safe progress, persistent pins and separately authorized cleanup. Its compact local history index has explicit migration and guarded rollback commands; wire catalogs and existing file kits remain compatible. Small HDD tests cover checkpoint catch-up, source repack, actual process termination and independent old/new restoration. Heavy scale/endurance tests remain deferred; this is not full G2 acceptance or a network service.

The [bounded G2 receipt](docs/g2-history-evidence.json) records180actual64KiB updates with the third holder offline, interrupted direct catch-up and independent old/new recovery. A separate holder check covers real TLS epoch transition, old-branch revocation and persistent rollback fences. These checks do not accept full distributed scale.

The [specification 1.5](docs/en/specification.md) requires parallel capture across authorized receivers, forwarding before generation sealing and a policy-defined release threshold. The [two-holder source candidate](docs/en/source-agent.md#parallel-capture-to-two-required-holders) forwards accepted packs before seal, keeps the verified two-full-copy default and offers explicit early release when both holders each cover the whole catalog or their assigned share. Workers can finish publication with the source offline. The candidate renews both grants in one signed source update.

The [G3 peer candidate](docs/en/peer-transfer.md) adds mutually authenticated HTTPS push/pull, durable operation journals and complete publication through an asynchronous bridge. Bounded fault tests include false acknowledgments, lost replies, cancelled parallel reads and independent restoration after source/bridge loss. Push defaults to full target readback; an explicit [reuse policy](docs/en/readback-reuse.md) retains original evidence age while avoiding unchanged-object downloads. The [external-upload candidate](docs/en/external-upload.md) adds S3-compatible/WebDAV adapters, three independent workers, cached signed plans, resumable multipart planning, failover and independently recoverable target generations. A separate owner policy enables cloud readback reuse with exact descriptor binding and original evidence age. Real endpoint admission, full traffic accounting and heavy G3 acceptance remain open.

The [controlled G3 measurements](docs/g3-latency-evidence.json) retain all throughput failures. Both protocols pass independent old/new recovery, but the shared CPU/HDD fixture has not consistently met the1.5x speedup target; G3 remains open.

The [idle polling receipt](docs/upload-idle-evidence.json) separates the verified reduction in waiting-worker requests and ordinary offline cloud recovery from an unresolved12s slot regression on the shared busy HDD. Full G3 throughput remains open.

S3-compatible signing now uses pinned SDK/protocol components with explicit credentials and the existing Outpost request limits. Independent signatures and real signed-framing checks are documented in the [storage adapter](docs/en/external-upload.md#request-signing-components); endpoint and full-product acceptance remain separate.

The [durable upload queue](docs/en/upload-queue.md) now admits signed plans, pins sources and runs independent targets with bounded concurrency, automatic delayed retries and process-crash recovery. Expired or permanently blocked jobs remain explicit and protected.

The [source and recovery components](docs/en/product-development.md) include bounded alias-aware scanning, a metadata-only streaming cache and whole-replica/directory recovery without the state index. [Authenticated source ingress](docs/en/source-ingress.md) adds current-policy admission, bounded verification and durable acknowledgement cleanup to workers. `restore-replica` validates an explicit checkpoint and publishes a complete selected result atomically. The [private source agent](docs/en/source-agent.md) now runs restartable best-effort capture over HTTPS and prepares the next signed generation. [Autonomous replication](docs/en/autonomous-replication.md) discovers new complete generations under explicit owner rules. [Signed copy observations](docs/en/copy-observations.md) support two-copy release through an outbound-only relay. The prepared provider accepts read-only Btrfs snapshots with native identity checks. Other filesystem providers and application-specific admission remain in development.

An optional [write-ahead source journal copy](docs/en/source-journal-copy.md) repairs a missing main journal from the exact signed state when the admitted copy and required capture records survive.

The [native Btrfs producer](docs/en/prepared-exports.md#native-btrfs-producer) creates one read-only snapshot for a durable signed operation. A separate producer action consumes the source's signed release ticket and removes the exact subvolume.

The `source-status` command reports the expiry of pending work and indicates whether the operator can resume it or needs owner action or receiver reconciliation. An expired operation prepared locally can be retired with owner approval until execution reaches the receiver fence.

For active and completed operations, `source-status` reports when the source observed release of its view and when checkpointed replicas verified their ciphertext. Independent decryption has its own restore receipt.

[Automatic receiver replacement](docs/en/source-agent.md#automatic-replacement-after-active) supports a standby for one copy and a reserve for two. Paired capture adjusts initial transfers to measured receiver throughput, including split coverage with a direct handoff to the assigned holder. Before full publication the worker estimates additional space from the signed catalog. With a complete surviving closure, the pair replays the signed catalog and reclaims the old slot after catch-up. [Scoped recovery](docs/en/source-settlement.md) lets both holders finish staged publication after expiry and distinguishes an unadmitted source operation from retained receiver work.

An [expired unsealed capture](docs/en/source-settlement.md#retire-an-admitted-capture-before-sealing) can retire with exact owner grants and evidence from every possible receiver. The old slot retains its staging until a fresh attempt is admitted at the same sequence and predecessor.

Worker bootstrap now requires [runtime volume admission](docs/en/runtime-volume.md). Missing markers or replaced paths stop work, while opened descriptors keep writes on the admitted tree. Encrypted per-file progress reuses accepted packs after a crash; the source is still reread. The [source job lifecycle](docs/en/source-jobs.md) defines enforced checkpoint/release ordering and the remaining network copy-threshold integration.

[Trusted content verification](docs/en/trusted-verification.md) decrypts selected retained versions without plaintext output or a replica index. Private reports preserve per-version outcomes and original check times; partial checks return a failure status. Ordinary workers remain keyless.

The [bounded source-ingress receipt](docs/source-ingress-evidence.json) records one full-catalog upload across multiple verification batches, legacy compatibility and actual expiry refusals. A physical 128 MiB source rehearsal and two clean-consumer complete-replica restores prepare the separate 100 GiB stage; they do not establish full-scale acceptance.

The [bounded maintenance-plan receipt](docs/maintenance-plan-evidence.json) covers export and exact restoration of a lost frozen deletion plan, including real process termination, stopped-worker admission and the selected CLI. The current index and signed retention ledger must survive; combined metadata loss remains open.

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
- [Delayed archive recovery](docs/en/archive-recovery.md) - selected S3 retrieval with signed part maps, bounded cost and a temporary availability window.
- [Autonomous external planning](docs/en/delegated-upload.md)
- [Immutable-object readback reuse contract](docs/en/readback-reuse.md)
- [G3 scoped requirement-to-check trace](docs/g3-trace.json)

[Repository checks](https://github.com/nd4y/outpost/actions) assess source/documentation mechanics. Product builds, releases, installation, restore and runtime acceptance remain separate. The pinned toolkit is autonomous and needs no private-repository credentials. CI verifies the unchanged scanner checksum even when using the official release API download route.

## Support and licensing

Track design defects and scoped proposals in [Issues](https://github.com/nd4y/outpost/issues). Use [SECURITY.md](SECURITY.md) for sensitive reports. No runtime compatibility or response-time SLA is promised at this stage. [CONTRIBUTING.md](CONTRIBUTING.md) explains bilingual PRs and owner merges.

Original project material is [MIT licensed](LICENSE). The vendored toolkit retains its [MIT notice](.standards/LICENSE). Restic and other future runtime dependencies retain their own licenses; none is bundled as a product release here.

The private source agent supports a [durable interval schedule](docs/en/source-scheduling.md) with pause, restart and unchanged pending-operation recovery. Explicit source-authority renewal preserves that history and migrates the signed journal without expanding scope. Initial installation publishes only a complete runtime, keeps interrupted candidates and bounds retries. Full product acceptance remains open.

The [management API candidate](docs/en/management-api.md) supports signed configuration, durable original-age reports and a signed command queue. Workers persist pause/resume across restart and policy changes, join active transfers before acknowledging pause, and retry the same receipt after a lost reply. Blocked-job retries use a durable token across worker/upload journals and never repeat a completed upload. Foreground reporting and command polling remain independent of backup execution. Asynchronous ciphertext scrub and separately signed maintenance preserve original results across restart. Signed reports expose bounded command progress separately from backup jobs. [Authorized replica repair](docs/en/integrity-repair.md) preserves quarantine and repairs detected damage through existing push/pull routes. [Trusted recovery](docs/en/trusted-recovery.md) and the [private management service](docs/en/management-service.md) have short process checks; the [bilingual operator interface](docs/en/management-ui.md) now has isolated browser checks for coverage, signed-policy preview and exact recovery requests. The persistent browser journal preserves exact retries across closed tabs and browser restart, coordinates concurrent tabs and rejects unsafe storage failures. Never-admitted request refusal has a bounded implementation candidate; external-target coverage, manual accessibility and full product acceptance remain open.

[Trusted recovery](docs/en/trusted-recovery.md) connects signed restore commands to a private local executor with separate output admission, atomic bundles, historical receipts and versioned reports. The normal worker remains keyless.

[Catalog repair](docs/en/integrity-repair.md#unreadable-catalogs) isolates damaged metadata without hiding healthy generations, preserves the original in quarantine and restores it through explicitly authorized peers.

[Management service commands](docs/en/management-service.md) provide private initialization, runtime status, profile revision, bounded reconciliation and TLS serving. Stop/join, volume-loss and real process-kill checks run on isolated fixtures; no live installation is implied.

Owners can now review and abandon an admitted request only while its effect remains unpublished. An independent resolution receipt and audit preserve the original request; replay cannot execute it. Published commands and durable configuration effects are refused. [The lifecycle contract](docs/en/management-service.md#resolving-unpublished-intents) describes the format fence, retained checkpoint and remaining recovery work.

The [private management snapshot](docs/en/management-snapshots.md) preserves administrative history and independently verifies a selected checkpoint without activating historical commands.

The interface now shows [external-copy observations](docs/en/external-copy-reporting.md) with their original verification time and explicit unknown state.

The [Linux distribution candidate](docs/en/distribution.md) builds source-bound amd64/arm64 archives and a shellless container input; installation and runtime acceptance remain explicit gates.

The [durable telemetry process](docs/en/telemetry.md) provides a signed bounded OTLP queue, retained source positions, explicit scope renewal and independent delivery. Short checks include a real collector and backup/restore during a slow sink; complete instrumentation and operational acceptance remain open.

The [monitoring rules](docs/en/telemetry.md#monitoring-rules-and-independent-watchdog) distinguish missing telemetry from measured failures and provide a separate watchdog for receipt of the monitoring heartbeat.

The [owner recovery package](docs/en/owner-recovery-package.md) keeps read-only decryption material, original checkpoint age and selected offline tools in private owner storage. The [key epoch preparation](docs/en/owner-recovery-package.md#prepare-a-new-key-epoch) creates a separate domain and records the authenticated prior package and checkpoint. Activation, retirement and full-scale acceptance have separate gates.

The [expired-operation settlement workflow](docs/en/source-settlement.md) retrieves only an already durable original receipt under fresh owner permission and current receiver policy. It preserves original verification age and the independent-copy threshold. Missing receipt or expired observation permission remains pending; an immutable write intent is never renewed by settlement.

The [receiver renewal workflow](docs/en/receiver-renewal.md) admits a fresh same-scope grant in the existing registry after explicit quiescent maintenance. It preserves historical receipts and generations, fences previous readers and uses the current receiver policy and disk budget.

[Missing receipt recovery](docs/en/receipt-recovery.md) uses separate fresh owner permission and current receiver policy to reconstruct a receipt only from an already complete generation and unchanged original publication proof. It preserves the original verification age and signed audit; ordinary settlement remains a separate step. Truly unpublished operations and lost journals remain pending.

[Prepared application exports](docs/en/prepared-exports.md) bind a native producer's signed closed inventory to an immutable source operation, preserving original age and file history. Current/previous CLI and actual SIGKILL checks include independent restoration and reopening of two native SQLite exports. Read-only Btrfs snapshot capture uses the same signed inventory. Snapshot production and retention belong to the native producer.

WebDAV targets without conditional `PUT` can use the explicit MOVE profile. Workers save each staging attempt, verify the ciphertext and publish with `Overwrite: F`. The process fixture restarts workers on both sides of MOVE and restores two retained generations independently. [External upload](docs/en/external-upload.md).

`restore-external` restores a selected file version, directory or generation directly from an S3-compatible or WebDAV copy with read-only credentials and the owner kit. It verifies the selected checkpoint and publishes the output atomically. [Independent external recovery](docs/en/external-upload.md#independent-external-recovery).

Stopped workers can export an index-bound metadata checkpoint and explicitly recover simultaneous loss of the primary index, retention ledger and pending frozen plans while the current signed index copy and anchor survive. See [the prerequisites and replay procedure](docs/en/generation-replicas.md#combined-replica-metadata-loss). Complete-volume recovery and whole-product acceptance remain separate.

Native CI now prepares allowlisted downloadable development candidates with commit/run selection, checksums, binary-bound SBOM and [bilingual candidate notes](docs/en/release-notes.md). [Independent download verification](docs/en/distribution.md#downloadable-ci-candidates) remains separate from runtime acceptance and release.

The [downloaded installation evidence](docs/downloaded-install-evidence.json) records seven isolated amd64 install/upgrade/rollback/recovery checks using real CI candidate binaries; cold-host and production admission remain separate.

The [interactive keyboard receipt](docs/manual-keyboard-evidence.json) records a scoped English/Russian review and visible focus at 320px alongside the automated accessibility checks.

The [replacement dataset check](docs/dataset-rebuild-evidence.json) exercises a fresh owner-enrolled node through an actual selected CLI after loss of all old local runtime/replica data, with independent two-version recovery. Its bounded HDD result remains separate from native/physical/full-scale acceptance.

The [guest-kernel evidence](docs/vm-powerloss-evidence.json) records four actual virtual power cuts and five cold volume-ordering cases using independently selected recovery CLIs. All 14 phases passed in a bounded networkless guest; physical host power loss, real disk unlocking and full-scale acceptance remain separate.
