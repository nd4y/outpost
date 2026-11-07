# Product completion

[Русский](../ru/product-development.md)

Outpost is in development. The [completion map](../product-status.json) covers every requirement and acceptance scenario in the [specification](specification.md). It records existing code and executable checks separately from work still required. A passing component test does not accept an entire scenario or authorize a production installation.

## Configuration and placement

Source path rules and labels stay on the trusted source. Selection defaults to deny, matching exclusions override allow priorities, and incompatible equal-priority rules are rejected. Hardlink aliases must all belong to the same permitted domain before capture. The source scanner must supply the complete alias set; the selector alone is not a filesystem scanner.

Each domain has explicit holders, transit nodes, data-flow edges and per-node external-target grants. A push edge is dialed by its sender; a pull edge is dialed by its recipient. This permits an outbound-only node to receive through an authorized intermediate. Node category or possession of a copy grants no additional route or cloud upload permission. Placement preview lists changed recipients and routes; data-volume estimation is still part of source planning.

The owner signs canonical, bounded, per-node configuration. The owner key is separate from generation writing, maintenance and upload planning. Configuration contains opaque job identifiers, explicit executors, public trust, routes, target profiles, expiry and resource limits. Source paths, decryption keys and storage credentials are not shared jobs. HTTPS distribution uses mutual TLS, certificate public-key identities, explicit recipient ACLs and no redirects or proxy fallback. Relays preserve the original signed bytes.

The private cache persists the highest revision and each domain's authority epoch, including removed domains. A lower revision, different document at the same revision or changed authority at the same epoch is rejected. Expiry, a not-yet-active replacement and clock rollback disable new work while preserving replicas, pins and recovery material. The cache cannot protect against an administrator rolling back its entire disk; recovery must use an independently retained owner checkpoint.

## Worker integration

[Runtime volume admission](runtime-volume.md) binds bootstrap2 to an enrolled node scope, epoch and filesystem sentinel. Runtime writes use held directory descriptors, and identity loss cancels active work. Short checks cover initialization/reopen, marker loss, path replacement and absence of fallback writes. Physical cold boot/unlock, blocked device I/O and identity migration remain separate admission work.

The worker joins cached configuration, peer journals and per-operation upload queues. Incoming transfers must match the signed operation, executor, domain, generation and direction. A new configuration cancels and joins old attempts before enabling its jobs. Withdrawn jobs retain protected data. Failed or expired work never becomes a complete target merely because a request was sent.

The `outpost` CLI provides worker initialization, execution, status and explicit retry, configuration signing/application and independent kit recovery. Node certificates and target credentials come from private local bootstrap files. The running worker uses bounded attempts, persists retries and isolates conflicting operation identifiers. Receiver configuration lag remains retryable until the required signed revision arrives; it never broadens access.

Capacity admission reserves space before replica, journal, configuration and queue writes. A shared persistent ledger separates data, spool and telemetry allowances, preserves free-space and inode reserves, and coordinates independent processes. Reconciliation waits for active writers and measures retained files after a crash without deleting them. An over-budget new generation is blocked while the previous complete generation remains recoverable. Accounting is conservative; supported local filesystems are ext4, Btrfs and XFS. These checks do not measure production throughput or certify arbitrary filesystems.

Bounded integration checks cover signed HTTPS relay, offline cache restart, policy cancellation, sender-to-intermediate-to-outbound-only-recipient recovery, both external protocols, process-kill quota reconciliation and retained-history recovery under capacity pressure. Source capture, automatic discovery and scheduling of new generations, maintenance, operator API/UI and packaging remain open deliverables. Local schema and configuration limits are implementation bounds, not measured production capacity. Full-scale tests and operational admission remain separate.

## Source and independent dataset recovery

The [source ingress contract](source-ingress.md) defines signed dynamic admission, bounded verification, durable receipts and acknowledgement cleanup, including the current-policy binding required for worker integration.

The trusted source scanner inventories a bounded tree without following symbolic links or crossing mount boundaries, including bind mounts. It groups every discovered hardlink alias before selecting a domain. A denied alias excludes the inode; conflicting permitted domains, an undiscovered external alias, unsupported selected types or exceeded limits stop capture. The planner checks identities before and after each rooted read and rechecks the observed tree before publication. A live-tree scan remains best effort: metadata comparisons cannot detect every modification within a filesystem timestamp tick and do not establish application consistency. Snapshot/application-provider orchestration and actual source enrollment remain open.

`OpenStreamingStore` keeps version envelopes in a local metadata cache with caller-supplied capacity admission while sending ciphertext to an `ObjectBackend`. Previous descriptors permit block reuse; unchanged payload is checked for presence and length without being downloaded through the source. The backend must acknowledge verified durable acceptance. `BuildCatalog` signs the descriptor closure without rereading payload through the source; it is not a durable replica receipt and cannot release a source snapshot. Maintenance through a streaming source cache is refused because the receiving replica owns those objects.

The worker admits dynamic capture intents only under an exact owner-signed ingress capability, current placement and source certificate identity. Its persistent sequence fence and one reusable domain slot survive restart without accepting an old or competing operation. New ciphertext is fsynced and read back through mutual TLS. Catalog verification runs in bounded batches; a complete receipt retains its original observation time after lost replies. Source acknowledgement releases only its own pins and accepted staged copies, returns measured blocks to the shared quota and leaves replica history intact. Policy withdrawal cancels access while retained data remains recoverable. Eight real process-kill boundaries and an integrated worker capture/restart/revocation/recovery scenario have short synthetic checks.

The [source job lifecycle](source-jobs.md) specifies checkpoint-before-release-before-acknowledgement ordering. The source must still orchestrate durable jobs, consistent providers, copy thresholds, recovery checkpoints and provider release before sending acknowledgement. Grant renewal/rebinding, safe orphan reconciliation, verification-cache maintenance and final-scale admission remain open. Unknown staging files block slot reuse. A compromised receiver can misreport persistence; the receipt is an observed verification level, not a permanent durability guarantee.

`restore-replica` recovers a chosen checkpoint directly from immutable `catalogs` and `objects`, with public generation trust and the private recovery owner file. It does not need the replica state index, source, queue or control service. An optional private selection file chooses exact versions or a relative directory. Ambiguous versions of the same file are refused. Directory selection restores only the selected names, including hardlink aliases inside that scope. The supplied checkpoint identifies the intended generation; matching it does not prove that no newer checkpoint exists elsewhere.

The reader validates names and ancestor types before creating output, preserves hardlinks and symbolic links, applies directory attributes after children and atomically publishes a new destination without overwrite. Missing or corrupt payload never produces a successful partial restore. A selection without its ancestor directory kits creates implicit directories with mode 0700 and reports their count. Current recovery bounds are 4096 kits, 64 MiB of aggregate authenticated metadata and 32768 names/directories. These are explicit admission limits, not production scale measurements. Recover from a retained materialized view; concurrent live GC can invalidate a read.

```sh
outpost restore-replica --key /private/recovery-owner.json \
  --trust /private/generation-trust.json --store /recovery/replica \
  --generation EXPECTED_CHECKPOINT --output /recovery/restored
```

## Completion boundary

Finish the applicable main profile through M4 with an installable artifact, standalone recovery, exact-source checks and measured limits. The delayed archive profile remains a separate M5 admission. Production deployment, endpoint credentials, real notifications and destructive infrastructure tests require their own authorized environment. Keep the [roadmap](roadmap.md), English/Russian documentation, requirement links and actual acceptance evidence consistent throughout development.
