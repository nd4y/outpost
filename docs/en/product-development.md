# Product completion

[Русский](../ru/product-development.md)

Outpost is in development. The [completion map](../product-status.json) covers every requirement and acceptance scenario in the [specification](specification.md). It records existing code and executable checks separately from work still required. A passing component test does not accept an entire scenario or authorize a production installation.

## Configuration and placement

Source path rules and labels stay on the trusted source. Selection defaults to deny, matching exclusions override allow priorities, and incompatible equal-priority rules are rejected. Hardlink aliases must all belong to the same permitted domain before capture. The source scanner must supply the complete alias set; the selector alone is not a filesystem scanner.

Each domain has explicit holders, transit nodes, data-flow edges and per-node external-target grants. A push edge is dialed by its sender; a pull edge is dialed by its recipient. This permits an outbound-only node to receive through an authorized intermediate. Node category or possession of a copy grants no additional route or cloud upload permission. Placement preview lists changed recipients and routes; data-volume estimation is still part of source planning.

The owner signs canonical, bounded, per-node configuration. The owner key is separate from generation writing, maintenance and upload planning. Configuration contains opaque job identifiers, explicit executors, public trust, routes, target profiles, expiry and resource limits. Source paths, decryption keys and storage credentials are not shared jobs. HTTPS distribution uses mutual TLS, certificate public-key identities, explicit recipient ACLs and no redirects or proxy fallback. Relays preserve the original signed bytes.

The private cache persists the highest revision and each domain's authority epoch, including removed domains. A lower revision, different document at the same revision or changed authority at the same epoch is rejected. Expiry, a not-yet-active replacement and clock rollback disable new work while preserving replicas, pins and recovery material. The cache cannot protect against an administrator rolling back its entire disk; recovery must use an independently retained owner checkpoint.

## Worker integration

The worker joins cached configuration, peer journals and per-operation upload queues. Incoming transfers must match the signed operation, executor, domain, generation and direction. A new configuration cancels and joins old attempts before enabling its jobs. Withdrawn jobs retain protected data. Failed or expired work never becomes a complete target merely because a request was sent.

The `outpost` CLI provides worker initialization, execution, status and explicit retry, configuration signing/application and independent kit recovery. Node certificates and target credentials come from private local bootstrap files. The running worker uses bounded attempts, persists retries and isolates conflicting operation identifiers. Receiver configuration lag remains retryable until the required signed revision arrives; it never broadens access.

Capacity admission reserves space before replica, journal, configuration and queue writes. A shared persistent ledger separates data, spool and telemetry allowances, preserves free-space and inode reserves, and coordinates independent processes. Reconciliation waits for active writers and measures retained files after a crash without deleting them. An over-budget new generation is blocked while the previous complete generation remains recoverable. Accounting is conservative; supported local filesystems are ext4, Btrfs and XFS. These checks do not measure production throughput or certify arbitrary filesystems.

Bounded integration checks cover signed HTTPS relay, offline cache restart, policy cancellation, sender-to-intermediate-to-outbound-only-recipient recovery, both external protocols, process-kill quota reconciliation and retained-history recovery under capacity pressure. Source capture, automatic discovery and scheduling of new generations, maintenance, operator API/UI and packaging remain open deliverables. Local schema and configuration limits are implementation bounds, not measured production capacity. Full-scale tests and operational admission remain separate.

## Completion boundary

Finish the applicable main profile through M4 with an installable artifact, standalone recovery, exact-source checks and measured limits. The delayed archive profile remains a separate M5 admission. Production deployment, endpoint credentials, real notifications and destructive infrastructure tests require their own authorized environment. Keep the [roadmap](roadmap.md), English/Russian documentation, requirement links and actual acceptance evidence consistent throughout development.
