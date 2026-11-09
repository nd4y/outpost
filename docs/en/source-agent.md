# Private source agent

[Русский](../ru/source-agent.md)

The Linux agent joins the [source lifecycle](source-jobs.md) to an enrolled [runtime volume](runtime-volume.md), private metadata cache and HTTPS ingress. The installed tree provider declares `best-effort` consistency. It verifies the enrolled filesystem/root inode, rejects links and overlap with runtime storage, and never deletes, unmounts or changes source files when releasing its view.

The private `outpost-source-agent-1` bootstrap contains `local` (bootstrap2 node, owner public key, volume, runtime directory and certificate/key/CA files), `profile` (opaque ID/origin, selection, bounds, consistency and copies), `tree` (the observation from `source-probe`), `dataKeyFile`, `writerKeyFile`, `authorityFile`, HTTPS `endpoint` and disk-budget `limits`. Profile `view` is empty; the agent assigns the operation ID. The writer file uses a `privateKey` JSON field. Control endpoints, listeners and cloud credentials are not source-agent inputs. Source rules and decryption keys never enter shared jobs.

Key/configuration files must be private regular files; ancestor and final symlinks are refused. The source and runtime parent must already exist. Initialization checks overlap before creating runtime state and refuses an existing destination. A new installation initializes a private sibling directory on the enrolled volume, syncs its signed idle state and publishes it under the final name with a no-overwrite rename. Missing sentinels, substituted directories, changed bootstrap/key bindings and clock rollback stop admission.

The executable accepts best-effort profiles and explicitly enrolled [prepared application exports and read-only Btrfs snapshots](prepared-exports.md), requiring one or two copies. A two-copy bootstrap using an observation collector adds a private `observationFile` containing the [owner-signed observation grant](copy-observations.md). Its reader is this source, collector is the ingress, and targets are distinct approved replica nodes in `profile.copyTargets`. The ingress itself is excluded from that grant because its original receipt already counts once. Missing configuration and unsupported consistency providers return `CAPABILITY_UNAVAILABLE` without lowering the policy. Prepared filesystem and application consistency require the producer-attested bootstrap. An ordinary tree profile cannot claim either.

The source authenticates relayed node signatures, generation and original verification age. Its signed checkpoint retains the exact second-copy observation. No observation leaves the job in `WAITING_COPIES`; retry `source-run` after the required replica becomes available. A short integration check restarts the waiting source, admits an outbound-only replica, completes the threshold and restores that replica independently after source loss.

```sh
outpost source-probe --store /source/tree --node ORIGIN_ID --output /private/tree.json
outpost source-authority-sign --key /private/owner-key.json \
  --input /private/authority-input.json --output /private/authority.json
outpost source-init --bootstrap /private/source.json
outpost source-next --bootstrap /private/source.json
outpost source-run --bootstrap /private/source.json
outpost source-status --bootstrap /private/source.json
outpost source-checkpoint --bootstrap /private/source.json --output /private/checkpoint.json
```

`source-next` signs an operation from the durable generation head and prepares its local job. Repeating it reuses the exact pending intent. `source-prepare --bootstrap FILE --input SIGNED_INTENT` accepts a supplied intent under the same fence. A successful local preparation leaves the source in `PREPARING` and sends no admission request. `source-run` persists `ACTIVE` before requesting admission. It reuses the prepared operation and remains idempotent after completion.

Signed agent state fences the operation before provider preparation. Signed file results and encrypted accepted-pack progress survive restart. The source is never reopened after sealing. A lost final head update resumes the completed job and exports its verified checkpoint/lineage. The cache holds encrypted metadata/progress rather than a complete payload copy. Quotas and reconciliation preserve unaccepted files instead of deleting them.

Status exposes opaque identities, phases and copy observations without source names or keys. SIGINT/SIGTERM preserve durable progress. A joined volume monitor cancels outstanding HTTPS requests after identity loss; forcibly interrupting a filesystem call stuck inside the kernel is not promised. Checkpoint output uses a new private file without overwrite. Independent recovery also needs the file-kit recovery owner, public generation trust and complete ciphertext; a checkpoint or source cache alone is not a backup.

## Parallel capture to two required holders

On a new two-copy installation, add `companionIngress` to the private bootstrap with an HTTPS `endpoint` and an `authorityFile`. Keep the primary `endpoint` and `authorityFile`. Sign both receiver grants with the owner key. They bind different ingress identities and use the same source, profile, tenant, repository, writer epoch, revision, validity and object limits. Include the companion in `profile.copyTargets` and in the primary collector's signed observation grant.

Apply `outpost-control-2` to both receivers with the other receiver's ID in `captureStagingPeers` on the domain. Admit each receiver's own ingress grant and the source-to-receiver push edges. Both receivers need a signed HTTPS endpoint and explicit pull edges in both directions between the two holders. The receiving worker selects the endpoint from that signed policy and verifies the origin's signed intent and receiver grant. Keep optional holders on ordinary replication routes for complete generations.

The source keeps at most two payload packs in flight. With the default full-copy policy and the two-holder coverage policy, it starts with equal allocation of initial ciphertext bytes, then uses smoothed throughput from successful durable PUTs of at least 256 KiB. The target ratio for initial bytes is capped at 4:1. The source starts measuring again after a restart. Small metadata, skipped uploads and peer pulls do not influence the measured rate. A receiver reads an accepted object directly from its peer over mTLS. The object is durable before the destination confirms it. The source records pack progress after both writes and seals the generation only after all required packs and metadata are available. An accepted exact ciphertext object can be reused on retry. The two holders verify the complete catalog independently in bounded steps. After a transient publication timeout the source replays the same catalog with a limited number of attempts. By default, snapshot release waits for the verified two-copy checkpoint.

The bootstrap anchors and signed companion receipt are private installation state. Preserve them and both receiver histories across restart. With a fixed pair, both configured holders remain required throughout the operation.

### Release on durable coverage from both holders

Set `profile.releasePolicy` to `two-holder-coverage` in a new paired installation with two selected holders. Each holder persists the signed catalog and confirms its complete dependency inventory over authenticated HTTPS. The source checks both holder identities, exact signed intents and the dependency digest, then signs and syncs a separate coverage checkpoint before releasing the view. If a dependency or required receipt is missing, the view stays open.

During early release, `source-status` shows the pending job's `stagedRelease` separately from its publication phase. The source still needs the two complete, verified copies for `source-checkpoint`, receiver cleanup and advancement of the generation head. Workers can continue bounded full verification and publication after a restart with the source offline, while the signed capture intent and worker policy are valid. Staged data and predecessor pins remain protected until safe acknowledgement. Coverage relies on the holders' durable staging and the pinned, previously accepted predecessor. Full publication reads and verifies the ciphertext.

The `two-holder-coverage` policy requires two holders for every dependency.

Set `profile.releasePolicy` to `paired-split-coverage` to accept one staged copy per dependency before release. New object ownership is stable across retries and derived from its opaque ID and the two holder identities. Both holders retain the final catalog. The source validates the union by recomputing the assigned dependency list for each holder. A required dependency cannot be covered by an unrelated holder or intent.

After seal, each worker pulls missing dependencies only from its configured peer and verifies the entire generation before publication. Protect both holders until assembly completes. Failure of a holder can lose a newly captured object during the interval with only one staged copy. The [publication recovery workflow](source-settlement.md#finish-an-expired-staged-publication) covers accepted staging after expiry. Partition ownership stays deterministic for coverage verification. Asymmetric throughput acceptance remains open.

Keep the source and workers on a version that understands the pending coverage journal until both complete receipts have been acknowledged. Pausing preserves the staged data and generation pins.

## Standby before admission

A single-copy installation can set `standby` to `true` and supply the standby endpoint and separate owner-signed grant in `companionIngress`. List both receiver IDs in `profile.copyTargets` and configure each holder with the same scope and its own push admission. The standby must have the exact previous complete generation before it accepts an incremental capture.

For a fresh operation, `source-next` probes the primary with an authenticated, read-only readiness request. It checks the standby when the primary is unavailable or has a conflicting predecessor or slot. The source records the selected receiver in its signed intent before any write request. `source-status` exposes that receiver. Before entering `ACTIVE`, `source-run` checks the selected receiver again. A readiness failure can select the other authorized receiver while preserving the local view and predecessor. Renewal of a standby installation uses both grants.

With `standby` alone, a failed admission or transfer after `ACTIVE` stays with the chosen receiver.

## Automatic replacement after ACTIVE

Set `activeFailover` to `true` in a new standby installation. For two copies, use `companionIngress` for the second active holder and add `reserveIngress` with its own HTTPS `endpoint` and owner-signed `authorityFile`. List all three IDs in `profile.copyTargets`. The reserve installation uses authenticated receipts from the selected receivers and omits `observationFile`. Give all three holders matching grant scope, revision and validity, independent push admissions and signed pull routes between each potential pair. Keep the reserve caught up through ordinary replication so its readiness check can verify the exact predecessor.

During capture, an authenticated readiness probe must confirm that the eligible replacement and any surviving holder can accept the operation. If the selected holder still answers readiness, retry the original admission after a lost reply. One replacement per operation is recorded in the signed source journal before sending to the replacement. It keeps the same operation, source plan and predecessor. The new pair imports available staged payload and encrypted descriptor parts from the survivor. It reads the retained view for missing data and checks every catalog dependency against the selected holders. The source releases the view only after satisfying the original full-copy or coverage policy.

Between durable catalog and full-copy checkpoint, a two-copy installation can still use its one replacement if the surviving receiver can supply every dependency. The source durably records the catalog digest with the changed route. The new pair transfers only missing ciphertext and publishes the exact signed catalog, including when the survivor already published it. This path leaves the source view unopened and waits for both complete receipts. If a split capture loses a unique dependency, or the sole holder of a single-copy capture is unavailable, publication waits for recoverable ciphertext. The owner-grant workflow still applies when an intent expires.

`source-status` shows `receivers`, the previous route in `supersededReceivers` and `PREPARE_RECEIVER_ROUTE` when initialization must resume. After a durable full-copy checkpoint, the source queues a signed cleanup authorization for the replaced holder. Ordinary replication must deliver the exact generation to that holder. It checks the complete catalog and ciphertext locally in bounded batches before committing the cleanup fence and releasing its own staging and pins. The generation and other slots remain protected by their own retention policy. `pendingReclaims` lists outstanding holders. The enabled schedule and later source commands retry cleanup independently of the generation head. Cleanup of historical staging requires a current, compatible receiver authorization and a matching historical intent.

## Renewing source authority

`source-renew` accepts a separately owner-signed grant with a higher revision and current validity. Pause the foreground scheduler first. Renewal accepts `IDLE`, `COMPLETE` and an owner-authorized `ABANDONED` operation. The command holds the same execution lease as capture, preserves the generation head and schedule, and refuses a pending `PREPARING` or `ACTIVE` operation. It does not extend an immutable intent or discard work whose grant has expired.

```sh
outpost source-renew --bootstrap /private/source.json \
  --input /private/renewed-authority.json
outpost source-status --bootstrap /private/source.json
```

Keep the original bootstrap, `authorityFile` and `observationFile` unchanged as installation anchors. Current signed grants live in the agent journal after renewal; replacing the original files changes the installation binding and is rejected. A two-copy source can supply `--trust /private/renewed-observation.json` with a nondecreasing observation epoch. Its collector, reader, targets and freshness bound remain identical. Source, ingress, domain, repository, keys, limits and selection also remain unchanged; a renewal cannot expand their scope. Admit the corresponding receiver capability separately before sending the next generation.

For a paired installation, pass `--companion /private/renewed-companion-authority.json` as well. Both grants must have the same revision and validity window. The source commits them in one signed state update and keeps the original grants for any retained operation. Use the [receiver renewal workflow](receiver-renewal.md) separately on both existing registries before the next capture. Keep the original authority files as bootstrap anchors. When a reserve is configured, renew all three registries and pass `--reserve /private/renewed-reserve-authority.json` in the same source command.

The first renewal explicitly migrates signed runtime state from `outpost-source-agent-1` to `outpost-source-agent-2`. The installation bootstrap format remains unchanged, including the distinct prepared-export bootstrap when selected. An exact signed version-1 checkpoint is retained under its digest before the atomic journal replacement. Later renewals preserve that checkpoint. Completed intents retain their original authority so old generations and receipts remain verifiable. Restart/reopen the source process after renewal; an already-open process returns `AUTHORITY_CHANGED` rather than continuing with stale authority. Repeating identical current input is idempotent; lower revisions or altered content at the same revision are refused.

The previous executable refuses the migrated journal. Downgrading the executable or replacing the active journal with its historical checkpoint is not a supported rollback. Preserve the entire runtime and use a compatible executable; independent ciphertext recovery remains available with its recovery material. Short checks cover old/new independent restoration, actual process kills on both sides of publication, and refusal by the previous CLI without changing the migrated head. Expired unpublished-operation resolution and recovery after loss of the whole source journal remain open work.

## Interrupted initial installation

The final runtime path appears only after its lease, capacity ledger and signed initial agent state are durable. All signed bindings name the final bootstrap path; the temporary physical path is never a different source profile. A crash before publication leaves a private `.outpost-source-install-...` candidate and no final runtime. Run the same `source-init` again to create a fresh candidate. The earlier candidate is retained, not reused or deleted. After an uncertain reply, check `source-status` first: publication may have succeeded. A present valid runtime is reopened normally; repeated initialization refuses to overwrite it.

Admission uses an interruptible cross-process lock on the private parent. At most four unpublished candidates for the same final path are admitted, and parent inspection is bounded to 4096 entries. Reaching either bound returns a capacity error without erasing anything. A successful competing initializer wins the final name atomically; other candidates remain. These small initialization artifacts contain metadata, not captured payload, and are retained on the enrolled volume. Inspection and separately authorized cleanup are required after exhaustion; there is no automatic directory cleanup command.

A partially initialized final directory created by an earlier executable is preserved and still requires inspection. This mechanism does not reset a damaged active journal or recover its lost history. Short tests kill actual processes at directory creation, store creation, durable initial state and final publication. They also check concurrent initializers, cancellation while admission is locked, the candidate limit, foreign-directory preservation, volume loss, and byte-exact recovery after capture by the newly installed runtime.

The [owner recovery package](owner-recovery-package.md) keeps read-only decryption material, original checkpoint age and selected offline tools in private owner storage. Export, digest-anchored inspection and atomic extraction leave signing authority out of the package. Selected-file and complete-replica recovery have separate small process checks; key lifecycle and full-scale acceptance remain open.

The [expired-operation settlement workflow](source-settlement.md) retrieves only an already durable original receipt under fresh owner permission and current receiver policy. It preserves original verification age and the independent-copy threshold. Missing receipt or expired observation permission remains pending; an immutable write intent is never renewed by settlement.

An expired intent still in `PREPARING` can use [owner-authorized retirement](source-settlement.md#retire-an-expired-unstarted-intent). A later capture starts under renewed authority from the previous completed checkpoint.

For a pending intent, `source-status` reports its signed expiry as `result.pending.intentExpiresUnix` and an action in `result.pending.action`. `RESUME` identifies an intent still within its validity window. `RETIRE_UNSTARTED` identifies expired `PREPARING` work that requires the owner's retirement permit. `RECONCILE_RECEIVER` identifies expired `ACTIVE` work. Use [authenticated receiver reconciliation](source-settlement.md#reconcile-an-expired-active-operation) to distinguish the durable fence, catalog and receipt before choosing a recovery action. A missing receipt alone gives no assurance about publication. The action describes local state and carries no execution authority.

The [receiver renewal workflow](receiver-renewal.md) admits a fresh same-scope grant in the existing registry after explicit quiescent maintenance. It preserves historical receipts and generations, fences previous readers and uses the current receiver policy and disk budget.

[Missing receipt recovery](receipt-recovery.md) uses separate fresh owner permission and current receiver policy to reconstruct a receipt only from an already complete generation and unchanged original publication proof. It preserves the original verification age and signed audit; ordinary settlement remains a separate step. Truly unpublished operations and lost journals remain pending.
