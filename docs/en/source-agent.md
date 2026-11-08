# Private source agent

[Русский](../ru/source-agent.md)

The Linux agent joins the [source lifecycle](source-jobs.md) to an enrolled [runtime volume](runtime-volume.md), private metadata cache and HTTPS ingress. The installed tree provider declares `best-effort` consistency. It verifies the enrolled filesystem/root inode, rejects links and overlap with runtime storage, and never deletes, unmounts or changes source files when releasing its view.

The private `outpost-source-agent-1` bootstrap contains `local` (bootstrap2 node, owner public key, volume, runtime directory and certificate/key/CA files), `profile` (opaque ID/origin, selection, bounds, consistency and copies), `tree` (the observation from `source-probe`), `dataKeyFile`, `writerKeyFile`, `authorityFile`, HTTPS `endpoint` and disk-budget `limits`. Profile `view` is empty; the agent assigns the operation ID. The writer file uses a `privateKey` JSON field. Control endpoints, listeners and cloud credentials are not source-agent inputs. Source rules and decryption keys never enter shared jobs.

Key/configuration files must be private regular files; ancestor and final symlinks are refused. The source and runtime parent must already exist. Initialization checks overlap before creating runtime state and refuses an existing destination. A new installation initializes a private sibling directory on the enrolled volume, syncs its signed idle state and publishes it under the final name with a no-overwrite rename. Missing sentinels, substituted directories, changed bootstrap/key bindings and clock rollback stop admission.

The executable accepts best-effort profiles requiring one or two copies. A two-copy bootstrap adds a private `observationFile` containing the [owner-signed observation grant](copy-observations.md). Its reader is this source, collector is the ingress, and targets are distinct approved replica nodes in `profile.copyTargets`. The ingress itself is excluded from that grant because its original receipt already counts once. Missing configuration, filesystem-snapshot or application-consistent profiles return `CAPABILITY_UNAVAILABLE` without lowering the policy.

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

`source-next` signs an operation from the durable generation head. Repeating it during a pending operation resumes that operation; after completion it prepares the next sequence and exact parent. `source-prepare --bootstrap FILE --input SIGNED_INTENT` accepts a supplied intent under the same fence. `source-run` executes/resumes the prepared operation and remains idempotent after completion; it does not schedule or create another generation.

Signed agent state fences the operation before provider preparation. Signed file results and encrypted accepted-pack progress survive restart. The source is never reopened after sealing. A lost final head update resumes the completed job and exports its verified checkpoint/lineage. The cache holds encrypted metadata/progress rather than a complete payload copy. Quotas and reconciliation preserve unaccepted files instead of deleting them.

Status exposes opaque identities, phases and copy observations without source names or keys. SIGINT/SIGTERM preserve durable progress. A joined volume monitor cancels outstanding HTTPS requests after identity loss; forcibly interrupting a filesystem call stuck inside the kernel is not promised. Checkpoint output uses a new private file without overwrite. Independent recovery also needs the file-kit recovery owner, public generation trust and complete ciphertext; a checkpoint or source cache alone is not a backup.

## Renewing source authority

`source-renew` accepts a separately owner-signed grant with a higher revision and current validity. Pause the foreground scheduler and wait for the source to be `IDLE` or `COMPLETE` first. The command holds the same execution lease as capture, preserves the generation head and schedule, and refuses a pending `PREPARING` or `ACTIVE` operation. It does not extend an immutable intent or discard work whose grant has expired.

```sh
outpost source-renew --bootstrap /private/source.json \
  --input /private/renewed-authority.json
outpost source-status --bootstrap /private/source.json
```

Keep the original bootstrap, `authorityFile` and `observationFile` unchanged as installation anchors. Current signed grants live in the agent journal after renewal; replacing the original files changes the installation binding and is rejected. A two-copy source can supply `--trust /private/renewed-observation.json` with a nondecreasing observation epoch. Its collector, reader, targets and freshness bound remain identical. Source, ingress, domain, repository, keys, limits and selection also remain unchanged; a renewal cannot expand their scope. Admit the corresponding receiver capability separately before sending the next generation.

The first renewal explicitly migrates signed runtime state from `outpost-source-agent-1` to `outpost-source-agent-2`. The bootstrap format stays at version 1. An exact signed version-1 checkpoint is retained under its digest before the atomic journal replacement. Later renewals preserve that checkpoint. Completed intents retain their original authority so old generations and receipts remain verifiable. Restart/reopen the source process after renewal; an already-open process returns `AUTHORITY_CHANGED` rather than continuing with stale authority. Repeating identical current input is idempotent; lower revisions or altered content at the same revision are refused.

The previous executable refuses the migrated journal. Downgrading the executable or replacing the active journal with its historical checkpoint is not a supported rollback. Preserve the entire runtime and use a compatible executable; independent ciphertext recovery remains available with its recovery material. Short checks cover old/new independent restoration, actual process kills on both sides of publication, and refusal by the previous CLI without changing the migrated head. Expired pending-operation resolution and recovery after loss of the whole source journal remain open work.

## Interrupted initial installation

The final runtime path appears only after its lease, capacity ledger and signed initial agent state are durable. All signed bindings name the final bootstrap path; the temporary physical path is never a different source profile. A crash before publication leaves a private `.outpost-source-install-...` candidate and no final runtime. Run the same `source-init` again to create a fresh candidate. The earlier candidate is retained, not reused or deleted. After an uncertain reply, check `source-status` first: publication may have succeeded. A present valid runtime is reopened normally; repeated initialization refuses to overwrite it.

Admission uses an interruptible cross-process lock on the private parent. At most four unpublished candidates for the same final path are admitted, and parent inspection is bounded to 4096 entries. Reaching either bound returns a capacity error without erasing anything. A successful competing initializer wins the final name atomically; other candidates remain. These small initialization artifacts contain metadata, not captured payload, and are retained on the enrolled volume. Inspection and separately authorized cleanup are required after exhaustion; there is no automatic directory cleanup command.

A partially initialized final directory created by an earlier executable is preserved and still requires inspection. This mechanism does not reset a damaged active journal or recover its lost history. Short tests kill actual processes at directory creation, store creation, durable initial state and final publication. They also check concurrent initializers, cancellation while admission is locked, the candidate limit, foreign-directory preservation, volume loss, and byte-exact recovery after capture by the newly installed runtime.

The [owner recovery package](owner-recovery-package.md) keeps read-only decryption material, original checkpoint age and selected offline tools in private owner storage. Export, digest-anchored inspection and atomic extraction leave signing authority out of the package. Selected-file and complete-replica recovery have separate small process checks; key lifecycle and full-scale acceptance remain open.
