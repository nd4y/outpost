# Trusted recovery executor

[Русский](../ru/trusted-recovery.md)

The local executor restores selected retained versions from a worker replica into a separately admitted output tree. It uses the existing independent file reader and encrypted metadata. An ordinary worker stays keyless; membership in the trusted node class does not give it a recovery key.

The owner prepares a private `outpost-trusted-recovery-1` profile containing `node`, an absolute `directory`, a separately enrolled `volume` binding, `limits` and `presets`. Each preset binds an opaque `id` to one `domain`, `repository`, writer `epoch` and private absolute `ownerFile`. The profile and owner files must have private permissions. Paths and keys are never accepted from command envelopes or included in reports. The enrolled volume scope must match the worker identity. Source replica and output tree must be disjoint in both directions.

```sh
outpost recovery-init --input /private/recovery-profile.json
outpost trusted-worker-run --bootstrap /private/worker.json   --input /private/recovery-profile.json
```

Initialization requires a new output directory. Profile contents are bound to its journal; changing them requires a defined migration, not silent reinitialization. The normal `worker-run` command never loads this profile. A separate command poller can use the normal worker bootstrap while the trusted runtime owns the execution lease.

A signed `restore` command selects a preset, generation and up to 256 exact version IDs. The authority must permit restore for this trusted node, tenant, domain, repository and writer epoch. The exact accepted configuration revision and envelope digest fence execution. A keyless runtime can durably queue the command, but makes no decryption attempt. Admitting restore promotes the local journal to `outpost-worker-4`; older journal formats cannot carry restore state. Scrub scheduling preserves this fence, and control rollback refuses it.

Metadata and names are authenticated before output admission. `limits` contains `bytes`, `entries`, `freeBytes` and `freeInodes`; it applies to the entire output tree, including retained attempts, published results and journals. The executor reserves conservative bytes and entries before writing, checks physical free space/inodes and the enrolled volume during work, and checks measured growth before publication. Multiple processes share the same admission lock. Limits and volume enrollment are immutable for this output tree. At most 64 presets, 1024 operation journals and three copying attempts per operation are admitted; exhaustion is explicit, without erasing older output.

Data and an opaque `receipt.json` are published together as `results/OPERATION_ID/{data,receipt.json}` by a no-overwrite rename. Final publication holds the accepted policy and durable operator-control locks: a saved pause or withdrawn configuration cannot race that rename. Pause cancels and joins active work; resume retains its operation identity and starts a new staging attempt if necessary. Unpublished stages are retained for investigation. A new operation never overwrites an existing bundle.

A restart after publication reconciles the prepared receipt digest, preserves its original verification time and releases only the matching source pin and reservation. Replay does not reload the data key or copy plaintext again. Terminal cleanup fences further copying and retains staged/output bytes. `cleanupPending` remains explicit if the enrolled destination or matching domain replica is unavailable; cleanup resumes under an active matching view. An expired command without a confirmed worker result is reported as failed with an unconfirmed effect where an attempt ran. A retained bundle must then be inspected using its original local receipt; expiration cannot certify absence of output.

Signed `outpost-management-report-3` and report view 3 carry restore observations. `DECRYPTED` applies only to the requested selected result, not the whole generation or current health of already restored files. Reports contain opaque IDs, counts and original times, without names or local paths. Command-status pages use version 2 for report view 3; older reports keep their existing versions. ACK replay is historical and never refreshes the result's age.

Short isolated checks cover actual restored bytes after source/cache loss, keyless admission, local key removal before replay, pause/publication ordering, policy withdrawal, foreign pin preservation, quota and inode exhaustion, volume/path replacement, tampering and process SIGKILL across admission, executor and worker-result boundaries. Installation, output retention/migration, key lifecycle, unavailable-domain cleanup, full-scale restore/repair and the remaining main-profile gates are still open. No live storage or service acceptance is implied.

The [owner recovery package](owner-recovery-package.md) keeps read-only decryption material, original checkpoint age and selected offline tools in private owner storage. Export, digest-anchored inspection and atomic extraction leave signing authority out of the package. Selected-file and complete-replica recovery have separate small process checks; key lifecycle and full-scale acceptance remain open.
