# Generation catalogs and protected local replicas

[Русский](../ru/generation-replicas.md)

The G2 candidate in `internal/generation` adds signed generation catalogs, keyless local receivers, durable reception progress and protected cleanup to the [file-kit format](file-kit-format.md). This is a library and executable test fixture, not a peer service. Full G1/G2/G3 acceptance and heavy scale/endurance tests remain deferred. The implementation does not start or migrate a working service.

## Authority and data flow

`Seal` uses `filekit.Store.WithSealedKits` to hold one shared source maintenance lock across descriptor validation and object copying. Backup, retirement and repack cannot change that view. The trusted source decrypts descriptors to enumerate their complete closure. It signs the resulting catalog with a separate generation-author key. There is no extra source-local copy: ciphertext goes directly to the receiving replica. This local locking boundary is not an application-consistent source snapshot or distributed lock.

`outpost-generation-1` binds domain, repository, writer epoch, sequence, parent checkpoint, snapshot time, policy version, file-kit format and each selected kit's root and complete physical object list. IDs are SHA-256; names and attributes remain inside encrypted file descriptors. Ordered kit/object lists and exact Go JSON serialization are canonical. Duplicate/unknown fields, alternative encodings, inconsistent lengths and unsafe IDs are rejected. Ed25519 signatures have distinct catalog and maintenance purpose prefixes.

The receiver stores only public author and maintenance verification keys. Neither data-decryption keys nor signing keys belong in its persistent state. Trust/domain/repository/epoch are provisioned separately and immutable for this candidate; a writer cannot grant itself a new epoch or deletion authority. Epoch transition, transport authority expiry/revocation and placement/route enforcement need the later configuration/transport layer. Direct library access assumes an authorized local process, not an exposed remote administration API.

## Reception and recovery

`Begin` persists a verified complete dependency manifest and highest accepted sequence before accepting objects. An unfinished reception protects every listed dependency until an explicit maintenance cancellation. `Put` checks membership, length and content hash, then fsyncs and atomically publishes the object. `Complete` reads and verifies every dependency before atomically publishing the state containing COMPLETE. The previous latest known complete generation remains usable when reception is interrupted.

Batched reception syncs the replica root before the first verification checkpoint, including after an interrupted creation that left the directory behind. Once an existing checkpoint has been validated, each update still writes atomically and syncs the checkpoint directory. Previously verified object stamps are checked again before publishing the generation.

Repeated delivery reuses present verified objects. Conflicting signed catalogs at the same current epoch/sequence fail; a new older checkpoint cannot roll the receiver back. A full signed checkpoint can advance directly from sequence 1 to 181 without intermediate catalogs. This checks sequence-gap behavior, not 180 days of operation or a 180-generation storage benchmark. Wall-clock timestamps do not select the newest generation.

`ExportKit` copies only the selected kit's ciphertext and root into separate inodes, while excluding maintenance. It publishes a new directory without replacing an existing destination. The existing recovery-only owner material and `outpost-kit restore` can then restore this kit without the replica state, source, peers or generation catalogs. Export/reception reject damaged objects; automatic repair and ongoing health tracking remain later work. Status describes durable accepted state, not a fresh scrub of every payload.

## Pins and deletion

Complete generations remain protected until explicitly retired. The latest complete generation cannot be retired, including when a newer reception is incomplete. Explicit `generation`, `kit` and `restore` pins survive restart and have no calendar expiry. A kit pin conservatively protects its entire containing generation in this candidate. `ReleasePin` only changes local protection; it grants no deletion permission.

`Maintain` requires a separately signed permit bound to the domain, repository, epoch, local state revision, operation ID and exact retirement list. It rejects a stale revision, a changed meaning for a recorded operation ID, active pins and retirement of the latest complete generation. It verifies all current complete closures and inventories stored objects before changing roots or deleting bytes. Remaining complete generations and unfinished receptions independently protect their referenced objects. Unknown inventory, malformed state or damaged complete dependencies abort cleanup.

Retirement is committed before whole unreferenced objects are removed. An interruption can leave extra bytes. An identical signed operation can resume cleanup after restart using the current references; it cannot repeat an unsafe root transition. Different nodes maintain independent state and pins, so an absent node does not hold every other node's garbage indefinitely. This local mechanism is not yet an external-target receipt or distributed retention protocol.

## Bounds and commands

The development format accepts at most 4096 kits and 32768 unique objects per catalog, 8 MiB per object/catalog, 128 KiB per file-kit root, 256 retained or receiving catalogs, 1024 explicit pins and 1024 maintenance receipts. All bounds apply together. Serialized local state is capped at 32 MiB; cleanup inventory at 131072 objects. Reaching a bound rejects admission instead of silently dropping protected history. These are parser/admission caps, not measured production capacity. Receipt compaction, automatic retention scheduling and full-scale history costs remain unaccepted.

Local state format `outpost-replica-state-2` keeps a compact sequence/size/completion index. Signed catalogs are immutable separate files, published before the index refers to them. Object writes no longer parse every historical catalog. A process-wide 64 MiB estimated cache checks file identity, size and modification/change times; it does not prove disk integrity. Opening a replica, completing a generation, exporting a kit, maintenance and explicit verification reread the relevant catalogs. Maintenance protects referenced catalogs and removes retired catalog files only after the root transition is durable.

Existing state requires explicit `outpost replica-migrate --bootstrap FILE --domain ID`. Stop that worker first; the command refuses a busy worker lease and uses its existing quota. Migration verifies complete payloads, preserves exact old state in `state.v1.json`, durably writes catalogs and atomically switches the index. Cancellation or a process crash before that switch retains the old state and permits retry. Wire catalogs, encrypted objects and independent file kits keep their formats. `outpost replica-rollback --bootstrap FILE --domain ID` restores the old state only before any new state mutation and after rechecking payloads. The migration backup is not a perpetual retention root or permission to discard subsequent generations, pins or maintenance receipts. Keep it on private admitted storage and account for its space.

On an authorized Linux test filesystem, with Go pinned by `go.mod`:

```sh
go test -count=1 -timeout=180s ./internal/generation
go test -count=1 -run '^TestSealedViewExcludesMaintenance$' ./internal/filekit
go vet ./...
```

Set `TMPDIR` and `OUTPOST_TEST_ROOT` to the admitted test volume. If the build uses executable scratch via `GOTMPDIR`, use `go test -exec "env -u GOTMPDIR"` so test data stays on that volume. The integrated consumer is `TestSealedReplicaSurvivesSourceRepackAndAbsence`: it calls `Seal`, `Receive`, `Pin`, `ExportKit` and `Maintain`, then invokes the independent file reader. It uses a 2 MiB random source and verifies actual old/new restored bytes, mode and hard-link identity after source repack/retirement and deletion of the source and other holder.

The [machine trace](../g2-trace.json) connects the scoped G2 requirements to checks. Five additional child-process tests confirm actual SIGKILL at object durability, pre-COMPLETE, completed-state durability, retirement durability and object deletion, followed by reopen/retry and verified complete closure. These are process-failure tests, not hardware power-loss certification. A bounded external DeepSeek review identified malformed maintenance-key validation; a negative regression now covers it. Revision-zero permits are valid only for the initial empty state, and replay protection is enforced against persisted state.

## Retained history admission

Ordinary `Begin` keeps its rollback guard. Explicit `BeginHistorical`, reserved for owner-authorized retained-history acquisition, can admit an older signed catalog without lowering the highest accepted sequence or latest complete generation. It rejects an already known conflicting sequence and locally retired catalog IDs. Catch-up validates independent catalogs without requiring every intervening catalog to remain available. Inventory exposes recorded complete publications in sequence order; it is not a fresh integrity check.

The separate `outpost-retention-ledger-1` sidecar preserves exact signed maintenance permits before retirement changes the replica index. A process crash may retain extra data, but must not lose the authority that prohibits reacquisition. Pending retirement authority is conservative: existing copies remain readable, while re-admission may remain blocked. The state2 reader contract and immutable file kits are unchanged. A missing or incomplete ledger with existing maintenance receipts blocks historical admission; it never means that nothing was retired. Explicit reconstruction requires every retained signed permit to match the committed receipt digest and cannot overwrite a present ledger. Maintenance performed by an older binary without corresponding ledger records is detectable by that coverage check.

A sixth real SIGKILL boundary now checks the interval between durable retirement authority and index mutation. Reopen/retry preserves the latest complete closure and refuses retired historical reacquisition. HTTPS history admission also requires an explicit local grant; ordinary peer access does not expand it. Full autonomous discovery, queue and operator workflow acceptance is tracked separately.

Remaining acceptance includes full-scale G1, large catalogs/history, multi-node scheduling and policy, epoch transitions, real network cuts and cloud semantics, volume loss during I/O, cold boot and production installation. The [roadmap](roadmap.md) and whole-product acceptance scenarios remain NOT_VERIFIED.

## Frozen maintenance replay

Detected object corruption advances local metadata to `outpost-replica-state-4`, preserving state3 maintenance history. The [integrity contract](integrity-repair.md) defines shared-generation fencing, admitted quarantine and separately authorized repair. Older writers reject state4; immutable catalogs, objects and independent recovery retain their formats.

The first explicit new maintenance operation upgrades local metadata to `outpost-replica-state-3`. State2 remains readable; wire catalogs, encryption and independent file-kit recovery do not change. Older state writers reject v3. This feature transition has no automatic downgrade: retain the current reader and recover from the unchanged catalogs/kits; binary rollback cannot discard maintenance history.

Before retiring a generation, maintenance writes a sorted immutable GC candidate set and binds its hash to the accepted permit in local state. Retried work uses this original set, never a new orphan scan. Newly created orphan objects are outside the old permit; candidates that gained complete/receiving references are preserved. Missing or altered plan data blocks replay. A legacy receipt without a frozen set requires a newly signed revision-bound permit, not reconstruction of an old deletion scope.

Pending cleanup also requires the signed retention ledger and coverage of every committed receipt. To retain a checkpoint, stop the worker and run `outpost replica-retention-export --bootstrap FILE --domain ID --output NEW_PRIVATE_FILE`. Keep the output and its reported SHA-256 on independent storage. If the ledger is lost and the replica index still exists, run `outpost replica-retention-restore --bootstrap FILE --domain ID --input PRIVATE_FILE --sha256 EXPECTED_SHA256` while the worker is stopped. The command checks the independent digest, each permit and the current receipt coverage. It restores the missing ledger under the existing quota. A present ledger, stale checkpoint with incomplete receipt coverage or missing replica index blocks recovery. The normal maintenance path rechecks the frozen candidates and current protected references before resuming deletion. A completed operation still returns its original result without deleting bytes.

## Recovering a missing replica index

On a stopped worker, enable the optional index copy with `outpost replica-index-mirror-enable --bootstrap FILE --domain ID`. It advances the local revision, so earlier uncommitted maintenance permits must be reviewed. Every later update writes the node-signed index copy, its separate exact digest anchor and then the primary index. The three files use the existing admitted volume and quota. Update every worker executable before enabling this option. Keep the enrolled node key available. Earlier binaries cannot read the new index field, and an independent data recovery still uses only the owner kit and immutable data.

If the primary index is missing or an update was interrupted, stop the worker and run `outpost replica-index-recover --bootstrap FILE --domain ID`. The command verifies the enrolled node, replica trust, original index bytes, protected catalog closures, ciphertext of complete healthy generations, the retention ledger and pending cleanup plans. An interrupted anchor update can continue only from its exact live predecessor. A stale signed copy, a divergent primary or unknown dependencies block recovery. The command keeps the original revision, pins, receiving state and maintenance receipts. If the verified primary is already present, it leaves the index unchanged. Retained peer or ingress journals also prevent a missing replica directory from being enrolled again as empty. The copy and anchor share the replica volume. Retain an independent backup for loss of the volume or all index files.

The final historical result records candidate, absent and protected object/catalog counts and original completion time. Absent counts include candidates already removed before a retry; they are not a claim of physical erasure. Completed replay has no new deletion effect, even if an old object later reappears. Current references, ciphertext checks and per-step caller admission protect interrupted work. Synthetic tests include cancellation/revocation after one deletion and actual SIGKILL at plan, authority, retirement, object deletion and final-result boundaries. Hardware power loss and final scale acceptance remain separate.
