# Generation catalogs and protected local replicas

[Русский](../ru/generation-replicas.md)

The G2 candidate in `internal/generation` adds signed generation catalogs, keyless local receivers, durable reception progress and protected cleanup to the [file-kit format](file-kit-format.md). This is a library and executable test fixture, not a peer service. Full G1/G2/G3 acceptance and heavy scale/endurance tests remain deferred. The implementation does not start or migrate a working service.

## Authority and data flow

`Seal` uses `filekit.Store.WithSealedKits` to hold one shared source maintenance lock across descriptor validation and object copying. Backup, retirement and repack cannot change that view. The trusted source decrypts descriptors to enumerate their complete closure. It signs the resulting catalog with a separate generation-author key. There is no extra source-local copy: ciphertext goes directly to the receiving replica. This local locking boundary is not an application-consistent source snapshot or distributed lock.

`outpost-generation-1` binds domain, repository, writer epoch, sequence, parent checkpoint, snapshot time, policy version, file-kit format and each selected kit's root and complete physical object list. IDs are SHA-256; names and attributes remain inside encrypted file descriptors. Ordered kit/object lists and exact Go JSON serialization are canonical. Duplicate/unknown fields, alternative encodings, inconsistent lengths and unsafe IDs are rejected. Ed25519 signatures have distinct catalog and maintenance purpose prefixes.

The receiver stores only public author and maintenance verification keys. Neither data-decryption keys nor signing keys belong in its persistent state. Trust/domain/repository/epoch are provisioned separately and immutable for this candidate; a writer cannot grant itself a new epoch or deletion authority. Epoch transition, transport authority expiry/revocation and placement/route enforcement need the later configuration/transport layer. Direct library access assumes an authorized local process, not an exposed remote administration API.

## Reception and recovery

`Begin` persists a verified complete dependency manifest and highest accepted sequence before accepting objects. An unfinished reception protects every listed dependency until an explicit maintenance cancellation. `Put` checks membership, length and content hash, then fsyncs and atomically publishes the object. `Complete` reads and verifies every dependency before atomically publishing the state containing COMPLETE. The previous latest known complete generation remains usable when reception is interrupted.

Repeated delivery reuses present verified objects. Conflicting signed catalogs at the same current epoch/sequence fail; a new older checkpoint cannot roll the receiver back. A full signed checkpoint can advance directly from sequence 1 to 181 without intermediate catalogs. This checks sequence-gap behavior, not 180 days of operation or a 180-generation storage benchmark. Wall-clock timestamps do not select the newest generation.

`ExportKit` copies only the selected kit's ciphertext and root into separate inodes, while excluding maintenance. It publishes a new directory without replacing an existing destination. The existing recovery-only owner material and `outpost-kit restore` can then restore this kit without the replica state, source, peers or generation catalogs. Export/reception reject damaged objects; automatic repair and ongoing health tracking remain later work. Status describes durable accepted state, not a fresh scrub of every payload.

## Pins and deletion

Complete generations remain protected until explicitly retired. The latest complete generation cannot be retired, including when a newer reception is incomplete. Explicit `generation`, `kit` and `restore` pins survive restart and have no calendar expiry. A kit pin conservatively protects its entire containing generation in this candidate. `ReleasePin` only changes local protection; it grants no deletion permission.

`Maintain` requires a separately signed permit bound to the domain, repository, epoch, local state revision, operation ID and exact retirement list. It rejects a stale revision, a changed meaning for a recorded operation ID, active pins and retirement of the latest complete generation. It verifies all current complete closures and inventories stored objects before changing roots or deleting bytes. Remaining complete generations and unfinished receptions independently protect their referenced objects. Unknown inventory, malformed state or damaged complete dependencies abort cleanup.

Retirement is committed before whole unreferenced objects are removed. An interruption can leave extra bytes. An identical signed operation can resume cleanup after restart using the current references; it cannot repeat an unsafe root transition. Different nodes maintain independent state and pins, so an absent node does not hold every other node's garbage indefinitely. This local mechanism is not yet an external-target receipt or distributed retention protocol.

## Bounds and commands

The development format accepts at most 64 kits and 32768 unique objects per catalog, 8 MiB per object/catalog, 128 KiB per file-kit root, 256 retained or receiving catalogs, 1024 explicit pins and 1024 maintenance receipts. Serialized local state is capped at 32 MiB; cleanup inventory at 131072 objects. Reaching a bound rejects admission instead of silently dropping protected history. These are parser/admission caps, not measured production capacity. Large-history metadata cost, receipt compaction and automatic retention scheduling remain unaccepted.

On an authorized Linux test filesystem, with Go pinned by `go.mod`:

```sh
go test -count=1 -timeout=180s ./internal/generation
go test -count=1 -run '^TestSealedViewExcludesMaintenance$' ./internal/filekit
go vet ./...
```

Set `TMPDIR` and `OUTPOST_TEST_ROOT` to the admitted test volume. If the build uses executable scratch via `GOTMPDIR`, use `go test -exec "env -u GOTMPDIR"` so test data stays on that volume. The integrated consumer is `TestSealedReplicaSurvivesSourceRepackAndAbsence`: it calls `Seal`, `Receive`, `Pin`, `ExportKit` and `Maintain`, then invokes the independent file reader. It uses a 2 MiB random source and verifies actual old/new restored bytes, mode and hard-link identity after source repack/retirement and deletion of the source and other holder.

The [machine trace](../g2-trace.json) connects the scoped G2 requirements to checks. Five additional child-process tests confirm actual SIGKILL at object durability, pre-COMPLETE, completed-state durability, retirement durability and object deletion, followed by reopen/retry and verified complete closure. These are process-failure tests, not hardware power-loss certification. A bounded external DeepSeek review identified malformed maintenance-key validation; a negative regression now covers it. Revision-zero permits are valid only for the initial empty state, and replay protection is enforced against persisted state.

Remaining acceptance includes full-scale G1, large catalogs/history, multi-node scheduling and policy, epoch transitions, real network cuts and cloud semantics, volume loss during I/O, cold boot and production installation. The [roadmap](roadmap.md) and whole-product acceptance scenarios remain NOT_VERIFIED.
