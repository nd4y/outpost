# Bounded verification windows

[Русский](../ru/verification-windows.md)

Implementation contract; acceptance is recorded in the product trace. A window binds an admitted generation, immutable public trust, target and authenticated transfer operation. It records actual object reads across bounded requests. It grants no catalog admission, route, historical replay, repair, deletion or source-release authority.

## Peer protocol extension

A client requests `Outpost-Batch-Verification: 1` on the existing `POST missing` and `POST complete` endpoints. A server rejects other nonempty versions. Without the header, the existing full-read protocol is unchanged. An older server may ignore the header and return its stricter legacy full-read receipt; the client accepts that response explicitly.

With this header, `missing` checks only safe regular-file presence and declared size. Missing objects are transferred; wrong size and unsafe file types fail closed. Presence is not hash verification. `complete` reads and hashes at most eight objects and 8 MiB of payload per request. The receiver derives a private window identity from its exact authenticated operation binding. Existing catalog signature, scope, monotonic history and retention checks still apply. Window verification only accesses an already admitted generation; it cannot create a historical admission.

An incomplete window returns HTTP 202 and format `outpost-peer-verification-progress-1`, with operation ID, generation, verified and total object counts. The client checks all identities and count bounds against its signed closure, then requests another batch while its context and current grants permit. No 202 response is a receipt or permission to release a source pin. Success returns HTTP 200 and receipt format `outpost-peer-window-1`, level `target-window-read`; pull uses `local-window-read`. The receipt time is the oldest actual object read supporting that window, never the last request time. Legacy receipt formats remain readable. Old binaries cannot read the new receipt; upgrade readers before rollback or reuse of those journals.

Each verified object stores its original observation and device/inode/size/mtime/ctime stamp. Progress is durable before a successful batch response. Reopening the same operation reuses unchanged verified objects; a new operation uses a fresh window and reads all bytes again. Before publication, all dependency stamps are checked under the replica lock. A changed stamp requires a fresh hash read. A malformed checkpoint remains preserved and blocks that window. A read-only status or metadata-presence response never publishes an incomplete generation.

Sender-side independent target readback remains required after the target receipt, subject only to the separate explicit readback-reuse policy. A target window claim cannot refresh a sender's older payload evidence. Windows span time and cannot prove simultaneous or future persistence, especially on an untrusted target. Fresh audits start a new operation. Source pins remain until the appropriate durable client receipt. Quotas apply to verification metadata; cleanup requires separately authorized maintenance.

This bounds payload work per request, not the size of the signed catalog or the final metadata-stamp scan. Large catalog pagination, long-history throughput, physical power loss and final large-file acceptance remain separate checks.

## Cloud object prefixes

When cloud readback reuse is explicitly enabled, each actual physical-part read advances a private SHA-256 checkpoint bound to the operation, exact descriptor, target, reader and public trust. Only bounded hash state is saved, never a second ciphertext copy. Every part and the final logical object digest must match. A resumed prefix produces cached evidence with its original oldest read time. Zero-age fresh-only policy does not use this state.

Expired progress restarts. Malformed or incompatible hash-state encodings fail closed and are preserved for explicit metadata recovery; immutable backup formats do not change. Known loss or corruption invalidates evidence and fences in-flight writes. A sealed prefix with no usable whole-object evidence cannot resurrect it. A never-seen descriptor during initial upload may retain an unsealed prefix. Once a descriptor has been observed, its disappearance invalidates even an unsealed prefix and requires new reads. SHA state can contain a short ciphertext suffix, so it stays in private admitted state and is never logged or exported.

Known cloud-object loss also advances a private evidence epoch shared by concurrent operations for the exact descriptor/target/reader/trust. Cache keys include that epoch. The epoch is durable before old-record removal, so a crash cannot make a retained old record current again. Final evidence writes recheck the epoch under the shared lock; a stale operation retries with a new audit. Epoch files are quota-admitted, preserved on corruption and never automatically removed. This private verification state requires compatible readers; an older binary that ignores it is not a supported rollback while reuse is enabled.
