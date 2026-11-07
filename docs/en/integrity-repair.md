# Integrity and replica repair

[Русский](../ru/integrity-repair.md)

Fresh ciphertext verification records a missing or corrupt dependency in replica state4. Every admitted generation referencing that object loses its complete publication status. Catalog export, independent kit export and healthy-source discovery reject affected generations. Existing generation, kit and restore pins remain retention roots. Detection does not erase damaged bytes or create a new file version.

## Periodic ciphertext checks

The signed domain field `scrubIntervalSeconds` enables periodic local verification. Zero disables it; positive values are bounded from 1 second to 30 days. Operators should choose an interval appropriate to their admitted data volume and storage budget. The worker launches at most one batch per second, with up to eight objects and 8 MiB of payload. Scrubs use free slots in the same bounded queue as backup transfers and commands. A configured interval is a desired revisit time, not a promise that an arbitrarily large corpus finishes within it.

Each cycle gets a fresh durable verification window. Restart and cancellation resume the same window; a new cycle actually reads the payload again. Detected corruption revokes publication and lets explicitly authorized repair discovery act. After repair, a new window verifies that damage incarnation. Signed generation reports expose `CIPHERTEXT` and the oldest supporting read time only for a currently healthy generation with a matching completed scrub. Metadata polling never refreshes that time. Trusted decryption verification is a separate operation.

The first scheduled check promotes local worker metadata to `outpost-worker-3`. Existing worker1/worker2 state remains readable; worker3 requires signed controls and a bounded scrub journal. Older writers reject it. Control migration preserves worker3, and rollback that would drop scheduled evidence is refused. The schedule journal admits at most 4096 generation entries. Pause, schedule withdrawal, configuration expiry and volume loss use the shared cancel-and-join lifecycle. Quota admission precedes payload reads; failed attempts retain progress and bounded retry deadlines.

## Verified replacement

An explicit repair transfer accepts only the size and SHA-256 digest in an authenticated catalog. Before replacing an existing object, it persists a bounded repair intent and copies the original regular file into `quarantine/objects`. The quarantine copy is synced and checked before atomic replacement. Missing and empty originals have distinct records. Links, special files, oversized originals, changed evidence and quota denial stop the operation. Quarantine uses data capacity and is excluded from ordinary generation GC.

Replacement does not publish a generation. Each affected generation must complete a verification window over its entire dependency closure. Shared healthy objects need no network transfer. A durable repair record retains the original detection and completion times; replay does not refresh them. Quarantine and the repair journal survive restart and process termination. The current journal admits at most 1024 repair cases and fails closed at capacity. Automatic quarantine deletion is not implemented.

## Authorized autonomous repair

An owner-signed replication rule can opt into `repair: true`. This grants repair only along the existing domain, placement edge, direction and peer identity. Ordinary replication rules do not grant repair. The receiver creates an opaque incarnation token for detected generation damage. A new damage event after recovery changes that token, so an old repair cannot overwrite a later incident.

For pull, the receiver compares its local repair needs with the source's healthy inventory. For push, the sender reads bounded repair metadata from the receiver over its existing outbound HTTPS connection. The metadata endpoint requires the exact current push rule and mutual TLS. It exposes opaque generation IDs, sequence numbers and tokens; it creates no reverse connection and discloses no file names.

Discovery creates a separate immutable repair job bound to the rule, generation and token. Prior transfer jobs and their receipts remain unchanged. Both ends require explicit repair permission, and every incoming transfer must match the derived operation. Configuration expiry, withdrawal, pause and volume admission continue to apply. A push repair performs fresh readback; a pull repair verifies the local closure. A repaired object is not evidence that the underlying medium is healthy.

## Evidence and remaining acceptance

Short isolated tests cover shared dependencies, pins, missing/empty/unsafe entries, quota denial, quarantine tampering, six actual SIGKILL boundaries, both HTTPS directions, stale-token rejection and independent restoration. A three-node worker scenario repairs both a relay and an outbound-only receiver after restart from unchanged signed configuration. Exact command/source evidence is retained by the owner; these checks do not establish large-scale or production acceptance.

Trusted decryption scrub, detailed affected-version reporting, media-failure diagnosis and the final large-file run remain separate completion work. Absence of an authorized healthy source is unresolved damage, never a successful repair. The current inventory is bounded by 256 generations and 32768 dependencies per generation; those limits are not measured production capacity.
