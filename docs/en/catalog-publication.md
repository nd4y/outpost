# Bounded catalog publication

[Русский](../ru/catalog-publication.md)

A source sends the signed catalog after the encrypted closure is durably staged. Receiving a catalog does not make a generation complete. The receiver materializes and verifies the closure, saves its verification checkpoint, then publishes the complete generation and returns its bound receipt. The source retains its operation until that receipt is verified and saved.

Each ordinary HTTPS publication step now processes at most 8 MiB of payload, with at most 256 objects. This matches the maximum size of one uploaded object. Staging-enabled workers keep their existing one-object bound. An incomplete response is HTTP 202; the source continues the same signed catalog using its authenticated continuation hint. The 30-second source request limit, signed authority, closure checks and final readback are unchanged.

## Failure and causal check

The previous standalone receiver could process 256 MiB before saving its verification checkpoint. In the failed physical 100 GiB fixture, its first selected batch was exactly 35 objects and 263,980,668 bytes. Those same 35 objects were durable when the catalog request timed out; no verification checkpoint or complete generation existed. All 107,395,477,507 initial object-body bytes had already reached staging. This was a request timeout after roughly ten hours of source transfer, not the 36-hour test deadline. There were no OOM or swap events, but substantial memory reclaim occurred; memory headroom is not established.

`TestCatalogDeadlineBoundsAndReopenedVerificationProgress` uses real authenticated HTTP and two 24 MiB fixtures. Both use the same five-second test request limit and a controlled durability stall after one request materializes more than 8 MiB. The stall ends only when that actual HTTP request is cancelled. The explicit old batch reproduces the timeout before its verification checkpoint. The bounded default returns durable partial progress before the deadline. Both fixtures reopen the session and replica, finish the original catalog and restore every byte. A partial generation must never appear complete. An earlier proportional-delay control first failed with the old production default, then passed with the smaller default in ordinary builds; it was sensitive to race overhead. Its failed race run is preserved. The controlled stall avoids that timing ambiguity. No delay is added to production.

This establishes the batch/deadline mechanism and its fix. It does not identify one unique hardware cause for the original disk latency or establish full-size success. The full 100 GiB run and independent clean consumers must pass separately on the corrected source.

## Retained test state

The opt-in source scale fixture preserves its failed directory. It now fsyncs a private synthetic fixture context containing the original identities and bootstrap. This prevents loss of the receiver's private identity when only its test process exits. Keep this context only on the admitted test volume with private permissions; never export it with logs or public evidence. It is removed before successful independent recovery, together with source/runtime and operational key files. Context retention alone is not a verified resume command.

The scale harness allows at most three calls to the same durable source operation for a transport unavailability or individual request timeout, as the executable source loop does. It records each failed attempt and counts all received bodies across attempts. It never renews authority, changes an intent, extends a request deadline or discards traffic accounting to obtain a pass. Authentication and other failures stop immediately. The 2 GiB source budget, 8 MiB edit, 128 MiB changed-body bound and zero unchanged file-payload requirement remain in force.
