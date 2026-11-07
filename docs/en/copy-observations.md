# Authenticated copy observations

[Русский](../ru/copy-observations.md)

An owner-signed observation grant names the exact domain trust, source reader, collector, permitted replica nodes, expiry and maximum accepted observation age. This is a separate metadata route. Placement or a transfer receipt alone does not authorize it. Nodes send their own signed observations to the collector using outgoing mutual TLS; the source reads them over its outgoing connection. Neither participant needs a reverse connection.

Each observation binds the grant, generation, replica public-key identity, ciphertext verification level and original verification time. The collector stores and relays the original signed bytes. It cannot substitute its identity for another replica or make an old observation fresh. The source verifies the owner grant and each node signature before counting distinct permitted copies. Missing, expired or invalid evidence leaves the source job waiting and preserves its provider view.

The verification cache checks content and records its verification window. Repeated requests preserve that time; they are not fresh scrubs. A node can lose data after verification, and a compromised permitted node can lie about its storage. An observation therefore reports authenticated verification evidence, not a permanent durability guarantee. Independent recovery and periodic scrub remain necessary.

The development protocol uses `PUT /v1/DOMAIN/observations/GRANT/GENERATION/NODE` for a node's own observation and `GET /v1/DOMAIN/observations/GRANT/GENERATION` for the designated reader. No query, encoded path, redirect, credential or private source name is admitted. Both endpoints require the collector's current signed configuration. Revocation cancels and joins active requests. Replies and stored observations are bounded; capacity failure never lowers the source's required copy count.

Implementation checks and full acceptance remain separate in the [completion map](../product-status.json).

`observation-grant-sign --key OWNER_KEY --input GRANT --output NEW_SIGNED_GRANT` creates the separate grant. Include its exact bytes in each participant worker's `observations` configuration list. Its validity must cover that configuration's validity. The source uses its private `observationFile`; `worker-observation-status --bootstrap FILE` reports the last persisted generation/phase/error per grant. Observation failures do not replace transfer receipts. The current loop visits one generation per grant and pass; grants admit at most 32 targets and configurations at most 64 grants. Metadata requests share the worker's bounded metadata slots.

Short checks verify signature/identity/age tampering, policy expansion denial, original-byte relay across collector restart, retained evidence after revocation, and source restart while waiting for the second replica. The latter restores independently from that replica after stopping the workers and removing the synthetic source. Race checks cover the integrated worker/source path. Stale evidence requires a new verification window; replay is never a scrub. Scheduling fresh scrubs and final-scale costs remain open.

Fresh-observation renewal must create a new private verification window when the previous signed proof exceeds its grant age. The window binds the grant, generation, target and previous-proof digest. A persisted start time bounds its lifetime; an expired unfinished window starts again rather than refreshing old payload timestamps. Invalid old signatures or future times fail closed. The original proof remains available for historical inspection until a newer independently verified proof is durable. This renews observations only; it does not repair corrupt payload or grant new transfers.

The worker now renews an expired proof through that bounded window and requires an already complete local catalog before starting. Same-size corruption prevents renewal and preserves the old signed bytes. A new proof is published only after a new successful read; replay of an unexpired proof remains byte-identical. These checks do not establish scheduled decrypt verification or corruption repair.
