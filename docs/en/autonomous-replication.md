# Autonomous replication contract

[Русский](../ru/autonomous-replication.md)

This development contract extends the concrete-job worker with explicit owner-delegated discovery. The implementation and acceptance map remain separate; signing a rule does not itself prove a running scheduler or complete retained history.

An optional configuration `replication` list contains domain, from/to nodes, push/pull mode, a positive route epoch and the peer's minimum accepted configuration revision. Each rule must match an existing placement edge and involve the configuration recipient. Two active incarnations of the same edge are rejected. Placement without this rule does not start work. Changing a route epoch creates different operation identities; removing a rule withdraws its authority.

The stable operation binds the rule, domain trust and exact generation digest. It is independent of unrelated configuration edits. Push discovery reads the local complete inventory. Pull discovery uses the allowed source endpoint, so the recipient can be outbound-only. Only current, mutually authenticated rule participants can use inventory. Metadata permission never implies an unapproved payload route.

## Inventory protocol

`GET /v1/DOMAIN/inventory` carries `Outpost-Replication` (the exact rule ID) and `Outpost-Required-Revision`. It has no body, query or alternate encoded path. Only the peer of an admitted pull rule serves it. A lower peer revision returns 503; denied identity or rule returns 403. Replies are bounded to 64 KiB and at most the admitted generation count. The `outpost-inventory-1` reply binds domain, repository, writer epoch and rule ID, and lists unique generation IDs with increasing positive sequences.

Inventory is a discovery hint about recorded COMPLETE publications, not a fresh verification receipt or proof that no newer generation exists elsewhere. The receiver still verifies the signed catalog, every dependency and complete publication. No redirect, proxy fallback, private source name or credential belongs in this protocol.

Durable derived jobs retain exact operation binding, retries, receipts and current-rule checks across restart. Independent routes may progress while another is unavailable. Revocation cancels and joins discovery and transfers before a replacement view starts. [Historical admission](generation-replicas.md) preserves highest-sequence fencing and signed retirement evidence; older history cannot silently change the current head or resurrect locally retired IDs. Capacity or missing retirement evidence remains explicit rather than dropping history and calling the result complete.

`worker-discovery-status --bootstrap FILE` reports the configuration revision and each route's `PENDING`, `DISCOVERED`, `RETRY_WAIT` or `BLOCKED` observation separately from transfer receipts. Unchanged observations are persisted at most once per 30 seconds; their timestamp is the last persisted observation. A discovered generation is not automatically a verified target copy.

Short checks cover two-generation catch-up through an intermediate, independent old/new recovery with the original sender offline, unchanged receipts after restart, denied reverse inventory, route withdrawal and peer configuration lag. A slow authorized request body is interrupted on withdrawal before the replacement view starts. Race checks cover the discovery/queue/request lifetime. Long outage and final-scale acceptance remain open.
