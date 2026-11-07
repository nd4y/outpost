# Delegated external planning contract

[Русский](../ru/delegated-upload.md)

This development contract removes per-generation planner requests while preserving separate authorities. The upload planner signs a bounded delegation containing the exact generation trust, external profile, eligible workers/classes, start, expiry and assignment-slot duration. The owner separately includes the delegation in each eligible worker's current configuration. Both checks are required. Workers receive neither planner nor data-decryption private keys.

For each locally complete generation, eligible workers derive the same canonical version-2 plan from that delegation and the writer-signed catalog. The operation binds the delegation digest and generation. Object partitioning is deterministic under the profile's hard limit. Workers describe one bounded ciphertext object at a time and persist the resulting plan before queue admission. A planning pin protects the generation until the durable upload queue owns its independent pin. Policy withdrawal stops new work and preserves pending pins.

The delegation authorizes a scope rather than signing a concrete part map. A derived map is untrusted until checked against actual object bytes: part hashes, full reconstructed-object hashes and the signed catalog closure must all match. Publication and successful receipts still require complete target readback. Honest workers derive identical plan bytes, sharing assignment/claim identities; an altered map cannot become a valid restored generation merely by carrying a valid delegation. Immutable conflicts remain explicit.

Version-1 individually signed plans remain supported. Version-2 plans require upgraded readers; unknown formats fail closed without removing old generations. Existing storage object/blob/catalog formats remain unchanged. Cached configuration and delegation validity permit autonomous work without the control plane; no delegation grants new credentials, recipients or deletion rights.

The first integration is bounded by existing catalog, object, job and plan limits. Final acceptance must measure planning reads, multipart costs, duplicate attempts, shared-link/account budgets and retained history. This contract alone does not establish executable implementation or scale acceptance; see the [completion map](../product-status.json).
