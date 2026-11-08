# Source ingress protocol

[Русский](../ru/source-ingress.md)

This development contract extends [peer transfer](peer-transfer.md). Source scheduling and provider acceptance remain required. The receiver gets ciphertext and technical IDs only; paths, labels and decryption keys stay in the trusted source profile.

## Authority and admission

The owner signs `outpost-ingress-authority-1`: tenant, opaque profile digest, source/receiver certificate identities, revision, validity, generation trust and byte/object limits. The writer signs `outpost-capture-intent-1`: the exact authority digest, operation, participants, domain/repository/epoch, sequence/parent, policy, snapshot observation time and bounded validity/limits. Intents cannot expand authority. Configuration, writer, maintenance and node keys are distinct.

Worker integration requires the exact capability in current signed configuration, an explicit push edge, a trusted source and an assigned receiver. Category alone grants nothing. Withdrawal cancels and joins requests before replacement. Changing a grant must not silently rebind pending data; reauthorization requires a separate recovery procedure.

TLS 1.3 mutual authentication verifies CA, hostname, public-key identity and current certificate validity. Requests carry `Outpost-Authority`. No redirects, proxies, query or encoded paths. Prefix: `/v1/tenants/{tenant}/domains/{domain}/captures/{operation}`; components are opaque IDs.

| Method/suffix           | Request                                       | Result                                                    |
| ----------------------- | --------------------------------------------- | --------------------------------------------------------- |
| PUT `intent`            | Canonical signed intent, at most 16 KiB       | Exact operation/sequence after durable admission          |
| PUT `objects/{id}`      | Ciphertext and `Outpost-Bytes`, at most 8 MiB | Immutable fsynced acceptance followed by client readback  |
| GET/HEAD `objects/{id}` | Exact length                                  | Scoped bytes / presence-length hint                       |
| PUT `catalog`           | Signed closure, at most 8 MiB                 | 202 bounded verification progress or 200 complete receipt |
| GET `catalog`           | None                                          | Exact published catalog before acknowledgement            |
| PUT `ack`               | Exact saved receipt, at most 4 KiB            | Bounded cleanup progress, not a new verification          |

One capture occupies a receiver's domain slot. Its durable fence prevents replay or displacement. The next capture advances the sequence by one and names the acknowledged parent. Reusing the compact slot never retires replica history. Admission/slot-replacement crashes resume from the persisted fence. Initial catch-up requires an available valid parent.

## Publication and acknowledgement

The source-side capture-progress contract uses a private append-only encrypted log bound to domain, file, operation, source identity and capture options. A record names only packs already durably accepted by the receiver. Records carry sequence and previous-record digest; authenticated complete-record corruption stops resume, while an incomplete final record may be removed and its pack retried. Resume may reread source bytes while reusing accepted encrypted blocks. This local log is not a recovery kit, a complete generation or permission to release a snapshot. Provider/job integration and source-read costs need separate acceptance.

Presence alone is not completeness. Verification processes at most 256 objects/256 MiB per request, persisting object identity/modification stamps. Publication requires the full closure, unchanged stamps and valid signed lineage. This records a verification window, not immunity to future corruption. Fresh scrub still rereads all bytes.

A receipt identifies operation, ingress, tenant/domain, generation, new bytes/objects and original verification time. Lost replies preserve that time. The client confirms the exact published catalog. Body counters include attempted sends and reads; they are not TCP/TLS wire counters. A compromised receiver can lie about persistence, so report verification level and observation age.

Before acknowledging, the source must durably save its verified receipt/checkpoint, satisfy its copy threshold and finish provider release. Acknowledgement persists first, then releases only its own pins and removes its accepted staged copies in bounded steps. Retry the identical acknowledgement after a lost response. Acknowledged operations cannot accept or expose payload; replica recovery remains available. Retirement needs separate signed maintenance authority.

A completed operation can acknowledge its exact original receipt after its capture intent expires. The cleanup-only client cannot begin or access payload. Registry routing still requires current owner authority and current worker placement/TLS; expiry does not renew those grants. Reopening cleanup cannot initialize a slot. An incomplete operation cannot use this path.

403 means denied authority; 404 absent scoped object; 409 operation/lineage conflict; 412 incomplete data; 429 request capacity; 503 temporary unavailability; 507 storage admission refused. None permits a broader route. Expiry/rollback preserve retained data. Unknown files are never removed; interrupted temporary files need explicit owned-file reconciliation.

The [expired-operation settlement workflow](source-settlement.md) retrieves only an already durable original receipt under fresh owner permission and current receiver policy. It preserves original verification age and the independent-copy threshold. Missing receipt or expired observation permission remains pending; an immutable write intent is never renewed by settlement.
