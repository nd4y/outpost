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

One capture occupies a receiver's domain slot. Its durable fence prevents replay or displacement. After an acknowledged capture, the next one advances the sequence by one and names the acknowledged parent. After [retirement before sealing](source-settlement.md#retire-an-admitted-capture-before-sealing), a fresh intent can reuse the uncommitted sequence and its exact predecessor. Reusing the compact slot preserves replica history. Admission and slot-replacement crashes resume from the persisted fence. Initial catch-up requires an available valid parent.

## Publication and acknowledgement

The source-side capture-progress contract uses a private append-only encrypted log bound to domain, file, operation, source identity and capture options. A record names only packs already durably accepted by the receiver. Records carry sequence and previous-record digest; authenticated complete-record corruption stops resume, while an incomplete final record may be removed and its pack retried. Resume may reread source bytes while reusing accepted encrypted blocks. This local log is not a recovery kit, a complete generation or permission to release a snapshot. Provider/job integration and source-read costs need separate acceptance.

Presence alone is not completeness. Verification processes at most 256 objects/256 MiB per request, persisting object identity/modification stamps. Publication requires the full closure, unchanged stamps and valid signed lineage. This records a verification window, not immunity to future corruption. Fresh scrub still rereads all bytes.

A receipt identifies operation, ingress, tenant/domain, generation, new bytes/objects and original verification time. Lost replies preserve that time. After the receipt is durable, an exact retry checks the existing publication and returns the stored receipt without rewriting the completed session solely to repeat it. Advances of the clock fence still persist. The client confirms the exact published catalog. Body counters include attempted sends and reads; they are not TCP/TLS wire counters. A compromised receiver can lie about persistence, so report verification level and observation age.

Before acknowledging, the source must durably save its verified receipt/checkpoint, satisfy its copy threshold and finish provider release. Acknowledgement persists first, then releases only its own pins and removes its accepted staged copies in bounded steps. Retry the identical acknowledgement after a lost response. Acknowledged operations cannot accept or expose payload; replica recovery remains available. Retirement needs separate signed maintenance authority.

A completed operation can acknowledge its exact original receipt after its capture intent expires. The cleanup-only client cannot begin or access payload. Registry routing still requires current owner authority and current worker placement/TLS; expiry does not renew those grants. Reopening cleanup cannot initialize a slot. An incomplete operation cannot use this path.

403 means denied authority; 404 absent scoped object; 409 operation/lineage conflict; 412 incomplete data; 429 request capacity; 503 temporary unavailability; 507 storage admission refused. None permits a broader route. Expiry/rollback preserve retained data. Unknown files are never removed; interrupted temporary files need explicit owned-file reconciliation.

The [expired-operation settlement workflow](source-settlement.md) retrieves only an already durable original receipt under fresh owner permission and current receiver policy. It preserves original verification age and the independent-copy threshold. Missing receipt or expired observation permission remains pending; an immutable write intent is never renewed by settlement.

The [receiver renewal workflow](receiver-renewal.md) admits a fresh same-scope grant in the existing registry after explicit quiescent maintenance. It preserves historical receipts and generations, fences previous readers and uses the current receiver policy and disk budget.

[Missing receipt recovery](receipt-recovery.md) uses separate fresh owner permission and current receiver policy to reconstruct a receipt only from an already complete generation and unchanged original publication proof. It preserves the original verification age and signed audit; ordinary settlement remains a separate step. Operations with uncertain evidence and lost journals remain pending.

On a stopped receiver, `outpost worker-ingress-journal-enable --bootstrap FILE --domain ID --input SIGNED_AUTHORITY` enables an optional registry copy. Pass the exact original authority for the retained registry, or its exact current authority after a renewal. The receiver writes a node-signed registry copy, separate digest anchor and primary file in that order. This uses the existing admitted volume and quota. Update the receiver executable before enabling the option.

`outpost worker-ingress-journal-recover --bootstrap FILE --domain ID --input SIGNED_AUTHORITY` verifies the copy, original authority and the retained session before restoring the missing registry. An interrupted write can continue from its exact live predecessor and an observed eligible slot. A stale signed copy or unavailable session keeps recovery blocked. The command preserves original intents, authority history and receipt times. It opens no listener and creates no session or publication. The copy and anchor share the receiver volume. Complete runtime loss requires independent recovery evidence.

## Continuing verification without resending the catalog

After the receiver has durably saved a valid catalog and returns 202, it may return `Outpost-Catalog-Resume` containing that catalog's exact SHA-256. The source accepts one hint only when it equals its own signed catalog digest and the returned progress passes the existing checks. A later `PUT catalog` may then have an empty body and the same header. The receiver reads only that operation's saved candidate and still runs the original signature, intent, dependency, bounded verification, publication and receipt checks. The header grants no new authority and does not renew an expiry or verification time.

A missing candidate, changed digest, multiple request hints or a simultaneous body and hint fail. TLS identity, current policy, operation scope and deadlines apply before continuation. Closing and reopening the session preserves the candidate. A client restart can resend the original signed bytes; the hint is an in-memory optimization. After a failed continuation request the client forgets its hint, returns the error and leaves any retry to its caller.

The catalog, JSON replies and durable state formats are unchanged. An older server advertises no hint, so the source continues sending the full catalog. An older client may ignore the header and keep the original full-body requests. A different or ambiguous response hint is ignored. The small TLS regressions force multiple verification batches and check body-byte accounting, reopen, legacy requests and rejected scope substitutions. These checks do not accept the 100 GiB integrated traffic target.

## Bounded acceptance and scale profile

The [execution receipt](../source-ingress-evidence.json) distinguishes the catalog optimization, expiry regressions and a physical 128 MiB source rehearsal from full 100 GiB acceptance. The small TLS fixture sends a full catalog once across three verification requests; the original implementation sent it three times. Independent signed fixtures may differ in catalog length. Legacy-client/server paths, malformed progress, exact-scope substitutions, actual expiry, reopening and original-age complete retries have separate assertions.

The scale test is opt-in: `TestSourceIngressScaleAndOfflineMaterializedReplica` accepts only 128 MiB and 100 GiB. Run 128 MiB first. Select the exact built fixture executable, distribution manifest and admitted HDD filesystem identity through the `OUTPOST_INGRESS_*`, `OUTPOST_RECOVERY_DISTRIBUTION` and `OUTPOST_RECOVERY_MANIFEST_SHA256` inputs declared in the test. The runner must also verify the host mount, pinned artifacts, free space and resource limits. Its conservative admission reserves 20 percent plus the planned overlapping copies. The source runtime has a 2 GiB quota; the test does not keep another complete source repository there.

The scenario measures received object bodies separately from other PUT bodies. Encrypted descriptor roots and parts are metadata; unchanged-file capture must transfer zero file payload, while metadata may change. An 8 MiB replacement must stay within 128 MiB of combined new object and other PUT bodies. Counters are not physical wire traffic. Both complete replica generations are restored with the selected standalone reader after removing the original source, runtime and operational private keys and closing the receiver. Separate fresh consumers use only copied immutable objects/catalogs, the owner kit and new output; no replica state index or network is available. The 128 MiB result does not accept the 100 GiB target.

Expiry regression fixtures use a nonempty 32 KiB file and a 30-second signed test grant to allow preparation on a constrained HDD with race detection. They wait for the actual signed expiry before checking denied payload access and the separately authorized historical operation. Product TTL policy, request timeouts and authority validation are unchanged. A shorter five-second fixture reproduced preparation failures on both the original and changed implementation; reducing data alone was insufficient.
