# G3 peer transfer and complete publication candidate

[Русский](../ru/peer-transfer.md)

The [bounded verification-window contract](verification-windows.md) specifies the compatible HTTPS extension and original-time receipts for resumable verification.

Status: bounded Linux library candidate in `internal/peer`, built on the [G2 replica](generation-replicas.md). It transfers real encrypted file kits over mutually authenticated HTTPS. Full G3, distributed external upload, large-file bandwidth and operational acceptance remain **NOT_VERIFIED**. No worker daemon, live certificates or network configuration are installed by this change.

## Trust and routes

Each domain/repository/epoch uses an explicitly provisioned `Policy`, a CA-verified TLS certificate and pinned peer public-key identities (SHA-256 of the certificate SPKI). The policy defines the local class, allowed classes and concrete peer grants for push/pull with expiry. Trusted status grants no decryption key. An external S3-compatible or WebDAV target is not a peer.

The client accepts one explicit HTTPS origin. It validates the CA, hostname and pinned identity; it follows no redirects, ambient proxy settings, discovery or alternate routes. The server requires a verified client certificate, TLS 1.3 and an allowed peer/operation on every request. Grants and leaf certificates are checked for expiry, including reused connections. Requests are scoped to a domain; the replica's immutable public trust binds the repository, epoch and catalog author. A sender cannot supply a replacement author key or classify itself as trusted.

Policies and certificates are fixed for each constructed client/server. Provisioning, hot reload, owner-signed policy distribution, verification of live replication permissions, host firewall enforcement and revocation of already distributed ciphertext remain separate work. This candidate enforces configured edges at its own endpoints; it cannot make a compromised authorized holder obey transit policy.

### Inspect declared routes offline

```sh
outpost config-routes --input /private/signed-config.json \
  --trust /private/owner-public.json --node NODE_ID --domain DOMAIN_ID
```

The trust file contains the owner's independently obtained public key as a JSON `publicKey` field (base64). The command verifies the signature, intended node and validity period, then reports the signed document's SHA-256 and revision. It lists every holder in the selected domain, sorted by opaque ID, with a shortest declared path in data-flow order. On a pull edge, the receiving node dials the sender. A reachable local holder has no hops. An unreachable holder has `reachable: false` and no hops. The command also accepts an origin assigned only for transit.

The report describes one signed document. Keep it private with the configuration. The command opens no connections and leaves the applied worker configuration untouched.

### Compare two signed peer configurations

```sh
outpost config-route-compare --input /private/signed-config.json --node NODE_ID \
  --peer-config /private/signed-peer.json --peer PEER_ID \
  --trust /private/owner-public.json --domain DOMAIN_ID
```

Both documents must be active, addressed to the specified distinct nodes and signed by the same trusted owner. Each node must have a holder or transit role in the selected domain of its document. The report identifies each document by node, revision and SHA-256. It compares domain trust, allowed peer classes, holder and transit sets, directed peer edges, and the class and endpoint of each placed node. Array order, configuration revision and policies for external targets do not affect the comparison.

Check `consistent` and the `differences` array in the returned JSON. The command returns a report for valid documents that disagree and an error for invalid, expired or misaddressed input. Keep the report private. Check the configuration of each participating node and verify replication permissions, credentials and network access separately before deployment.

### Audit the signed topology for one domain

```sh
outpost config-route-audit --input /private/signed-reference.json --node REFERENCE_ID \
  --peer-configs /private/route-index.json --trust /private/owner-public.json --domain DOMAIN_ID
```

Create a private index with the absolute path to each available peer document. Omit the reference node, whose document is passed separately.

```json
{
  "format": "outpost-config-route-index-1",
  "peers": [{ "node": "PEER_ID", "config": "/private/signed-peer.json" }]
}
```

The signed reference defines the expected holders and transit nodes. Omitted documents appear in `missingPeers`. Each supplied document must be active, signed by the same owner and addressed to its listed node. Duplicate or unexpected nodes and invalid documents cause an error. The index is limited to 256 KiB and the signed documents together to 128 MiB.

A report with `complete: true` has every expected document. `consistent: true` also requires every supplied graph and domain trust to match. Use the per-peer `differences` to locate discrepancies.

The `replication` array checks each directed edge in the reference. For push, the executor is the sender. For pull, the executor is the recipient. The audit compares the exact rule identities used by the workers and the executor's minimum peer revision with the supplied peer revision.

| State                   | Meaning                                                          |
| ----------------------- | ---------------------------------------------------------------- |
| `RULES_MATCH`           | Both documents authorize the same rule at the required revision. |
| `UNDELEGATED`           | Neither document delegates autonomous replication on the edge.   |
| `DOCUMENT_MISSING`      | A document for one or both endpoints is missing.                 |
| `EXECUTOR_RULE_MISSING` | Only the HTTPS peer declares a rule.                             |
| `PEER_RULE_MISSING`     | The executor's rule has no peer counterpart.                     |
| `PEER_REVISION_TOO_OLD` | The supplied peer revision is below the required minimum.        |
| `RULE_MISMATCH`         | The documents declare different rule identities.                 |

`consistent` still describes placement and domain trust. Check `replication` separately for every edge intended for autonomous operation. The audit uses local documents. Before deployment, verify the revisions active on workers, their credentials and connectivity. Explicit per-generation jobs use separate authorizations.

### Staged objects across two authorized hops

A receiver can serve an object it previously imported and durably accepted into the same capture. Each adjacent hop uses its own admitted intent, explicit origin and reader, and mutually authenticated HTTPS. The registry keeps a fixed copy of its admitted routes for the lifetime of that view.

An isolated check stages ciphertext at the first receiver, imports it at the bridge, then closes the first receiver and reopens the bridge on its retained state. The source requests the second hop using the bridge. The last receiver refuses an undeclared shortcut, keeps the unsealed capture out of complete inventory and publishes only after verifying the signed catalog. It restores independently after the first receiver and bridge are offline.

The source can queue one object import per admitted capture with `Client.QueueStaged`. The `queued-imports` endpoint returns HTTP 202 after durable acceptance or when the exact object is already available. Check object availability separately. Repeating the same request reuses the pending record. A second pending object or origin returns HTTP 409.

During a paired capture, the source asks the destination to queue an import after a temporary synchronous failure if the origin already confirmed the object. The capture keeps the failed handoff pending until the destination confirms the object is available.

The worker retries the queued import over its current authorized route while the capture is active and unpaused. The staging test sends SIGKILL at two points. After the recipient saves the queued request but before it returns HTTP 202, reopening preserves the request and the source can repeat it without creating a second entry. The test also kills the recipient after it saves the object and before it clears the queued import. After the bridge goes offline, the reopened recipient confirms the local object, clears the queue, and restores the published generation independently. The signed catalog still controls publication. If the capture is sealed, publication owns the remaining work. Complete publication or signed retirement clears any pending import. Before downgrading the receiver, finish the queued import, publish, or retire the capture using this version. Scheduling a whole chain without source admission for each hop remains open.

## Transfer and publication

`NewServer` returns an HTTP server with TLS configuration but opens no listener. An integrating caller supplies admitted replica/journal directories and credentials and explicitly serves TLS. `NewClient` supplies `Push` and `Pull`; workers need public verification material and ciphertext, not owner decryption or catalog signing keys. Journal initialization is explicit and requires an existing empty directory. The storage admission/UUID checks belong to the caller, as in G2.

| Step            | Push                                                                                            | Pull                                                                     |
| --------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Protect source  | Persist a local generation pin                                                                  | Request a persistent source lease/pin                                    |
| Accept catalog  | Verify signature, scope and complete dependency list at target                                  | Fetch and verify the signed complete source catalog                      |
| Transfer        | Target reports missing dependencies; send immutable objects in parallel                         | Local target reports missing dependencies; fetch objects in parallel     |
| Verify          | Target checks object lengths/hashes, flushes data and atomically publishes COMPLETE             | Local target verifies the full closure and atomically publishes COMPLETE |
| Record evidence | Persist target receipt; independently read back catalog and every object before sender COMPLETE | Persist local full-read receipt after local COMPLETE                     |
| Release source  | Release local pin after sender journal commit                                                   | Release remote lease after local journal commit                          |

An object acknowledgment follows immutable membership, length/hash and filesystem durability checks. An existing corrupt object fails closed; this version has no quarantine/repair API. An interrupted reception stays pending. Publication rechecks the complete signed closure through the G2 transaction and preserves the previous complete generation on failure. Catalog GET never publishes pending state.

Push requires explicit read as well as write authority because it audits the target. A `target-full-read` receipt is the target's claim. `client-full-readback` means the sender fetched and checked the full closure through the pinned peer; `local-full-read` records local verified publication. Receipts identify target, generation/catalog digest, operation, verification type and observation time. They are persisted evidence from the authenticated exchange, not separately signed transferable attestations. Readback establishes byte availability at observation time; it cannot prove future persistence on a malicious holder. Freshness, replica minima and source-snapshot release policy are not inferred from one receipt.

An asynchronous bridge holds complete generations durably. A source may push to it, disappear, and an outbound-only recipient may pull later. No simultaneous end-to-end tunnel or inbound listener at that recipient is required. If the bridge is unavailable, the recipient keeps its previous complete copy and the operation remains retryable. No route is added automatically.

## Retry, durability and resource limits

The journal binds a stable operation ID to kind, domain/repository/epoch, generation, peer, executor and expected catalog digest. Attempts, phase, last receipt and counters survive reopening. A changed binding under the same peer/operation conflicts. Per-operation local locks prevent concurrent execution of the same job; immutable writes tolerate duplicate remote deliveries. Repeating the same API call resumes from verified present objects. The integrating worker provides [owner-authorized discovery](autonomous-replication.md); the library does not create routes or grant distributed executor leases.

Journal updates use file flush, atomic rename and directory flush under a process lock. Incomplete scratch files are never authoritative. A crash between replica commit and journal/response can leave a complete target with a retryable sender; replay verifies it again. Interrupted source pins remain, conservatively preventing collection. Successful transfer with failed pin release returns `CleanupPending`; it does not roll back verified publication. Expired/abandoned lease recovery and bounded journal/pin retention need a separately authorized maintenance design before unattended operation.

- Concurrency: 1-4 object requests; attempts: 1-3 per request; timeout: positive and at most 5 minutes, further bounded by context and grant/certificate expiry.
- Receiver rejects excess concurrent requests with 429. Bodies, headers and response reads are bounded. TLS, cancellation and retry paths never downgrade to plaintext.
- Objects/catalogs inherit G2's 8 MiB bounds; a journal holds at most 1024 jobs and 4 MiB. Capacity exhaustion rejects new work. There is no claim of months of continuous scheduling within this fixed journal.
- `objectBytesSubmitted` sums full object request bodies per attempt, not actual socket bytes. `objectBytesReceived` counts verified payloads fetched by pull. `readbackBytes` counts successful catalog/object audit reads in the last attempt. These omit failed partial responses, protocol overhead and metadata requests.

By default, push independently rereads the full generation in reverse. An explicit owner [readback-reuse policy](readback-reuse.md) permits previous immutable-object evidence for the exact reader, endpoint, target and trust scope. The new `client-cached-readback` receipt retains the oldest supporting read time; it is distinct from a fresh full read and from the target's claim. An unchanged retry then reads only the catalog, while a changed generation reads new objects. Short 16 MiB checks measure endpoint response payloads and recover both versions independently. Full wire cost, local scans, scheduled fresh verification and the 100 GiB target remain unaccepted.

## Bounded verification and remaining acceptance

Run `go test -count=1 ./...` and `go vet ./...` in the admitted Linux test environment. Set `TMPDIR` and `OUTPOST_TEST_ROOT` to its data volume; keep executable Go scratch separate if that volume is non-executable. Tests use temporary CA/leaf keys and real loopback TLS sockets, without real endpoints or secrets.

The 2 MiB integration fixture transfers two generations through a bridge, removes the original source, then independently restores both versions at the recipient after the bridge also stops. It checks actual bytes, modes and hardlinks. Other checks cover a lost response after durable write, restart and duplicate delivery, conflicting operation reuse, false acknowledgments, truncated/corrupt reads, premature publication, invalid/oversized objects, missing client certificates, wrong identity/author/domain/class/operation, expired grants, forbidden redirects, retry/cancellation bounds and bounded concurrent object requests. G2's real SIGKILL tests remain in the suite; the G3 restart test reopens persisted state after a socket cut, not a hardware power loss.

The corruption fixture requires an actual injected data fault and forwards cancelled sibling requests as cancellation responses. This avoids confusing normal parallel cancellation with a broken fault fixture.

`TestOfflineHistoryAcrossMaintenanceAndPolicyChange` simulates three daily updates by default. It keeps one recipient offline while the bridge's permitted peers change and the other holders retire previous complete generations. An interrupted final HTTPS pull leaves the recipient's old complete generation available. The retry fetches the final generation directly and restores both versions after the source and bridge stop. The final-scale variant uses `OUTPOST_OFFLINE_180=1` with `OUTPOST_TEST_ROOT` on the admitted HDD. It simulates 180 daily updates and uses 187-day authority. The fixture does not change the system clock or measure 180 days of operation.

The [G3 trace](../g3-trace.json) links scoped implementation checks to all six gate requirements. The [external-upload candidate](external-upload.md) extends REQ-27 coverage with three independent processes, cached signed assignment, SIGKILL takeover, multipart adapters and complete external-target recovery. Peer tests alone remain prerequisites. Real S3-compatible/WebDAV limits and ACLs, power loss, large history, long partitions, low-memory deployment, full traffic accounting and heavy G1-G3 acceptance remain open. Keep the [roadmap](roadmap.md) and private deployment holds in force.

The current peer client uses operation-bound [verification windows](verification-windows.md). New peers return `target-window-read` or `local-window-read` with the oldest supporting read time; legacy peers retain full-read receipts. Metadata presence never substitutes for the mandatory final hash verification. A new operation starts a fresh window. Payload work is bounded per request, while the final catalog/stamp scan still needs large-scale acceptance.
