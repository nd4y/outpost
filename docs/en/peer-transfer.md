# G3 peer transfer and complete publication candidate

[Русский](../ru/peer-transfer.md)

Status: bounded Linux library candidate in `internal/peer`, built on the [G2 replica](generation-replicas.md). It transfers real encrypted file kits over mutually authenticated HTTPS. Full G3, distributed external upload, large-file bandwidth and operational acceptance remain **NOT_VERIFIED**. No worker daemon, live certificates or network configuration are installed by this change.

## Trust and routes

Each domain/repository/epoch uses an explicitly provisioned `Policy`, a CA-verified TLS certificate and pinned peer public-key identities (SHA-256 of the certificate SPKI). The policy defines the local class, allowed classes and concrete peer grants for push/pull with expiry. Trusted status grants no decryption key. An external S3-compatible or WebDAV target is not a peer.

The client accepts one explicit HTTPS origin. It validates the CA, hostname and pinned identity; it follows no redirects, ambient proxy settings, discovery or alternate routes. The server requires a verified client certificate, TLS 1.3 and an allowed peer/operation on every request. Grants and leaf certificates are checked for expiry, including reused connections. Requests are scoped to a domain; the replica's immutable public trust binds the repository, epoch and catalog author. A sender cannot supply a replacement author key or classify itself as trusted.

Policies and certificates are fixed for each constructed client/server. Provisioning, hot reload, owner-signed policy distribution, global graph validation, host firewall enforcement and revocation of already distributed ciphertext remain separate work. This candidate enforces configured edges at its own endpoints; it cannot make a compromised authorized holder obey transit policy.

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

The [G3 trace](../g3-trace.json) links scoped implementation checks to all six gate requirements. The [external-upload candidate](external-upload.md) extends REQ-27 coverage with three independent processes, cached signed assignment, SIGKILL takeover, multipart adapters and complete external-target recovery. Peer tests alone remain prerequisites. Real S3-compatible/WebDAV limits and ACLs, power loss, large history, long partitions, low-memory deployment, full traffic accounting and heavy G1-G3 acceptance remain open. Keep the [roadmap](roadmap.md) and private deployment holds in force.
