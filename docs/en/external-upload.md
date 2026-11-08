# Distributed external upload candidate

[Русский](../ru/external-upload.md)

The G3 candidate adds S3-compatible and WebDAV adapters in `internal/storage` and cached signed upload plans in `internal/upload`. Three independent Linux worker processes can upload different ciphertext parts of the same file, take over after a worker stops and publish a complete generation. No continuously available control plane or coordinator is required after plan delivery. The installed worker uses the same durable upload queue and backend adapters. Full G3 and M3 acceptance remain **NOT_VERIFIED**.

The [durable upload queue](upload-queue.md) can admit and drain multiple signed plans with automatic retries, independent target progress and source protection across process restarts. Direct `Journal.Run` remains available for one operation.

## Placement and execution

A planner selects one already policy-separated generation, an external target and eligible workers. `AllowExternal`, allowed node classes and the target namespace are checked before reading payloads or creating tasks. Every selected worker must already hold the complete encrypted generation and have an explicitly admitted route to that target. A denied target receives no plan. The per-file classification and policy compiler that produce these separated generations remain upstream work; the upload library does not decide where plaintext belongs.

The plan binds an operation ID, signed catalog, exact ciphertext dependencies, target profile, worker public identities, start time, expiry and slot duration. Its Ed25519 planner key is pinned independently of the generation author's key. Canonical encoding, bounds, signatures and domain/repository/epoch are verified on opening. Untrusted workers may receive only namespace-scoped credentials; ordinary trusted workers also need no decryption keys. `CredentialScope` and `NoDelete` describe operator-verified permissions, not an ACL the client can enforce on a storage account. Real credential issuance, revocation and ACL admission are still required.

Rendezvous ordering assigns each physical part to one worker per time slot. The ordering rotates on the next slot, so surviving holders can finish abandoned parts using only the cached plan and external target. Workers write signed immutable claims, recheck already present parts and persist attempt/progress state. Claims are evidence, not a consensus lock: clock skew and slow requests can overlap, while conditional creation and byte verification make duplicates safe. Synchronize clocks and choose slots for the actual latency. No adaptive bandwidth scheduler or guarantee of optimal load balance is claimed.

Each worker has its own durable journal and source-generation pin. Journal writes flush the file, atomically rename it and flush the directory under a process lock. A restart resumes the same binding; changed plans cannot silently reuse the journal or remote operation ID. An interrupted initialization fails closed. Successful full verification releases the pin; interrupted work retains it. `CleanupPending` reports a failed release without undoing publication. Plan expiry stops further work; it does not retract ciphertext already sent. Credential distribution and automatic cleanup of abandoned journals, claims, probes and pins are not implemented.

## Storage contract

The endpoint is an explicitly configured HTTPS URL for an existing bucket prefix or WebDAV collection. There is no provider allowlist, automatic provisioning, redirect following, ambient proxy or plaintext fallback. All remote names are flat namespace-prefixed opaque IDs; source names and file metadata stay encrypted by G1. Ciphertext hashes and part sizes can still reveal equality and size information within the admitted namespace.

| Capability            | Implemented contract                                                                                                                                                                                                                       |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Authentication        | S3 Signature V4 with configured region and optional session token; WebDAV Basic over verified TLS. Credentials have an explicit expiry and are excluded from serialized profiles/plans.                                                    |
| TLS and routing       | TLS 1.2 or later, CA and hostname verification; explicit endpoint, no redirects. Private CA roots may be supplied. Endpoint/egress admission remains the operator's responsibility.                                                        |
| Object size           | Configured physical part limit from 64 KiB to 8 MiB; a logical encrypted object is at most 8 MiB and at most 128 parts. Large original files consist of many G1 objects.                                                                   |
| Creation              | S3-compatible storage and the default WebDAV profile use conditional `PUT`. The explicit `webdav-move-1` profile uses verified staging and `MOVE` with `Overwrite: F`. Both require exact readback of the canonical object.                |
| Capability probe      | Fixed public diagnostic bytes check readback and refusal to replace a destination in the selected mode. An immutable layout record binds the part size. Incompatible endpoints and layout changes fail closed.                             |
| Resume and integrity  | Resume at verified physical-part boundaries. Part hash/length and reconstructed logical hash must match. No native provider multipart session or partial-range resume is required.                                                         |
| Ranges and listing    | Neither is required. Bounded read retries tolerate short visibility delays. Only the explicit MOVE profile requires a same-namespace move.                                                                                                 |
| Quotas and throttling | Local size admission, 413/507 capacity errors and bounded retries for 409/429/transient server errors. `Retry-After` affects all queues sharing the exact target profile in one worker process. The delay is bounded by credential expiry. |
| Bounds                | 1-4 concurrent requests, 1-1000 request admissions per second and 1-3 attempts per request. The timeout includes admission and backoff, with a maximum of 5 minutes and additional context and expiry bounds.                              |
| Retention and archive | No delete, listing-based GC or delayed-retrieval archive tier. Probes do not prove physical durability, future persistence or actual ACL restrictions.                                                                                     |

Admission requires the capabilities of the signed target profile. Run capability and failure tests against the actual endpoint before using it for backups. The current checks use synthetic endpoints.

Concurrent jobs share request slots and pacing for an exact signed profile in the same worker process. An in-process configuration refresh preserves the gate for retained profiles. Each queue keeps its own transport and privately resolves credentials. Distinct profiles use independent target gates and can also share a private account allowance.

### Private account allowances

In the local `outpost-bootstrap-2` file, `externalRequestBudgets` optionally defines an array of groups. Each group lists exact storage profile IDs in `targets` and sets `concurrency` from 1 to 4 and `requestsPerSecond` from 1 to 1000. Once configured, every key in `credentialFiles` must belong to exactly one nonempty group. Unknown, duplicate and unassigned targets block bootstrap before volume admission. Omit the field to keep the existing profile-only admission.

Set each group to the allowance allocated to this worker for that account. Requests must satisfy both target and account limits. A `Retry-After` response delays all targets in that group. Different groups remain independent. The private bootstrap owns the grouping. Shared jobs cannot increase it, and the group is never sent with plans or telemetry.

The account limit covers this worker process. Configuration refresh retains its state, and restart reopens the private bootstrap. Queues preserve their own durable retry deadlines. Coordinating slices across workers or constraining shared physical links requires separate evidence. Upgrade the worker before adding the option. An older strict bootstrap reader refuses the new field.

### Private link allowances

Use `externalLinkBudgets` to group credential-bearing target profiles that share this worker's external link. In each group set `targets` to the exact profile IDs and `bodyBytesPerSecond` to an integer from 65536 to 1073741824. The link groups independently partition every key in `credentialFiles` and can be configured together with account groups. Omit the field to keep the previous behavior.

Each group shares one allowance for reading outgoing request bodies and consuming incoming response bodies, including verification and retries. Reads reserve up to 32 KiB at a time. Short reads can leave some of a reservation unused. The existing request deadline includes time spent pacing. The transport can buffer bytes, and TLS, TCP, IP, peer replication and traffic from other processes are outside this allowance. The configured rate represents this process's share of the link. Measure a real shared link separately before choosing combined rates for several workers.

## WebDAV targets without conditional PUT

In the signed storage profile set `kind` to `webdav`, `writeMode` to `webdav-move-1`, and `maxStagingAttempts` to a value from 1 to 8. Keep `noDelete` enabled. Selecting this mode changes the target profile ID. Sign and distribute the matching target, placement and upload authorization together. The old profile has both new fields omitted.

Each worker saves a unique attempt name under its plan and target binding before writing ciphertext. It reads the temporary object back and compares the bytes before moving it to the final name in the same namespace. The request specifies `Overwrite: F`. The worker checks the final bytes before recording success. MOVE consumes only the worker's temporary resource. Protected objects never serve as the source of a move. A separate collision probe checks that an existing destination survives the operation. [RFC 4918, MOVE](https://www.rfc-editor.org/rfc/rfc4918.html#section-9.9) and [Overwrite](https://www.rfc-editor.org/rfc/rfc4918.html#section-10.6).

An uncertain write is read back before retrying. If the previous attempt still has no usable bytes after its request window, the worker saves a different name and retains the previous record. The local attempt book uses the worker's existing disk budget. A missing initialized book or exhausted staging limit blocks the operation while retaining the previous complete copies. Budget for possible temporary objects at the target, including residue from interrupted or competing attempts. The worker issues no `DELETE` requests. Use a separately authorized process for cleanup.

The mode keeps the same part, descriptor, catalog and complete-marker formats. A prior writer that does not recognize the profile fields refuses the configuration. The owner can recover existing ciphertext with a compatible reader and the same endpoint, namespace, part size, generation and keys.

## Complete generations and recovery

Completed immutable parts remain completed when assignment slots rotate. If a publication read discovers an absent part, only that part loses its local completion mark. Other verified progress survives. This prevents a slow executor from repeatedly restarting its completed prefix while preserving full publication checks. A delayed-slot test also physically removes an acknowledged fixture part and requires its independent reupload before recovery.

A part can become durable as its slot expires before the local acknowledgment is saved. Final verification requires the exact planned blob descriptors, then reconciles recorded part completion in the same transaction as the receipt. This resolves uncertain local acknowledgments without inventing submitted-byte counts. A valid target object cannot certify a different planned part map.

Workers upload and verify physical parts first, then seal immutable logical-object descriptors. Publication verifies **all** dependencies against the signed generation catalog, uploads that catalog and finally creates the per-generation complete marker. Each external target has its own closure and readiness; success elsewhere does not make this target complete. A complete marker is a hint, never proof by itself. `Catalog` validates the marker/catalog binding, while `Recover` fetches and validates every dependency. Worker completion defaults to the same full readback; explicit owner policy can use [original-age evidence](readback-reuse.md) for unchanged immutable objects. A false acknowledgment, truncated object or forged marker cannot create a verified complete replica.

Old generations and shared chunks remain immutable. A later version uploads missing ciphertext parts, while both versions remain recoverable. This is reuse of G1's chunked version format, not encryption of the whole original file as one object. No mutable `latest` pointer or listing is needed. Recovery needs a selected generation ID, public generation trust, target read credentials and the owner's file-kit key for final plaintext restoration. A retained recovery inventory must supply the IDs/keys; discovery and key escrow are separate work.

Minimal library sequence, using the admitted resources supplied by the caller:

1. Open complete G2 source replicas. Construct `storage.Profile`, including `Namespace = storage.Hash([]byte(domain + "/" + repository))`, endpoint, region where applicable and verified capability limits.
2. On the planner, call `upload.Build(ctx, source, generationID, plan, plannerKey)`. Supply `Format`, a fresh opaque `Operation`, profile, explicit placement, worker public keys/identities and timing. The function fills catalog/dependencies and signs the plan. Deliver the returned bytes and pinned public `upload.Authority` to each eligible worker; credentials and worker private keys travel separately.
3. Each worker calls `storage.New(profile, credentials, roots)` and `upload.Open(existingAbsoluteJournalDir, rawPlan, workerID, authority, true)`, then `journal.Run(ctx, source, backend, workerPrivateKey)`. Use `false` to reopen an initialized journal. The caller must provide a persistent directory with the documented G2 filesystem semantics and keep it on the admitted data volume. Close the backend when finished.
4. For recovery, open an empty G2 destination with the pinned public trust and call `backend.Recover(ctx, generationID, destination)`. Then export/restore the selected G1 file kit using the existing [generation API](generation-replicas.md). Recovery does not require the planner, original worker journals or other nodes.

Plans are limited to 16 MiB, 32768 distinct physical parts and 32 workers; journal state is limited to 8 MiB. Slots are 500 ms to 5 minutes. These are fail-closed prototype limits, not large-history acceptance. The APIs are internal and may change before a versioned product contract. Errors distinguish denied policy/credentials, conflicts, capacity, integrity, unsupported capability and retryable unavailability; cancellation/deadline errors remain visible. Error handling must not disable verification or release pins after failed work.

The diagnostic probe is reused across retries and process restarts. Existing probes verify conflict rejection and readback, but do not prove permission to create a new object, account ACLs or physical durability. Each payload still requires its own verified upload/readback. Older random probe objects are preserved; this change performs no remote cleanup.

## Independent external recovery

Keep a private `outpost-external-recovery-1` JSON file with `format`, `target` (the expected profile ID), `profile` (the exact storage profile), `credentialFile` (an absolute path to read-only credentials) and optional `caFile` (an absolute path to trusted PEM roots). The credential file uses `access`, `secret`, `expiresUnix` and optional `sessionToken` for S3-compatible access. Keep the recovery owner kit and public generation trust separately. The external namespace must match that trust.

```sh
outpost restore-external --bootstrap /private/external-reader.json \
  --key /private/recovery-owner.json --trust /private/generation-trust.json \
  --generation EXPECTED_CHECKPOINT --version EXPECTED_VERSION \
  --output /recovery/new-output
```

Omit `--version` to restore the selected generation. Use `--input` with the existing version-list or directory selection JSON for a narrower restore. The output must be a new directory under an existing parent. The command opens the exact complete marker and verifies the signed catalog, then reads the selected immutable dependencies. It publishes the restored tree atomically after validating and decrypting the selected content. It streams objects directly from the target and needs no source, control service, other worker or temporary ciphertext replica.

A successful selection proves the restored versions match the specified checkpoint. Directory selection reads the candidate file metadata to resolve paths. An explicit version selects its metadata directly. Missing or corrupt required data prevents publication. Other versions and current target health require their own evidence. The CLI receipt contains opaque identities and restored counts.

## Verify an external generation

```sh
outpost audit-external --bootstrap /private/external-reader.json \
  --trust /private/generation-trust.json --generation EXPECTED_CHECKPOINT \
  --output /private/new-external-audit.json
```

The audit uses the same read-only profile and public trust. It verifies the exact marker, signed catalog and every ciphertext dependency with fresh reads. `VERIFIED_CIPHERTEXT` means the complete closure was checked. If a dependency cannot be verified, the audit stops and returns a failure status. A private report records the original time window, verified count and first failed stage. The expected count is unknown until the catalog is authenticated. The outcome distinguishes missing content, invalid content, denied access, cancellation and an unavailable target.

The optional `--output` saves that typed report even when the verification fails. Choose a new path. The output excludes private names, credentials and remote diagnostic text. The audit grants no repair authority. Verify plaintext by restoring with the owner kit.

### Resume an audit of a retained upload

For a retained complete upload, the stopped worker can reopen a verification window from its queue. Use a private `outpost-worker-external-audit-1` JSON file containing `format`, a fresh opaque 64-character hexadecimal `window` and `maxAgeSeconds` from 1 to 31622400. Use the existing enrolled worker bootstrap and original upload operation ID.

```sh
outpost worker-external-audit-init --bootstrap /private/worker.json \
  --operation UPLOAD_ID --input /private/window.json
outpost worker-external-audit --bootstrap /private/worker.json \
  --operation UPLOAD_ID --input /private/window.json
```

Initialize once. The second command resumes the exact same window with its durable partial hash progress. A missing or changed scope prevents resumption. Both commands require the exclusive worker lease, current placement, the original complete queue receipt and the admitted local volume. Audit progress uses the telemetry allowance and remote reads stop on observed policy withdrawal. The report's `observedUnix` is the oldest supporting read. `finishedUnix` is the end of this invocation. A new window reads the data again. The original upload receipt remains historical.

## Repair a selected external copy

Build a fresh plan from a retained healthy holder's materialized ciphertext. The planner needs its private signing key, public generation trust and a private `outpost-upload-plan-request-1` JSON document. The document contains `format`, the expected public `planner` key and a `plan` template in `outpost-external-plan-1` format. Set the new `operationId`, exact `profile`, `allowExternal`, `allowedClasses`, eligible `workers` and the signed `startMillis`, `expiresUnix` and `slotMillis`. The builder supplies the catalog, blob map and signature.

```sh
outpost upload-plan-build --key /private/upload-planner.json \
  --trust /private/generation-trust.json --store /recovery/materialized-holder \
  --generation EXPECTED_CHECKPOINT --input /private/plan-request.json \
  --output /private/new-signed-plan.json
```

The command reads the selected signed catalog from `catalogs` and the ciphertext needed to describe multipart objects from `objects`. Keep these files private. It needs no mutable replica index or remote credentials. The plan binds exact object references. The worker checks that it holds a complete admitted source before execution.

The owner admits the signed plan as a fresh `upload` job in the current configuration. Use fresh target readback for repair by setting `cloudReadbackMaxAgeSeconds` to zero. Missing immutable data can be added with the existing create-only writes and checked again. A conflicting canonical object blocks completion and keeps its bytes. To replace that copy, authorize a separately provisioned target profile and verify independent restoration there before considering retirement. Original receipts retain their operation and observation time. Periodic external repair remains open.

## Evidence and remaining costs

Run `go test -count=1 ./...` and `go vet ./...` in the admitted Linux test environment. Point `TMPDIR` and `OUTPOST_TEST_ROOT` to its data volume; executable Go scratch may use a separate bounded tmpfs. The tests use ephemeral credentials, real loopback TLS and disk-backed independent S3-signature/WebDAV authentication handlers. No real storage account is contacted.

The 3 MiB fixture creates 52 physical parts, launches three actual worker processes, checks simultaneous uploads from distinct identities and verifies immutable duplicate handling. A separate case sends real SIGKILL during a part PUT, waits for survivors to complete, and restarts the killed process from its journal. Two generations restore independently with matching bytes, modes and hardlinks after source replicas are removed. Tests also inject missing parts, a forged complete marker, false success responses, lost replies after durable writes, corruption, truncation, quota errors, throttling including an overflowing retry hint, expired credentials/plans, wrong identities, policy exclusions, invalid TLS and redirects.

The fixture compares one and three workers with an injected 40 ms delay per part, logging elapsed times and the ratio. This establishes a controlled concurrency scenario; it does not certify real network throughput or the AT-14 infrastructure target. See the [G3 requirement-to-check trace](../g3-trace.json) for the precise tested subsets and open work.

Unsplit planning uses signed references; multipart planning reads uncached objects. Each upload attempt binds and pins the exact recorded complete source catalog, verifies payload when read and checks evidence for the full target closure before completion. The default reads all target payload; optional owner-controlled reuse is reported with its original age. A separate source scrub checks current source integrity. These reads can dominate cost, and the large-file delta-bandwidth target remains open.

Journal `SubmittedBytes` counts part payloads passed to upload attempts. The worker also measures HTTP body traffic for each attempt, including retries and verification reads. [Telemetry](telemetry.md#external-upload-attempts) explains the counters and their coverage.

Full network and cost accounting, real endpoint limits and ACLs, low-memory and large-history profiles, long partitions, power loss and heavy G1-G3 tests remain open. [Deployment holds](roadmap.md) require their own acceptance evidence.
