# Management service contract

[Русский](../ru/management-api.md)

Design contract published before implementation under REQ-37/38/45. The [OpenAPI document](../management.openapi.json) uses [OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html). Endpoints are not accepted merely because this document exists. Peer object exchange keeps its existing independent protocol; the management service does not proxy payload or hold data-decryption keys.

The service stores owner-signed enrollment/configuration, bounded signed node reports, scoped commands and audit records. Workers keep executing admitted cached policy when it is unavailable. A report is an observation at its signed time; receiving it again never refreshes data age. Missing, stale, incomplete, corrupt and complete are separate states. Backup creation, target readback and successful trusted restore have separate fields and provenance.

## Identity and scope

TLS 1.3 with verified client certificates is mandatory. Principals are certificate public-key identities, explicitly assigned tenant/domain scopes and roles by private owner configuration. Roles are owner, operator, viewer, recovery and node. A trusted storage node is not automatically an owner or recovery principal. Node identities can report/fetch only their enrolled scope. Unknown or revoked identities fail closed. A relay requires an explicit per-recipient grant and cannot alter signed documents.

Enrollment carries an owner signature, monotonic revision, tenant, node identity, approved domain/repository epochs and capability declarations. Capability statements are not acceptance evidence. The service never generates or returns a node private key, storage password or owner recovery kit. Configuration publication still requires the existing owner signature. Operator commands cannot add a route, target, credential, decrypt permission or maintenance authority.

Every request and response is bounded. Lists use a revision-bound cursor and bounded page size. Unknown query parameters, encoded path aliases, duplicate critical fields and unsupported formats are rejected. Error bodies use stable codes and opaque operation IDs, without filesystem paths or provider responses. Requests for another tenant/domain are indistinguishable from unavailable objects. Browsers use the same authenticated origin; mutations require an exact Origin match and a non-simple request header. No wildcard CORS, ambient cookie credential or third-party script is used.

## Durable changes

Every mutation carries an operation ID and reason code. Retrying identical content returns the recorded result; the same ID with different content is a conflict. The service persists an admitted audit intent before the effect, then reconciles the effect before marking the result complete. Lost replies do not create another operation. Quota exhaustion blocks a new mutation without deleting old audit, commands, configuration or backups.

Configuration preview returns the exact candidate digest, current revision and changed recipients/routes/targets. Volume/capacity estimates are explicitly unknown when no matching observation exists. Apply requires that digest and expected current revision; stale previews fail. Tightening takes effect through a new signed policy and normal worker cancellation. It does not claim erasure from an untrusted administrator's disk.

Commands are limited to admitted operations: retry, pause, resume, scrub and an explicitly authorized recovery/maintenance request. Workers persist an execution receipt before acknowledging completion and check current local owner policy again at execution. Pause preserves intent and pins. Recovery uses a locally enrolled trusted preset and opaque selection IDs; the service cannot supply paths, keys or arbitrary programs. Physical deletion additionally requires the separate signed maintenance plan. No command creates a replacement authority when an existing grant expires.

## Reports and UI

Signed reports identify node, tenant, configuration revision, sequence and original observation time. A higher report sequence cannot move observation time backwards. Equal sequence with equal bytes is idempotent; changed bytes or an older sequence is a conflict. The service preserves a last-known report through an outage and labels its age. Epoch reset requires explicit owner admission, never automatic sequence reset.

### Retention coverage preview

`POST /api/v1/tenants/{tenant}/domains/{domain}/retention/preview` accepts an `outpost-retention-coverage-request-1` from an owner or operator scoped to the domain. Supply sorted unique `nodes`, their `retiringNodes` subset, `generations`, and a `minimumCopies` threshold. One request evaluates up to eight nodes and 64 generations at one registry revision. The usual `X-Outpost-Request` header applies.

The preview counts distinct, currently enrolled trusted holders outside the retirement set. Their signed reports must match the current owner configuration and repository epoch, show an explicit pin and a complete copy, and carry a fresh ciphertext verification time. The response lists the signed report digest and original observation and verification times. Matching evidence can meet the requested threshold, while missing evidence and conflicting catalog observations are shown separately. The response always carries `authorization: NONE`. Actual retention requires separate admission and pins that remain in force during execution. Physical failure-domain independence and external copies are outside this preview.

#### Protect a surviving generation on a holder

Prepare an `outpost-retention-protection-1` grant with `node`, `domain`, `repository`, `epoch`, `operationId`, `generation`, `action: HOLD` and a validity window (`notBefore`, `expiresUnix` in Unix seconds, up to 24 hours). Sign it with `outpost retention-protection-sign --key PRIVATE_MAINTENANCE_KEY --input PRIVATE_GRANT --output NEW_SIGNED_GRANT`. Apply it on the stopped trusted holder with `outpost replica-retention-protect --bootstrap FILE --domain ID --input SIGNED_GRANT`.

The holder rereads and verifies the complete ciphertext before committing the pin and its signed `HELD` receipt together. The pin prevents local retirement even after a restart or grant expiry. To remove it, sign and apply a `RELEASE` grant for the same scope, operation and generation, with `holdDigest` copied from the `HELD` receipt. The holder records a signed `RELEASED` receipt. Identical retries return the original signed receipt with its original observation time while that action remains current. A released operation cannot be held again. The index retains up to 256 operation records, including released ones. Keep a reader that supports these records when reopening the replica.

These local operations prepare protection on individual holders. The distributed coordinator must still prove sufficient pinned survivors and keep their holds in force throughout retirement.

The interface has three primary journeys: inspect backup coverage and the last verified copy, preview/apply an owner-signed policy, and select a generation for authorized recovery with a visible result. Russian and English share the same state model. Native form controls, keyboard focus, non-color status labels, zoom and narrow-screen layout are required. Empty/offline/stale/forbidden/error states are tested independently. Restore selection never silently substitutes the latest generation.

Acceptance includes tenant/role isolation, replay and conflicting IDs, stale preview rejection, malicious reports, restart between audit/effect/result, quota/slow-client overload with a reserved stop path, stale-data display and an API consumer. UI/manual accessibility, real installation and target admission remain separate evidence. This contract grants no permission to expose a management port or change a running service.

## Implemented core and remaining integration

The current management candidate implements signed enrollment/revocation records, tenant/domain fences, owner-policy preview/apply, exact configuration retrieval, signed original-age reports and scoped node/job/generation/audit/operation views. The existing worker `control.Fetcher` uses `/v1/config/{node}` with mutual TLS and exact signed bytes; a relay needs a recipient ACL and matching scopes. The command queue now exposes admission, node-only retrieval and signed execution receipts. Worker pause/resume, blocked-job retry, ciphertext scrub and separately authorized local maintenance are connected. Trusted recovery execution, the protected management service and [browser operator journeys](management-ui.md) have isolated checks. Lifecycle and installed-service acceptance remain open.

Enrollment and configuration changes retain an admitted audit intent before their effect. Configuration publication stages an immutable candidate, updates the existing monotonic authority cache and then commits the registry pointer/result. A cache/pointer mismatch is unavailable until the same operation reconciles it. Initial cache writes are quota-accounted. Node reports use two slots per node/domain; the signed pointer changes only after a slot is durable. Replays retain their original observation time. Revoked or changed enrollment makes a retained report stale, not empty or fresh.

Seven process-kill boundaries cover enrollment, reports and configuration; three more cover the worker reporting journal, four cover command publication/acknowledgement, and seven cover worker command execution/format migration. Short race checks include tenant/role isolation, lost/false replies, quota, stale policy/cursors, invalid HTTP input and a reserved command lane under report/inventory congestion. The pause test joins an active TLS transfer while the controller fetch is blocked. These checks do not accept a production installation, UI accessibility or large-scale metadata costs. [Automatic registry reconciliation](management-service.md#pending-operations) has separate bounded restart checks.

Current admission bounds are 128 enrolled nodes, 128 retained domain fences, 2048 audited configuration/enrollment/command operations, 256 generations and 4096 jobs per report, and 8 MiB per signed report. Configuration retains its 32 MiB limit. Command pages contain at most 32 envelopes and 5 MiB of signed payload, keeping the encoded response below 8 MiB. Large configuration/report requests and command requests have separate slots. Preview capacity remains unknown without a matching volume estimate. Audit export/retention, larger inventories and journal-loss recovery remain open.

## Durable worker reports

The reporting client uses pinned mutual TLS, no proxy or redirects and bounded replies. It verifies the exact report digest and original observation time in the acknowledgement. A signed local journal retains one pending report per domain before sending; losing the reply or restarting sends exactly those bytes again. Three process-kill boundaries cover local enqueue, remote acknowledgement and durable local acknowledgement. Explicit owner-signed enrollment renewal preserves the counter and may supersede obsolete telemetry. Missing/corrupt state is not initialized automatically. Network I/O holds a separate delivery lease so local status and renewal remain available.

Worker snapshots read the admitted held filesystem, authenticated generation catalogs and actual job state. `COMPLETE` records publication, while `verification: NONE` and zero verification time explicitly mean no known payload-read timestamp. Logical size and transfer progress are null when unavailable. `inventoryState: UNAVAILABLE` differs from an observed empty inventory. The worker refuses to claim a newly cached configuration is already applied. Physical/free bytes describe the whole volume; `accountedBytes` is the separate conservative Outpost ledger. No data-decryption key is used.

Reporter files are charged to the worker telemetry allowance. A full queue/quota blocks reporting without mutating accepted backup jobs or spending backup spool allowance. The report retains up to all 4096 worker jobs; exceeding a bound never silently truncates it. Large reports can require more than the minimum telemetry allowance. Typed transport JSON accepts normal whitespace and field order while rejecting duplicates/unknown fields; embedded signed documents retain canonical byte validation. New unknown-value fields are a candidate format extension: old strict readers are not a supported downgrade until migration acceptance.

## Reporting process and local profile

After explicit worker initialization and owner-policy acceptance, provision an owner-signed management enrollment and a private report profile. The management registry must independently admit the same enrollment. The example uses placeholder opaque IDs; substitute the actual service SPKI and domain, and protect the profile/enrollment/key files with private permissions. The worker bootstrap supplies the existing volume binding, TLS identity and CA. No new listener or data-decryption permission is created.

```json
{
  "format": "outpost-report-profile-1",
  "endpoint": "https://control.example",
  "identity": "1111111111111111111111111111111111111111111111111111111111111111",
  "domain": "2222222222222222222222222222222222222222222222222222222222222222",
  "enrollmentFile": "/run/secrets/report-enrollment.json",
  "schedule": {
    "format": "outpost-report-dispatch-1",
    "revision": 1,
    "enabled": true,
    "intervalSeconds": 60,
    "retrySeconds": 10,
    "attemptSeconds": 5
  }
}
```

```sh
outpost management-enrollment-sign --key /private/owner.json --input /private/enrollment.json --output /private/signed-enrollment.json
outpost worker-report-init --bootstrap /private/worker.json --input /private/report.json
outpost worker-report-status --bootstrap /private/worker.json --input /private/report.json
outpost worker-report-loop --bootstrap /private/worker.json --input /private/report.json
```

`worker-report-loop` runs in the foreground as a separate supervised process from `worker-run`. Missing state is an error: only `worker-report-init` initializes the queue. Reporting failures do not stop the backup process. Status includes the original queued/acknowledged observation, enrollment activity and persisted dispatch phase/deadline/error code. Intervals/retries coalesce missed observations rather than reconstructing data that was never observed.

To pause or resume, change `enabled`, increase the schedule revision and run `worker-report-set` with the same bootstrap/profile arguments. Pause cancels and joins active HTTPS while retaining the pending bytes. Retry deadlines are persisted before I/O and survive restart. Changing the profile file alone does not change the persisted schedule or grant. Apply a new owner-signed enrollment explicitly with `worker-report-renew`; snapshot revision fencing prevents observations made under the previous grant from being relabeled. Reporting uses an independent existing-budget handle and cannot reconcile another process's live reservations.

## Command authority and completion contract

Command execution requires a separate owner-signed authority naming the service public key, worker, tenant/domain/repository and writer/authority epochs, permitted command kinds and validity. The service and worker keys are distinct. The exact grant must be admitted by current owner policy; operator roles cannot introduce a grant or expand that policy. Requests carry an expected configuration revision, stable operation/reason and opaque selections. A path, program, credential or recovery key is never a request field. Maintenance carries its separate domain permit; recovery identifies a locally provisioned trusted preset.

The service signs an envelope binding the original actor, node, sequence, configuration digest and request. It limits the execution deadline to the grant/policy lifetime and at most 24 hours after admission. HTTP admission is distinct from completion. A node-signed execution acknowledgement binds the exact envelope, actual start/observation times and result digest. A completed pause/resume also names an applied control revision. Expired unexecuted work may report failure; it cannot report successful execution after the admitted deadline. Historical signature verification remains available after expiry without reactivating authority.

The registry first saves the request and its original actor/policy audit intent, then the signed envelope and publication pointer. An unpublished earlier intent blocks later delivery. All mutation types share the operation-ID collision fence and quota. Admission returns 202; only a valid node-signed result marks execution complete. Queue expiry alone never invents a failed execution because an acknowledgement may have been lost. Pages use scoped revision-bound cursors; restart from the first page after an acknowledgement or cursor conflict.

## Worker command runtime

New workers use `outpost-worker-2`. Its signed control state stores domain/job holds, command sequence fences, original execution acknowledgements and polling deadlines. The worker cancels and joins the previous view before acknowledging an applied control revision. Holds also cover ingress, inventory, observations and autonomous discovery. A new policy or process restart preserves them; replaying an old pause after resume returns the original receipt without applying pause again. Current executable kinds are `pause`, `resume`, `retry`, `scrub`, `maintenance` and explicitly enrolled [trusted restore](trusted-recovery.md).

`worker-controls-migrate --bootstrap FILE` upgrades legacy worker1 under the execution lease, retains an exact state backup and commits the new format atomically. It refuses a running worker. `worker-controls-rollback` preserves current jobs but refuses command history, pending effects or holds. An old reader rejects worker2. Missing command state is not silently initialized. A signed receipt cannot establish physical erasure or compliant behavior by an untrusted administrator.

`command-authority-sign --key OWNER_KEY --input AUTHORITY --output NEW_FILE` prepares a grant; its exact bytes must also be in the signed node configuration. `worker-command-apply --bootstrap FILE --input SIGNED_ENVELOPE` admits a locally supplied signed envelope. A long operation returns `QUEUED` with `completed: false`; a completed operation returns its original durable node receipt. `worker-command-once` and `worker-command-loop` take `--bootstrap FILE --input COMMAND_PROFILE` and use the authenticated HTTPS queue. The loop runs as a separate foreground process, keeps retry deadlines across restart and resumes the same pending operation. Backup execution remains independent. `worker-status` exposes the original command records and delivery state.

The private `outpost-command-profile-1` profile contains `endpoint`, pinned service `identity`, an absolute `enrollmentFile`, `pollSeconds` and `retrySeconds` (1-3600) and `attemptSeconds` (1-300). Bootstrap supplies TLS files and the admitted volume. Profile/enrollment replacement requires restarting this local process; remote commands cannot change endpoint, files or trust. Loss of a reply repeats the stored acknowledgement. If an accepted effect cannot be confirmed before its deadline, the result is `EFFECT_UNCONFIRMED`; durable holds are preserved for explicit reconciliation.

A reopened execution process installs the existing quota before recording an applied control revision. An exhausted journal budget preserves the pending hold and cannot produce a successful acknowledgement.

A retry requires the existing job to be `BLOCKED` and still match the current owner policy. It preserves domain/job holds and upload pins. Upload retry atomically records a bounded one-time token in `outpost-upload-queue-2`; older queue readers reject this format. The worker stores its queued job and signed command result in one state write. A crash between the two journals resumes the same token, and replay after later completion cannot restart the upload. Local `worker-retry` uses the same transaction and refuses to overtake a pending signed retry. Retry completion means the scheduling action was applied; backup completion still requires the job receipt. Expired upload plans and missing/corrupt journals are not silently renewed or recreated.

Command queue format `outpost-management-commands-2` delivers pause/resume before work commands and preserves sequence order within each group. Cursors bind this ordering version; old cursors and old queue readers fail closed. Workers keep independent control/work replay fences, so a later pause does not invalidate earlier work that has not arrived. At most one unfinished control command and 32 unfinished work commands are admitted. Scrub and local maintenance use the bounded asynchronous runtime; trusted recovery uses a separately enrolled private executor.

## Long operations and their observations

`scrub` and `maintenance` share the backup executor's concurrency limit, cancellation and join boundary. The command poller can continue fetching priority pause/resume requests while work is running. Scrub requires an already published generation, reads fresh ciphertext in batches of at most 16 objects/64 MiB and persists progress. It does not turn a receiving generation into a complete backup. A successful result retains the original verification time and digest; replay is historical, not a new scrub. Corruption produces a failed result and preserves the bytes. Quarantine and authorized automatic repair are described in [integrity and repair](integrity-repair.md).

Maintenance additionally verifies the separate domain maintenance signature, exact command operation ID and replica revision. The service transports a bounded opaque permit; admission alone does not validate or execute deletion. The worker rechecks current command authority before retirement and each removal. It retains current complete/receiving dependencies, pins and the latest complete generation. Frozen candidates and an original durable outcome survive a crash between replica work and the node acknowledgement. See [local GC replay and format compatibility](generation-replicas.md). Neither expiry nor a failed/interrupted result proves that no partial effect occurred; `EFFECT_UNCONFIRMED` requires reconciliation.

For a planned window, the maintenance signer runs `outpost maintenance-permit-sign --key PRIVATE_MAINTENANCE_KEY --input PRIVATE_PERMIT --output NEW_SIGNED_PERMIT`. Use format `outpost-maintenance-permit-2` with the ordinary domain, repository, writer epoch, replica revision, operation and retirement list. Include a `window` object with `node`, `startUnix` and `expiresUnix`. Start is inclusive, expiry is exclusive and the window can last at most 24 hours. The worker persists the admitted command before the window and can run it from its signed configuration cache with the center offline. It checks the exact node, current command admission and window before retirement and each deletion. Policy changes, pauses, protected references and expiry can stop the work. A new attempt outside the window requires new authority; historical results remain readable. Enable this format only after updating every executable that can open the replica for maintenance. Older readers cannot validate the new signed permits in the retention ledger.

Use `outpost replica-maintenance-preview --bootstrap FILE --domain ID --input PRIVATE_SELECTION --output NEW_PERMIT_DRAFT` on a stopped worker to calculate candidates. The input format is `outpost-retention-selection-1` with `operation`, `keepLatest`, `olderThanUnix`, `maxRetire`, `startUnix` and `expiresUnix`. The preview reads signed catalog dates and keeps at least the requested number of latest complete generations, all local pins and all unfinished receptions. It selects the oldest eligible generations up to the limit. It leaves the index intact and writes no draft when the candidate list is empty. The draft carries the exact local revision and node. Review the required copies on other nodes separately before signing. The worker checks the revision and all protected references again during execution.

An unstarted expired command obtains a signed terminal result even when no active policy can start the executor. Interrupted work is reconciled under the exclusive execution lease. Command-process cache writes use the existing shared spool budget without taking execution ownership or reconciling another process's reservations.

Reports with long-operation observations use `outpost-management-report-2` and report views use `outpost-management-report-view-2`; v1 reports remain readable and are still emitted when no command observations are present. Older consumers reject v2 instead of silently dropping fields. The independent `commands` collection contains at most 2048 entries and does not share IDs or progress with backup jobs. `GET /api/v1/tenants/{tenant}/nodes/{node}/domains/{domain}/command-status` paginates it with the signed report's original observation time and stale/current state. Cursors bind the report digest, scope and route.

Each observation identifies its envelope, phase, attempts, next retry and original completion time. Scrub includes object progress and original ciphertext verification time; maintenance includes its historical bounded outcome. The result digest identifies the actual durable worker result. A node report is an observation, distinct from the management audit's signed execution acknowledgement; it cannot certify an untrusted administrator's behavior or refresh whole-generation integrity merely because the report arrived recently. Tenant/domain selection occurs before reporting. Ordinary workers receive no data or maintenance private keys.

Periodic ciphertext verification is governed by the signed domain schedule described in [integrity and repair](integrity-repair.md). Its first durable admission promotes local state to worker3 while retaining signed controls. CLI worker status includes bounded per-generation scrub phase, progress and original verification time. Signed generation reports use that time only while the matching publication remains healthy; command observations remain separate. Control migration cannot downgrade worker3 or discard its journal.

Restore commands promote worker state to worker4 and reports to report3. Command-status page version 2 and report view 3 carry the bounded opaque result and explicit cleanup status. Selected decryption never refreshes generation-wide health. See [trusted recovery](trusted-recovery.md) for private enrollment, cancellation, replay and remaining limits.

Unreadable catalogs are isolated and repaired through existing authorized routes. Report4/view4 and generation page2 explicitly mark unavailable metadata while retaining healthy history. Diagnosis writes respect shared quotas and foreign reservations. See [catalog repair](integrity-repair.md#unreadable-catalogs).

The [private management service](management-service.md) now exposes the API from an enrolled volume with mTLS, shared quota, a revision-bound local ACL and automatic intent reconciliation. Its status command preserves foreign reservations. Actual process-kill and CLI checks retain original receipts after restart; deployment, UI and journal lifecycle remain separate acceptance work.

The scoped `GET /api/v1/tenants/{tenant}/nodes/{node}/domains/{domain}/policy` contract supplies the browser with selected-domain assignments, opaque sources, node classes, external-target protocols and command grants usable by the current actor. It omits private paths, endpoint URLs, credentials and unrelated domains. The response is bounded to 2 MiB, distinguishes active from historical inactive policy, and never certifies copy coverage. Grants are not a replacement for fresh mutation authorization; a viewer receives no command grants. See the `DomainPolicy` OpenAPI schema.

Owner-only resolution preview and mutation are described in the [service lifecycle](management-service.md#resolving-unpublished-intents). Original request receipts may be `ABANDONED`; the independent resolution receipt is `COMPLETE`. Both remain scoped and separately audited. This path never represents a worker execution acknowledgement.

Version5 [external-copy observations](external-copy-reporting.md) now carry original-age S3-compatible/WebDAV readback receipts. Unknown/missing proof and legacy-report support remain explicit; these observations do not assert current cloud health.

Report6 and view6 carry the latest scoped scheduled audit alongside that historical receipt, with separate observation and expiry times.
