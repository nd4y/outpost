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

The interface has three primary journeys: inspect backup coverage and the last verified copy, preview/apply an owner-signed policy, and select a generation for authorized recovery with a visible result. Russian and English share the same state model. Native form controls, keyboard focus, non-color status labels, zoom and narrow-screen layout are required. Empty/offline/stale/forbidden/error states are tested independently. Restore selection never silently substitutes the latest generation.

Acceptance includes tenant/role isolation, replay and conflicting IDs, stale preview rejection, malicious reports, restart between audit/effect/result, quota/slow-client overload with a reserved stop path, stale-data display and an API consumer. UI/manual accessibility, real installation and target admission remain separate evidence. This contract grants no permission to expose a management port or change a running service.

## Implemented core and remaining integration

The current management candidate implements signed enrollment/revocation records, tenant/domain fences, owner-policy preview/apply, exact configuration retrieval, signed original-age reports and scoped node/job/generation/audit/operation views. The existing worker `control.Fetcher` uses `/v1/config/{node}` with the same mutual TLS and exact signed bytes. A relay needs an explicit recipient ACL and matching scopes. Command queue/execution, management service bootstrap and browser UI remain in development; command endpoints currently return `UNSUPPORTED`.

Enrollment and configuration changes retain an admitted audit intent before their effect. Configuration publication stages an immutable candidate, updates the existing monotonic authority cache and then commits the registry pointer/result. A cache/pointer mismatch is unavailable until the same operation reconciles it. Initial cache writes are quota-accounted. Node reports use two slots per node/domain; the signed pointer changes only after a slot is durable. Replays retain their original observation time. Revoked or changed enrollment makes a retained report stale, not empty or fresh.

Seven actual process-kill boundaries cover enrollment intent/result, report slot/pointer and configuration intent/cache/result. Short race checks also cover stale previews, operation conflicts, quota, retained tenant/epoch fences, foreign report/config scopes, duplicate JSON/query fields, oversized/deep bodies, encoded path aliases, CSRF and mixed-revision cursors. A real HTTPS consumer and the existing worker fetcher exercise the published paths. These tests do not yet accept slow-client stop handling, command execution, automatic crash reconciliation, installed services, UI accessibility or large-scale metadata cost.

Current admission bounds are 128 enrolled nodes, 128 retained domain fences, 2048 audited configuration/enrollment operations, 256 generations and 4096 jobs per scoped report and 8 MiB per signed report. Configuration keeps the existing 32 MiB limit. Large configuration/report requests have a separate single slot; metadata concurrency and request deadlines are explicit. Capacity remains unknown in preview without a matching volume estimate. Audit export/retention, larger inventories and journal-loss recovery need their own completed workflow before production capacity is claimed.

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
