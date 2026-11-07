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
