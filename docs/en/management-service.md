# Private management service

[Русский](../ru/management-service.md)

The Linux management process serves the [operator API](management-api.md) over mutual TLS and reconciles admitted registry operations after restart. It uses an explicitly enrolled local volume, shared persistent quota and a process lease. It does not need a data-decryption key. The embedded browser interface has isolated journey checks; packaged installation and full product acceptance remain open.

## Local enrollment

Prepare a private `outpost-management-service-1` JSON profile, readable only by its owner. `local` uses the worker bootstrap2 fields for the runtime directory, volume binding, service identity, owner public key and certificate/key/CA files. Its control endpoint, worker listener, storage CA and storage credentials must be absent. The service certificate key is Ed25519 and signs the management journal; it must differ from the owner configuration-signing key. The certificate chain and server name must validate against the configured origin and CA.

The outer profile also contains a positive `revision`, explicit IP/port `listen`, HTTPS `origin`, current `principals`, optional scoped `relays`, disk-budget `limits`, `concurrency` (1-8), `timeoutMillis` (100-10000), `reportMaxAgeSeconds` (1-86400) and `reconcileSeconds` (1-3600). Principals have opaque actor IDs, roles and exact tenant/domain scopes. These values are private local enrollment, never remotely supplied jobs. Ordinary backup workers do not become management owners.

Enroll the empty volume with the existing `volume-probe` and `volume-enroll` commands, using the service's certificate public-key identity as scope. Choose a new runtime subdirectory beneath it, then run:

```sh
outpost management-init --input /private/management.json
outpost management-status --input /private/management.json
outpost management-run --input /private/management.json
```

Initialization first records the exact signed pending profile and admits it only after the initial registry is durable. The listener remains closed until `management-run` accepts the admitted profile. If installation was interrupted after the pending profile was recorded, repeat `management-init` with the same profile on the original bound volume. The command preserves the original initial registry bytes when available, reconciles pending quota reservations, and rejects a changed profile or an existing registry without the pending record. Use the separate [journal repair procedure](management-snapshots.md) after an admitted registry is lost.

Retain independent copies of the owner configuration, private profile, certificate material and registry backup. The process needs write access only to its enrolled runtime and read access to its own private files. API requests carry typed operations.

## Restart and local changes

`management-run` holds the execution lease, reconciles the budget against retained files, opens the configured TLS listener and performs bounded registry reconciliation. Requests have body/header/deadline/concurrency bounds, and live sockets are limited before TLS admission. Commands keep their separate request lane. The process checks the volume and admitted profile while running. Volume replacement/loss or invalid local state stops serving; cancellation closes the listener and joins active requests.

The periodic pass also publishes owner-staged [retention steps](management-api.md#require-surviving-copies-in-the-signed-domain-policy) when prerequisites are present. It retains the original operation ID and rechecks the current local ACL and policy. It carries signed inputs supplied by the owner, including the separate maintenance signature. An isolated test drives the staged HOLD, retirement, CLOSE and RELEASE through the worker executor and signed reports. The retirement case verifies removal of the old catalog and its unshared objects, while the newer head and the survivor copy remain complete. The expiry case interrupts retirement before publication and uses the normal command poller to deliver CLOSE and RELEASE after the signed window ends. Both copies of the old generation remain complete and the survivor hold stays in place until the signed release.

`management-status` reads the profile and budget without reconciling another process's active reservations. It reports admitted identity/revision and measured budget state, not successful backup or listener readiness. `management-reconcile` performs one local bounded pass under the execution lease. Do not run this mutating command as a health probe.

Stop the running process before applying a local ACL/listener change. Prepare a higher profile revision and run `management-profile-set --input /private/management.json`, then restart. An identical replay is harmless; lower or changed same-revision profiles are refused. Old profiles cannot start or report current state after the new revision is accepted. Renew certificate material under the same admitted identity and restart; identity migration is a separate operation. Service stop/restart and network changes require the environment owner's deployment authorization.

## Pending operations

Reconciliation reads signed registry intents in original sequence order, at most 64 per pass. It uses the current local ACL for the original actor and the current signed policy before creating an effect. Removed roles, expired authority, changed candidates and exhausted quota remain explicit blocked intents. Paging prevents a blocked early intent from starving unrelated later reconciliation; delivery still cannot overtake an unpublished earlier command.

An exactly matching, already-durable configuration cache can finish its original registry receipt without reapplying the policy, even when the original actor has since been removed. This confirms a previous local effect. It does not grant new access or certify execution by a node. Command publication stays `ADMITTED` until a valid node acknowledgement arrives. Historical completed receipts keep their original timestamps. Reconciliation deletes neither intents nor audit evidence.

Short isolated checks cover current/revoked roles, quota, candidate corruption, cancelled contexts, original receipts and actual process-kill recovery without replay from the original client. Private journal export and historical inspection have isolated checks. Full installation, active recovery, retention, published-command uncertainty, manual UI accessibility and admitted-scale operation remain acceptance work.

The same authenticated origin serves the [embedded interface](management-ui.md). Shutdown closes new application admission before joining handlers. After the three-second grace period, silent TLS sockets are closed; a successful forced close is an orderly stop. Independent state or close errors remain errors. Handler completion still depends on operating-system I/O; an uninterruptible device stall is not certified by these short tests.

## Resolving unpublished intents

An owner may explicitly abandon an admitted intent only when the registry can prove that it has not published an effect. Read `/api/v1/tenants/{tenant}/operations/{operation}/resolution` for the current eligibility and original request digest. POST to the same path with a new resolution operation identifier, that exact `targetRequestDigest` and reason `ABANDON_UNPUBLISHED`. Preview is advisory; the locked mutation repeats authorization and effect checks. This is not a generic cancel or a claim that a published command never ran.

Commands with a published envelope cannot be abandoned, even if no worker acknowledgement exists. A configuration whose candidate reached the durable cache cannot be abandoned; reconcile its original receipt. Enrollment effects and receipts are committed together. Missing, corrupt or ambiguous effect state blocks resolution. Current owner scope must cover every original domain. A different owner can resolve an expired or revoked actor's unpublished intent without reauthorizing its original effect.

Successful resolution retains the original request and audit, appends a separate owner audit action and makes the original receipt `ABANDONED`. Replaying the exact original request returns that receipt and cannot publish it. The resolution has its own durable `COMPLETE` receipt and idempotency binding. Later queue entries may proceed past the abandoned unpublished intent. Backups, source data, signed policy and payload blobs are not removed.

The first resolution promotes registry1 to registry2 and retains an immutable exact registry1 checkpoint within the same admitted volume budget before publication. Older readers reject registry2. That checkpoint is evidence and recovery material, not permission to restore an earlier state and forget abandonment fences. There is no automatic downgrade after resolution. Crash, quota, replay, scope and publication-race tests must pass before this candidate is accepted. Never-admitted browser requests use the explicit refusal below; archive retention and whole-environment recovery remain separate work.

The implemented resolution path has isolated race checks for authorization, original replay, later queue delivery, a concurrently published command and both configuration persistence boundaries. Real process-kill checks cover the legacy checkpoint and abandonment commit. Browser checks refuse published commands and retry an actual lost resolution response from a full local journal. These checks establish the bounded path, not journal-loss recovery or production admission. POST input is limited to 4 KiB.

A stopped service can now export and independently inspect a [private management snapshot](management-snapshots.md). The reader recovers historical audit and receipts without replay; active journal-loss recovery and retention remain open.

## Never-admitted request refusal

A browser can retain an exact command or signed configuration that never reached admission. HTTP404 alone cannot close that record: an earlier delivery can still be in flight. An owner first POSTs the retained `UnseenRequest` to `/api/v1/tenants/{tenant}/operations/{operation}/refusal-preview`, then explicitly confirms with `UnseenResolutionRequest` at the sibling `/refusal` route. The latter contains `resolution` (the existing three-field resolution request) and `original` (node plus exactly one command or signed configuration mutation). The body limit is twice the larger signed-config/command limit plus4KiB; role rejection precedes body reading.

The registry must already have an admitted healthy signed journal copy and matching primary/anchor. Under the same lock as ordinary admission, first refusal checks current owner/tenant/domain scope, active enrolled node, repository fences, exact request proof and both unused identifiers. Old execution grants may have expired; refusal publishes no executable work. Already admitted or published requests cannot enter this branch. The normal resolution path remains separate. Missing/corrupt initialized history fails closed.

One signed registry commit records a target `ABANDONED` receipt, a separate resolution `COMPLETE` receipt and `ABANDON_UNSEEN` audit action. There is no intermediate runnable `ADMITTED` request. Original and resolution identifiers remain unavailable to enrollment, configuration, commands and retention admission. Identical retries and both receipt reads retain original times. The first refusal promotes registry1/2 to registry3 and preserves the exact signed predecessor; old readers reject it. Predecessors are inspection evidence, never an active downgrade that could discard permanent fences.

Metadata snapshots include both receipts, the audit, exact request/candidate blobs and the predecessor. Missing proof prevents a complete export or journal repair; it does not erase a surviving signed fence. A local copy and anchor do not establish freshness after replacing the entire environment with an older backup: independent owner checkpoints and service fencing still govern active recovery. Whole-volume takeover, bounded audit retention and installed-service admission remain separate.
