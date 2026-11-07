# Private management service

[Русский](../ru/management-service.md)

The Linux management process serves the [operator API](management-api.md) over mutual TLS and reconciles admitted registry operations after restart. It uses an explicitly enrolled local volume, shared persistent quota and a process lease. It does not need a data-decryption key. The browser interface and packaged installation are separate work in progress.

## Local enrollment

Prepare a private `outpost-management-service-1` JSON profile, readable only by its owner. `local` uses the worker bootstrap2 fields for the runtime directory, volume binding, service identity, owner public key and certificate/key/CA files. Its control endpoint, worker listener, storage CA and storage credentials must be absent. The service certificate key is Ed25519 and signs the management journal; it must differ from the owner configuration-signing key. The certificate chain and server name must validate against the configured origin and CA.

The outer profile also contains a positive `revision`, explicit IP/port `listen`, HTTPS `origin`, current `principals`, optional scoped `relays`, disk-budget `limits`, `concurrency` (1-8), `timeoutMillis` (100-10000), `reportMaxAgeSeconds` (1-86400) and `reconcileSeconds` (1-3600). Principals have opaque actor IDs, roles and exact tenant/domain scopes. These values are private local enrollment, never remotely supplied jobs. Ordinary backup workers do not become management owners.

Enroll the empty volume with the existing `volume-probe` and `volume-enroll` commands, using the service's certificate public-key identity as scope. Choose a new runtime subdirectory beneath it, then run:

```sh
outpost management-init --input /private/management.json
outpost management-status --input /private/management.json
outpost management-run --input /private/management.json
```

Initialization does not open a listener. An existing runtime, lost journal or missing volume marker is never silently initialized. Retain an independent copy of the owner configuration, private profile, certificate material and registry backup; these commands are not journal-loss recovery. The process needs write access only to its enrolled runtime and read access to its own private files. No shell commands come from the API.

## Restart and local changes

`management-run` holds the execution lease, reconciles the budget against retained files, opens the configured TLS listener and performs bounded registry reconciliation. Requests have body/header/deadline/concurrency bounds, and live sockets are limited before TLS admission. Commands keep their separate request lane. The process checks the volume and admitted profile while running. Volume replacement/loss or invalid local state stops serving; cancellation closes the listener and joins active requests.

`management-status` reads the profile and budget without reconciling another process's active reservations. It reports admitted identity/revision and measured budget state, not successful backup or listener readiness. `management-reconcile` performs one local bounded pass under the execution lease. Do not run this mutating command as a health probe.

Stop the running process before applying a local ACL/listener change. Prepare a higher profile revision and run `management-profile-set --input /private/management.json`, then restart. An identical replay is harmless; lower or changed same-revision profiles are refused. Old profiles cannot start or report current state after the new revision is accepted. Renew certificate material under the same admitted identity and restart; identity migration is a separate operation. Service stop/restart and network changes require the environment owner's deployment authorization.

## Pending operations

Reconciliation reads signed registry intents in original sequence order, at most 64 per pass. It uses the current local ACL for the original actor and the current signed policy before creating an effect. Removed roles, expired authority, changed candidates and exhausted quota remain explicit blocked intents. Paging prevents a blocked early intent from starving unrelated later reconciliation; delivery still cannot overtake an unpublished earlier command.

An exactly matching, already-durable configuration cache can finish its original registry receipt without reapplying the policy, even when the original actor has since been removed. This confirms a previous local effect. It does not grant new access or certify execution by a node. Command publication stays `ADMITTED` until a valid node acknowledgement arrives. Historical completed receipts keep their original timestamps. Reconciliation deletes neither intents nor audit evidence.

Short isolated checks cover current/revoked roles, quota, candidate corruption, cancelled contexts, original receipts and actual process-kill recovery without replay from the original client. Full installation, journal export/retention and recovery, explicit resolution of permanently blocked intents, UI accessibility and admitted-scale operation remain acceptance work.

The same authenticated origin serves the [embedded interface](management-ui.md). Shutdown closes new application admission before joining handlers. After the three-second grace period, silent TLS sockets are closed; a successful forced close is an orderly stop. Independent state or close errors remain errors. Handler completion still depends on operating-system I/O; an uninterruptible device stall is not certified by these short tests.
