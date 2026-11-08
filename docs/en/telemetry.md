# Durable telemetry contract

[Русский](../ru/telemetry.md)

The worker has a separate, bounded OTLP/HTTP JSON outbox and foreground process. Short isolated checks cover durable positions, process interruption, scope revocation, queue limits, concurrent backup/restore and an actual compatible collector. This is component evidence for REQ-42/43/44/48/52, not full operational acceptance. Resource instrumentation, complete event coverage and the alert chain remain open.

## Ownership and data flow

The worker's telemetry process is independent of backup execution. Its local private profile selects one admitted domain, a collector endpoint, expected TLS public-key identity, owner-signed reporting scope and bounded queue/schedule. Shared jobs cannot change the endpoint, private credential paths or export scope. The process uses the existing volume admission, telemetry budget and mutual TLS transport. It has no recovery key or source-content access.

Only typed observations enter the journal: opaque node/domain/operation identifiers, enumerated events/states/error codes and bounded numerical measurements. Arbitrary log text, filenames, source paths, URLs, credentials, keys and backup objects are not accepted fields. Endpoint error bodies are bounded and classified locally; they are not forwarded as log messages. Metric labels use a fixed vocabulary and bounded identities; operation identifiers belong in event records, not unbounded metric labels.

The adapter emits OTLP/HTTP JSON logs and metrics to a separately admitted collector, which may be Alloy. It reuses Outpost's durable state and capacity admission instead of making the worker depend on a collector's experimental local log queue. Collector installation and forwarding to real monitoring destinations require their own infrastructure profile. No public endpoint or notification recipient is supplied by default.

## Journal, positions and capacity

A journal position is the monotonic sequence of a typed telemetry record, not an offset into arbitrary application or dataset files. A durable enqueue commits the record, source position and duplicate binding together. An uncertain enqueue is resolved from that retained state. Pending requests retain their original observations and exact content across process restart.

The configured byte and item limits include journal metadata, pending content and the peak of atomic replacement. Storage admission uses the telemetry category; it cannot borrow the reserve or delete backup data. Exhaustion rejects new telemetry while preserving already admitted records and their positions. It does not stop a backup, purge a copy or pretend that observations were delivered. No accepted entry expires silently. Explicit operator handling of a permanently rejected record must preserve its disposition and distinguish it from successful delivery.

One dispatcher owns the delivery lease. Network waits do not hold the journal's short mutation lock. A crash after remote acceptance but before durable local acknowledgement can resend the same request with the same timestamps. Delivery is at least once; exactly-once ingestion is not promised. Queue state and original observation age remain separate from the collector's current availability.

The signed journal reserves 1 KiB of its own byte limit for outcome metadata. Physical atomic replacement still requires a budget reservation for the old and new files. Other telemetry writers or host space exhaustion can block an attempt or acknowledgement; the accepted request remains pending. Restore capacity within the admitted telemetry allocation before retrying. This is distinct from the logical queue being full: do not borrow backup reserve or delete protected copies. The queue retains rejected-record counts, warning counts and a cumulative explicit-discard chain. It is not an unlimited audit archive.

## Local profile and commands

Provision a private `outpost-telemetry-profile-1` JSON profile with `endpoint`, pinned TLS `identity`, one `domain`, absolute `enrollmentFile`, `maxBytes` (4096-4194304), `maxItems` (1-128), `intervalSeconds` (1-86400) and `enabled`. The queue limits include the signed state and fixed signal bodies; they are not usable payload capacity. The endpoint, identity, domain, limits and owner remain bound to the existing queue. A local schedule or enrollment-file path change does not change export authority. Use the worker bootstrap's admitted certificate and CA roots; the destination must support the same mutual TLS profile.

```sh
outpost worker-telemetry-init --bootstrap /run/outpost/worker.json --input /run/outpost/telemetry.json
outpost worker-telemetry-status --bootstrap /run/outpost/worker.json --input /run/outpost/telemetry.json
outpost worker-telemetry-once --bootstrap /run/outpost/worker.json --input /run/outpost/telemetry.json
outpost worker-telemetry-loop --require-isolation --bootstrap /run/outpost/worker.json --input /run/outpost/telemetry.json
outpost worker-telemetry-renew --bootstrap /run/outpost/worker.json --input /run/outpost/telemetry.json
```

`init` requires a new queue directory and active owner-signed reporting enrollment. `renew` explicitly commits a newer enrollment or revocation without resetting positions; replay of an older grant fails. Changing the input file alone does not replace the durable grant. Revocation is checked again before sending; it cannot recall an already submitted request. Status remains readable after expiry or revocation. `enabled: false` makes `once` report `PAUSED`; `loop` requires an enabled profile. Restart the separate process to apply a changed local schedule.

After inspecting a terminal rejection, an operator may use `worker-telemetry-discard` with the same bootstrap/profile and `--operation EXPECTED_REQUEST_DIGEST`. It discards only the currently blocked signal with that exact digest, records its disposition and never increments the accepted count. No scheduler calls this command. Missing/corrupt journals and interrupted initial provisioning fail closed; normal open never silently recreates them. Preserve the state and investigate before an explicit recovery procedure.

## Transport outcomes

The wire format follows the [OTLP specification](https://opentelemetry.io/docs/specs/otlp/): logs use `/v1/logs`, metrics use `/v1/metrics`, and JSON uses the Protobuf mapping. Bodies, responses and attempt duration have explicit smaller limits than general collector defaults. Redirects cannot expand the admitted destination.

Successful acceptance requires a valid response. Partial acceptance records its actual disposition and is never retried automatically. Transport uncertainty and retryable HTTP429/502/503/504 use persisted backoff and bounded `Retry-After`; permanent errors do not create an endless retry loop. A partial warning with no rejected records is distinguished from rejection. Raw remote diagnostic text is not a success criterion.

## Truthful observations and quiet events

Original generation verification time is never replaced by report or export time. Missing measurements remain unknown; absence of a fresh sample is not zero load or health. Initial coverage uses the existing scoped worker observations. Required source-read, unique-byte, wire/duplicate-byte and route-throughput measurements need their own instrumentation and acceptance before they can be advertised.

Local inventory state logs use a retained transition identity. An unchanged state does not generate another log. Metrics have a heartbeat interval. Alert coverage, recovery notices and independent monitoring-failure detection still require implementation and acceptance; external notices remain limited to explicitly authorized test destinations.

Current worker projection covers configuration revision, bounded job-state counts, volume accounting, complete local generation count/sequence and original ciphertext-verification time for the latest complete local generation. Initial logs describe changes in that local inventory state. Unknown numeric values have a separate `_known` gauge and no fabricated measured zero. Metrics do not use operation IDs as labels. Per-operation audit/alert transitions, all external-copy measurements and source/wire counters remain separate work.

## Required checks

- Actual restart and process interruption around enqueue, send and acknowledgement preserve the journal and source position.
- An unavailable or slow collector, permanent rejection, partial acceptance and `Retry-After` produce the specified distinct states.
- Queue exhaustion preserves accepted records and leaves a concurrent backup/restore unaffected.
- Revoked or expired reporting scope blocks export; another domain, wrong TLS identity and redirected destination are rejected.
- Captured requests contain only allowed fields and original timestamps. Corrupt local records cannot introduce arbitrary text or metric labels.
- An isolated real collector accepts both signals. A protocol-shaped mock alone does not establish collector compatibility.
- Alert delivery, recovery, quiet unchanged state and independent monitoring-failure detection are exercised before AT-35 acceptance.

The existing [management reporting](management-service.md) remains a separate signed protocol with its own acknowledgement. A collector's HTTP response must not be forged into a management receipt.

## Reproducible component checks

Run the `Telemetry` tests in `internal/telemetry`, `internal/worker` and `cmd/outpost` with the race detector in an isolated Linux environment. The slow-sink fixture fills the logical queue while a 256 KiB encrypted generation transfers and restores independently. A separate shared-budget test refuses an unreserved attempt without losing its request or backup inventory.

`TestTelemetryRealCollectorAcceptsBothSignals` is opt-in: supply `OUTPOST_TELEMETRY_COLLECTOR` with an absolute binary path and `OUTPOST_TELEMETRY_COLLECTOR_SHA256` with its independently selected SHA-256. It runs a temporary child collector with synthetic mTLS credentials and a local file exporter, verifies both signals and original timestamps, then stops it. Run it only inside an isolated no-network test container with explicit CPU/memory and temporary-execution limits. The accepted fixture uses Collector Contrib 0.163.2 image digest `sha256:7f22d2a6748110ffb6a59bc0df448bccbf501cdb667d610ede4c61d3863d5849`; extracted binary SHA-256 is `dbd12d55073b70add777895457040f8ede59fc1ee7198d6ae179a37087eea8bb`. Its large binary needs extra fixture-only temporary space; this does not change production isolation or certify a live monitoring route.
