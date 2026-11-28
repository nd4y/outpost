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

Generation verification keeps its original time through reporting and export. Missing measurements remain unknown. The optional [source status measurement](source-agent.md) reads original per-entry capture receipts locally. Aggregate source reads, unique physical occupancy, peer network traffic, throughput and billing require additional measurements.

Local inventory state logs use a retained transition identity. An unchanged state does not generate another log. Metrics have a heartbeat interval. The monitoring rules below preserve a stable alert identity across an unchanged failure. Validate actual notifications and recovery through an authorized test destination.

Current worker projection covers configuration revision, bounded job-state counts, volume accounting, complete local generation count/sequence and original ciphertext-verification time for the latest complete local generation. Initial logs describe changes in that local inventory state. Unknown numeric values have a separate `_known` gauge. Metrics do not use operation IDs as labels. Per-operation audit and alert transitions remain open.

### Local replica damage

`damaged_local_generations` counts generations marked corrupt in the complete local inventory read under the worker's existing signed domain enrollment. It includes recorded payload damage and authenticated catalog failures. It uses the existing OTLP integer gauge and node/domain labels. An unavailable or incomplete inventory supplies only `damaged_local_generations_known` with value 0. A measured zero means the observed inventory has no recorded damage. Use the verification age to learn when the ciphertext was last read.

Set `observeLocalReplicaDamage: true` in the private telemetry profile to send this gauge on the usual sampling interval. Omit the field for the existing sampling behavior. A current executable reads previously accepted frames. An older executable cannot reopen a queue with pending frames containing the new gauge. Before downgrade, stop sampling the gauge by restoring the previous profile, let the current executable deliver the held frames, then stop the telemetry process and verify `worker-telemetry-status` reports `pending: 0`. If delivery is blocked, keep the current executable and preserve the queue. The profile change uses the same endpoint, domain, queue binding and budgets.

`OutpostLocalReplicaCorrupt` fires on a known positive count from the same original timestamp as the fresh report. The alert groups by node and domain, so a changed positive count keeps the same alert identity. Loss of current telemetry can remove the corruption alert and trigger `OutpostTelemetryMissing`. Confirm a fresh known zero and follow the integrity runbook before recording recovery.

### Managed restore failures

Set `observeRestoreFailures: true` in the private telemetry profile. For the admitted node and domain, `restore_command_failures_retained` counts terminal failed restore commands retained by the signed local command journal. `restore_last_failure_timestamp_seconds` preserves the original finish time of the latest such command across sampling and restart. A validated restore-capable journal with no retained failures reports a measured zero count. If no such journal can be observed, the count is unknown. The timestamp remains unknown until an observed failure exists.

The gauge covers retained managed commands. Retries in progress and local standalone recovery are outside its scope. An operator should read the command result for the cause of a failure. Omit the option for the previous sampling behavior. Before downgrading, restore the previous profile and drain pending frames with the current executable as described for [local replica damage](#local-replica-damage).

### External upload attempts

The worker observes each admitted external upload attempt with a meter scoped to its target profile. It counts submissions to the HTTP client, bytes the transport actually reads from request bodies, and bytes the backend reads from bounded response bodies. These include retries by Outpost and verification reads. The replay metric counts overlapping offsets read again from the same immutable request body within a logical request, including transport body replays. Internal transport retries do not increment the request count. The measurements exclude HTTP headers, unread response bytes and TLS/TCP/IP overhead. Aggregate traffic, duplicates across workers or separate attempts, and storage-provider billing remain open.

A signed local record retains the latest attempt for each node, domain and target, with its operation binding, outcome and original observation time. The record uses the existing telemetry budget. A missing, invalid or unfinished observation reports unknown values. A recorded attempt with incomplete counters retains its original observation timestamp and reports unknown counts. A failed or interrupted observation has no authority over upload completion, source pins or recovery.

The separate telemetry process selects up to six opaque target IDs from the admitted domain's external-copy observations per sample. Selection rotates by the configured interval. `external_http_targets_in_scope` and `external_http_targets_selected` describe that sample's coverage. Per-target gauges report requests, request and response body bytes, known replay bytes and the original attempt observation timestamp. Sample the gauges with that timestamp and their `_known` companions. Adding consecutive samples can count the same attempt multiple times.

`outpost worker-external-transfer-status --bootstrap FILE --operation UPLOAD_ID` reads the latest signed local HTTP attempt for that operation's currently allowed external route. The command performs local reads. It includes `attempt` only when the successful attempt, signed upload plan, completed queue entry and worker receipt agree and the HTTP body counts are complete. The sample keeps its original start and finish in Unix milliseconds, outgoing request body bytes, incoming response body bytes and locally observed request replay bytes.

For a positive elapsed interval, each rate is the corresponding body byte count divided by the entire attempt duration, rounded down to whole bytes per second. That duration includes local preparation, waits and verification. A valid zero count has a zero rate. Equal millisecond timestamps or a rate outside the supported integer range leave the rate absent. An absent, failed, replaced or incomplete attempt leaves the sample unknown. Existing storage may have supplied verified data with few outgoing bytes. The sample measures one worker's HTTP bodies. Aggregate rates, unique data delivery and link throughput require separate evidence.

`external_audit_result` reports 1 for verified ciphertext, 2 for missing data, 3 for invalid content and 4 for an unavailable audit. A stale or missing observation has only the `_known` value 0 for this result. `external_audit_observed_timestamp_seconds` and `external_audit_expires_timestamp_seconds` retain the recorded times. Compare the expiry with the current clock when reading stored metrics. All audit and HTTP gauges share the six-target page and the existing OTLP frame limit.

### Local ingress object bodies

Set `observeIngressObjectBodies` to `true` in the receiving worker's private bootstrap to enable a local observation of direct source object PUTs. After the authenticated receiver consumes a complete body and accepts it, it can record `acceptedBodyBytes`. The `alreadyPresentBodyBytes` value equals that length when the receiver compares the object with identical content it already holds. A newly materialized object has zero already-present bytes. An already-present object may come from an earlier generation or another route. These measurements cover successful application request bodies. They exclude headers, transport overhead, failed requests, other methods and storage-provider traffic.

`worker-status` returns `ingressObjectBodyObservations` for currently authorized routes with valid retained records. Each row contains one latest saved sample and its original `observedUnixMillis`. A sample with an earlier time cannot replace it. For equal times the last saved sample wins. A bounded nonblocking queue and the existing telemetry allocation keep this observation off the acknowledgment path. If the queue fills, the worker stops, or persistence fails, the sample may be lost. The previous saved time and counts stay historical. An absent or invalid record is unknown. The signed record contains an opaque route ID, time and counts. The local field is separate from the management report and the OTLP queue. Route IDs do not appear in metric labels.

Enable this option on the receiving worker only. The source agent rejects an enabled option in its embedded local bootstrap. Before starting an older worker, restore its earlier bootstrap or remove the `observeIngressObjectBodies` key. An older strict decoder rejects an unfamiliar key even if its value is `false`. The local retained records need no queue drain or deletion.

### Local outbound peer object bodies

Set `observePeerObjectBodies` to `true` in a worker's private bootstrap to observe ordinary object PUTs on its peer push routes. Use `outpost worker-peer-object-transfer-status --bootstrap FILE --domain DOMAIN_ID --peer PEER_ID` to read one currently authorized route. Remove the setting before reverting to an older worker that uses a strict bootstrap decoder.

The optional `sample` is the latest saved successful exchange for one object. It keeps the sender's original acknowledgment time in `observedUnixMillis`, the application body bytes its HTTP transport read in `transportReadBodyBytes`, and the exact object length confirmed by the authenticated receiver in `acknowledgedBodyBytes`. The receiver acknowledges after accepting the complete hash-checked object. If that peer indicates whether the same object was already present when it accepted the PUT, `alreadyPresentBodyBytes` is the entire body length for an existing object or zero for a newly stored object. A missing or malformed indication leaves the field absent.

`elapsedNanos` gives the sender's monotonic elapsed time from starting the successful HTTP attempt through reading its acknowledgment. Divide the acknowledged bytes by that duration in seconds for the observed application-level throughput of the exchange. A failed exchange, ambiguous transport replay, incomplete body or invalid acknowledgement yields no sample from that attempt. The bounded local telemetry queue can drop a sample without changing the push result. A retained sample keeps its original time. Aggregate data, wire traffic, unique delivery, other routes and generation publication require separate evidence.

The worker keeps at most one signed version 2 record per route under its existing telemetry quota and preserves any version 1 record. The newer reader accepts both versions and uses the newest valid sample. The version 1 sample lacks elapsed time and already-present bytes. A downgraded reader can still read any version 1 sample it retained.

### Local source outgoing object bodies

`outpost source-run --bootstrap FILE --observe-direct-source-bodies` can include `outgoingIngressObjectBodies` in that run's result. The result has `retention: CURRENT_PROCESS_RUN` and the latest available sample per selected route whose signed source authority still matches. A sample includes an opaque route ID, the original times of PUT start, authenticated response and matching ciphertext readback in Unix milliseconds, and the complete PUT body count read by the HTTP transport. If the receiver explicitly acknowledges an identical object already held in staging or the base generation, the already-present count equals the PUT body count. A newly staged object has zero already-present bytes.

The sample describes one successful direct exchange. An already-present object may have reached the receiver on another route. The original interval from PUT start to verified readback includes any wait, response and verification, and may be less than a millisecond. HEAD requests, receiver-to-receiver relays, failed verification, ambiguous body replays and legacy replies without an explicit creation result do not yield a sample. Aggregate bytes, wire traffic, unique completed delivery and overall throughput require separate evidence.

The process uses at most three in-memory slots and can drop a concurrent update. No sample is written to disk. A later process, an interrupted run, a run with no confirmed direct PUT, or an expired or replaced route supplies no observation. The optional result leaves the source's bootstrap, receipts and disk admission unchanged.

Omit the flag with an older executable. Reading the last observation after restart needs independently provisioned telemetry storage with its own quota and volume binding.

## Required checks

- Actual restart and process interruption around enqueue, send and acknowledgement preserve the journal and source position.
- An unavailable or slow collector, permanent rejection, partial acceptance and `Retry-After` produce the specified distinct states.
- Queue exhaustion preserves accepted records and leaves a concurrent backup/restore unaffected.
- Revoked or expired reporting scope blocks export; another domain, wrong TLS identity and redirected destination are rejected.
- Captured requests contain only allowed fields and original timestamps. Corrupt local records cannot introduce arbitrary text or metric labels.
- An isolated real collector accepts both signals. A protocol-shaped mock alone does not establish collector compatibility.
- Alert delivery, recovery, quiet unchanged state and independent monitoring-failure detection are exercised before AT-35 acceptance.

The existing [management reporting](management-service.md) remains a separate signed protocol with its own acknowledgement. A collector's HTTP response must not be forged into a management receipt.

## Monitoring rules and independent watchdog

Load [the primary rules](../../packaging/monitoring/outpost.rules.yml) in a PromQL-compatible evaluator. Keep the original OTLP sample timestamp and normalize the point labels to `outpost_node`, `outpost_domain` and, for per-target metrics, `outpost_target`. Select one series for each admitted node/domain or node/domain/target. Build the expected inventory separately from received telemetry so a silent worker remains in scope. Set positive per-scope thresholds through `outpost_expected_telemetry_max_age_seconds`, `outpost_expected_free_bytes` and `outpost_expected_copy_max_age_seconds`. The owner chooses these values from the admitted heartbeat interval, disk reserve and verification window.

Missing, stale or future reports trigger `OutpostTelemetryMissing`. Fresh reports distinguish unknown inventory and unknown space from observed resource pressure. Blocked jobs and low space use values from the same original report. The per-replica alert measures the age of successful ciphertext verification. External-audit failures require a current result inside its own validity window.

Route `OutpostMonitorHeartbeat` only to a dedicated, authenticated heartbeat receiver. Give the primary evaluator a stable `outpost_monitor` label. The receiver exports `outpost_monitor_heartbeat_received_timestamp_seconds` using the time it received the delivery. Load [the watchdog rules](../../packaging/monitoring/watchdog.rules.yml) on an independent evaluator, supply `outpost_expected_monitor_max_age_seconds` for each primary monitor and route watchdog alarms separately from the primary path. A query of the primary service's own heartbeat metric cannot establish notification delivery.

The [PromQL fixture](../../packaging/monitoring/rules.test.yml) tests rule states, timestamps and stable labels with `promtool test rules`. The [delivery fixture](../../scripts/check-monitoring-delivery.py) takes the paths and SHA-256 digests of Prometheus and Alertmanager executables, the rules directory and a writable test directory. Run it in an isolated environment. It checks first delivery, stable deduplication, resolved delivery, primary-path interruption and watchdog recovery through authenticated loopback webhooks. For local corruption, the fixture requires one firing, an observed increase in the positive count without a second notification, and one resolution after the evaluator observes an explicit zero. A separate case keeps scraping a previously healthy report. After one `OutpostTelemetryMissing` notification, it requires at least two further scrapes, a successful scrape status, the original report timestamp in the evaluator and at least one heartbeat received after the alert fires. The alert stays unresolved and quiet while the old report is replayed and resolves once after fresh reports resume. The private operations profile records the actual thresholds, routes, recipients and rollback paths for the separate operational drills. [Rule testing reference](https://prometheus.io/docs/prometheus/3.9/configuration/unit_testing_rules/)

## Reproducible component checks

Run the `Telemetry` tests in `internal/telemetry`, `internal/worker` and `cmd/outpost` with the race detector in an isolated Linux environment. The slow-sink fixture fills the logical queue while a 256 KiB encrypted generation transfers and restores independently. A separate shared-budget test refuses an unreserved attempt without losing its request or backup inventory.

The HDD slow-sink fixture retains the original five-second job/RPC budgets and 15-second telemetry transport timeout. Its 60-second observation window includes worker startup and ordinary durable retries, within a 90-second caller bound. Before releasing the receiver, the test must confirm that transfer and full restore completed while that receiver remained blocked and telemetry remained queued without an acknowledgement. After recovery it can retry a normally timed-out delivery. Privacy checks cover every captured request. These bounds coordinate the test and do not establish a backup latency guarantee.

`TestTelemetryTCPOutageReopenAndSameTargetRecovery` closes a real TCP listener, checks the accepted request and retry state in the byte-identical signed journal after reopen, and returns the same mutually authenticated endpoint to drain that exact request. It checks the original byte/item bounds and verifies that arbitrary warning/rejection diagnostics do not enter persisted content or operator status. The existing test clock helper makes the retained request eligible after the persistence assertions; this does not measure elapsed backoff. Separate SIGKILL tests cover uncertain acknowledgement. The returned listener is a synthetic protocol peer, so this test does not establish real Collector interoperability or live monitoring acceptance.

`TestTelemetryRealCollectorAcceptsBothSignals` is opt-in: supply `OUTPOST_TELEMETRY_COLLECTOR` with an absolute binary path and `OUTPOST_TELEMETRY_COLLECTOR_SHA256` with its independently selected SHA-256. It runs a temporary child collector with synthetic mTLS credentials and a local file exporter, verifies both signals and original timestamps, then stops it. Run it only inside an isolated no-network test container with explicit CPU/memory and temporary-execution limits. The accepted fixture uses Collector Contrib 0.163.2 image digest `sha256:7f22d2a6748110ffb6a59bc0df448bccbf501cdb667d610ede4c61d3863d5849`; extracted binary SHA-256 is `dbd12d55073b70add777895457040f8ede59fc1ee7198d6ae179a37087eea8bb`. Its large binary needs extra fixture-only temporary space; this does not change production isolation or certify a live monitoring route.

The [scoped HDD receipt](../telemetry-outage-evidence.json) binds the ordinary/race observations to the exact 527-input source snapshot. Of the preceding inputs, 525 are unchanged; one existing worker test extends its observation window, verifies the still-blocked receiver and checks the privacy of every captured request. Production code, job/RPC budgets and module inputs are unchanged. The receipt records same-endpoint transport failure and return, journal limits, native formatting, module verification, vet and enforced container limits, including memory-limit events and total cgroup memory with page cache. Collector and installed-profile acceptance remain separate.

The [current Collector receipt](component-acceptance.md#actual-pinned-collector) records the actual pinned 0.163.2 child process with both signals, original timestamps, the unknown marker and current-source cgroup evidence. This closes the isolated Collector component check; live endpoints, notifications and the full installed profile retain their separate admission.
