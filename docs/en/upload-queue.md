# Durable upload queue candidate

[Русский](../ru/upload-queue.md)

`internal/upload.Queue` extends the [G3 external-upload library](external-upload.md) with persistent admission and autonomous execution of several cached signed plans. A temporarily unavailable target retries without another control-plane request. Independent targets can progress concurrently; a slow resolver or transfer consumes only its configured execution slot. This remains a Linux library candidate, with no installed service or automatic policy/credential delivery. Full G3 is **NOT_VERIFIED**.

## Admission and crash recovery

Create one queue in an explicitly admitted persistent directory. Its identity binds the worker, generation/planner public authority and resource limits. Each new queue also has a random persistent instance ID, so separate queue instances do not share source pins. The same signed operation is idempotent; changed plan bytes under an existing operation ID conflict. Secrets and worker private keys are never serialized into queue state. Do not clone a live queue directory or place its mutable state in a file-synchronization folder.

`Enqueue` verifies signature, worker membership, target/placement policy, source trust and expiry before admission. It saves an `ADMITTING` intent, pins the source generation, prepares the ordinary upload journal and only then acknowledges `QUEUED`. A crash between those steps is recoverable from the signed intent. A failed admission can retain an intent or pin; it never grants deletion authority. The queue cannot reconstruct a missing accepted journal as a new job or silently ignore corrupt state.

`Run` takes an exclusive process lock, reconciles interrupted `RUNNING` attempts and drains admitted work. Job attempts have independent deadlines and share a bounded worker-wide concurrency limit. Each target profile reuses a backend within a run, preserving its connection/rate limits and observed throttling. The credential/CA resolver runs inside the attempt deadline and must honor its context. Resolvers are caller-supplied trusted code; the queue cannot forcibly stop one that ignores cancellation.

| State        | Meaning and next action                                                                                                                                                      |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ADMITTING`  | Durable intent exists; pin/journal preparation will be completed before execution. No prior success is inferred.                                                             |
| `QUEUED`     | Source is pinned; wait until the signed start time and a free execution slot.                                                                                                |
| `RUNNING`    | Attempt number is durable before dispatch; a restart schedules reconciliation.                                                                                               |
| `RETRY_WAIT` | A transient network/deadline/cancellation failure occurred. Persisted exponential backoff, bounded jitter and any observed `Retry-After` govern the next attempt.            |
| `BLOCKED`    | Authorization, quota, integrity, conflict, unsupported capability or local-state failure requires correction. `Run` returns `ErrBlocked` after other eligible work finishes. |
| `EXPIRED`    | Signed plan authority expired. No further target requests; source protection remains. A new authorized operation is needed.                                                  |
| `COMPLETE`   | The ordinary G3 worker returned a bound full-target-readback receipt. This records observed availability, not future durability.                                             |

Completion is persisted with `CleanupPending` before releasing queue/worker pins. A crash after receipt storage therefore allows local pin release to finish on reopening. Releasing a pin does not itself remove any data; G2 maintenance still requires separate authority. Expiry, cancellation and blocked work retain pins. Error classes are stable bounded codes, not raw endpoint errors that could expose credentials. Operator `Retry` only requeues a blocked, still-valid plan after its cause is corrected; it cannot change the plan or revive expiry. Terminal duplicate admission performs no upload.

## Minimal consumer sequence and bounds

1. Open the admitted G2 source replica. Call `OpenQueue(absoluteDir, workerID, authority, limits, true)` once; reopen with `false` thereafter.
2. Call `queue.Enqueue(ctx, source, signedPlan)` for each already-authorized target/generation. The queue retains a copy of the signed bytes.
3. Supply a `BackendResolver` that returns `storage.New(profile, credentials, roots)` for exactly the requested admitted profile, using secrets from outside queue state. `Run(ctx, source, resolver, workerKey)` drains available plans with autonomous delayed retries. Cancel its context to stop and join attempts. Close the queue after `Run` returns.
4. Inspect `Status(ctx)` for per-operation phase, attempt, next retry time, error code and receipt. `ErrBlocked` is an incomplete outcome. Correct a blocked cause, call `Retry(ctx, operationID)` and invoke `Run` again with fresh credentials. New plan delivery, service supervision and UI remain caller responsibilities.

`QueueLimits` admits 1-64 retained jobs and 1-4 active attempts. An attempt lasts 100 ms to 5 minutes. Retry base is 50 ms to 1 minute, with a maximum between the base and 1 hour. The serialized queue is capped at 32 MiB; individual signed plans and upload journals keep their existing limits. Resource limits and authority cannot silently change on reopening. Completed jobs count toward capacity, and no job/probe/claim/history garbage collector is provided. Capacity exhaustion rejects admission rather than discarding history or pins.

The queue does not impose a quota shared by multiple workers or distinct target profiles on one account. Network-wide adaptive scheduling, source pin retention administration and automatic renewal are still open. A too-short attempt deadline can prevent completion of full-generation audits; select it for the admitted data/latency profile and measure actual cost. Filesystem flushes rely on the admitted storage contract; a stopped or faulty kernel/device is outside a request context's ability to guarantee a deadline.

## Bounded evidence

The short Linux HDD suite covers two independently authenticated targets, temporary 503 failure with automatic recovery, a slow resolver, cancellation, 507 capacity blocking and explicit retry, duplicate/conflicting admission, job-count limits, corrupt state, separate queue pins, interrupted admission, expiry, retained source protection and deferred pin release after completion. A 60-second throttle is checked without waiting for the whole delay, including reopen without a new request. Real subprocess tests send SIGKILL during a part PUT, reopen the same queue and independently restore bytes and attributes through both S3-compatible and WebDAV fixtures.

Run the existing `go test -count=1 ./...` and `go vet ./...` in the admitted environment, with `TMPDIR`/`OUTPOST_TEST_ROOT` on its data volume. Tests use synthetic 3 MiB sources and loopback TLS; no actual storage accounts, live services or heavy acceptance run is required. The [G3 trace](../g3-trace.json) ties these cases to tested requirement subsets. Large history, prolonged real partitions, hardware power loss, real endpoint ACL/capabilities, aggregate traffic/cost and heavy G1-G3 acceptance remain open.

The WebDAV MOVE profile gives each upload journal a separate durable attempt book under the same volume and disk budget. It saves the ready flag before the first target write. A restarted worker reads the recorded stage or final object before taking further action. Loss of initialized history stops the job. The configured per-object attempt limit bounds new staging names. [WebDAV without conditional PUT](external-upload.md#webdav-targets-without-conditional-put).
