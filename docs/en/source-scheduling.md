# Durable source scheduling

[Русский](../ru/source-scheduling.md)

Implemented for bounded private source profiles; full product and scale acceptance remain open. Scheduling is private source configuration; a shared worker/control job cannot select source paths, keys, providers or commands. The schedule uses the enrolled source profile, writer authority, data volume and budgets. It does not extend an expired grant or lower a copy/consistency requirement.

`source-schedule-set --bootstrap FILE --input SCHEDULE` explicitly installs or updates a versioned interval schedule. `source-schedule-status --bootstrap FILE` reads its durable state. `source-loop --bootstrap FILE` runs it in the foreground until cancellation; an installer may later supervise that executable. None of these commands installs a host timer or changes another service.

The input has format `outpost-source-schedule-1`, a strictly increasing revision, enabled flag, interval, retry delay, attempt deadline and initial due time. Values have explicit bounds. Equal revision with identical input is an idempotent retry; changed content at the same revision or a lower revision is rejected. Schedule state is bound to the source bootstrap and authenticated with the source writer key. Unknown or corrupt state is preserved and blocks execution. Status contains opaque IDs, phase, due/retry times, accepted sequence and stable error codes, without source names or secrets.

Only one scheduler may execute against a runtime at once. Schedule updates and status do not wait for a whole file capture. Each attempt freezes the schedule revision; disabling or replacing it cancels and joins that attempt. Source capture has its own lease, shared with manual `source-next`/`source-run`, so concurrent clients cannot admit competing generations. Volume loss and SIGINT/SIGTERM preserve existing cancellation and progress rules.

A pending source intent is resumed before another generation is prepared. Completion advances the durable source head before the schedule records its next due time. If the process dies between those writes, reopening recognizes the accepted sequence and schedules from the recorded completion; it does not capture the same due event again. Missed intervals coalesce into one current capture instead of an unbounded catch-up queue. A manually completed generation likewise advances the next due calculation. Failed attempts preserve the same pending source operation, record a bounded retry time and never report a successful backup.

Pausing leaves pending work, provider views, source pins and completed data intact. Resuming continues the same operation. Expired authority, missing copies, capacity limits and unsupported consistency remain visible failures/waits; scheduling does not repair or bypass them. A new grant or provider requires its separate validated transition. A capture attempt deadline must cover the configured source workload; resumable encrypted output does not mean the source can skip all earlier disk reads.

Short native/race checks cover actual capture and independent recovery of successive generations, lost completion acknowledgement, schedule restart without duplicate capture, revision conflicts, cancellation while network IO is pending, private-state corruption, quotas and clock rollback. Small fixtures do not prove long-outage or large-file capacity.

An independent OS process opens the restricted schedule-control interface without taking the capture lease or reconciling active capacity reservations. Its status/pause check completes within a 500 ms test deadline while another process is waiting on HTTPS. Normal execution still performs reconciliation. A real SIGKILL after the source head is durable is recovered without a duplicate generation. These are isolated fixtures, not deployed service or long-outage evidence.

[Explicit source-authority renewal](source-agent.md#renewing-source-authority) preserves schedule state and its accepted head. Pause and stop the loop, complete pending work, renew, then reopen the process and resume the schedule. Expired pending work cannot be bypassed with a renewal.
