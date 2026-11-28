# Whole-operation windows

[Русский](../ru/operation-windows.md)

An operation may require many individually bounded requests. For example, reading 100 GiB over 100 Mbit/s takes at least 8,589.93 seconds; at 500 Mbit/s it takes at least 1,717.99 seconds. These are lower bounds for one read, excluding encryption, latency, metadata, retries, flushes and additional verification passes. A five-minute whole-operation ceiling cannot admit that fresh verification profile.

## Explicit owner policy

The owner may include `limits.operationMillis` in the signed per-node configuration. Zero or omission preserves the existing effective operation budget from `limits.attemptMillis` and the old canonical configuration bytes. A nonzero value must be at least `attemptMillis` and at most 86,400,000 ms (24 hours). A changed unsigned value is rejected.

`attemptMillis` retains its existing 100 ms to 300,000 ms range. Peer/ingress HTTP limits, external target request timeouts, assignment slots and claims are unchanged. Whole job execution, capture continuation, scheduled target audits and admitted asynchronous actions use the operation window. Parent cancellation, configuration replacement/expiry, command expiry, signed plan expiry and existing credential/transport checks can stop work earlier. A local credential resolver is also bounded by its signed plan's expiry before a backend exists.

For example, an already admitted limits object can specify `attemptMillis: 30000` and `operationMillis: 21600000` to separate a 30-second request budget from an upper bound of six hours for a whole operation. This does not establish that a particular dataset fits six hours. Admit the complete data/latency/verification profile and measure its actual cost. No authority, credential or certificate is renewed by this setting.

## Persistent queue compatibility

Default new external queues keep the five-minute ceiling. Only an explicitly selected operation window above five minutes creates a queue with the known 24-hour internal ceiling; the caller's shorter operation/configuration context still wins. The ceiling remains part of the queue's immutable identity.

Opening a retained queue tries only the exact known legacy five-minute identity and the exact new 24-hour identity. It never initializes missing state, changes an instance, migrates resource bounds or adopts an unknown/corrupt identity. Inspection, retry, retained audit and separately authorized abandonment use this same bounded compatibility path.

Increasing current policy does not widen a previously admitted five-minute queue. If its verification cannot fit, admit a fresh operation scope with the required window. Existing immutable parts may be checked and reused, while the previous job, receipts, pins and history remain intact. Abandonment requires its existing separate maintenance signature and expiry checks.

Older workers reject a configuration containing this new nonzero field and cannot reopen the new long queue identity. Default configuration/queue identities remain compatible. A rollback must account for explicitly admitted long jobs instead of converting or deleting their state. The encrypted generation/file-kit format is unchanged; a worker scheduling feature does not require new data decryption material.

## Verification scope

`TestSignedOperationWindowKeepsRequestBudgetAndLegacyCanonicalBytes` checks owner signatures, unchanged default bytes and bounds, including overflow. `TestLongQueueAttemptKeepsPlanExpiryAndParentCancellation` exercises real resolver cancellation and separately signed abandonment after expiry. `TestExternalQueueWindowPreservesLegacyAndKnownLongIdentity` reopens both identities, preserves bytes/instance/revision, and refuses changed authority, unknown limits, corruption and missing state. `TestWorkerLongOperationKeepsShortRequestsAndConfigurationExpiry` uses an actual worker dispatch with a long owner window and short request budget, then observes expiry without false completion.

The long-window retry and retained-audit cases reuse the existing crash/reopen, policy-withdrawal, missing-part repair and separate corrupt-copy replacement scenarios. Their default variants remain in the suite. Short synthetic checks prove scheduling/authority behavior; they do not measure a multi-hour transfer, select production budgets or close the final 100 GiB/profile acceptance.

## Assignment slots remain a separate admission bound

A longer operation does not make an undersized assignment slot feasible. The claim PUT/readback, target request admission and payload IO still have to fit the original signed slot. A controlled1200ms claim delay produces zero payload PUTs with a500ms slot and preserves the source pin; a separately signed4000ms control completes. The new full-worker functional retry/audit cases use a5000ms slot and60s polling per condition, fixed before admission. Earlier500/1000ms HDD profiles failed even with60s polling and remain unaccepted; default tests and the original G3 numeric thresholds were not changed. See the [receipt](../operation-window-evidence.json) for exact source, failed samples and resource scope.
