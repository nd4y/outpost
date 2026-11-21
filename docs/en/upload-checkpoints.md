# Upload claims and checkpoints

[Русский](../ru/upload-checkpoints.md)

The [external uploader](external-upload.md) separates assignment authority, durable local intent, verified target bytes and complete-generation publication. A claim never proves that a part exists. A local intention never grants a future assignment or permission to decrypt data.

## Bounded signed claims

Normal uploads group at most 32 distinct pending physical parts in an `outpost-external-claims-1` document, capped at 32 KiB and the target's object limit. Every member retains its original individually signed claim: exact plan, part, worker, current assignment round and original expiry. An additional Ed25519 signature binds the canonical container and the ordered member list. Unknown or duplicate fields, altered scope, signatures, reordered/truncated lists, duplicates and oversized documents fail closed.

The worker creates a content-addressed immutable claim object and requires actual byte-for-byte readback before reusing that claim within its round. The cache is cleared when the round changes. It cannot authorize a future round or extend a network request past the existing slot, plan or credential deadline. Missing-part repair keeps its separately scoped single-part claim. The verifier continues to accept legacy individual claims. Mixed-version worker rollout requires its own admission; accepting an old claim is not proof of such a rollout.

## Durable progress with bounded pending metadata

The worker prepares up to 32 plan members in one admitted journal transaction before sending any of their payloads. Preparation is not network authority: after the flush, the worker checks the actual owner and slot again. Retrying an already durable intention rechecks the current volume guard and quota reservation without rewriting the same intention. The reservation is cancelled when no file is written. `Attempts` counts durable preparations rather than HTTP requests.

After actual part readback, the current invocation may retain at most 32 acknowledgements in private memory. Other status readers continue to see durable pending intentions. The worker flushes acknowledgements at the bound, when its assigned work is complete, and before publication or a COMPLETE result, including completion discovered from another worker's marker. Each acknowledgement records the actual claim round and submitted payload bytes. A local acknowledgement may finish after its network slot; that performs no new network transfer and remains bounded by cancellation and the plan deadline.

The existing journal format and atomic file/rename/directory-flush contract remain unchanged. Guard or quota failure, cancellation and failed journal writes prevent completion and retain source pins. After SIGKILL, any remotely accepted part lacking a durable acknowledgement is read back again. Conditional creation and verified immutable bytes make this retry safe. Publication still checks the entire target closure. Pending metadata is never a substitute for target verification.

## Checks and evidence boundaries

`TestSignedClaimBatchesKeepLegacyAuthorityAndBounds` and `TestClaimBatchCacheRequiresActualReadbackAndCurrentLease` exercise the claim codec, canonical limits and cache. `TestPreparedPartRetryRechecksGuardAndCancelsQuotaReservation` checks live admission without a fabricated commit. `TestJournalBatchesAreBoundedAtomicAndAdmitted` covers transaction bounds, atomic refusal, guard/quota/cancellation, reopening and counter overflow. `TestJournalBatchSIGKILLRechecksUncommittedAcknowledgement` kills an actual worker between target readback and local acknowledgement, then checks real readback, one immutable write, source pins and independent recovery after restart.

The optional `TestPreviousKitRestoresBothBatchUploadedGenerations` uses a separately acquired older packaged executable. Set `OUTPOST_TEST_PREVIOUS_KIT` to its absolute path, `OUTPOST_TEST_PREVIOUS_KIT_SHA256` to its verified checksum and `OUTPOST_TEST_PREVIOUS_REVISION` to its full source commit. Without this explicit input the test skips; it never downloads or replaces a reader. Both protocols produce two generations, remove plaintext/source/runtime and restore exported kits with the previous executable, checking bytes, permissions and hardlinks. This tests recovery compatibility, not mixed-version workers or another physical failure domain.

The [checkpoint receipt](../upload-checkpoints-evidence.json), [latency receipt](../g3-latency-evidence.json) and [G3 trace](../g3-trace.json) preserve the separate performance and correctness gates. The 500 ms assignment/12 s rotation test and the 150 ms, 3 MiB, 52-part, minimum 1.5 speedup profile retain their original thresholds. Full short-deadline HDD regression failures remain failures; a hosted CI pass or a successful subset cannot relabel those samples. Real endpoint admission, physical failure domains and full-product acceptance remain separate.
