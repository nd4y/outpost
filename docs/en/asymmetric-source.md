# Asymmetric source acceptance

[Русский](../ru/asymmetric-source.md)

This opt-in test covers the asymmetric variant of [AT-01](specification.md#22-acceptance-scenarios), initial and incremental capture under REQ-04/05. It compares a single initial recipient with the actual adaptive paired sink using the same plaintext corpus, edit, cryptographic epoch, copy threshold and resource profile. It does not add a product routing mode.

## Reference and topology

`TestAsymmetricSourceComparison` creates three ordinary authenticated workers. A and B accept source uploads and have signed staged-pull routes to each other. C has no listener, no source route and no route to B; it pulls complete generations from A. C stays stopped until the source has released its view and closed. Neither A nor B is an optional member of the two-copy release threshold.

The library reference fixes every initial object PUT at A with one outstanding write. In complete-copy mode B pulls the actual accepted ciphertext through the same staged-delivery method used by the paired sink. In split mode the ordinary coverage protocol imports the exact deterministic partition. The reference promotes the pair's real Begin, Coverage, CoverageBindings, FinishStep and AcknowledgeStep methods unchanged. It neither fabricates receipts nor edits coordinator state. The paired comparison uses the unwrapped production `parallelSink` with its ordinary two-write window and measured distribution. Both compositions use the same capture engine and authenticated clients. After completion the normal agent exports the real checkpoint and advances lineage. This is a capture-library comparison; ordinary CLI routing and process isolation have separate tests.

## Measurements and refusal controls

The bounded corpus is one incompressible 24 MiB regular file. The second capture replaces a contiguous 8 MiB region at offset 4 MiB without changing its inode, mode or mtime. All four cases reuse the same original bytes, replacement bytes and data-key epoch: single and paired ingress, each with complete-copy release and explicitly enabled split coverage. Input SHA-256 values accompany the results.

The HTTP fixture caps application request/response bodies at 500/500/100 Mbit/s for A/B/C and 1,000 Mbit/s for the source. Concurrent requests share each node's directional budget. A path waits for the latest gate reservation rather than adding independent link delays. These are maximum body rates, excluding TLS/TCP headers, retransmissions and a real network's behavior. Record actual source throughput and shared CPU/HDD limits; caps do not prove link saturation or a speedup.

`ASYMMETRIC_CAPTURE` records actual counted source reads, ciphertext readback, distinct initial object bytes, duplicate object-body bytes, per-route request/response bytes, actual request intervals ending after durable acceptance, forwarding before seal, seal/release/completion/catch-up durations and authenticated first/per-target replica times. Read/body rates over time to seal and the actual large-PUT overlap flag are measurements. The capture can be source/readback limited or have too few new packs for PUT overlap, even when both receivers accept data; this does not turn a declared cap into measured throughput. The separate two-ready-object control strictly requires real concurrent reception. Complete-copy release time comes from the provider-release durability hook; split release is observed separately from full publication. Required proof is withheld before release: a real observation for complete-copy mode, the second holder's partition/coverage response for split mode. The test requires a hit on that gate, the expected refusal and a durable state with no release observation. Reopening the gate must allow the same operation to finish.

In split mode the source path is removed after durable coverage release and before publication. C then catches up with the source agent closed and its input path absent. All three replica directories independently restore actual bytes, mode and mtime. After the edit they restore both retained generations again. The source's inode is moved back only to prepare the next capture. These worker instances and recovery calls share one test process and HDD; this does not establish separate physical failure domains, owner-key absence from that process, or clean-reader namespace isolation.

## Commands and acceptance boundary

Run inside an admitted Linux HDD environment with an existing Go toolchain and bounded CPU/RAM/disk. Keep compiler scratch separate from the admitted runtime temporary directory. With `OUTPOST_TEST_ROOT` and `TMPDIR` set to that directory:

```sh
go test -exec 'env -u GOTMPDIR' -count=1 -run '^TestAsymmetricBodyRateReservations$' ./internal/sourceagent
OUTPOST_ASYMMETRIC_SOURCE=1 go test -exec 'env -u GOTMPDIR' -count=1 -timeout=110m -run '^TestAsymmetricSourceComparison$' -v ./internal/sourceagent
```

The deterministic rate-reservation/cancellation control runs in ordinary CI. The comparison is opt-in because its four matched cases include real encryption, readback, durable publication, background catch-up and retained restores. Its bounded result cannot accept the physical 100 GiB profile. Full-size runs, fresh independent executable recovery, final resource admission and exact-commit publication remain separate mandatory evidence. No current result is claimed by the existence of this document or test symbol.

`TestSplitIngressColdSameOwnerUsesTwoInitialRecipients` separately prepares two opaque transport objects with the same required owner and no throughput samples. A bounded eight-second rendezvous requires real source PUT requests at both authenticated receivers before either proceeds. Each PUT still performs ordinary durable acceptance, readback and exact delivery to the assigned owner. This control verifies scheduling when two objects are already ready; it does not add a barrier to capture timing, validate a file-kit envelope or claim wire throughput. Sequential preference, capped rate weighting, failed handoff and quota-fallback reservation accounting have separate controls.

`TestAsymmetricSourceScale` streams a separately admitted 128 MiB rehearsal or physical 100 GiB profile with a contiguous 8 MiB edit. It requires a pinned fixture/oracle executable, the admitted filesystem identity and a 20% reserve plus projected overlap for all four cases with three holders. Each source runtime has a 2 GiB state budget. Generation hashes, all source request bodies, the 1.08 initial object amplification bound and 128 MiB edit-body bound are checked. After each capture, every holder restores the current and retained version with a full-byte/attribute oracle. Verified scratch restores are removed only from their own newly created directories; failed restores, holder ciphertext, keys and result manifests remain private for diagnosis and later fresh-reader acceptance. The large profile is opt-in and never starts merely because CI compiles it. Its runner must verify no conflicting producer, final code readiness, resources and independent recovery before recording full acceptance.

## Recorded bounded result

The [source-bound receipt](../asymmetric-source-evidence.json) records all four matched 24 MiB cases: eight captures, 36 byte/mode/mtime restores and zero duplicate object bodies. Both policies refuse the withheld required proof; the outbound-only follower catches up after source closure. Six targeted race controls pass three times each, including actual cold same-owner dispatch, interrupted handoff and quota-fallback accounting. The original controlled dispatch fails on its exact earlier source and passes after pending-slot allocation.

| Policy | Initial recipient | Phase   | Source object bodies, bytes | Seal, s | Provider release, s | Optional follower ready, s | Actual large PUT overlap |
| ------ | ----------------- | ------- | --------------------------: | ------: | ------------------: | -------------------------: | ------------------------ |
| full   | single            | base    |                    25170781 |  45.564 |              82.218 |                    108.058 | false                    |
| full   | single            | patched |                    12068821 |  28.036 |              69.765 |                    100.537 | false                    |
| full   | paired            | base    |                    25170781 |  35.075 |              68.515 |                    104.056 | true                     |
| full   | paired            | patched |                    12068821 |  31.782 |              68.353 |                     98.826 | false                    |
| split  | single            | base    |                    25170781 |  39.709 |              45.023 |                    122.836 | false                    |
| split  | single            | patched |                    12068821 |  29.767 |              37.000 |                    109.154 | false                    |
| split  | paired            | base    |                    25170781 |  37.542 |              44.063 |                    123.136 | true                     |
| split  | paired            | patched |                    12068821 |  26.114 |              30.914 |                    128.449 | true                     |

The cohosted 0.5 CPU / 512 MiB profile includes shared resource and deliberate proof-refusal costs. Its cgroup peak is 536,875,008 bytes against 536,870,912 bytes, with 4 limit events and no swap or OOM: memory pressure, without a headroom claim. The small transient excess is kept exactly, as explained in the [G1 resource boundary](g1-acceptance.md). A false overlap flag is retained as a measurement. Actual concurrency is separately proved when two objects are already ready; no wire-rate/throughput promise is inferred. The streaming/full-size and fresh executable-reader stages remain open.
