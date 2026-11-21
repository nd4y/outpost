# Full external-generation acceptance

[Русский](../ru/full-external-scale.md)

`TestFullGenerationExternalScale` is an opt-in acceptance harness for complete retained generations in S3-compatible storage and WebDAV. Its presence or an ordinary CI skip is not execution evidence. It supplements the unchanged small [latency and failure controls](../g3-latency-evidence.json); a shared CPU and HDD cannot establish the 1.5x throughput target.

Run a bounded 128 MiB rehearsal before admitting the physical 100 GiB profile. The input must come from a terminal successful [source-ingress scale run](source-ingress.md), including its base, 8 MiB replacement and unchanged generations. Preserve the source receipt, exact code and tool hashes, physical allocation, traffic and independent recovery results. Never reuse a failed or still-running producer as an accepted input.

## Input and authority

The runner mounts a read-only directory containing `input.json`, signed `catalogs` and immutable ciphertext `objects`. The manifest uses `outpost-external-scale-input-1`, `sourceBytes` (134217728 or 107374182400), public generation `trust`, and the exact `base`, `patched` and `unchanged` checkpoint IDs. It contains no decryption key, source signing key, source credentials or private inventory. The harness verifies catalog signatures and object digests through bounded reads under an `os.Root` boundary.

The lab creates fresh assignment-signing and worker identities. They authorize only new synthetic upload plans; they do not renew an expired source operation or impersonate its former owner. Three separate local holders physically copy the complete retained generations. Their payload files are not hardlinks or shards. The host and controller remain shared, so this does not establish three physical failure domains.

## Admitted execution

Set `OUTPOST_FULL_EXTERNAL_SCALE=1`, `OUTPOST_FULL_EXTERNAL_INPUT` to the immutable input directory, `OUTPOST_TEST_ROOT` to a new admitted HDD root and `OUTPOST_FULL_EXTERNAL_FSID` to its verified filesystem ID. These are private test-runner inputs, not product enrollment settings. The runner must separately verify the mounted volume, pinned artifacts, idle test runtime, available memory and free reserve before launch.

The scenario refuses existing fixture roots and requires a 20 percent reserve plus a conservative fourteen-times-source overlap and 1 GiB. It retains its owned data and logs after failure. Use the private execution profile for CPU, memory, swap and deadlines; do not run it concurrently with another heavy fixture.

The recorded small functional rehearsal used a separately admitted exception: 0.5 CPU and 512 MiB alongside one existing source capture. Its consumer stage used 0.5 CPU and 384 MiB. Fresh admission checked both jobs and system reserve. These shared intervals belong in the source timing record and provide no throughput guarantee. The 100 GiB external scenario still requires an idle test runtime and a separate cost review.

Readback reuse is a separate, explicitly selected profile of the existing [owner policy](readback-reuse.md). `OUTPOST_FULL_EXTERNAL_READBACK_MAX_AGE_SECONDS` defaults to zero, preserving fresh-only verification. The harness also admits 3600 seconds for its small rehearsal or 86400 seconds for the large profile. Each worker keeps its own bounded cache across the three generations. Records for retained objects keep their original observation times. A receipt reports the oldest supporting time for its current dependencies and uses `cached-target-readback` when it reuses evidence. Removing the oldest object can change that minimum without refreshing retained records. The unchanged phase must not fetch retained payload parts. This does not make a historical observation a current persistence guarantee. The later adapter downloads and all independent reader/oracle restores always read actual bytes and never use this cache. Record its selected age and costs separately from the accepted fresh-only control.

Each disk-backed HTTPS protocol fixture admits 8 MiB objects and a disclosed 10 ms part-write delay. Three actual subprocesses use separately admitted 30-second assignment slots and bounded 24-hour operation contexts. Existing small default, failover and latency profiles remain unchanged. A failed child causes the remaining children to be stopped and joined before its endpoint closes; the next protocol is not started after failure.

The checks require:

- Three distinct concurrent uploaders and immutable target keys written physically once.
- Complete base, replacement and unchanged generations on each target, with refusal of the incomplete replacement before upload.
- At most 128 MiB of received PUT bodies for the 8 MiB replacement, conservatively including its negative publication check. HTTP responses and TCP/TLS overhead are separate costs.
- No retransmission of retained dependency parts during the unchanged phase, and at most 64 KiB of new dependency part bodies for this corpus. Measure newly signed catalog parts separately by their exact physical IDs and body sizes. Include both classes in the total HTTP byte count. The producer's independent zero file-payload observation remains part of the combined evidence.
- A fresh complete materialized store downloaded through each actual storage adapter, retaining all three checkpoints.

Retained-traffic checks use physical part IDs from the verified upload plan, including split objects. Logical object IDs cannot identify their smaller parts. `TestScaleRetainedTrafficUsesActualMultipartIDs` reads a real split object over HTTPS and repeats a conditional part PUT: it checks that both operations are counted while the immutable target key is physically written once. Scope this result separately from a corpus whose objects fit the target cap without splitting.

`TestScaleUnchangedPartsSeparateSignedCatalog` measures a signed multipart catalog larger than 64 KiB over HTTPS. It checks that all catalog attempts stay in the total and that retained or unknown parts, oversized dependency traffic and incorrect catalog part lengths are rejected.

The endpoint holds the first authenticated part request from each identity at a bounded 15-second rendezvous before any of those payloads is written. All three must arrive; cancellation or a missing participant fails the check. The ordinary temporary-file, fsync, immutable creation and readback follow this barrier. This controls request concurrency rather than claiming simultaneous physical disk operations or throughput. A separate real-HTTP check proves that two waiting participants create no part files and that a third releases three actual writes; cancellation keeps them unwritten.

## Independent consumers and completion

The harness ends with `standalone-consumers-pending=true`. This is an explicit incomplete acceptance stage. After it stops, fresh consumer processes must mount only the recovered immutable catalogs/objects, owner recovery material, a separately acquired and checksum-pinned standalone reader, and an empty output directory. Source input, all upload journals, holder indexes, planner/worker keys, running endpoints and network must be absent from those mount namespaces.

Restore and independently compare the full base and replacement bytes and declared attributes for both protocols. Record terminal results, exact executable revisions, resource peaks, actual traffic and reserve observations. A 128 MiB rehearsal does not accept 100 GiB. These receipts also leave asymmetric source-ingress timing, physical fault domains, real endpoint admission and the overall operational run as separate gates.

## Recorded 128 MiB result

The [source-bound receipt](../full-external-rehearsal-evidence.json) records a successful 2026-11-15 functional rehearsal, not 100 GiB acceptance. Both protocol targets retained three complete generations. Three physically copied holders and seven fresh offline restores using the separately acquired `0ad4d17` reader verified all bytes and declared attributes. Its executable SHA-256 is recorded in the receipt. Scoped race checks also passed for the rendezvous and existing multipart, immutable readback, authorization and false-publication controls.

| Protocol      | Phase             | Received PUT bodies, bytes | Worker response bodies, bytes | Seconds |
| ------------- | ----------------- | -------------------------: | ----------------------------: | ------: |
| S3-compatible | Base              |                  134296923 |                    1800079483 |  283.40 |
| S3-compatible | 8 MiB replacement |                   12916415 |                    1534701582 |  212.27 |
| S3-compatible | Unchanged         |                      25548 |                    1537294753 |  207.18 |
| WebDAV        | Base              |                  134281570 |                    1551804329 |  223.49 |
| WebDAV        | 8 MiB replacement |                   12916415 |                    1514988402 |  196.70 |
| WebDAV        | Unchanged         |                      25548 |                    1544421911 |  205.19 |

Each unchanged phase created 7644 bytes of encrypted metadata parts and retransmitted no retained part. The low PUT count does not describe total traffic: fresh verification reads are substantial. Response counts above sum the three workers; parent checks, subsequent downloads and TCP/TLS framing add separate costs. Review this measured read amplification before admitting the large run or advertising transfer costs.

The uploader's 512 MiB cgroup recorded a 538292224-byte peak and 5468 memory-limit events, with no OOM or swap. This is memory pressure, not evidence of headroom. All seven reader peaks were below their 384 MiB caps. The original delay-only WebDAV profile failed with peak concurrency two; the declared rendezvous profile does not change that result. A rejected noncanonical input and a rejected race invocation outside the admitted temporary root also remain recorded. No verifier or filesystem guard was weakened. Earlier short-deadline HDD failures and the asymmetric ingress, physical failure-domain and production gates remain open.

## Recorded explicit-policy result

The separate [explicit-policy receipt](../external-readback-scale-evidence.json) records the corrected 128 MiB run with a 3600-second age policy and seven new offline older-reader restores. Both generic protocols retain all three generations. Retained object records keep their original times and lengths; each receipt matches the minimum over its current dependencies. The multipart GET/repeated-PUT control, evidence epochs, descriptor loss, concurrency and existing protocol refusal checks pass under the race detector.

| Protocol      | Phase             | Received PUT bodies, bytes | Worker response bodies, bytes | Worker HTTP requests | Seconds |
| ------------- | ----------------- | -------------------------: | ----------------------------: | -------------------: | ------: |
| S3-compatible | Base              |                  134281534 |                     745025723 |                  525 |  166.66 |
| S3-compatible | 8 MiB replacement |                   12900636 |                      51601088 |                  240 |   17.65 |
| S3-compatible | Unchanged         |                       4459 |                         46025 |                  173 |    1.92 |
| WebDAV        | Base              |                  134273912 |                     743020419 |                  513 |  145.63 |
| WebDAV        | 8 MiB replacement |                   12900636 |                      51599443 |                  233 |   19.00 |
| WebDAV        | Unchanged         |                       4459 |                         46025 |                  172 |    3.90 |

Each unchanged phase had zero retained-part GETs and 2548 bytes of new encrypted metadata parts. Parent checks and later fresh adapter downloads are recorded separately in the receipt; TCP/TLS framing is excluded. The two small profiles have different host/cache conditions, so their times do not establish a throughput guarantee. The 512 MiB group recorded a 537665536-byte peak and 2822 limit events without OOM or swap. This remains memory pressure.

The earlier comparison with the base generation's aggregate minimum was invalid when an old object left the dependency set; that failed control remains recorded. The corrected per-object check and physical-part map are exercised by this exact source. Fresh-only defaults, independent uncached recovery, original failed profiles and all full-size/physical/production gates remain unchanged. The proposed one-day large-data policy still needs its own admitted execution.
