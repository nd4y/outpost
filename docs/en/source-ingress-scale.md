# Retained 100 GiB capture and independent recovery

[Русский](../ru/source-ingress-scale.md)

The [source-bound receipt](../source-ingress-scale-evidence.json) records an incompressible, physically allocated 100 GiB source, a contiguous 8 MiB replacement and an unchanged capture. Four fresh standalone reader processes recover the full old/edited versions after source and operational-key loss. The combined edited request bodies total **33724819 bytes**, below 128 MiB; the unchanged capture sends zero file payload. The largest measured source-state checkpoint is **4042752 bytes** under the declared 2 GiB source-state admission budget. This checkpoint measurement is not an independently sampled all-time peak; source-file and source-view space are accounted separately.

## Actual failure and recovery chain

The original `7eec7ff` driver reached a complete base generation and durable edited progress, then failed its 36-hour alarm. The `9f0f712` driver resumed the same sealed edit with unchanged identities, authority, certificates and original counters, and completed the unchanged capture. It then failed the private recovery export guard. Both drivers remain FAIL.

The [owner export correction](owner-export-mount.md) at `8c78370` admits an unchanged enrolled filesystem/root after a namespace-local mount ID change while retaining a fresh complete observation during export. Actual CLI export, package inspection and extraction succeeded on the retained corpus. Their wrapper then failed because it expected a loose executable instead of the verified native tools archive. A separate readback verified that existing effect and extracted the pinned reader; the export was not repeated. That wrapper also remains failed. This is an explicitly composed workflow, not a fabricated successful original Go test.

All three capture observations below are carried from those recorded drivers. The edited totals include the prior stable counters. Their lost old file/descriptor split stays unknown (`-1`); it is never replaced by zero. Edited time starts at the original snapshot and includes stopped intervals. Object bodies include encrypted descriptor/root objects; other PUT bodies are counted separately. HTTP/TLS headers, response readback, logical references and raw channel throughput are not these counters.

| Capture   | Object request-body bytes | Other PUT body bytes | Allocated source state at checkpoint, bytes |
| --------- | ------------------------: | -------------------: | ------------------------------------------: |
| base      |              107395477507 |              1336854 |                                     1359872 |
| patched   |                  31103221 |              2621598 |                                     2703360 |
| unchanged |                       820 |              1311521 |                                     4042752 |

## Four full independent restores

Only the owned synthetic source tree, source runtime and seven operational-key/context files were removed after the trusted owner package was verified. The retained package contains the separately required decryption material and public trust, without a signing key. Ciphertext generations and failure logs remain available.

Two fresh CLI processes use the actual selected packaged reader `8c783708704dbf55cbf05a2472be3436bc4a6d15`; two more use the independently selected previous reader `0ad4d17f51f7dfd334eae02eb9cfc3bc06bc72c6`. Each process mounts only immutable ciphertext objects/catalogs, two read-only owner/trust files, its pinned executable and a fresh output. It has no source, mutable holder index/runtime, operational credentials, endpoint configuration or network. Separate deterministic oracles read every byte, compare old/edited hashes and verify the declared mode, ownership, nanosecond timestamp and hardlink identity. The same retained versions pass in both reader versions.

These immutable views share ciphertext inodes. They prove independent process recovery, not extra physical replicas or failure domains. The receipt keeps every reader/oracle log hash, actual memory peak and memory-limit event count; no zero limit-event count or quiet-machine performance claim is invented.

The first previous-reader controller exited with code 1 after its base restore and independent oracle both returned 0. Its exception was not retained; that failed driver remains recorded. Only the not-yet-started edited restore and its oracle were continued with the same binaries, namespace and resource/deadline limits. The base pair was not replayed. The continuation stores controller diagnostics and each phase receipt before reporting success. The base CLI duration is a wall-clock observation, and its oracle reports its own elapsed time, as distinguished in the receipt.

## Resource and profile boundary

The source driver used one CPU, 768 MiB memory, no swap, 30-second requests, 8 MiB catalog batches and the 2 GiB source-state budget. Its recorded memory peak was 805572608 bytes with 99998 limit events and no OOM/swap. Source timing includes cohosted/stopped intervals. Fresh reader/oracle processes run sequentially at one CPU/768 MiB/no swap with an eight-hour deadline per phase and admitted HDD reserve. No live service, network rule, storage capacity or authority was changed to obtain success.

This accepts one retained complete receiver and the composed recovery chain. It does not establish fresh initial capture under current source code, the separate matched asymmetric 100 GiB profiles, full three-holder S3-compatible/WebDAV upload/recovery, current installation or complete product acceptance. Real profile/account admission, physical failure domains and RPO/RTO remain separate.
