# Scoped installation, Collector and current streaming checks

The [component receipt](../final-component-evidence.json) records three separately selected downloaded-binary installation runs, actual pinned Collector interoperability and a new current-code 128 MiB streaming check. These results finish component checks; full-scale cloud/asymmetric and product acceptance remain separate.

## Downloaded installation and compatibility

The current 8c candidate upgrades from and rolls back to 9f. The preceding 9f/e9 and e9/f2 pairs retain their own commits and helpers. Each pair passes the same seven installation checks: isolation, unsafe-start refusal, explicit volume enrollment, cached startup and upgrade/rollback, Compose constraints, missing/read-only volume refusal, and independent 19,456-byte recovery after source removal. Downloaded CLI bytes are independently verified and never substituted with the separately compiled test helper. Candidate manifests and embedded distribution manifests have different hashes; the receipt preserves both.

All three amd64 runs produced 23 exited containers: 18 successful commands and five expected refusal commands. Every container uses the declared one-CPU, 768 MiB, no-swap, no-network profile. Deliberately unsafe attempted profiles are refused before normal work; their requested settings do not certify successful unsafe operation. Current 8c has eight recorded cgroup peaks and fifteen short-lived unknown peaks; 9f has nine and fourteen; e9 has eight and fifteen. Missing cgroups encountered by the observer remain recorded. These partial samples do not establish a whole-host peak or headroom. Both native architectures have separate CI and strict archive/SBOM verification; this HDD host executes amd64.

## Actual pinned Collector

Collector Contrib 0.163.2 accepts both OTLP/HTTP signals through synthetic mutual TLS and exports original timestamps and the explicit unknown marker to local files. The current 527-input test passes in 11.15 seconds. The full test container, including temporary execution and page cache, peaks at 597,540,864 bytes under 768 MiB, with no memory-limit, OOM or swap events. The exact 419,160,226-byte executable and its SHA-256 are retained. This is real Collector process interoperability in an isolated fixture; live monitoring routes and notifications are not enrolled.

## Current bounded streaming

The current compiled source runs four matched single/paired cases under complete-copy and split-coverage release policies. Eight captures retain both versions on three physical holder stores; 24 new previous-format CLI processes restore both versions from every holder, each followed by a separate byte/attribute oracle. No source, mutable holder index or network is mounted in these recovery namespaces. Immutable views share ciphertext inodes and do not count as additional physical copies.

The producer is admitted idle with 0.5 CPU and 512 MiB. Its peak is 538,021,888 bytes with 2,459 memory-limit events, no OOM or swap; the kernel's observed transient peak and pressure remain explicit. The 48 consumer phases use 0.5 CPU and 384 MiB, peak at 304,132,096 bytes and record no memory-limit events. Eight source-state checkpoints reach at most 118,784 bytes under the separate 2 GiB disk-state budget; checkpoints are not an independent continuous peak. A legacy terminal shorthand says cohosted for every non-full run; the recorded actual admission is idle, and the raw terminal is preserved.

The receipt retains actual per-case routes, received body bytes, source reads, duplicate counts, required-proof refusal, release/catch-up times and every fresh-reader hash. Application-body caps are distinct from physical wire rate. The historical 128 MiB control is not relabelled. Physical 100 GiB asymmetric/cloud scenarios and final distinct requirement acceptance remain mandatory.

## Direct CLI usability trace

REQ-49 / AT-31 now directly link three existing checks: Unicode and spaces in configuration-key paths with no overwrite, stable public error and exit codes including 130 for cancellation, and the actual selected CLI process flow. The catalog contains 638 distinct checks, up from 636. Code and tests are unchanged. The full Go package run at 6571 covers the first two checks. The selected native flow passes on amd64 and arm64 with graceful SIGTERM joins, two workers and four independent 2 MiB restores. A separate SIGINT process result is not claimed.

All 31 current browser scenarios pass, including the three main interface flows, role and refusal handling, offline and empty states, bilingual keyboard accessibility, 320px reflow and 200 percent text size. All five frontend hashes still match the earlier manual keyboard sample. Its observations and limits for screen readers and wider device coverage remain unchanged, so another walkthrough is unnecessary. Source links, package results and named case results retain their own scopes; they do not certify the whole scenario.
