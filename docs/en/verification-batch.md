# Bounded verification work

[Русский](../ru/verification-batch.md)

The retained physical 100 GiB source-ingress run failed its 36-hour Go test alarm. Its first generation completed; the edited generation reached 13,295 verified objects and 98,114,908,963 bytes. This is a failed whole scenario. Independent full-size recovery acceptance remains open.

The receiver repeatedly checked the entire verified prefix twice for each small batch. A controlled HDD experiment reproduced 4,290 object-stamp checks for 65 objects delivered in 65 steps. The revised receiver performs 194 checks for the same objects and 1,436 content bytes. These counts establish the quadratic prefix-work mechanism; they do not establish its share of the full-run duration or a 100 GiB speedup.

Partial checkpoints retain content evidence. Each new batch checks newly read objects again before saving. The closing batch checks every dependency under the replica lock before publishing COMPLETE. Completed-checkpoint replay still checks all stamps and preserves its original verification time. A changed earlier object invalidates its durable evidence and prevents publication; reopening either rehashes an identical replacement or refuses corruption. Full content scrubbing remains independent.

The controlled candidate passed the full generation suite (66 top-level groups and 81 subtests), the focused race suite (11 groups and two subtests), retained-fixture reopening, and current source expiry/coverage checks. Two generation-suite skips are subprocess helper entrypoints. The [machine-readable evidence](../verification-batch-evidence.json) binds executed trees, source hashes, logs, resource peaks and counts. These results cover the candidate source, before publication and full-size resumption acceptance.

A test-only resumption path admits only the original base-complete, edited-sealed boundary. It checks the exact failed log, private synthetic context digest, unchanged authority, certificates, endpoint, physical source and generation lineage. It uses normal current-time validation and creates no replacement authority. Carried base observations are labelled separately. The prior process lost its in-memory object-type counters, so the edited transfer retains its observed aggregate wire totals and explicitly marks the old file-versus-descriptor split unknown. No deadline, certificate lifetime, request bound, batch size or resource cap is increased.
