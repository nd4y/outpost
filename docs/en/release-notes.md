# Development candidate release notes

[Русский](../ru/release-notes.md)

This is an experimental development candidate. It is not an accepted production release. Select the exact source commit, CI run, attempt, native architecture and independently retained candidate digest before downloading or executing its artifacts.

The candidate provides Linux amd64 and arm64 programs for source capture, peer replication, S3-compatible and WebDAV uploads, owner recovery and the management API/interface. Workers hold ciphertext without data decryption keys. Capture encrypts content and original paths before transfer. Retained file versions share unchanged encrypted blocks and remain independently recoverable with the corresponding owner material. Placement and transit permissions apply per domain.

Recent changes add exact continuation of a durably staged catalog, frozen maintenance-plan checkpoint restoration and combined primary-index/retention/pending-plan recovery. Combined metadata recovery requires the current signed index copy, its exact anti-rollback anchor, enrolled node key and immutable dependencies. It does not reconstruct a lost volume or authorize new deletion candidates.

The distribution includes checksums, license notices, packaging inputs and a binary-bound CycloneDX inventory. The CI candidate binds these files and both language versions of these notes to the selected commit and run. Provenance is a CI declaration checked against independently selected Actions metadata, not a release signature or a claim of current backup health.

Compatibility is format-specific. Inspect the selected CLI's `version` result and the source-bound installation documentation. The native CI baseline is the documented previous implementation, not a previously published production image. Keep existing owner kits and independent rollback evidence; never reset a replica format to make an upgrade succeed.

Whole-product acceptance remains open. In particular, full-scale distributed timing, topology and provider admission, the controlled G3 throughput profile, complete-volume loss, installed cold boot and operational RPO/RTO/costs require their own evidence. The live product requirement map retains these gates. CI artifacts expire after their stated retention period; preserve an accepted candidate and its independent selection evidence in owner-controlled storage. No migration, deployment, network change or notification is performed by downloading or verifying the package.
