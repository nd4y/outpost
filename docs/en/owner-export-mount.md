# Owner recovery export across mount namespaces

[Русский](../ru/owner-export-mount.md)

A saved Linux mount ID identifies a mount in the namespace that observed it. After a restart, the same enrolled filesystem, FSID, root inode and read-only state can have a different mount ID. Comparing the entire saved observation during owner-package export refused this otherwise valid source.

The export now validates every stable enrollment field and pins a fresh complete observation for that operation. Every later guard includes the fresh mount ID, so a root or mount replacement during export still fails. The private bootstrap is unchanged. Owner/runtime/source separation, private output permissions, checkpoint age and authority rules retain their checks.

The [bounded HDD receipt](../source-export-mount-evidence.json) preserves the pre-fix refusal and the fixed result. Four groups and seven subtests pass with modules and vet. The source-root case checks four distinct stable-identity refusals and replacement during export. A failed in-progress export retains its private candidate without publishing it; a failure before admission creates no new artifact. The original signed checkpoint remains unchanged.

The same run checks both configured authenticated ingress receivers refusing readiness. Three attempts with agent reopen retain the exact old checkpoint and a 584-byte logical cache inventory. No payload is admitted. The old copy restores locally during the outage; after the primary returns, exactly the next generation completes and both versions restore after source removal. This small corpus declares a 2 MiB logical cache bound, separate from full-size physical capacity.

The preceding 100 GiB case remains failed. All three captures completed and the unchanged file sent zero payload bytes, but private recovery export refused before any restore. That run recorded 99,998 memory-limit events without OOM or swap; it is not a quiet-machine performance result. The full failed-container namespace observation was not separately saved. Actual retained-data repair, fresh full-size readers, current native artifacts and final product acceptance remain separate gates. No grant, saved bootstrap, real endpoint or working service was changed.
