# Delivery and acceptance roadmap

[Русский](../ru/roadmap.md)

Current development includes the bilingual specification, pinned toolkit, [independent file kits](file-kit-format.md), autonomous source/worker processes, a protected management service with a bilingual interface and a [Linux distribution candidate](distribution.md). The [53-requirement implementation map](../product-status.json) keeps component checks separate from full acceptance. [G1 is accepted](g1-acceptance.md) on its recorded source after all 23 phases of the physical 100 GiB run and independent old/new recovery. Full G2/G3, production releases, target installation/upgrade/restore and operational SLOs remain NOT VERIFIED until their own evidence is accepted. The [native restic fixture](g1-prototype.md) is retained as a comparison.

| Stage | Goal                                                                   | Required evidence                                                                    |
| ----- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| M0    | Resolve independent file kits, maintenance and distributed publication | G1-G3 reproducible prototypes, measured costs and an accepted engine/format decision |
| M1    | Source consistency, encryption, history and independent recovery       | AT-02-AT-05 and AT-23                                                                |
| M2    | Autonomous replicas across partial connectivity                        | AT-01, AT-07-AT-13, AT-17, AT-20-AT-22, AT-24, AT-29                                 |
| M3    | External-storage profiles and distributed upload                       | AT-06, AT-14-AT-16, AT-18, AT-19, AT-27                                              |
| M4    | Operational release, UI/CLI, installation and telemetry                | AT-25, AT-26, AT-30-AT-35 and every other applicable main-profile scenario           |
| M5    | Delayed archive profile                                                | AT-28 and affected recovery/GC/integrity regressions                                 |

## Feasibility gates

The [G2 local-replica candidate](generation-replicas.md) now has bounded evidence for signed closures, durable reception, maintenance authority, pins and actual process interruption. It uses a 2 MiB integration source and a direct sequence 1-to-181 catch-up. This does not accept large-history costs, long-lived multi-node operation, epoch transitions or the deferred full-scale gates.

The [G3 peer candidate](peer-transfer.md) verifies bounded mTLS push/pull, durable retry and complete publication through an asynchronous bridge, including independent old/new restoration and false-ACK rejection. These transport components are connected to the autonomous worker and its durable policy/job state. The [external-upload candidate](external-upload.md) adds cached signed assignment, S3-compatible/WebDAV adapters and three actual worker processes with SIGKILL takeover and independent old/new cloud recovery in small fixtures. The [durable queue](upload-queue.md) adds bounded multi-target execution, persisted retry/cooldown, actual process restart and protected admission/completion boundaries. Real target capability/ACL admission, complete credential lifecycle, shared-account admission and traffic accounting, long partitions and heavy acceptance remain open; full G3 stays NOT_VERIFIED.

G1 must recover a pre-created file kit with no repository index, other-file payload or source access. G2 must preserve actual pinned dependencies and kits across sealing, prune/repack and long absence. G3 must never publish incomplete data after interrupted transfers, duplicate work or uncertain receipts.

An ordinary restic selective restore is not proof of G1. A signature is not proof that GC may remove a referenced object. A successful upload is not proof of target completeness. Preserve these requirements if the adapter or engine changes.

## Measurement ownership and stop conditions

The maintainer owns the M0 measurement plan and records exact code, hardware, datasets, commands and costs. Before releasing each profile, set supported capacity, RPO/RTO, resource/queue budgets, compatibility and retention. A simulated 180-generation gap does not prove 180 days of operation.

Each task has a bounded scope, relevant acceptance, rollback and stop condition. Source completion never starts deployment automatically. Real notifications and destructive fault tests need an explicitly authorized test environment. Legacy images and data need a separate migration plan.

The repository remains adopting until every applicable standard criterion has evidence. CI verifies repository mechanics only. New requirements keep stable IDs and are reflected in both languages and the [catalog](../requirements.json).
