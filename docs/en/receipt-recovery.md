# Recovering a missing ingress receipt

[Русский](../ru/receipt-recovery.md)

A process may stop after a generation becomes durable and complete, but before ingress saves its receipt. Ordinary [settlement](source-settlement.md) deliberately refuses to manufacture that receipt. Explicit local recovery can reconstruct it from the original publication evidence under a separate owner permission. This is maintenance on an existing receiver, not an upload or a new publication.

## Required evidence and permission

The source must retain its sealed catalog and original signed intent. The receiver must retain the exact registry slot, catalog, durable complete generation, original complete verification journal and unchanged identities of every referenced object. Missing or damaged evidence is refused. A replica head alone is insufficient. Reading this proof does not scrub, repair, publish, advance verification time or persist a new damage diagnosis.

The fresh `outpost-source-receipt-recovery-1` grant binds the original authority and intent hashes, source, receiver, tenant, domain, repository, writer epoch, operation and generation. Its signature domain differs from settlement. Neither grant can substitute for the other or renew the immutable write intent. The unsigned preview has a ten-minute default lifetime and proves no remote completion.

Pause the source scheduler and inspect the existing source installation:

```sh
outpost source-status --bootstrap /private/source.json
outpost source-receipt-recovery-preview --bootstrap /private/source.json \
  --output /private/receipt-request.json
```

Review the exact identifiers and validity interval. On the owner signing host:

```sh
outpost source-receipt-recovery-sign --key /private/owner-signing-key.json \
  --input /private/receipt-request.json --output /private/receipt-admission.json
```

The admission contains signed public documents, no file names, payload or private keys. Keep it in the private operational workflow. Signing it does not apply receiver policy or contact a node.

## Local receiver maintenance

Stop the receiver worker through its existing supervisor. Apply a current owner-signed configuration using the normal `config-sign`/`config-apply` workflow. It must retain the exact domain trust, a trusted source, this receiver as an allowed holder and an allowed source-to-receiver push edge. Its revision must cover the historical authority. A separate settlement admission can be provisioned as described in the settlement runbook; this recovery grant is not a new configuration field.

On the receiver, using its existing bootstrap and enrolled volume:

```sh
outpost worker-ingress-receipt-recover --bootstrap /private/receiver.json \
  --domain DOMAIN_ID --input /private/receipt-admission.json
```

The command requires the worker execution lease, holds the current policy lock and runs for at most 30 seconds, further bounded by the grant and configuration lifetimes. It uses the existing shared metadata budget and rejects unresolved reservations or changed limits. It never creates a missing installation, opens a listener, receives payload, clears staging or releases existing pins.

Recovery records a receiver-signed audit with the original owner grant, original session-state digest, publication evidence and receipt. Under the replica lock it revalidates the evidence, retains the receipt protection pin and writes the receipt with the **original verification time**. One bounded audit record per immutable intent remains under the same quota after slot reuse; automatic deletion is not provided. Preserve the receiver identity key with its history: identity rotation and missing-history recovery require separate migration.

## Resume and verify

If interrupted, keep all journals and retry the same admission while valid. If it expired, obtain another fresh grant for the same original documents and generation. The audit retains the first permission and records the last execution permission. Unknown staging files, changed proof, revoked policy or insufficient quota leave the operation pending; do not reset or delete the journals.

Restart the receiver only under its current settlement configuration. Use a **separately signed settlement admission** and run `source-settle` as described in the [settlement workflow](source-settlement.md). Success still requires the original receipt, source checkpoint and independent-copy threshold. Recovery does not refresh copy observations, lower their threshold or authorize the next capture.

Short tests execute the new CLI, refusal while the worker runs, ordinary settlement with the previous executable and byte-for-byte recovery of both 393,216-byte file versions with source payload unavailable. Three actual `SIGKILL` boundaries cover durable audit, replica pin and receipt. Native CI repeats the selected-artifact workflow on amd64 and arm64; inspect the exact commit results before accepting an architecture.

Truly unpublished expired operations, lost active journals, key lifecycle and admitted-scale acceptance remain open. The ingress session format is unchanged, so the previous executable can settle the recovered receipt; it rejects the new recovery commands. Preserve recovery audit records when changing executables. Full product acceptance remains separate.
