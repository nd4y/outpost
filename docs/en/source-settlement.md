# Completing an expired source operation

[Русский](../ru/source-settlement.md)

An immutable capture intent cannot be renewed. When the receiver durably completed a generation but the source lost its reply or stopped before saving its checkpoint, a fresh `outpost-source-settlement-1` owner grant can authorize retrieval and acknowledgement of that original receipt. The source must already have a sealed, signed catalog for that exact generation. The default receipt-only grant authorizes no payload transfer, capture or publication.

## Owner workflow

Pause the source scheduler and use the existing source installation. Inspect `source-status`; it can read authenticated pending local history after the original intent expires. Its `job.generation` is a local selection, not proof of remote completion.

```sh
outpost source-status --bootstrap /private/source.json
outpost source-settlement-preview --bootstrap /private/source.json \
  --output /private/settlement-request.json
```

The new request contains the original signed authority and intent plus an unsigned grant for the selected sealed generation. It contains no file names, payload or private key. Its default validity is ten minutes. Review the exact source, ingress, tenant, domain, repository, writer epoch, operation and generation; choose the intended validity before signing. The request alone grants no access and makes no remote request.

On the owner signing host:

```sh
outpost source-settlement-sign --key /private/owner-signing-key.json \
  --input /private/settlement-request.json --output /private/settlement-admission.json
```

Install the complete signed admission as one item in the receiver's `settlements` array. The enclosing configuration must use `format: "outpost-control-2"`, a newer accepted revision, a current validity interval wholly inside the settlement grant, and the same current trust and allowed source-to-ingress placement edge. Remove the ordinary `ingress` item for that same domain/receiver binding from this configuration. The two modes cannot own the same registry simultaneously. Sign and apply the complete current configuration through the existing owner workflow:

```sh
outpost config-sign --key /private/owner-signing-key.json \
  --input /private/receiver-config.json --output /private/receiver-config-signed.json
outpost config-apply --bootstrap /private/receiver.json \
  --input /private/receiver-config-signed.json
```

The receiver reopens its existing exact registry; missing history is an error. Current TLS identities, volume binding, placement, pause controls and configuration lifetime still apply. Replacing the configuration cancels in-flight settlement requests, including slow acknowledgement bodies.

Return the signed admission to the source and run:

```sh
outpost source-settle --bootstrap /private/source.json \
  --input /private/settlement-admission.json
outpost source-status --bootstrap /private/source.json
outpost source-checkpoint --bootstrap /private/source.json \
  --output /private/completed-checkpoint.json
```

Success requires `COMPLETE`, the selected generation, the original receipt verification time and the configured independent-copy threshold. The source holds its execution lease, verifies its sealed catalog against the original receipt, saves the normal checkpoint, releases the source view and acknowledges staging through the existing durable boundaries. It does not reopen source bytes. A repeated request for the same completed operation is idempotent while the fresh grant remains valid.

## Pending and uncertain outcomes

No receipt, a mismatched generation, revoked policy, expired TLS identity, expired settlement grant, unavailable volume or missing required copy leaves the operation pending. A settlement grant cannot extend an observation grant or lower `minimumCopies`. Original verification age is never replaced with settlement time. If the fresh grant expires mid-operation, retain the journal and obtain another explicit grant for the same original documents and generation.

For the receipt-only purpose, the receiver must already have persisted its complete receipt. A replica head by itself, a sealed local catalog, or absence of a receipt cannot prove that publication completed or that it is safe to abandon the operation. When publication is complete but the ingress receipt is missing, use the separate [local receipt recovery](receipt-recovery.md) workflow first. A lost source or receiver journal remains an unknown state.

## Finish an expired staged publication

When a receiver already accepted the exact catalog before expiry, prepare a request for that holder with `source-settlement-preview --purpose publish-staged --node RECEIVER_ID`. Sign and install each request using the owner workflow above. A local complete dependency set can be verified without a peer. For a partitioned capture, prepare and install a separate request at each holder and keep the signed staging peer rules and pull edges in both current policies.

The workers reopen the existing staged slots and finish without the source. A paired worker can pull only the missing catalog dependencies from the recorded peer over authenticated HTTPS. Both workers verify their current publication permissions. Source payload, new intents, changed catalogs and additional peers are refused. No full receipt is issued until the entire generation verifies. The receipt records the actual publication verification time and retains the owner grant that authorized it. Up to 16 distinct publication grants may be retained for an unfinished slot.

After publication, run `source-settle` with the primary admission in `--input` and, for a pair, the second admission in `--companion`. The source verifies the required original receipts before advancing its checkpoint or acknowledging cleanup. A missing required receipt or revoked policy keeps the operation pending.

## Reconcile an expired ACTIVE operation

Use `source-settlement-preview --purpose inspect-active --node RECEIVER_ID`, then sign and apply the admission above. Run `source-reconcile --bootstrap FILE --input SIGNED_ADMISSION` separately for each holder involved in the operation. After an automatic change, inspect both the selected and superseded receivers listed by `source-status`. Only the selected receivers can settle the final catalog. The source records each authenticated observation. The receiver distinguishes a durable intent fence, admitted staging, a sealed catalog, independently proven publication without a receipt and an existing receipt. It reports `NOT_ADMITTED` only with compatible durable registry history and an exact predecessor. Missing or contradictory evidence stays unknown.

If a source job is still `PLANNED` and every involved holder proves `NOT_ADMITTED`, the owner can issue new `retire-unadmitted` grants through the same workflow. Run `source-retire-active` with the primary grant in `--input` and the paired grant in `--companion` when applicable. The source rechecks all receivers under its execution lease, saves the signed evidence and records `ABANDONED`. It preserves the previous generation and local history. Unavailable receivers, admitted work and lost journals cannot authorize this transition. After an automatic change in `ACTIVE`, the source preserves the original admission and refuses retirement based on the replacement route.

## Retire an admitted capture before sealing

An expired capture with staged objects can be retired if the source has no sealed catalog and every possible receiver can prove either non-admission or an intact unsealed slot at the exact predecessor. Use `source-settlement-preview --purpose retire-unsealed --node RECEIVER_ID` for each distinct current or superseded receiver. Sign each grant and install it in the receiver's current settlement configuration. Keep the source scheduler paused.

```sh
outpost source-retire-active --bootstrap /private/source.json \
  --input /private/primary-retirement.json \
  --companion /private/companion-retirement.json \
  --superseded /private/superseded-retirement.json
```

Supply the current receivers in the order shown by `source-status`. Omit `--companion` for one copy and `--superseded` when there is no replaced receiver. Each grant binds the original intent and one receiver. The source checks all receivers before sending retirement requests. A sealed catalog, a changed predecessor, unavailable evidence or a lost journal keeps the source pending. If the source or a receiver already sealed the catalog, use the staged-publication or receipt recovery workflow.

The receiver durably fences the old intent and retains its staged objects and pins. After all receivers confirm, the source writes its signed audit, releases its view and commits `ABANDONED` at the previous checkpoint. Repeat the same command after an interrupted reply. With all original grants still current, the source can finish from its durable audit even if a receiver goes offline. If a grant expires before the transition, issue a fresh grant for the same intent and receiver. A receiver with an intact retirement record can return evidence under that fresh grant.

Renew the source and receiver authority after the source reports `ABANDONED`, then restore the ordinary ingress policy. A fresh signed attempt at the same sequence and exact predecessor can reclaim the retired slot in bounded steps. Unknown staging files still block reuse. The receiver keeps the previous complete generation and requires a compatible executable to read the new retirement record. Source view release follows the installed provider's existing contract.

## Retire an expired unstarted intent

The source agent can retire an exact expired intent while its signed journal is still `PREPARING`, including after successful local job preparation. At execution the agent checks validity again and durably saves `ACTIVE` before its first receiver admission request. Preview and retirement take the same execution lease as capture. The owner permit binds the exact source, intent, previous checkpoint and expiry. Existing and new `ACTIVE` intents require separate reconciliation even without a receipt.

```sh
outpost source-unstarted-preview --bootstrap /private/source.json \
  --output /private/retirement-request.json
outpost source-unstarted-sign --key /private/owner-signing-key.json \
  --input /private/retirement-request.json --output /private/signed-retirement.json
outpost source-unstarted-retire --bootstrap /private/source.json \
  --input /private/signed-retirement.json
```

Run the signing command on the owner host. A successful source response reports `ABANDONED` with the original operation and the previous completed generation. The source first stores a signed audit record, then commits the state transition. A restart between these writes can replay the same active permit. Local files, the previous checkpoint and the receiver remain intact. Before the next capture, renew authority on both the source and its existing receiver. A prepared-export source needs an advanced producer export.

The original source authority remains expired after settlement. A subsequent capture needs explicit authority renewal and compatible admission at the same receiver. Receiver renewal is an explicit local maintenance operation. Preserve the existing registry and old generations; do not replace its directory to bypass a binding conflict.

## Compatibility and acceptance

`outpost-control-1` retains its original signature domain and remains readable. The `settlements` field is forbidden in version 1. Version 2 uses a distinct signature domain so an older worker rejects it. The original intent remains immutable. Late receipts and retirement evidence add fields that older readers may refuse. Keep a compatible executable while the recovered operation is pending. Downgrading an executable does not add settlement support.

Short tests cover the fresh capability, same-directory HTTPS registry reopening, exact receipt replay, payload denial, current worker policy withdrawal, missing receipt and expired independent-copy authorization. The complete CLI preview/sign/config-apply/settle workflow runs against a current worker; a selected previous executable accepts control1 and refuses control2. Three actual `SIGKILL` boundaries cover receipt observation, checkpoint persistence and final source head. A queued grant is rechecked after the execution lease is acquired. Both 393,216-byte source generations restore byte-for-byte after settlement, including the ten-byte change, with the source tree unavailable.

The native distribution workflow repeats settlement and CLI cases on amd64 and arm64; inspect the exact commit's execution result before treating either architecture as verified. Full installation, key lifecycle, scale and product acceptance remain separate. Keep the full product acceptance open; this narrow recovery path is not a general solution for every expired operation.

The [receiver renewal workflow](receiver-renewal.md) admits a fresh same-scope grant in the existing registry after explicit quiescent maintenance. It preserves historical receipts and generations, fences previous readers and uses the current receiver policy and disk budget.

CLI checks wait for the exact authenticated receipt over HTTPS after a deliberate transient 503. Persisted ACTIVE status alone is not evidence that the receiver is serving.
