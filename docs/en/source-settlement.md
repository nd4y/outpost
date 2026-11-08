# Completing an expired source operation

[Русский](../ru/source-settlement.md)

An immutable capture intent cannot be renewed. When the receiver durably completed a generation but the source lost its reply or stopped before saving its checkpoint, a fresh `outpost-source-settlement-1` owner grant can authorize retrieval and acknowledgement of that original receipt. The source must already have a sealed, signed catalog for that exact generation. The grant does not authorize reading or writing ciphertext, starting a capture, or publishing a catalog.

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

The receiver must already have persisted its complete receipt. A replica head by itself, a sealed local catalog, or absence of a receipt cannot prove that publication completed or that it is safe to abandon the operation. When publication is complete but the ingress receipt is missing, use the separate [local receipt recovery](receipt-recovery.md) workflow first. Truly unpublished expired captures and lost active journals still need separate reconciliation. No reset, automatic abort or staging deletion is provided by this command.

The original source authority remains expired after settlement. A subsequent capture needs explicit authority renewal and compatible admission at the same receiver. Receiver renewal is an explicit local maintenance operation. Preserve the existing registry and old generations; do not replace its directory to bypass a binding conflict.

## Compatibility and acceptance

`outpost-control-1` retains its original signature domain and remains readable. The `settlements` field is forbidden in version 1. Version 2 uses a distinct signature domain so an older worker rejects it. Source/capture and ingress journal formats are unchanged: the fresh grant is supplied separately and never rewrites the original intent. Downgrading an executable does not add settlement support.

Short tests cover the fresh capability, same-directory HTTPS registry reopening, exact receipt replay, payload denial, current worker policy withdrawal, missing receipt and expired independent-copy authorization. The complete CLI preview/sign/config-apply/settle workflow runs against a current worker; a selected previous executable accepts control1 and refuses control2. Three actual `SIGKILL` boundaries cover receipt observation, checkpoint persistence and final source head. A queued grant is rechecked after the execution lease is acquired. Both 393,216-byte source generations restore byte-for-byte after settlement, including the ten-byte change, with the source tree unavailable.

The native distribution workflow repeats settlement and CLI cases on amd64 and arm64; inspect the exact commit's execution result before treating either architecture as verified. Full installation, key lifecycle, scale and product acceptance remain separate. Keep the full product acceptance open; this narrow recovery path is not a general solution for every expired operation.

The [receiver renewal workflow](receiver-renewal.md) admits a fresh same-scope grant in the existing registry after explicit quiescent maintenance. It preserves historical receipts and generations, fences previous readers and uses the current receiver policy and disk budget.
