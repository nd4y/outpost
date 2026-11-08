# Renewing source ingress authority

[Русский](../ru/receiver-renewal.md)

An expired source grant does not require a new receiver directory. `worker-ingress-renew` explicitly replaces the grant in the existing registry, retaining its last intent, receipt, sequence fence and replica generations. The separately signed replacement must have a higher revision and exactly the same source, receiver, domain, repository, writer epoch, keys, limits and profile. This operation does not rotate identities, expand placement or extend an existing write intent.

## Preconditions and order

Stop the source scheduler and join the receiver worker before maintenance. The registry must be either unused with no current slot, or complete and acknowledged with no staged objects, unknown temporary files or owned generation pins. Finish ordinary acknowledgement first. For an expired operation with an already durable receipt, use [settlement](source-settlement.md) before renewal. Missing receipts or incomplete transfers remain pending and cannot be discarded by this command.

1. Retain the old signed authority and prepare a fresh owner-signed authority with a higher revision. Keep the source's original bootstrap and authority file unchanged.
2. Sign and apply a fresh receiver configuration whose `ingress` includes the exact new authority. Its revision must cover the grant revision, and current placement must still permit the source-to-receiver route. Keep the existing disk limits for this maintenance step.
3. Renew the stopped receiver using the old signed authority as the expected previous value.
4. Renew the stopped source with the same new authority. Restart the compatible receiver and source processes, then prepare the next capture.

```sh
outpost source-authority-sign --key /private/owner-key.json \
  --input /private/authority-input.json --output /private/new-authority.json
outpost config-sign --key /private/owner-key.json \
  --input /private/receiver-config-input.json --output /private/receiver-config.json
outpost config-apply --bootstrap /private/receiver.json --input /private/receiver-config.json
outpost worker-ingress-renew --bootstrap /private/receiver.json --domain DOMAIN_ID \
  --trust /private/previous-authority.json --input /private/new-authority.json
outpost source-renew --bootstrap /private/source.json --input /private/new-authority.json
```

The source's two-copy observation permission has its own renewal rules in [source-agent.md](source-agent.md). These commands neither restart a service nor fetch signing keys. Use a new output file for each signing operation. A first receiver renewal may use the source's unchanged original authority file as `--trust`; subsequent renewals must use the actual previously accepted grant.

## Persistence and refusal

The command shares the worker execution lease and rejects a running worker. It holds the current configuration lock across the bounded local metadata transition, rechecks validity after lock waits and writes, and uses the enrolled volume and existing capacity ledger. It opens only existing replica and ingress directories. Changed disk limits, pending reservations, insufficient capacity, missing history or failed volume identity stop admission. The local operation has a 30-second context bound; a kernel filesystem call that does not return is outside that guarantee.

The first migration retains exact `outpost-ingress-registry-1` bytes under their digest, then atomically publishes `outpost-ingress-registry-2`. Version 2 retains signed original, previous, current and last-intent authorities without accumulating a checkpoint for every renewal. Original intent signatures and receipt age remain unchanged. A fresh settlement capability can still read the retained receipt until the next legitimate intent replaces that slot.

After an uncertain reply, repeat the same command with the same previous and new documents. An already committed identical transition returns its receipt. A later revision cannot be replaced by an older replay. The command never removes unfinished data or releases pins to make its preconditions pass.

The previous executable rejects registry version 2. Replacing the active journal with the retained version-1 checkpoint is not a supported rollback: it can lose the later sequence fence. Preserve the entire runtime and use a compatible executable. Independent recovery of retained ciphertext generations still uses the recovery owner and public generation trust.

## Verification boundary

Short synthetic checks cover the same receiver root after expiry, current policy and volume guards, active-worker refusal, historical receipt settlement, unknown staged files, quota failure, revision replay and checkpoint corruption. The CLI workflow signs and applies configuration, renews both sides, captures another version and independently restores both generations. Process interruption checks exercise durable migration and the next-intent/slot transition. These checks do not establish recovery from total registry loss, key rotation, long network partitions, physical disk failure or final large-file/RPO/RTO acceptance. Full product acceptance remains open.
