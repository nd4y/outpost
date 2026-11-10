# Private management snapshots

[Русский](../ru/management-snapshots.md)

`management-snapshot` writes a consistent private copy of the administrative journal and its referenced metadata. It preserves policy and authority fences, original receipts, signed command requests/envelopes, the current report slots, configuration caches and unpublished-intent abandonment evidence. It does not contain backup payloads or signing, TLS or recovery private keys. Retain the private service profile and key material separately under the owner's recovery procedure.

## Export and independent inspection

Choose a new file inside an existing private directory (mode 0700) outside the live management directory. The management process must already be stopped: export acquires its execution lease and never stops another process. Deployment authorization still governs service stop/start.

```sh
outpost management-snapshot --input /private/management.json --output /private/exports/checkpoint.ops --max-bytes 16777216
outpost management-snapshot-inspect --input /private/exports/checkpoint.ops --trust /private/checkpoint-trust.json --max-bytes 16777216
outpost management-snapshot-stage --input /private/exports/checkpoint.ops --trust /private/checkpoint-trust.json --output /private/exports/history --max-bytes 16777216
```

The first command returns a checkpoint digest, registry revision, original observation time, admitted profile revision/digest and exact byte/file counts. Save that receipt separately from the export. The private trust JSON has `format: outpost-management-snapshot-trust-1`, the expected base64 owner and service public keys (`owner`, `signer`) and the exact receipt digest (`checkpoint`). Use the keys from independently retained enrollment material. Choosing a digest supplied only by the archive itself does not establish that this was the selected checkpoint.

Inspection needs only the selected snapshot and that public trust record. It does not load any private key, contact the center, source or peers, create a live registry, change authority or reconcile operations. It returns original audit records and effective receipts, including `ABANDONED`. Results always say `state: HISTORICAL`, `currentState: UNKNOWN`, `replayAllowed: false`. An admitted or published command remains unconfirmed without its original node acknowledgement.

Staging uses the same checks to write the authenticated registry and its referenced files into a new directory under a private parent. It publishes that directory without replacement after verifying the entire stream and syncing the files and directories. Its receipt retains the historical status and replay restriction. Keep the staged directory outside the live runtime. An interrupted or rejected run may leave a private `.partial-management-*` directory for inspection. Retry with an unused output name if a previous result exists.

## Durability and limits

The versioned binary stream contains a canonical service-signed manifest followed by the exact ordered file bytes, with no compression. The registry determines all output paths. The manifest binds all sizes, SHA-256 digests, dependency paths and explicitly absent first-use caches. Inspection independently derives the complete dependency set from the verified registry and rejects missing, duplicate, additional or renamed dependencies, incorrect trust, truncation and trailing bytes. A cache written before its registry receipt is preserved as evidence of the original effect; it is never replaced by an older pointer.

Export holds the registry lock and reads each dependency twice, rejecting change between planning and writing. It never follows symbolic links or copies live locks, temporary files, unreferenced report slots or arbitrary files from the runtime. Memory is bounded by one metadata file plus the registry/manifest. The manifest limit is 8 MiB, each metadata file is bounded by its existing format limit, and the entire export has an explicit maximum of 1 GiB (default CLI limit 16 MiB). Larger supported-scale admission remains to be measured. This manual export is not an automatic retention policy or a reservation against other applications' writes to the export filesystem; filesystem exhaustion fails the export.

A new private `.partial-snapshot-*` file receives the stream and is synced before publication. The requested name is published without replacement and its directory is synced before success. Existing files are never overwritten. Failed/interrupted prefixes may remain under their private partial names and are not accepted snapshots; inspect the exact owned export before any cleanup. A successful retry uses a new partial file and preserves earlier evidence. A result lost after publication can be verified against the independently retained checkpoint; the existing file is not replaced by a retry.

## Recovery boundary

These commands recover administrative history for review. They do not activate an old runtime. Snapshot integrity and selection do not prove global freshness, fencing of an old service instance, or absence of later commands. Never copy an old registry or its format1 checkpoint over current format2 state: doing so could forget abandonment fences. Active control-plane recovery, identity transition and bounded audit retention remain separate implementation/acceptance work. Old backup data remains independently readable through the existing recovery tools.
