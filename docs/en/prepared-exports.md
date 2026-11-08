# Prepared application exports

[Русский](../ru/prepared-exports.md)

The source agent can capture a closed export created by a separately configured native application producer. The private `outpost-source-agent-prepared-1` bootstrap declares `profile.consistency: "application"` and binds the producer's public key, method, original timestamps and exact file inventory. The producer must finish its consistent export before signing it. `producer-signed` status identifies this attestation; a signature or matching file hash alone does not establish application consistency.

This provider does not execute application commands, freeze a live database, or create Btrfs, ZFS or LVM snapshots. Shared configuration cannot supply a shell command. The current executable still supports ordinary best-effort sources separately. Unsupported consistency providers fail closed.

## Private enrollment

Keep the source-agent bootstrap, volume binding, HTTPS identity, recovery owner and writer authority described in [source-agent.md](source-agent.md). Use a new runtime directory for this provider; changing an existing best-effort bootstrap is not a migration. Enroll the existing private parent containing immutable export directories with `source-probe`. It must be disjoint from runtime storage.

Change the bootstrap format to `outpost-source-agent-prepared-1`, set `profile.consistency` to `application`, and add:

```json
{
  "prepared": {
    "trust": {
      "profile": "PROFILE_ID",
      "origin": "ORIGIN_ID",
      "method": "native-application-export-v1",
      "producer": "BASE64_ED25519_PUBLIC_KEY",
      "maxBytes": 1073741824,
      "maxFiles": 4096
    },
    "manifestFile": "/private/current-export.json"
  }
}
```

These are placeholders within the complete private bootstrap. Profile/origin must match the source profile, and the producer byte limit cannot exceed `profile.maxSourceBytes`. The method is a locally agreed identifier, not an executable name. The manifest is bounded to 1 MiB and 4096 regular files. Paths remain relative to the enrolled producer parent; source filenames stay private.

The selected export must contain only the signed regular files and their necessary parent directories. Missing or extra files, extra empty directories, symbolic links, hardlink aliases, mount crossings, traversal, changed identity or changed content are refused. All selected entries must belong to the source's admitted domain. Split application exports into separate explicitly consistent profiles if their placement policies differ; silently excluding part of an admitted export is not allowed.

## Producer and capture

The native producer creates and durably finishes a new immutable directory, such as `export-42`. It records an increasing `sequence`, the original `snapshotUnix`, `completedUnix` and relative `root` in a private claim. Completion cannot precede the snapshot or lie in the future. The private producer signing file contains a `privateKey` field; it is separate from source writer and recovery keys.

```sh
outpost source-prepared-export-create --bootstrap /private/source.json \
  --key /private/producer-key.json --input /private/export-claim.json \
  --output /private/next-export.json
```

The command measures the exact closed inventory, checks stable identities, signs `outpost-prepared-export-1`, and creates a new private output without overwrite. It does not open source runtime or source encryption/writer key files. The producer then atomically publishes this manifest at its configured `manifestFile`, retaining the selected export unchanged. Establish producer retention before enabling capture; Outpost never deletes native exports.

```sh
outpost source-init --bootstrap /private/source.json
outpost source-next --bootstrap /private/source.json
outpost source-run --bootstrap /private/source.json
outpost source-status --bootstrap /private/source.json
```

The first manifest must already exist for initialization. `source-next` archives the exact signed manifest under its digest before committing the immutable intent. Once that intent is durable, retries use only the frozen manifest, even if the producer publishes a newer pointer. A missing frozen manifest stops recovery; it is not reconstructed from the current pointer. A crash before the intent can leave bounded retained manifest metadata without an admitted operation.

Successful captures retain the producer's original snapshot time. A subsequent export must advance its producer sequence and cannot move either original timestamp backwards. An unchanged export returns `EXPORT_NOT_ADVANCED`; the scheduler waits using its configured retry interval without refreshing the last completed generation or its age. Regular artifact names have stable keyed lineage within this provider binding, so recreated export inodes do not break file version history.

Full byte verification occurs on admission and before sealing. This deliberately adds source reads; low memory use does not imply low read amplification or proven large-file throughput. Native export creation, retained export bytes and snapshot churn need separate capacity/performance accounting. Runtime metadata uses the existing shared quota, volume identity and authority guards.

## Recovery and compatibility

The existing checkpoint, required-copy threshold, provider release and acknowledgement order remains intact. Release records only the consumer's durable completion; it does not open, delete or modify producer files. After sealing, receipt/checkpoint recovery does not need source payload access. Independent file and generation recovery uses the existing encrypted format and recovery material.

Previous executables refuse the prepared bootstrap without changing the journal. They can still recover compatible ciphertext. Preserve runtime state and use a compatible executable instead of changing the bootstrap format or discarding journals. Producer signing-key rotation, a different source root/method, and conversion of existing profiles require separate migration work.

Short tests cover closed-inventory refusal, current authority/quota/volume guards, unchanged-export scheduling, pointer changes, old/new file history and actual SIGKILL after manifest freeze, intent commit and provider release. The selected CLI test creates two real SQLite exports using the [Online Backup API](https://www.sqlite.org/backup.html) through [Python's SQLite backup interface](https://docs.python.org/3.11/library/sqlite3.html#sqlite3.Connection.backup), with a conflicting uncommitted WAL transaction left open. After the original application and export paths become unavailable, previous/current recovery executables restore the generations; SQLite checks integrity and exact committed records. This is synthetic application evidence, not acceptance of other applications or production sources. Full source-provider, scale and product gates remain open in the [completion map](../product-status.json).
