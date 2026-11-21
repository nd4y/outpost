# Prepared application exports

[Русский](../ru/prepared-exports.md)

The source agent can capture a closed export created by a separately configured native application producer. The private `outpost-source-agent-prepared-1` bootstrap declares `profile.consistency: "application"` and binds the producer's public key, method, original timestamps and exact file inventory. The producer must finish its consistent export before signing it. `producer-signed` status identifies this attestation; a signature or matching file hash alone does not establish application consistency.

This provider consumes completed native views. The configured application producer creates its consistent export. The local Btrfs producer can create a read-only snapshot on an admitted staging tree. Shared configuration supplies signed policy, while the private source profile selects the local producer. The executable supports ordinary best-effort sources separately and refuses unsupported consistency providers.

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

The command measures the exact closed inventory, checks stable identities, signs `outpost-prepared-export-1`, and creates a new private output without overwrite. It uses only the producer key. The producer then atomically publishes this manifest at its configured `manifestFile` and retains the selected export until release. Establish producer retention before enabling capture.

```sh
outpost source-init --bootstrap /private/source.json
outpost source-next --bootstrap /private/source.json
outpost source-run --bootstrap /private/source.json
outpost source-status --bootstrap /private/source.json
```

The first manifest must already exist for initialization. `source-next` archives the exact signed manifest under its digest before committing the immutable intent. Once that intent is durable, retries use only the frozen manifest, even if the producer publishes a newer pointer. A missing frozen manifest stops recovery; it is not reconstructed from the current pointer. A crash before the intent can leave bounded retained manifest metadata without an admitted operation.

Successful captures retain the producer's original snapshot time. A subsequent export must advance its producer sequence and cannot move either original timestamp backwards. An unchanged export returns `EXPORT_NOT_ADVANCED`; the scheduler waits using its configured retry interval without refreshing the last completed generation or its age. Regular artifact names have stable keyed lineage within this provider binding, so recreated export inodes do not break file version history.

Full byte verification occurs on admission and before sealing. This deliberately adds source reads; low memory use does not imply low read amplification or proven large-file throughput. Native export creation, retained export bytes and snapshot churn need separate capacity/performance accounting. Runtime metadata uses the existing shared quota, volume identity and authority guards.

## Read-only Btrfs snapshots

For filesystem consistency, use the same prepared bootstrap with `profile.consistency` set to `filesystem`. Set `prepared.trust.method` to `btrfs-readonly-snapshot-v1` and `prepared.trust.snapshotOrigin` to the source subvolume UUID as 32 lowercase hex digits. Enroll the private snapshot parent as the source tree. Keep the source subvolume and its snapshot directories accessible to the enrolled source user with private permissions.

The trusted producer runs `btrfs subvolume snapshot -r LIVE SNAPSHOT` on the source host, with `SNAPSHOT` below the enrolled parent. It uses the existing manifest command with an increasing sequence, the relative snapshot root and `completedUnix`. Omit `snapshotUnix` to use the snapshot creation time returned by the kernel, or supply that exact time. The signed manifest carries the snapshot UUID. Admission and pre-seal verification check the native read-only flag, original transaction, enrolled parent UUID, snapshot UUID and creation time. An ordinary directory, writable snapshot, changed snapshot or snapshot of another source is refused. These checks use an unprivileged consumer.

Keep the closed-inventory limits above. Btrfs snapshots do not include nested subvolumes. Enroll each required nested subvolume separately. Snapshot creation and retention remain with the producer. The filesystem profile establishes a filesystem view and makes no application-consistency claim.

### Native Btrfs producer

Use a private request with a `profile` of format `outpost-btrfs-producer-1`, an opaque `operationId` and `sequence` starting at 1. The profile includes `source` and `staging` tree bindings from `source-probe` with the same opaque origin. The trees must be disjoint and on the same Btrfs filesystem. The original source must be a subvolume with the UUID in `trust.snapshotOrigin`. Match `staging` to the prepared source agent's tree. Include the exact prepared `trust` object, a separately admitted `stateVolume` with `trust.profile` as its scope, a pre-created private `stateDirectory`, and `maxRetained` from 1 to 16.

```sh
outpost source-native-btrfs-export --input /private/snapshot-request.json \
  --key /private/producer-key.json --output /private/manifests/next-export.json
```

The producer persists its signed operation before the native snapshot call and verifies the resulting read-only subvolume, parent UUID and creation time. A repeated request reopens the same snapshot and returns the exact signed manifest. An unrecorded destination or a changed acquired UUID blocks the operation. The next producer operation advances the sequence by one and waits if the retained count reaches its limit. Keep the producer journal in its original admitted directory and select a private manifest parent disjoint from the source, staging and producer state. The manifest includes source names and stays in the trusted zone.

This profile snapshots one subvolume. Btrfs snapshot boundaries and the prepared export's regular-file restrictions apply. The source agent consumes the manifest through the ordinary prepared workflow.

#### Release a native snapshot

For a new filesystem runtime, set `prepared.nativeReleaseTickets` to `true` in the private source bootstrap. After the configured complete-copy or staged-coverage checkpoint is durable and the view is released, the source signs a ticket for the exact generation, operation and snapshot. `source-status` reports the digest and issue time alongside the separate provider release observation. Read the exact ticket with `source-native-release-ticket --bootstrap FILE --operation ID --output TICKET`. The operation is the SHA-256 of the signed manifest. This lookup can run while the capture process holds its execution lease.

The producer runs `source-native-btrfs-dispose --input PRIVATE_REQUEST --trust SOURCE_TRUST --key PRODUCER_KEY` in a separately authorized local context. Its request has format `outpost-btrfs-disposal-request-1` and contains the original `profile`, `manifestFile` and `ticketFile`. Use the source writer's independently retained public generation trust. The producer verifies both signatures and records a disposal intent before deleting by the kernel subvolume ID on the admitted staging filesystem. Keep the producer's disposal records and permissions separate from the source runtime.

The signed disposal result distinguishes `removedUnix`, observed after a successful kernel reply, from `pathAbsentUnix`, observed on the admitted staging filesystem. If the kernel reply is lost, replay can confirm absence without inventing a removal time. These observations measure the snapshot reference, while reclaimed bytes need separate filesystem accounting. An abandoned capture records a logical view release and leaves the producer's snapshot for separate retention handling.

## Recovery and compatibility

The checkpoint, required-copy threshold, consumer release and acknowledgement follow the same durable order. The producer handles physical disposal separately using its signed ticket. After sealing, receipt and checkpoint recovery use retained metadata. Independent file and generation recovery uses the encrypted format and recovery material.

Previous executables refuse the prepared bootstrap without changing the journal. They can still recover compatible ciphertext. Preserve runtime state and use a compatible executable instead of changing the bootstrap format or discarding journals. Producer signing-key rotation, a different source root/method, and conversion of existing profiles require separate migration work.

Short tests cover closed-inventory refusal, current authority/quota/volume guards, unchanged-export scheduling, pointer changes, old/new file history and actual SIGKILL after manifest freeze, intent commit and provider release. The selected CLI test creates two real SQLite exports using the [Online Backup API](https://www.sqlite.org/backup.html) through [Python's SQLite backup interface](https://docs.python.org/3.11/library/sqlite3.html#sqlite3.Connection.backup), with a conflicting uncommitted WAL transaction left open. After the original application and export paths become unavailable, previous/current recovery executables restore the generations; SQLite checks integrity and exact committed records. This is synthetic application evidence, not acceptance of other applications or production sources. Full source-provider, scale and product gates remain open in the [completion map](../product-status.json).

### Recorded native kernel check

The [scoped native receipt](../native-btrfs-evidence.json) records five actual, non-skipped test executions on source `1cb174ef12357c288233e9d3cf4e887d55b1ed05`. They verify read-only kernel snapshot identity/reuse, wrong-origin and substituted-path rejection, retention bounds, signed kernel removal and its interrupted-result readback, two independently recovered versions without source access, and replay-stable source release tickets under the execution lease. Consumers run without root; native disposal is tested separately with producer privileges.

The isolated run with 1 CPU and 768 MiB completed in 50.679 seconds, with peak cgroup memory of 76,902,400 bytes, zero swap and zero OOM events. A new 1 GiB sparse image supplied filesystem capacity for small synthetic files; it is not a native 100 GiB scale measurement. The owned loop/mount and introduced modules were removed, global mounts/module names matched the initial state, and no host package was installed. Actual source-profile admission, large snapshot retention/performance, application consistency and cold-boot acceptance remain open. G1's separately recorded physical 100 GiB file-kit acceptance is unchanged.
