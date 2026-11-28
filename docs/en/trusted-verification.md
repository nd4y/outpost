# Trusted content verification

[Русский](../ru/trusted-verification.md)

`verify-replica` authenticates and decrypts selected retained file versions from a materialized replica. It needs the owner's private recovery key and public generation trust, but no source, replica state index, controller or other node. Run it only in the owner's trusted environment against a retained view. Ordinary workers keep ciphertext and do not receive the recovery key.

```sh
outpost verify-replica --key /private/recovery-owner.json \
  --trust /private/generation-trust.json --store /recovery/replica \
  --generation EXPECTED_CHECKPOINT --output /private/new-verification.json
```

The optional `--input` file contains `{"versions":["EXACT_VERSION_ID"]}`. Omitting it checks every kit in the authenticated catalog, including independent old and new versions of the same file. Duplicate or unknown versions are rejected before payload reads. Directory selection belongs to restore; this verification command selects opaque versions.

The `outpost-content-verification-1` report contains opaque file/version IDs, counts, scope and original check times. It never includes names, attributes, plaintext hashes, contents or keys. `DECRYPTED` means the signed envelope, metadata, every encrypted chunk and the ordered plaintext digest passed. No plaintext files are created. `UNREADABLE` means that the version could not be authenticated/read; a wrong key, corruption and missing data are not distinguished as a device diagnosis. Cancellation leaves unvisited versions `NOT_VERIFIED`. Other readable versions remain visible in a partial report.

`complete` covers only the requested selection; `wholeGeneration` separately records its scope. Decryption does not prove that a destination filesystem can restore attributes, that all versions can share one output path, or that no newer checkpoint exists elsewhere. A new run performs fresh reads. A partial report returns a nonzero exit code and is still saved to the requested new private report file. Existing reports are never overwritten. Invalid/unreadable catalogs fail before a version report can be constructed.

The replica's `KnownDamage` API maps its detection ledger to the exact opaque versions referencing known damaged objects. This is a historical detection view, not a fresh scrub. After object repair, an empty affected list does not publish the generation: full ciphertext verification must finish first. Independent selected-version recovery remains possible when unrelated versions are damaged.

Trusted recovery planning authenticates selected metadata and names before estimating files, bytes and aliases; it does not read payload ciphertext. Multiple versions of one file require an explicit restore selection. The internal recovery API can publish through an already admitted parent directory descriptor, retaining that destination even if its external path is replaced. The [trusted recovery executor](trusted-recovery.md) now connects these primitives to private presets, signed commands and separate resource admission.

Short isolated tests cover source/index loss, retained versions, precise damage, unaffected restore, wrong keys, cancellation, invalid selection, catalog/file mismatch, typed entries, report privacy and nonzero partial-result status. Trusted command execution has separate short integration and crash checks. Full scale and installation remain separate acceptance gates.
