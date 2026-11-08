# Owner recovery package

[Русский](../ru/owner-recovery-package.md)

`outpost-owner-recovery-1` carries the material and selected tools needed to read independently retained ciphertext. It contains a read-only file-kit owner, public generation verification keys, supported file-kit formats, the last saved completed source checkpoint when available, the selected distribution manifest and Linux amd64/arm64 archives, and offline instructions in both languages. It contains no backup payload, cloud credentials, control-plane account or private signing key. Exporting it does not rotate or revoke any key.

The package contains **plaintext decryption secrets**. Keep it in owner-controlled private storage, separately from sources and replicas. It is not an artifact for untrusted nodes. Retain the package's SHA-256 separately in a trusted location; a digest calculated from an unknown package is not an independent trust anchor. Private permissions and disjoint directories do not prove separate hardware, media durability or an offline copy.

## Source export

Prepare a private `outpost-source-recovery-export-1` profile with these fields:

| Field                | Meaning                                                                     |
| -------------------- | --------------------------------------------------------------------------- |
| `format`             | `outpost-source-recovery-export-1`                                          |
| `volume`             | Separately enrolled owner-volume binding; its scope matches the source node |
| `directory`          | Existing absolute private directory inside that volume                      |
| `toolsDirectory`     | Existing distribution directory, outside the output directory               |
| `toolManifestSHA256` | Independently selected SHA-256 of that distribution's `manifest.json`       |

The owner volume root must be disjoint from both the source tree and the entire source runtime volume root. The output must be a new file directly in `directory`. All path components reject symbolic links. The profile, output directory and package are private; directories use mode 0700 and package files use 0600. The selected tool revision must equal the exporting CLI's embedded revision. The current distribution format, its declared architecture set, archive and member hashes, static Linux ELF headers and exact file set are checked before writing recovery secrets.

```sh
outpost source-recovery-export --bootstrap /private/source.json \
  --input /private/owner-export.json --output /owner/private/recovery-001.tar
```

Save the successful JSON result, including the complete package SHA-256, separately. The source snapshots decryption material, public trust and its last completed checkpoint under the execution lease, then releases that lease before copying tools. An already pending next capture does not replace the completed checkpoint. Volume and private path admission are checked again before publication. No source, policy, key or checkpoint is modified by export.

The operation currently requires the admitted source runtime and the enrolled source-tree identity to remain available. Prepare and retain packages before losing that runtime. Once exported, inspection, extraction and explicit offline restoration do not require the source volume, account or journal.

## Offline inspection and restoration

Use a previously trusted compatible executable and the separately retained package digest:

```sh
outpost recovery-package-inspect --input /owner/private/recovery-001.tar \
  --sha256 EXPECTED_PACKAGE_SHA256
outpost recovery-package-extract --input /owner/private/recovery-001.tar \
  --sha256 EXPECTED_PACKAGE_SHA256 --output /owner/private/unpacked-001
```

The whole artifact is authenticated before parsing secrets or creating an extraction candidate. Extraction validates the bytes again and publishes a new private directory only after all files and directories are synced. It does not unpack or execute the nested tool archives. Select and unpack the matching architecture archive into another private tools directory. If no compatible executable is installed, first verify the whole package with a separately trusted SHA-256 utility, then use the system archive utility to bootstrap those tools in a new private directory. Never bootstrap an unknown package merely by trusting the hashes written inside it.

For a complete materialized replica, use the extracted keys, an explicit retained generation and a new output directory:

```sh
/owner/tools/outpost restore-replica \
  --key /owner/private/unpacked-001/recovery-owner.json \
  --trust /owner/private/unpacked-001/trust.json \
  --store /ciphertext/replica --generation GENERATION_ID --output /restore/new
```

For a separately exported file kit, use `restore-kit --key ... --store ... --version VERSION_ID --output ...`. The two workflows are distinct: selected-file recovery does not establish complete-replica recovery. Neither requires the original source private signing key. Keep the packages for retained key epochs until old and new data have both been independently restored; automatic data-key rotation and retirement are not implemented by these commands.

`checkpoint.json` preserves the original signed checkpoint and verification time. Export time does not renew copy health or establish the newest existing version. A missing or old checkpoint limits freshness knowledge without preventing decryption of an explicitly selected valid version with matching keys. The result reports only opaque identities, versions, sizes, hashes and that original checkpoint time.

## Interruptions and bounds

No existing package or extraction result is overwritten. A private `.partial-recovery-...` candidate remains after an interrupted or rejected write. At most four candidates per exact output name are admitted under an interruptible directory lock; parent enumeration is bounded to 4096 entries. Failed candidates are retained for owner inspection, not reused or automatically erased. Package input is limited to 256 MiB, each compressed tool archive to 64 MiB, its expanded members to 128 MiB, and manifest input to 2 MiB. Only the fixed names, regular files and declared architectures are accepted. These are operation bounds, not a total owner-storage retention policy or proof of sufficient physical space.

After an uncertain reply, a final result may already exist. Inspect it only if its expected digest is independently known. If the export receipt was lost, preserve the uncertain result and export to a different new name from still-trusted source material; retain that new digest. Do not replace an existing package or manufacture trust by hashing the uncertain result.

Short HDD checks cover private admission, tampering, malformed archives, static tool validation, concurrency, lost replies, original checkpoint age, owner-volume loss, actual process kills, and independent old/new file and complete-replica restoration with a selected packaged executable. Exact execution records and current-tool acceptance remain separate from symbol links. Full-scale restoration, physical media loss, key lifecycle and full product acceptance remain open in [product status](../product-status.json).
