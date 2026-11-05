# Independent file kits: G1 candidate

[Русский](../ru/file-kit-format.md)

The `outpost-filekit-1` candidate implements REQ-09, REQ-10 and REQ-11 for stable Linux regular files. It is an M0 architecture experiment, not a deployed worker. The [acceptance plan](g1-acceptance.md) keeps full-scale evidence separate from unit and fixture checks. The format remains experimental until the gate is accepted; no compatibility promise for production archives is made.

## Engine decision

The earlier [native restic experiment](g1-prototype.md) remains a comparison, with its recorded results and limitations. Turning a selected file into a second native repository after the primary backup adds a full plaintext read and a second repository. That workflow does not satisfy the source-local storage and cost conditions for the chosen architecture.

The new candidate reuses restic's Rabin chunker, rather than a complete restic repository. It streams the source once directly into the assigned destination. Kopia/restic repositories and indexes are not dependencies of the independent reader. This is a new Outpost object/descriptor protocol using standard library cryptography, and therefore requires explicit format review, crash tests and resource measurements. Native repository compatibility is not claimed.

Content-defined boundaries are 256 KiB minimum, 1 MiB target and 4 MiB maximum, with polynomial `0x3da3358b4dc173`. Reuse is confined to the same file identity and policy domain. Another file with identical plaintext receives different encrypted objects. Source-tree scanning, consistent application snapshots and assigning logical identities belong to subsequent source adapters.

Incremental capture authenticates the previous descriptor and checks reused objects for presence and length; it does not reread all old payload as a scrub. Export/repack validate complete object hashes, and restoration also validates every chunk and the ordered plaintext. Capture success alone is not an integrity receipt for every replica.

## Keys and authenticated structure

An owner file contains a random domain identity, a 256-bit master key, an Ed25519 verification key and, for the producer, a signing key. Recovery material omits the signing key. Store it separately with mode 0600. An ordinary replication worker receives none of these decryption keys. This CLI runs only as an explicitly trusted producer or recovery client; it does not implement worker enrollment.

HKDF-SHA256 derives distinct keys from master, domain, random file identity and purpose. Each chunk purpose includes its plaintext SHA-256. AES-256-GCM uses the standard library's random-nonce API, with a fresh 96-bit nonce and 128-bit tag. Format, domain, file and purpose are authenticated associated data. Existing ciphertext records can be reused; changed content is encrypted under its own derived key and fresh nonce. The format does not use convergent encryption across files or domains.

The encrypted descriptor contains relative names and hard-link aliases, attributes, total length and SHA-256, and the ordered list of chunk hashes, lengths and physical locations. Its logical version is an HMAC over the canonical logical descriptor, excluding pack locations. Repacking changes physical descriptors without changing the selected logical version. The recovery caller must supply the expected opaque version from a trusted receipt; a signed older version is not evidence of current freshness.

The descriptor is encrypted as one authenticated message, then split into ordered parts of at most 4 MiB. The canonical JSON envelope signs format/domain/file/version and the entire ordered array of part hashes and lengths. Array position binds order; array length binds count. Here canonical encoding means the pinned Go `encoding/json.Marshal` representation, including its escaping and sorted map keys, not an unspecified JSON canonicalization scheme. Reordering or replacing a part invalidates the root signature or descriptor authentication. Neither paths nor plaintext chunk hashes appear in the envelope.

Ciphertext records are packed into objects of at most 8 MiB, named by SHA-256 of the complete object. Each block reference includes object hash, exact length, offset and ciphertext length. One pack belongs to one file/domain, although it may include chunks from several retained versions of that file. The reader validates the complete object and each referenced chunk. It also verifies the final ordered file length and hash. Lengths, opaque identities, timing and reuse patterns remain visible.

## Standalone recovery

A pre-created exported kit consists of `kit.json` and all descriptor/payload objects it names. Export copies separate inodes while holding a reader lock. It cannot be reconstructed after loss using only a surviving pointer to the canonical repository. Exporting duplicates the selected ciphertext; it is an explicit destination-side operation whose cost is measured. It creates no second repository beside the source.

Recovery needs only that kit, recovery owner material, the expected version and the reader executable. It needs no global index, source file, other file's payload, control plane or original repository. Objects may arrive through several parts, but all named dependencies must be present before success. Restore creates a private staging directory, verifies bytes and attributes, then publishes a new directory using no-replace atomic rename. An existing destination is never overwritten. Authentication or missing dependencies must not produce successful output.

Supported attributes are Linux permission bits, numeric UID/GID, nanosecond mtime, readable xattrs including POSIX ACLs, and explicitly supplied hard-link aliases. The caller needs permission to restore them; an unsupported or unauthorized attribute is an error. Directory metadata, symlink contents, device nodes, Windows ACLs, application quiescing and automatic hard-link discovery are not implemented by this regular-file gate. Metadata checks before/after capture detect ordinary source changes but do not replace an application/filesystem snapshot.

Logical names use normalized relative UTF-8 paths with slash separators, no backslash/NUL, at most 255 bytes per component and 4095 bytes in total. Oversized or ambiguous names are rejected before source capture and when reading a descriptor. The boundary test restores an actual 255-byte filename; arbitrary Linux byte names outside this profile are not silently rewritten.

## Publication and maintenance

Canonical operations use an exclusive process lock for backup/repack/retire/GC and a shared lock for restore/export. Use a separate `Store` handle for each concurrent operation. This is a local filesystem protocol, not distributed fencing.

Objects are written to private staging, file-synced, linked under an immutable hash name, and directory-synced before any root can reference them. The envelope is file-synced, atomically renamed, then its directory is synced. Repack copies authenticated ciphertext records into different packs, publishes each replacement root durably, then collects garbage. A crash can leave a mixture of equivalent old/new physical roots; every retained logical version remains a recovery root.

GC authenticates every retained root under the same exclusive lock, validates its dependencies against the full object inventory, and aborts on any invalid/unreadable root, unknown entry or missing dependency. It removes whole immutable pack objects only when no retained descriptor references them. Retiring versions durably removes their roots before GC; a multi-version retirement is not an all-or-nothing transaction. Copied independent kits own their payload and survive canonical retirement. Unpublished transaction files can be removed separately without interpreting them as committed roots.

SIGKILL tests exercise actual process death at object write/sync/link/durability, descriptor write/sync/rename/durability, repack publication, retirement and object deletion. They verify retained roots and pre-created kits after reopening and after GC. These tests do not certify power-loss behavior of hardware, distributed retention pins, cloud visibility or runtime disk-loss fencing; those have separate gates.

## Bounds and dependencies

The [machine-readable limits](../g1-acceptance.json) specify 128 GiB maximum file size, 524288 blocks, 64 MiB descriptor, 128 KiB root, 256 aliases and bounded attributes (256 names, 64 KiB per value, 1 MiB total). The trusted producer must remain within these limits. Owner-authenticated descriptors are required before typed payload parsing; unsigned storage input cannot manufacture new descriptors. File objects must be regular files confined to the selected kit.

Pinned Go modules are `github.com/restic/chunker` v0.5.0 (BSD-2-Clause) and `golang.org/x/sys` v0.37.0 (BSD-3-Clause). Go standard packages implement encryption and signatures. See [third-party notices](../../THIRD_PARTY_NOTICES.md). There is no custom cryptographic primitive, compression layer or global deduplication index.
