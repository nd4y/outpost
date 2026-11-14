# G1 acceptance and reproducible evidence

[Русский](../ru/g1-acceptance.md)

G1 is accepted for the independent regular-file architecture in REQ-09/10/11 on the exact source and environment in the [full-scale receipt](../g1-scale-evidence.json). The [format decision](file-kit-format.md) and [numeric limits](../g1-acceptance.json) retain the tested bounds. The physical 100 GiB run passed all 23 phases, including independent old/new recovery after physical repack and retirement. This accepts G1 only; whole-product scenarios, G2/G3 and deployment remain separate.

## Recorded full-scale result

The tested commit is `68bede552755edc0f37fba1060cebde0501a1861`, tree `624b6115be2eefe61898adc5f49d4d4d82afd481`. The original run completed on 2026-11-13 at 02:10 UTC. Its unchanged wrapper returned zero and created the complete PASS marker. Binary and original limit-document hashes are retained in the receipt; the later acceptance-status change does not alter any numeric limit. Raw metadata and execution logs remain in the private evidence archive, without publishing recovery keys, volume identity or owner inventory.

| Measurement                   | Accepted observation                                                                             |
| ----------------------------- | ------------------------------------------------------------------------------------------------ |
| Source                        | 107,374,182,400 physically allocated bytes, compression ratio 1.000082                           |
| 8 MiB replacement             | 31,103,218 added encrypted payload and metadata bytes, below 128 MiB                             |
| Unchanged capture             | Zero new payload, metadata and objects; same version                                             |
| Rename                        | Zero new payload; new encrypted metadata                                                         |
| Scattered changes / insertion | 40,009,709 / 20,926,724 added bytes; insertion is 1 MiB at 64 MiB before EOF                     |
| Independent recovery          | Both 100 GiB versions pass every byte, attributes and hard-link oracle after maintenance         |
| Physical maintenance          | 14,547 payload objects replaced; 14,572 garbage objects removed; three selected versions retired |
| Process memory                | Maximum kernel `maxRSSKiB` 231,444 under the 768 MiB container limit                             |
| Storage                       | Peak used test-filesystem bytes 325,515,743,232; required 20% reserve maintained                 |

Storage is an upper bound including test artifacts, not an enforced per-process filesystem quota. Every capture still reads the whole source once. These are local-kit costs, not measured cloud wire traffic or a production RPO/RTO promise. The benchmark used one virtual Linux/amd64 CPU without exposed AES/SHA acceleration; per-phase timings are in the receipt.

The 1,501 cgroup observations are point samples of 14 long phases, not continuous coverage of all phases. They record the configured one CPU, 805,306,368-byte memory limit, zero swap limit and 128 PIDs, with no observed swap or OOM. Raw `memory.peak` reached 805,572,608 bytes, 266,240 above `memory.max`; it includes charged cache/kernel memory and the [kernel-documented transient excess](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-interface-files). This value is retained separately from process RSS and has not been rounded down. All 23 commands report kernel RSS independently.

The accepted scale run exercises the serial local-kit path on the recorded source. Later optional concurrent-write changes have separate bounded regressions; this receipt does not establish full-scale asymmetric WAN throughput, native source consistency or installed-service acceptance. The documentation check validates the scoped receipt, original limits, phase sequence and negative metadata cases. It does not execute the benchmark or independently certify its private runtime evidence.

## Requirement-to-check trace

| Requirement                  | Proof required for this gate                                                                                                                         | Executable check                                                                                                                                                                          |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| REQ-09, block history        | One source read, reused ciphertext, changed bytes bounded, previous version recoverable                                                              | `TestIndependentVersionsAndAttributes`, `TestCrossFileCiphertextAndVersionSubstitution`; large fixture baseline/replacement/unchanged/rename/scattered/insertion receipts                 |
| REQ-10, independent recovery | Pre-created copied kit, no original repository/index/source/other payload, encrypted names, ordered complete dependencies, byte and attribute parity | `TestIndependentVersionsAndAttributes`, `TestConfidentialNamesAndFileDomainIsolation`, `TestMultipartDescriptorIsSelfContained`; isolated old/new recovery and independent fixture oracle |
| REQ-10, rejection            | Wrong key/version, reordered/missing/substituted/truncated/extra bytes and unsafe paths fail without publishing output                               | `TestTamperedKitNeverPublishesOutput`, `TestCrossFileCiphertextAndVersionSubstitution`, `TestFailureDoesNotPublishOrOverwrite`                                                            |
| REQ-11, maintenance          | Actual changed pack objects, old/new logical versions and independent copy survive repack/retirement                                                 | `TestRepackAndRetirePreserveKits`; large fixture repack counters and old/new independent recovery after retirement                                                                        |
| REQ-11, process interruption | SIGKILL at publication/deletion boundaries leaves only complete committed roots; readers exclude maintenance                                         | `TestSIGKILLCommitBoundaries`, `TestReaderBlocksRetirement`, `TestGCAbortsBeforeDeletionOnInvalidRootOrMissingDependency`                                                                 |
| REQ-11, costs                | Initial duplication/objects, incremental payload and metadata, full source reads, actual restored files, RSS, temporary space and free-space reserve | Machine limits and `experiments/filekit/run.py` receipts, generator allocation/compression and oracle results                                                                             |

The [machine-readable trace](../g1-trace.json) binds each G1 requirement to existing test functions and fixture phases; the documentation checker rejects dangling references. These checks cover the G1 portions of AT-02/03/04/05/12 and the regular-file metadata part of AT-23. They do not change whole-product acceptance statuses to PASS. AT-12 distributed pins, offline generations and publication receipts remain with G2/G3. Application-consistent source snapshots and full source-tree restore remain M1 work.

`TestSpecialSourceAndOwnerInputsRejectWithoutBlocking` additionally checks FIFO/source-link/directory rejection and bounded failure while opening an invalid owner file. All three input classes (source, owner and encrypted objects) open without blocking on named pipes, then require a regular file.

## Commands

On an authorized Linux ext4 test volume with xattr/POSIX ACL support:

```sh
go test -count=1 ./...
go vet ./...
mkdir -p out
CGO_ENABLED=0 go build -trimpath -o out/outpost-kit ./cmd/outpost-kit
CGO_ENABLED=0 go build -trimpath -o out/outpost-fixture ./cmd/outpost-fixture
python3 experiments/filekit/run.py --root "$TEST_VOLUME/g1-small" \
  --kit-binary "$PWD/out/outpost-kit" --fixture-binary "$PWD/out/outpost-fixture" \
  --limits "$PWD/docs/g1-acceptance.json" --bytes 134217728
```

The destination must not exist. Full scale uses `--bytes 107374182400`. For acceptance, add `--container-image "$PINNED_IMAGE_DIGEST" --filesystem-uuid "$TEST_VOLUME_UUID"`. The image must have a POSIX shell and `cp`; the supplied static Go binaries are copied into a 32 MiB executable tmpfs. Generated source, ciphertext, staging and restored data remain on the selected test volume. Compiler scratch space is separate from test fixtures. When Go uses `GOTMPDIR`, unset it only for the test executable (`go test -exec "env -u GOTMPDIR"`) and set `TMPDIR` to the test volume to keep `testing.TempDir` there.

Container mode fixes one CPU, 768 MiB RAM without swap, no network, no capabilities, no new privileges and read-only root. Recovery gets only its selected read-only kit, a read-only recovery key, expected version, executable and writable output directory. The independent oracle runs afterwards, reads the materialized output and generates expected bytes from public synthetic seeds; the recovery reader cannot consult that oracle.

The full 100 GiB runner requires both the image digest and filesystem UUID before it creates any fixture. Smaller native runs remain diagnostic fixtures. Reports distinguish overall `RUNNING`, `FAIL` and `PASS` from successful individual commands. A failed postcondition records its phase and exception type, preserves previous receipts and never creates a PASS marker. Raw error text stays in the private stderr log. [Runner regressions](../../experiments/filekit/test_run.py) verify missing pins, malformed digests, a successful command followed by a failed source-read assertion, and a nonzero subprocess. These diagnostic stubs do not establish content or full-scale acceptance.

Independent readers mount a separate read-only directory containing only `owner.json` with recovery authority. The source's signing-capable owner file stays outside that directory. Mounting the key as an individual bind file crosses its parent's mount identity and is rejected by the private-file reader. The fixture preserves that boundary check.

Each phase has a 7200-second default deadline. On an admitted slower test volume, select a measured budget with `--phase-timeout-seconds`, between 60 and 43200 seconds. The selected deadline is recorded in the report and does not change any byte, memory, integrity or free-space limit. Use the measured storage rate to admit the run; timeout or cancellation remains a failed incomplete phase. The runner regressions check rejected budgets and the recorded explicit and default values.

The 100 GiB fixture is physically allocated AES-CTR test data, with a compression-ratio check, not a sparse file or a stream discarded into a hash. It replaces 8 MiB, repeats unchanged capture, changes the logical/physical name, scatters eight 1 MiB replacements, and inserts 1 MiB at 64 MiB before EOF. That insertion position is explicit; it is not a claim of exhaustive offset coverage. Captures read the whole source once. Only encrypted changes and new metadata are added to the current local target; cloud/network transfer is a later G3 measurement.

The runner restores the combined changes to a physical file and checks every byte, length, mode, numeric owner, nanosecond time, POSIX ACL, user xattr and hard-link identity. It then removes only its own synthetic source/output, pre-creates a separately allocated old kit, performs physical repacking and version retirement, and recovers old/new versions in clean containers. It removes its own completed intermediate copies to bound peak storage; previous runs and unrelated files are never cleaned. Receipts and the final independent new kit remain. The owner key is private fixture material and must not be published with receipts.

## Cost interpretation and limits

The source performs no second full local repository write. Initial assigned ciphertext is bounded to 1.08 times the file, with at most 32768 objects for the selected 100 GiB kit. An independent exported copy adds roughly another full selected ciphertext copy at the receiving side. Repack temporarily needs old and new packs. Source, canonical store, independent copies, restore output, history, metadata and repack overlap all count toward capacity. The runner checks the projected next phase and samples actual free space throughout each subprocess, preserving 20% of the filesystem.

The contiguous 8 MiB change must add at most 128 MiB including encrypted metadata. Unchanged and rename captures add zero payload; rename still writes metadata and reads the complete source. Other changes have measured costs, not an invented 8 MiB universal bound. Source temporary disk use is bounded at 2 GiB; the implementation writes none beside its read-only source mount. Descriptor/pack staging is at the destination and is included in storage use.

Restore verifies full packs, so bytes read may exceed file length when versions reuse a subset of a pack. The bound is four times file length plus 128 MiB. RSS is the process high-water mark reported by the kernel, separately from heap reservation and the container hard limit. `peakBufferBytes` is a conservative named-buffer estimate, not an RSS measurement. Receipts include binary SHA-256, pinned container, limit-file SHA-256, operation timings, objects and byte counters. Public evidence must identify the tested source snapshot and distinguish later corrections and their regression checks.

## Review and remaining boundaries

A bounded external DeepSeek review through RouterAI examined publication/GC invariants. It required aborting GC on any invalid root, deleting whole packs only when unreferenced, signing an ordered descriptor-part list and testing process-kill boundaries. The implementation and named checks address these points. This is an independent design review, not a third-party cryptographic certification or proof of executed tests; the maintainer owns execution and acceptance.

Hardware power failure, source disk disappearance during active I/O, cold boot, distributed fencing/pins, real S3-compatible/WebDAV endpoints and production rollout remain separate. No working service, legacy data or device is changed by G1 source acceptance. The recorded G1 evidence is accepted; those separate gates retain their own outstanding criteria.
