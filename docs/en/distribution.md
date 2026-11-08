# Linux distribution candidate

[Русский](../ru/distribution.md)

The distribution is in development. Building an archive or image does not establish installation, runtime isolation, an arm64 execution result or complete product acceptance. No release image is published by these commands. Production deployment still requires the separately authorized infrastructure profile.

## Build and verify before installation

`scripts/build-release.py` uses the exact Go version in `go.mod`, with CGO disabled, stripped build paths and a fixed architecture baseline. It builds `outpost` and the independent `outpost-kit` reader for Linux amd64 and arm64. The known development compiler image is `golang@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5`; its Go and Python versions must still be checked in the selected environment. The script needs Python3.11+ and Go1.27.3. Prepare the checksum-pinned Go modules in the build environment before an offline run.

```sh
GOTOOLCHAIN=local GOFLAGS=-p=1 python3 scripts/build-release.py --output /build/outpost-dist
python3 scripts/verify-release.py --root /build/outpost-dist --manifest-sha256 SELECTED_MANIFEST_SHA256
```

The output parent must already exist. The selected output directory must be new, absolute, outside the source checkout and have no symbolic-link parent. Existing output is never reused or overwritten. An interrupted or failed build may leave a partial directory; it is not an accepted distribution. Source hashes are checked before and after compilation. The final receipt identifies the source digest, manifest hash, revision and included architectures. Standard output contains exactly that JSON object; compiler and module diagnostics go to standard error. Automation must parse the entire output, not select its last line. Without an explicit independently verified commit, the revision is `dev-` followed by the exact input digest. A supplied commit label is not a cryptographic attestation of the checkout.

Keep the manifest hash separately from the downloaded or copied artifact. Computing it from an unknown manifest and immediately trusting that value establishes no provenance. The offline verifier checks the selected hash, exact file set, all payload hashes, static ELF architecture, archive contents and normalized archive metadata. It rejects additional files, symbolic links, changed payloads, missing archive members and unexpected paths without extracting them. Results explicitly distinguish verified artifacts from runtime acceptance. The archives include the project, module and Go runtime license notices; no source dataset or private profile belongs in the build output.

Each architecture archive contains both binaries and license notices. Timestamps, ownership, ordering and compression headers are normalized. Repeated build equality and hostile-artifact checks run separately from executing the product. The independent reader needs selected keys/checkpoints according to the [file-kit contract](file-kit-format.md); no running service or repository-wide catalog is introduced by packaging.

## Software inventory

Create a CycloneDX 1.6 SBOM for each selected executable and architecture. Use the [official cyclonedx-gomod 1.12.0 release archive](https://github.com/CycloneDX/cyclonedx-gomod/releases/tag/v1.12.0) for the Linux machine generating the inventories. The script checks the pinned archive SHA-256 and reads the exact verified binaries without executing them or downloading modules. The Go command on the path must support reading the selected binary build information.

```sh
python3 scripts/build-sbom.py --root /build/outpost-dist \
  --manifest-sha256 SELECTED_MANIFEST_SHA256 \
  --generator-archive /build/cyclonedx-gomod-linux.tar.gz \
  --output /build/outpost-sbom
```

Use a new output directory outside the distribution. The final `sbom-manifest.json` binds the distribution manifest, revision, exact binary SHA-256 and SBOM SHA-256. Store this receipt alongside the selected distribution evidence. Each SBOM includes the linked Go modules and standard library version. This inventory covers the selected binaries. Release signatures and published installation acceptance remain separate.

## Container and private runtime preparation

The [Dockerfile](../../packaging/Dockerfile) consumes the verified output directory. It starts from an empty root filesystem and copies only the two binaries and license notices. It contains no shell, package manager, source code, credentials or runtime initialization. Select the matching platform and `TARGETARCH`, pass the verified revision, build a local candidate image and retain its immutable image ID. Building an arm64 image without executing it is only a cross-build result.

The [Compose candidate](../../packaging/compose.yaml) requires an explicit nonzero `OUTPOST_UID`/`OUTPOST_GID` (the image default is65532:65532), a read-only root filesystem, dropped capabilities, no-new-privileges, a bounded non-executable temporary filesystem and explicit CPU/memory/PID/log limits. It publishes no host port and uses no host network, TUN device, privileged mode or arbitrary host mount. Its two bind paths must already exist; automatic host-directory creation is disabled. These are requested settings until actual enforcement is checked on the selected container runtime.

Prepare a private configuration directory and a separate empty data-volume root owned by the selected nonzero runtime UID/GID. Use the same identity for local enrollment, initialization and runtime; do not change ownership of an existing production volume as part of installation. Resolve the actual storage mount first. Use the [volume probe/enrollment procedure](runtime-volume.md) in a local owner provisioning step, with the exact final container data path `/var/lib/outpost`. Provision private certificates, owner public trust and the bootstrap file with the runtime directory `/var/lib/outpost/worker`. Runtime profiles and secrets are under `/run/outpost`; group/world-readable private files are rejected. The provisioning step needs a separately bounded writable configuration output. The running Compose services mount that configuration read-only.

`outpost runtime-observe` reads actual process identity, capability masks, seccomp/no-new-privileges, root and temporary mount flags, TUN absence and private cgroup-v1/v2 resource limits. `runtime-check` rejects unknown or unbounded controls. Packaged worker, command and report loops pass `--require-isolation`, so failed checks stop before reading private bootstrap data. This is process admission, not certification of host network separation, allowed host mounts or cold-boot ordering. Verify those separately on the selected host.

Initialize the worker explicitly, apply its owner-signed policy, and initialize the report journal if reporting is enabled. A missing state directory is an error during normal startup. Do not delete state, change the sentinel, replace a bootstrap binding or rerun initialization to repair a failed admission. The image does not provision a certificate authority or invent storage credentials.

Set `OUTPOST_IMAGE` to the verified immutable local image ID or registry digest, `OUTPOST_DATA` to the enrolled data root and `OUTPOST_PRIVATE` to the private profile directory. The default service is the autonomous keyless worker. Optional `commands`, `reports` and `telemetry` profiles start separate foreground pollers with their respective existing private profiles. All share the same admitted worker journal and quota ledger. Reporting failures do not stop backup execution. A management service uses the same binary but requires its own [management profile](management-service.md), private directory and enrolled volume; do not reuse a receiver's credentials or runtime as the operator plane.

## Restart, upgrade and open gates

The container receives SIGTERM directly and has a bounded stop grace period. The example bounds failed restarts; the owner must order startup after the real mount/unlock operation. A container restart does not prove a cold-host boot or unlock ordering. Missing/replaced/read-only volumes must fail closed without creating fallback state. Networking exposure and source snapshot privileges belong to separate admitted profiles.

Before an upgrade, retain the old image ID, private profiles and independently restorable data/checkpoints. Run the format-specific migration and rollback procedures; an old binary cannot safely read a newer state merely because Docker can restart it. Image replacement never initializes, deletes or resets a data directory. Private management snapshots recover historical evidence and do not yet activate a recovered control plane.

Artifact checks are bounded and synthetic. Actual container isolation, cached-policy startup, stop/join, image replacement, arm64 execution, cold boot, supported identity migration, manual UI acceptance and final scale remain acceptance gates. The separate [telemetry process](telemetry.md) has a durable outbound queue and short isolated evidence; complete instrumentation and operational release evidence remain open. Bounded container logs do not replace that queue.

## Isolated runtime verification

Compile the native synthetic fixture with `CGO_ENABLED=0 go test -c -trimpath -o /build/container-fixture.test ./cmd/outpost`. Select separately verified current and previous distributions, then run:

```sh
python3 scripts/check-container.py --root /build/current --manifest-sha256 CURRENT_SELECTED_HASH \
  --previous-root /build/previous --previous-manifest-sha256 PREVIOUS_SELECTED_HASH \
  --fixture-binary /build/container-fixture.test --work /build/new-container-checks
```

The runner requires Linux, Docker, Compose2.15+ and an explicit non-root filesystem owner. It builds only scratch-based local test images, uses no network or real credentials, and retains its new private fixture directory. Generated keys never enter a published artifact. Ordinary workers mount no recovery keys. Checks cover actual kernel controls, rejected unsafe starts, explicit volume enrollment, cached-policy startup, a distinct old/current image pair, policy update, SIGTERM join, rollback without a format reset, missing/read-only volume refusal, exact encrypted-object preservation and two independent restores after removing the original source cache. Compose expansion verifies all four service profiles without starting them. Only containers created and labeled by the run are removed; no shared cleanup occurs.

The documented previous implementation is commit `7747e0b7fd53b4cb4f78911eeb78053e2c58dad1`. Native CI builds that implementation with the candidate packager, recording the resulting inputs rather than claiming a released older image. The [native workflow](../../.github/workflows/distribution.yml) uses separate amd64 and arm64 machines. Native ARM runners are available for public repositories in the [GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). Inspect the actual selected commit's result; workflow existence is not execution evidence.

Cgroup-v1 hosts require an explicitly private cgroup namespace and readable memory, combined memory+swap, CPU quota/period and PID controllers. Missing controllers, ambiguous mounts, host-relative cgroup paths and unlimited settings are rejected. The v1 swap observation is the additional combined memory+swap allowance; it does not claim that the kernel never swaps a physical page. V1 parsing checks are distinct from actual host admission. The candidate never switches a host between cgroup versions or changes kernel boot options. Compose's private namespace setting requires [Compose2.15 or later](https://docs.docker.com/reference/compose-file/services/#cgroup). Controller semantics follow the [kernel memory controller](https://docs.kernel.org/admin-guide/cgroup-v1/memory.html).

The [owner recovery package](owner-recovery-package.md) keeps read-only decryption material, original checkpoint age and selected offline tools in private owner storage. Export, digest-anchored inspection and atomic extraction leave signing authority out of the package. Selected-file and complete-replica recovery have separate small process checks; key lifecycle and full-scale acceptance remain open.

Native CI also runs the selected distribution's `restore-external` against isolated read-only S3-compatible and WebDAV fixtures. It verifies complete and selected recovery after the source paths become unavailable. [Independent external recovery](external-upload.md#independent-external-recovery).
