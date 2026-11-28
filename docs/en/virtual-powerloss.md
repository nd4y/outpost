# Guest-kernel power loss and volume ordering

[Русский](../ru/virtual-powerloss.md)

The opt-in VM fixture distinguishes loss of a guest's whole kernel and volatile filesystem state from killing an Outpost process. It runs inside an admitted resource container. It never reboots the host, attaches a host block device, installs a host package or joins a network.

## Inputs and admission

Build the helper in the authorized build environment:

```sh
CGO_ENABLED=0 go test -c -o /approved-output/worker-vm.test ./internal/worker
```

Ordinary tests skip `TestVMKernelFixture`. Execution requires an explicit guest environment flag, root inside the guest and an exact `outpost_vm_fixture=1` kernel argument. The outer controller remains non-root with no capabilities, no-new-privileges, seccomp, a read-only root, loopback only, no KVM and enforced cgroup limits: at most one CPU, 768 MiB, no swap and 128 PIDs.

Supply QEMU, a Linux kernel and matching dependency-ordered virtio/ext4 modules, static BusyBox, filesystem utilities and an independently selected `outpost`/`outpost-kit` pair. Pin provenance, versions and hashes before execution. These are test dependencies, not bundled product binaries. Never copy a host initramfs or host configuration; they can contain credentials.

Run only inside the admitted container:

```sh
python3 scripts/check-vm-powerloss.py --config PRIVATE_CONFIG
```

The owner-controlled JSON contains `schemaVersion: 1`; a new absolute `workspace`; six `inputs` entries named `qemu`, `kernel`, `helper`, `busybox`, `outpost` and `outpost-kit`, each with `path`/`sha256`; ordered `modules` with the same fields; `bios`/`biosSHA256`, `qemuData`, `libraryPath`, `mke2fs` and `debugfs`; and the source and independent CLI selection for reporting. These local inputs are not shared job arguments.

The controller creates one new 2 GiB regular raw file and formats only that file. It refuses existing output. Initial admission requires the 20 percent free reserve plus disk and scratch space. Devices, existing images and live backup datasets cannot be formatting targets. Resource, log and phase limits remain enforced.

## Crash and recovery

Four encrypted fixtures retain two 2 MiB versions each, Unicode paths, mode and a hardlink alias. Original plaintext and source caches are removed before the fault sequence. The receiver gets generation verification authority; retirement uses a separately signed maintenance permit.

Only the controller's own QEMU process is terminated at `object-durable`, `before-complete`, `state-durable` and `retirement-durable`. The next boot uses the same virtual data filesystem. A file written without fsync after the boundary must disappear, establishing actual loss of volatile guest state. Incomplete reception preserves the earlier complete generation; durable publication survives. Maintenance resumes its recorded operation, preserving the latest complete view and the separately exported old file kit.

The selected standalone CLIs restore both versions. Every byte is checked against the pre-recorded SHA256, together with mode, Unicode path and hardlink identity. The receiving process has ended before recovery material is used.

Five further boots check an absent disk, a wrong filesystem, a read-only disk, delayed mount followed by initialization, and a later correctly mounted identity. The real CLI must return `VOLUME_UNAVAILABLE` with exit code 5 for unavailable storage and create no fallback state. A direct volume-guard assertion attributes refusal to storage admission. Correct storage must preserve the enrolled identity.

## Interpretation

The guest uses ext4 with a 60-second periodic commit interval; explicit fsync remains required. QEMU uses a regular raw file with `cache=directsync`. [QEMU invocation](https://www.qemu.org/docs/master/system/invocation.html) documents accelerator/cache controls; its [block-driver reference](https://www.qemu.org/docs/master/system/qemu-block-drivers.html) describes raw images. The backing host stays alive. This does not certify physical controller caches, host power loss, actual disk unlocking or another hardware failure domain.

Evidence must identify the helper tree/binary, controller hash, selected CLI revision, kernel/modules, tool packages, resource observations, individual phase logs and failed controls. A skipped Go test, successful boot or source symbol is not acceptance. This bounded corpus does not replace 100 GiB, asymmetric ingress, cloud throughput or real profile gates.

The [recorded bounded run](../vm-powerloss-evidence.json) passed all 14 phases: setup, four cuts with four recovery boots, and five volume-ordering boots. Peak memory was 609,734,656 bytes under a 768 MiB cap, with zero swap or OOM events. Failed observer controls are retained with their causes. These measurements certify only the scope described above.
