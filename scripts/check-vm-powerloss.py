#!/usr/bin/env python3
"""Opt-in guest-kernel crash fixture. Run inside an admitted resource container.

Inputs are pinned public tools plus the independently selected CLI pair. Output
is a new private directory containing one disposable raw disk and synthetic
recovery keys. Never use a host block device or a production disk image here.
"""
import argparse
import gzip
import hashlib
import json
import os
import pathlib
import selectors
import signal
import stat
import subprocess
import time
import uuid

POINTS = ["object-durable", "before-complete", "state-durable", "retirement-durable"]
MAX_MEMORY = 768 << 20
DISK_BYTES = 2 << 30


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            result.update(chunk)
    return result.hexdigest()


def checked_file(name, expected):
    path = pathlib.Path(name)
    assert path.is_absolute() and not path.is_symlink() and path.is_file()
    assert stat.S_ISREG(path.stat().st_mode) and digest(path) == expected
    return path


def resource_admission():
    assert os.getuid() != 0 and not pathlib.Path("/dev/kvm").exists()
    assert set(os.listdir("/sys/class/net")) == {"lo"}
    assert os.statvfs("/").f_flag & os.ST_RDONLY
    status = pathlib.Path("/proc/self/status").read_text().splitlines()
    fields = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status if ":" in line}
    assert int(fields["CapEff"], 16) == 0 and fields["NoNewPrivs"] == "1" and fields["Seccomp"] == "2"
    root = pathlib.Path("/sys/fs/cgroup")
    memory = int((root / "memory.max").read_text().strip())
    swap = int((root / "memory.swap.max").read_text().strip())
    quota, period = map(int, (root / "cpu.max").read_text().split())
    pids = int((root / "pids.max").read_text().strip())
    assert 0 < memory <= MAX_MEMORY and swap == 0
    assert 0 < quota <= period and 0 < pids <= 128
    return {"memoryMaxBytes": memory, "swapMaxBytes": swap, "cpuMax": [quota, period], "pidsMax": pids}


def write_initrd(path, inputs, modules, phase, private):
    """Stream newc into gzip; do not retain a second uncompressed root image."""
    init = """#!/bin/sh
export PATH=/bin:/sbin
ulimit -c 0
/bin/busybox mount -t proc proc /proc || exit 90
/bin/busybox mount -t sysfs sysfs /sys || exit 91
/bin/busybox mount -t devtmpfs devtmpfs /dev || exit 92
@MODULES@
echo 'OUTPOST_VM_BOOT phase=@PHASE@'
/bin/busybox mkdir -p /mnt/data
@MOUNT@
export GOMAXPROCS=1 GOMEMLIMIT=96MiB TMPDIR=/mnt/data/tmp OUTPOST_VM_GUEST=1
export OUTPOST_VM_PHASE=@GO_PHASE@
/tools/worker-vm.test -test.run '^TestVMKernelFixture$' -test.v -test.timeout=8m
result=$?
@AFTER@
/bin/busybox sync
case '@PHASE@' in
volume-absent) ;;
*) /bin/busybox umount /mnt/data || result=99 ;;
esac
echo "OUTPOST_VM_PHASE_DONE phase=@PHASE@ code=$result"
/bin/busybox poweroff -f
while true; do /bin/busybox sleep 60; done
"""
    mount = "/bin/busybox mount -t ext4 -o rw,commit=60 /dev/vda /mnt/data || exit 93\n/bin/busybox mkdir -p /mnt/data/tmp"
    go_phase = phase
    after = ""
    if phase == "volume-absent":
        mount = "/bin/busybox mkdir -p /mnt/data/volume"
        go_phase = "volume-refuse"
    elif phase == "volume-wrong":
        mount = "/bin/busybox mount -t tmpfs -o size=8m wrong /mnt/data || exit 94\n/bin/busybox mkdir -p /mnt/data/volume"
        go_phase = "volume-refuse"
    elif phase == "volume-readonly":
        mount = "/bin/busybox mount -t ext4 -o ro,noload /dev/vda /mnt/data || exit 95"
        go_phase = "volume-refuse"
    elif phase == "volume-delayed":
        mount = "/bin/busybox mkdir -p /mnt/data/volume"
        go_phase = "volume-refuse"
        after = """test "$result" = 0 || exit 96
/bin/busybox mount -t ext4 -o rw,commit=60 /dev/vda /mnt/data || exit 97
export OUTPOST_VM_PHASE=volume-initialize
/tools/worker-vm.test -test.run '^TestVMKernelFixture$' -test.v -test.timeout=8m
result=$?
"""
    elif phase == "volume-status":
        go_phase = "volume-status"
    init = init.replace("@MODULES@", "\n".join("/bin/busybox insmod /modules/" + p.name + " || exit 98" for p in modules))
    init = init.replace("@MOUNT@", mount).replace("@GO_PHASE@", go_phase).replace("@AFTER@", after).replace("@PHASE@", phase)
    members = {
        ".": (stat.S_IFDIR | 0o755, None),
        **{p: (stat.S_IFDIR | 0o755, None) for p in ["bin", "sbin", "dev", "proc", "sys", "tmp", "mnt", "mnt/data", "tools", "modules"]},
        "private": (stat.S_IFDIR | 0o700, None),
        "dev/console": (stat.S_IFCHR | 0o600, (5, 1)),
        "dev/null": (stat.S_IFCHR | 0o666, (1, 3)),
        "bin/sh": (stat.S_IFLNK | 0o777, b"busybox"),
        "sbin/modprobe": (stat.S_IFLNK | 0o777, b"../bin/busybox"),
        "init": (stat.S_IFREG | 0o755, init.encode()),
        "bin/busybox": (stat.S_IFREG | 0o755, inputs["busybox"]),
        "tools/worker-vm.test": (stat.S_IFREG | 0o755, inputs["helper"]),
        "tools/outpost": (stat.S_IFREG | 0o755, inputs["outpost"]),
        "tools/outpost-kit": (stat.S_IFREG | 0o755, inputs["outpost-kit"]),
    }
    members.update({"modules/" + p.name: (stat.S_IFREG | 0o644, p) for p in modules})
    members.update({"private/" + p.name: (stat.S_IFREG | 0o600, p) for p in private})
    with path.open("xb") as output, gzip.GzipFile(fileobj=output, mode="wb", compresslevel=1, mtime=0) as archive:
        def entry(index, name, mode, payload):
            encoded = name.encode() + b"\0"
            special = stat.S_ISCHR(mode)
            size = payload.stat().st_size if isinstance(payload, pathlib.Path) else len(payload) if isinstance(payload, bytes) else 0
            major, minor = payload if special else (0, 0)
            fields = [index, mode, 0, 0, 1, 0, size, 0, 0, major, minor, len(encoded), 0]
            header = b"070701" + b"".join(f"{v:08x}".encode() for v in fields)
            archive.write(header + encoded)
            archive.write(b"\0" * (-(len(header) + len(encoded)) % 4))
            if isinstance(payload, pathlib.Path):
                with payload.open("rb") as source:
                    for chunk in iter(lambda: source.read(1 << 20), b""):
                        archive.write(chunk)
            elif isinstance(payload, bytes):
                archive.write(payload)
            archive.write(b"\0" * (-size % 4))
        for index, (name, (mode, payload)) in enumerate(members.items(), 1):
            entry(index, name, mode, payload)
        entry(len(members) + 1, "TRAILER!!!", 0, b"")
    os.chmod(path, 0o600)
    assert path.stat().st_size <= 128 << 20


def run_guest(cfg, inputs, modules, workspace, disk, phase, private):
    resource_admission()
    initrd = workspace / (phase.replace(":", "-") + ".cpio.gz")
    write_initrd(initrd, inputs, modules, phase, private)
    command = [str(inputs["qemu"]), "-no-user-config", "-nodefaults", "-machine", "pc,dump-guest-core=off", "-accel", "tcg,thread=single", "-cpu", "max", "-smp", "1", "-m", "384", "-display", "none", "-monitor", "none", "-serial", "stdio", "-nic", "none", "-no-reboot", "-bios", cfg["bios"], "-L", cfg["qemuData"], "-kernel", str(inputs["kernel"]), "-initrd", str(initrd), "-append", "console=ttyS0 panic=-1 rdinit=/init outpost_vm_fixture=1", "-object", "rng-random,id=rng0,filename=/dev/urandom", "-device", "virtio-rng-pci,rng=rng0"]
    if phase != "volume-absent":
        assert disk.is_file() and not disk.is_symlink() and disk.stat().st_size == DISK_BYTES
        command += ["-drive", "file=" + str(disk) + ",format=raw,if=virtio,cache=directsync,aio=threads"]
    env = {**os.environ, "LD_LIBRARY_PATH": cfg["libraryPath"]}
    log = workspace / (phase.replace(":", "-") + ".log")
    start = time.monotonic()
    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    buffer = b""
    markers = []
    expected_cut = phase.startswith("cut:")
    cut_at = None
    try:
        with log.open("xb") as output:
            while True:
                if time.monotonic() - start > 600 or output.tell() > 8 << 20:
                    raise RuntimeError("owned guest exceeded its fixed deadline/log bound")
                for key, _ in selector.select(0.25):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(proc.stdout)
                        continue
                    output.write(chunk)
                    output.flush()
                    buffer += chunk
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        text = line.decode(errors="replace").strip()
                        if "OUTPOST_VM_" in text:
                            markers.append(text)
                        if expected_cut and "OUTPOST_VM_CUT_READY point=" + phase[4:] in text:
                            cut_at = time.monotonic()
                            proc.kill()
                if proc.poll() is not None and not selector.get_map():
                    break
            code = proc.wait(timeout=10)
        if expected_cut:
            assert cut_at is not None and code == -signal.SIGKILL
            result = {"status": "EXPECTED_GUEST_KERNEL_POWER_CUT", "exitCode": code, "seconds": time.monotonic() - start, "markers": markers}
        else:
            assert code == 0 and any("OUTPOST_VM_PHASE_DONE phase=" + phase + " code=0" in line for line in markers), "guest phase failed; preserved " + str(log)
            result = {"status": "PASS", "exitCode": code, "seconds": time.monotonic() - start, "markers": markers}
        result["logSHA256"] = digest(log)
        result["initrdSHA256"] = digest(initrd)
        (workspace / (phase.replace(":", "-") + ".result.json")).write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"phase": phase, "status": result["status"], "seconds": result["seconds"]}), flush=True)
        return result
    finally:
        selector.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    cfg = json.loads(pathlib.Path(args.config).read_text())
    assert cfg["schemaVersion"] == 1
    resources = resource_admission()
    inputs = {name: checked_file(value["path"], value["sha256"]) for name, value in cfg["inputs"].items()}
    checked_file(cfg["bios"], cfg["biosSHA256"])
    assert set(inputs) == {"qemu", "kernel", "helper", "busybox", "outpost", "outpost-kit"}
    modules = [checked_file(value["path"], value["sha256"]) for value in cfg["modules"]]
    workspace = pathlib.Path(cfg["workspace"])
    assert workspace.is_absolute() and not workspace.exists() and not workspace.parent.is_symlink()
    workspace.mkdir(mode=0o700)
    volume = os.statvfs(workspace)
    assert volume.f_bavail * volume.f_frsize > volume.f_blocks * volume.f_frsize // 5 + DISK_BYTES + (1 << 30)
    disk = workspace / "guest-data.raw"
    fd = os.open(disk, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.posix_fallocate(fd, 0, DISK_BYTES)
        os.fsync(fd)
    finally:
        os.close(fd)
    env = {**os.environ, "LD_LIBRARY_PATH": cfg["libraryPath"]}
    with (workspace / "mkfs.log").open("xb") as log:
        subprocess.run([cfg["mke2fs"], "-q", "-F", "-t", "ext4", "-b", "4096", "-E", "lazy_itable_init=0,lazy_journal_init=0", "-U", str(uuid.uuid4()), str(disk)], check=True, stdout=log, stderr=subprocess.STDOUT, env=env, timeout=120)
    results = {"setup": run_guest(cfg, inputs, modules, workspace, disk, "setup", [])}
    private_dir = workspace / "boot-private"
    private_dir.mkdir(mode=0o700)
    private = []
    for name in ["bootstrap.json", "node.crt", "node.key", "ca.crt"]:
        destination = private_dir / name
        assert not any(c in str(destination) for c in ['"', "\\", "\n", "\r"])
        command = f'dump -p /boot-private/{name} "{destination}"'
        with (workspace / ("extract-" + name + ".log")).open("xb") as log:
            subprocess.run([cfg["debugfs"], "-R", command, str(disk)], check=True, stdout=log, stderr=subprocess.STDOUT, env=env, timeout=30)
        assert destination.is_file() and 0 < destination.stat().st_size < 65536
        os.chmod(destination, 0o600)
        private.append(destination)
    for point in POINTS:
        results["cut:" + point] = run_guest(cfg, inputs, modules, workspace, disk, "cut:" + point, private)
        results["verify:" + point] = run_guest(cfg, inputs, modules, workspace, disk, "verify:" + point, private)
    for phase in ["volume-absent", "volume-wrong", "volume-readonly", "volume-delayed", "volume-status"]:
        results[phase] = run_guest(cfg, inputs, modules, workspace, disk, phase, private)
    summary = {"status": "PASS_BOUNDED_GUEST_KERNEL_POWERLOSS_AND_BOOT_ORDERING", "source": cfg["source"], "selectedCLICommit": cfg["selectedCLICommit"], "resources": resources, "diskBytes": DISK_BYTES, "sourceBytesPerVersion": 2 << 20, "results": results,
               "scope": "TCG guest kernel and its volatile state, ext4 commit=60 and a regular raw file with QEMU directsync; only QEMU is SIGKILLed at the cut marker. Negative unflushed-write loss and independently selected actual CLI restores are required. This is not physical host/storage-controller power loss, real unlock ordering or 100GiB acceptance."}
    summary["resources"]["memoryPeakBytes"] = int(pathlib.Path("/sys/fs/cgroup/memory.peak").read_text())
    events = {name: int(value) for name, value in (line.split() for line in pathlib.Path("/sys/fs/cgroup/memory.events").read_text().splitlines())}
    assert events["oom"] == 0 and events["oom_kill"] == 0
    assert int(pathlib.Path("/sys/fs/cgroup/memory.swap.current").read_text()) == 0
    summary["resources"]["memoryEvents"] = events
    summary["resources"]["swapCurrentBytes"] = 0
    (workspace / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"status": summary["status"], "phases": len(results)}), flush=True)


if __name__ == "__main__":
    main()
