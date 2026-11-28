#!/usr/bin/env python3
"""Reproducible G1 synthetic acceptance. Never point at existing source data.

Requires an absent absolute root and already built Linux binaries. The Docker
mode uses isolated, unprivileged, networkless containers. Recovery containers
receive only a selected copied kit, recovery key, trusted version and output.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import time


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=pathlib.Path, required=True)
    p.add_argument("--kit-binary", type=pathlib.Path, required=True)
    p.add_argument("--fixture-binary", type=pathlib.Path, required=True)
    p.add_argument("--limits", type=pathlib.Path, required=True)
    p.add_argument("--bytes", type=int, default=100 << 30)
    p.add_argument("--container-image", default="")
    p.add_argument("--filesystem-uuid", default="")
    p.add_argument("--phase-timeout-seconds", type=int, default=7200)
    a = p.parse_args()
    limits = json.loads(a.limits.read_text())
    root = a.root
    assert root.is_absolute() and not root.exists(), "new isolated root required"
    assert 128 << 20 <= a.bytes <= 100 << 30
    assert 60 <= a.phase_timeout_seconds <= 43200, "phase timeout must be between 60 and 43200 seconds"
    for binary in (a.kit_binary, a.fixture_binary):
        assert binary.is_absolute() and binary.is_file()
    if a.container_image:
        digest = a.container_image.removeprefix("sha256:")
        assert a.container_image.startswith("sha256:") and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest), "pin the container image"
    if a.bytes == limits["sourceBytes"]:
        assert a.container_image and a.filesystem_uuid, "full-scale acceptance requires container and filesystem pins"
    # Admission happens before mkdir so a missing mount cannot write to root.
    if a.filesystem_uuid:
        actual = subprocess.check_output(["findmnt", "-n", "-o", "UUID", "--target", str(root.parent)], text=True).strip()
        assert actual == a.filesystem_uuid, "test filesystem missing or changed"
    initial = shutil.disk_usage(root.parent)
    assert initial.free - a.bytes >= initial.total * limits["minimumFilesystemFreeRatio"], "insufficient test capacity"
    root.mkdir(mode=0o700)
    for directory in ("source", "keys", "recovery", "outputs", "results"):
        (root / directory).mkdir(mode=0o700)
    receipts = []
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    peak_used = 0
    min_free = 1.0
    calls = 0
    overall_status = "RUNNING"
    failure = None
    active_label = None

    def capacity(additional=0):
        nonlocal peak_used, min_free
        if a.filesystem_uuid:
            actual = subprocess.check_output(["findmnt", "-n", "-o", "UUID", "--target", str(root)], text=True).strip()
            assert actual == a.filesystem_uuid, "test filesystem changed"
        u = shutil.disk_usage(root)
        peak_used = max(peak_used, u.used)
        min_free = min(min_free, u.free / u.total)
        assert u.free - additional >= u.total * limits["minimumFilesystemFreeRatio"], "free-space reserve would be crossed"
        return {"total": u.total, "used": u.used, "free": u.free}

    def save():
        report = {"started": started, "observedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "status": overall_status, "failure": failure,
                  "baselineBytes": a.bytes, "fullScale": a.bytes == limits["sourceBytes"],
                  "isolation": "networkless-container" if a.container_image else "native-fixture",
                  "image": a.container_image, "filesystemUUID": a.filesystem_uuid,
                  "phaseTimeoutSeconds": a.phase_timeout_seconds,
                  "filesystemBytes": initial.total, "peakObservedFilesystemUsed": peak_used,
                  "minimumObservedFilesystemFreeRatio": min_free, "operations": receipts,
                  "binarySha256": {"kit": hashlib.sha256(a.kit_binary.read_bytes()).hexdigest(),
                                   "fixture": hashlib.sha256(a.fixture_binary.read_bytes()).hexdigest()},
                  "limitsSha256": hashlib.sha256(a.limits.read_bytes()).hexdigest()}
        temp = root / "results/report.pending"
        temp.write_text(json.dumps(report, indent=2) + "\n")
        temp.replace(root / "results/report.json")

    def call(label, binary, args, mounts, additional=0):
        nonlocal calls, active_label
        active_label = label
        before = capacity(additional)
        calls += 1
        print(json.dumps({"event": "start", "label": label, "time": time.time(), "capacity": before}), flush=True)
        if a.container_image:
            cmd = ["docker", "run", "--rm", "--name", "outpost-kit-" + root.name + "-" + str(calls),
                   "--network", "none", "--cpus", "1", "--memory", str(limits["containerMemoryBytes"]),
                   "--memory-swap", str(limits["containerMemoryBytes"]), "--pids-limit", "128",
                   "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--read-only",
                   "--tmpfs", "/tmp:rw,nosuid,nodev,exec,size=32m", "-e", "GOMAXPROCS=1",
                   "-v", str(binary) + ":/tool:ro"]
            for host, inside, access in mounts:
                cmd += ["-v", str(host) + ":" + inside + ":" + access]
            cmd += [a.container_image, "sh", "-ec", 'cp /tool /tmp/tool; exec /tmp/tool "$@"', "runner"] + args
        else:
            translated = []
            for arg in args:
                for host, inside, _ in sorted(mounts, key=lambda m: -len(m[1])):
                    if arg == inside or arg.startswith(inside + "/"):
                        arg = str(host) + arg[len(inside):]
                        break
                translated.append(arg)
            cmd = [str(binary)] + translated
        stdout_path = root / ("results/" + label + ".stdout")
        stderr_path = root / ("results/" + label + ".stderr")
        with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
            process = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, text=True)
            deadline = time.monotonic() + a.phase_timeout_seconds
            try:
                while process.poll() is None:
                    capacity()
                    if time.monotonic() > deadline:
                        raise TimeoutError(label)
                    time.sleep(2)
            except BaseException:
                if a.container_image:
                    subprocess.run(["docker", "stop", "--time", "10", "outpost-kit-" + root.name + "-" + str(calls)], check=False, capture_output=True)
                else:
                    process.terminate()
                process.wait(timeout=30)
                save()
                raise
        if process.returncode:
            receipts.append({"label": label, "exitCode": process.returncode, "status": "FAIL"})
            save()
            raise RuntimeError(label + ": " + stderr_path.read_text()[-2000:])
        data = json.loads(stdout_path.read_text())
        assert data["maxRSSKiB"] * 1024 <= limits["containerMemoryBytes"], "RSS bound exceeded"
        receipts.append({"label": label, "exitCode": 0, "status": "PASS", "before": before, "after": capacity(), "result": data})
        (root / ("results/" + label + ".json")).write_text(json.dumps(data, indent=2) + "\n")
        save()
        print(json.dumps({"event": "done", "label": label, "seconds": data.get("elapsedSeconds")}), flush=True)
        return data

    key_mount = (root / "keys", "/keys", "ro")
    source_mount = (root / "source", "/source", "ro")
    store_mount = (root / "store", "/store", "rw")
    output_mount = (root / "outputs", "/outputs", "rw")
    key = ["-owner", "/keys/owner.json"]
    common = key + ["-store", "/store"]
    root_store = root / "store"
    root_store.mkdir(mode=0o700)

    def kit(label, args, mounts, additional=0):
        return call(label, a.kit_binary, args, mounts, additional)

    def fixture(label, op, phase, filename, mounts, alias="", additional=0):
        args = ["-op", op, "-phase", phase, "-file", filename, "-bytes", str(a.bytes)]
        if alias:
            args += ["-alias", alias]
        return call(label, a.fixture_binary, args, mounts, additional)

    def remove_owned(path):
        resolved = path.resolve()
        assert resolved.is_relative_to(root.resolve()) and resolved != root.resolve()
        assert path in [root / "source/source.bin", root / "source/renamed.bin", root / "kit-old"] or path.parent == root / "outputs"
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        capacity()

    def backup(label, previous=None, source="source.bin", name="file.bin"):
        args = ["backup"] + common + ["-source", "/source/" + source, "-name", name, "-aliases", "alias.bin"]
        if previous:
            args += ["-file", previous["file"], "-previous", previous["version"]]
        data = kit(label, args, [key_mount, source_mount, store_mount], int(a.bytes * 1.08) if previous is None else 256 << 20)["result"]
        expected = a.bytes + ((1 << 20) if label == "backup-inserted" else 0)
        assert data["sourceBytes"] == expected
        assert len(list((root / "source").iterdir())) == 1, "source-local temporary data found"
        return data

    def restore(label, version, phase, selected=None, name="file.bin"):
        if selected:
            mounts = [(selected, "/kit", "ro"), (root / "recovery", "/recovery", "ro"), output_mount]
            args = ["restore", "-owner", "/recovery/owner.json", "-store", "/kit"]
        else:
            mounts = [key_mount, store_mount, output_mount]
            args = ["restore-store"] + common
        data = kit(label, args + ["-version", version, "-dest", "/outputs/" + label], mounts, a.bytes + (1 << 20))
        assert data["result"]["io"]["verifiedReadBytes"] <= a.bytes * limits["maximumRestoreReadRatio"] + limits["restoreReadAllowanceBytes"]
        fixture(label + "-oracle", "verify", phase, "/outputs/" + label + "/" + name,
                [(root / "outputs", "/outputs", "ro")], "/outputs/" + label + "/alias.bin")
        remove_owned(root / "outputs" / label)

    def export(label, version, dest):
        data = kit(label, ["export"] + common + ["-version", version, "-dest", "/exports/" + dest],
                   [key_mount, store_mount, (root, "/exports", "rw")], int(a.bytes * 1.08))
        # The copy must not share payload inodes with the canonical store.
        selected = root / dest
        for obj in (selected / "objects").glob("*/*"):
            original = root / "store/objects" / obj.parent.name / obj.name
            assert not os.path.samefile(obj, original), "export aliases canonical payload"
        # Remove scaffolding: independent readers receive only root + objects.
        for entry in ("versions", ".txn", ".lock", "store.json"):
            target = selected / entry
            if target.is_dir(): shutil.rmtree(target)
            elif target.exists(): target.unlink()
        return data

    try:
        kit("keygen", ["keygen"] + key, [(root / "keys", "/keys", "rw")])
        kit("recovery-key", ["recovery-key"] + key + ["-dest", "/keys/recovery.json"], [(root / "keys", "/keys", "rw")])
        # A file bind is a separate mount beneath its parent. ReadOwner refuses
        # that crossing. Admit a directory containing only the recovery key,
        # keeping the source's signing-capable owner file out of the reader.
        shutil.copy2(root / "keys/recovery.json", root / "recovery/owner.json")
        fixture("generate", "generate", "base", "/source/source.bin", [(root / "source", "/source", "rw")], additional=a.bytes)
        base = backup("backup-base")
        inventory = kit("inspect-base", ["inspect"] + common + ["-version", base["version"]], [key_mount, (root / "store", "/store", "ro")])["result"]
        assert inventory["storedBytes"] <= a.bytes * limits["maximumInitialKitRatio"]
        assert inventory["objects"] <= limits["maximumSelectedKitObjects"]
        fixture("patch", "mutate", "patched", "/source/source.bin", [(root / "source", "/source", "rw")])
        changed = backup("backup-patched", base)
        assert changed["newPayloadBytes"] + changed["newMetadataBytes"] <= limits["maximumIncrementalBytes"]
        unchanged = backup("backup-unchanged", changed)
        assert unchanged["version"] == changed["version"] and unchanged["newPayloadBytes"] == 0 and unchanged["newMetadataBytes"] == 0
        (root / "source/source.bin").rename(root / "source/renamed.bin")
        renamed = backup("backup-renamed", changed, "renamed.bin", "renamed.bin")
        assert renamed["newPayloadBytes"] == 0 and renamed["version"] != changed["version"]
        fixture("scatter", "mutate", "scattered", "/source/renamed.bin", [(root / "source", "/source", "rw")])
        scattered = backup("backup-scattered", renamed, "renamed.bin", "renamed.bin")
        fixture("insert", "mutate", "inserted", "/source/renamed.bin", [(root / "source", "/source", "rw")], additional=1 << 20)
        inserted = backup("backup-inserted", scattered, "renamed.bin", "renamed.bin")
        restore("restore-inserted", inserted["version"], "inserted", name="renamed.bin")
        remove_owned(root / "source/renamed.bin")
        export("export-before-maintenance", base["version"], "kit-old")
        repack = kit("repack", ["repack"] + common, [key_mount, store_mount], int(a.bytes * 1.08))["result"]
        assert repack["payloadObjectsReplaced"] > 0 and repack["garbageObjectsRemoved"] > 0
        kit("retire", ["retire"] + common + ["-version", ",".join([base["version"], renamed["version"], scattered["version"]])], [key_mount, store_mount])
        restore("independent-old-after-maintenance", base["version"], "base", root / "kit-old")
        remove_owned(root / "kit-old")
        export("export-retained-new", changed["version"], "kit-new")
        restore("independent-new-after-maintenance", changed["version"], "patched", root / "kit-new")
        capacity()
        overall_status = "PASS"
        save()
        (root / "results/PASS").write_text("Full scale G1 fixture PASS\n" if a.bytes == limits["sourceBytes"] else "Bounded fixture PASS; not full-scale acceptance\n")
        print("PASS: synthetic file-kit acceptance", flush=True)
    except BaseException as error:
        overall_status = "FAIL"
        failure = {"afterLabel": active_label, "errorType": type(error).__name__}
        save()
        raise


if __name__ == "__main__":
    main()
