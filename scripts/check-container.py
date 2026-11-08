#!/usr/bin/env python3
"""Run bounded synthetic installation/recovery checks on a native Linux Docker host.

Requires independently selected current/previous distributions and a native,
static cmd/outpost test executable. Never loads a real profile or contacts peers.
All fixture material stays in a new private work directory. Only containers
created by this invocation are removed; images and evidence are retained.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import time
import uuid

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("outpost_verify", Path(__file__).with_name("verify-release.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
MEMORY = 768 << 20
TMPFS = "/tmp:rw,nosuid,nodev,noexec,size=67108864,mode=1777"
LABEL = "org.outpost.synthetic-check"


def command(args, timeout=45, env=None):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
    if result.returncode:
        raise RuntimeError("bounded command failed: " + result.stderr[-2400:])
    return result.stdout


def write_json(path, value):
    with path.open("x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        json.dump(value, output, sort_keys=True)
        output.write("\n")


class Suite:
    def __init__(self, args):
        self.args = args
        self.arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
        self.uid, self.gid = os.getuid(), os.getgid()
        if self.uid == 0 or self.gid == 0:
            raise ValueError("run as the explicit non-root owner of a fresh fixture directory")
        self.work = args.work
        if (not self.work.is_absolute() or self.work.exists() or self.work.is_symlink()
                or not self.work.parent.is_dir() or self.work.parent.resolve() != self.work.parent):
            raise ValueError("new absolute work directory with an existing nonsymlink parent required")
        self.current = verifier.verify(args.root, args.manifest_sha256)
        self.previous = verifier.verify(args.previous_root, args.previous_manifest_sha256)
        with verifier.regular(args.root / "manifest.json", 2 << 20) as manifest:
            raw = manifest.read()
        if hashlib.sha256(raw).hexdigest() != args.manifest_sha256:
            raise ValueError("selected manifest changed")
        self.payloads = json.loads(raw)["files"]
        if self.current["sourceDigest"] == self.previous["sourceDigest"]:
            raise ValueError("upgrade requires distinct selected source versions")
        verifier.builder.verify_elf(args.fixture_binary, self.arch)
        os.mkdir(self.work, 0o700)
        self.token = uuid.uuid4().hex
        self.containers = []
        self.results = []
        self.fixture = self.work / "fixtures" / "container-fixture-current"
        self.fixture.parent.mkdir(mode=0o700)
        self.image = self.build_image(args.root, self.current, "current")
        self.old_image = self.build_image(args.previous_root, self.previous, "previous")
        helper = self.work / "helper"
        helper.mkdir(mode=0o700)
        shutil.copyfile(args.fixture_binary, helper / "fixture")
        (helper / "Dockerfile").write_text("FROM scratch\nCOPY --chmod=0555 fixture /fixture\nUSER 65532:65532\nENTRYPOINT [\"/fixture\"]\n", encoding="utf-8")
        self.helper_image = self.docker_build(helper, "fixture")

    def docker_build(self, root, name, extra=()):
        output = command(["docker", "build", "--quiet", "--network=none", "--pull=false", "--platform", "linux/" + self.arch,
                          "--label", LABEL + "=" + self.token, *extra, str(root)], timeout=90).strip().splitlines()[-1]
        info = json.loads(command(["docker", "image", "inspect", output]))[0]
        assert info["Architecture"] == self.arch and info["Os"] == "linux"
        write_json(self.work / (name + "-image.json"), {"id": info["Id"], "architecture": info["Architecture"], "config": info["Config"]})
        return info["Id"]

    def build_image(self, root, manifest, name):
        image = self.docker_build(root, name, ["--build-arg", "TARGETARCH=" + self.arch, "--build-arg", "REVISION=" + manifest["revision"]])
        verifier.verify(root, manifest["manifestSHA256"])
        return image

    def create(self, image, args, mounts=(), user=None, readonly=True, nnp=True, entrypoint=None, env=()):
        name = "outpost-check-" + self.token[:12] + "-" + str(len(self.containers))
        options = ["docker", "create", "--name", name, "--label", LABEL + "=" + self.token, "--network=none", "--cgroupns=private",
                   "--cpus=1", "--memory=" + str(MEMORY), "--memory-swap=" + str(MEMORY), "--pids-limit=128", "--cap-drop=ALL",
                   "--tmpfs", TMPFS, "--log-driver=local", "--log-opt=max-size=1m", "--log-opt=max-file=2"]
        if user is not None:
            options += ["--user", user]
        if readonly:
            options += ["--read-only"]
        if nnp:
            options += ["--security-opt=no-new-privileges"]
        if entrypoint:
            options += ["--entrypoint", entrypoint]
        for source, dest, ro in mounts:
            if source.is_symlink() or not source.exists() or "," in str(source):
                raise ValueError("pre-existing nonsymlink bind source required")
            options += ["--mount", "type=bind,src=" + str(source) + ",dst=" + dest + (",readonly" if ro else "")]
        for name_value in env:
            options += ["--env", name_value]
        command([*options, image, *args])
        self.containers.append(name)
        return name

    def inspect(self, name):
        result = json.loads(command(["docker", "inspect", name]))[0]
        assert result["Config"]["Labels"].get(LABEL) == self.token
        return result

    def once(self, image, args, expected=0, **kwargs):
        name = self.create(image, args, **kwargs)
        result = subprocess.run(["docker", "start", "--attach", name], capture_output=True, text=True, timeout=45)
        state = self.inspect(name)["State"]
        assert not state["Running"] and not state["OOMKilled"]
        if state["ExitCode"] != expected or result.returncode != expected:
            raise AssertionError("container " + name + " exit=" + str(state["ExitCode"]) + " stdout=" + result.stdout[:1200] + " stderr=" + result.stderr[:1200])
        return result, name

    def result(self, name, **values):
        self.results.append({"test": name, "state": "PASS", **values})
        print("PASS " + name, flush=True)

    def worker_mounts(self, data_readonly=False):
        return [(self.fixture / "data", "/var/lib/outpost", data_readonly), (self.fixture / "private", "/run/outpost", True)]

    def worker(self, operation, extra=(), old=False, expected=0, **kwargs):
        return self.once(self.old_image if old else self.image,
                         [operation, *([] if old else ["--require-isolation"]), "--bootstrap", "/run/outpost/worker.json", *extra],
                         expected=expected, user=str(self.uid) + ":" + str(self.gid), mounts=kwargs.pop("mounts", self.worker_mounts()), **kwargs)

    def cleanup(self):
        for name in reversed(self.containers):
            # No wildcard, general pruning, shared image removal or host change.
            self.inspect(name)
            command(["docker", "rm", "--force", name])


def test_image_and_enforced_isolation(s):
    result, name = s.once(s.image, ["runtime-check"])
    observation = json.loads(result.stdout)["result"]
    assert observation["uid"] == 65532 and observation["effectiveUid"] == 65532
    assert observation["violations"] == [] and not observation["runtimeAcceptance"]
    assert observation["networkNamespace"] != os.stat("/proc/self/ns/net").st_ino
    assert observation["memory"] == {"state": "LIMITED", "value": MEMORY}
    assert observation["swap"] == {"state": "LIMITED"}
    assert observation["pids"] == {"state": "LIMITED", "value": 128}
    assert observation["cpuQuota"]["value"] == observation["cpuPeriod"]
    info = s.inspect(name)
    host = info["HostConfig"]
    assert host["NetworkMode"] == "none" and not host["Privileged"] and not host["Devices"]
    assert host["ReadonlyRootfs"] and host["CapDrop"] == ["ALL"] and not host["PortBindings"]
    assert not [m for m in info["Mounts"] if m["Type"] == "bind"]
    archive_path = s.work / "image-root.tar"
    command(["docker", "export", "--output", str(archive_path), name])
    binaries = set()
    with tarfile.open(archive_path) as archive:
        for member in archive:
            assert not member.mode & 0o6000 and not any("capability" in k for k in member.pax_headers)
            if member.isfile() and member.mode & 0o111:
                # Docker exports these generated mountpoint placeholders as
                # empty regular files. They contain no executable payload.
                if member.name in (".dockerenv", "dev/console", "etc/hostname", "etc/hosts", "etc/resolv.conf"):
                    assert member.size == 0
                    continue
                assert member.name in ("outpost", "outpost-kit")
                binaries.add(member.name)
                assert hashlib.sha256(archive.extractfile(member).read()).hexdigest() == s.payloads["linux_" + s.arch + "/" + member.name]["sha256"]
            assert member.name not in ("bin/sh", "bin/bash", "usr/bin/apt", "sbin/apk")
    assert binaries == {"outpost", "outpost-kit"}
    write_json(s.work / "isolation.json", observation)
    s.result("image_and_enforced_isolation", architecture=s.arch)


def test_unsafe_runtime_rejected_before_profile(s):
    for overrides in ({"user": "0:0"}, {"readonly": False}, {"nnp": False}):
        result, _ = s.once(s.image, ["worker-init", "--require-isolation", "--bootstrap", "/missing-private-profile"], expected=5, **overrides)
        assert json.loads(result.stderr)["error"]["code"] == "CAPABILITY_UNAVAILABLE"
    s.result("unsafe_runtime_rejected_before_profile", cases=3)


def test_explicit_installation(s):
    s.once(s.helper_image, ["-test.run=^TestContainerPackagingFixture$", "-test.count=1"],
           user=str(s.uid) + ":" + str(s.gid), mounts=[(s.fixture.parent, "/fixtures", False)],
           env=["OUTPOST_CONTAINER_FIXTURE=/fixtures/container-fixture-current"])
    meta = json.loads((s.fixture / "metadata.json").read_text())
    mounts = [(s.fixture / "data", "/var/lib/outpost", False), (s.fixture / "private", "/run/outpost", False)]
    for args in (["volume-probe", "--store", "/var/lib/outpost", "--output", "/run/outpost/probe.json"],
                 ["volume-enroll", "--store", "/var/lib/outpost", "--input", "/run/outpost/probe.json", "--node", meta["node"], "--epoch", "1", "--output", "/run/outpost/binding.json"]):
        s.once(s.image, [*args, "--require-isolation"], user=str(s.uid) + ":" + str(s.gid), mounts=mounts)
    bootstrap = json.loads((s.fixture / "private/bootstrap-template.json").read_text())
    bootstrap["volume"] = json.loads((s.fixture / "private/binding.json").read_text())
    write_json(s.fixture / "private/worker.json", bootstrap)
    # First real initialization and revision1 use the previous candidate.
    s.worker("worker-init", old=True)
    s.worker("config-apply", ["--input", "/run/outpost/policy.json"], old=True)
    s.once(s.helper_image, ["-test.run=^TestContainerPackagingFixture$", "-test.count=1"],
           user=str(s.uid) + ":" + str(s.gid), mounts=[(s.fixture.parent, "/fixtures", False), (s.fixture / "data", "/var/lib/outpost", False)],
           env=["OUTPOST_CONTAINER_FIXTURE=/fixtures/container-fixture-current", "OUTPOST_CONTAINER_FIXTURE_STAGE=seed"])
    assert not (s.fixture / "source-store").exists() and not (s.fixture / "sample.input").exists()
    s.result("explicit_installation", node=meta["node"], clearSourceAbsent=True)


def test_cached_start_upgrade_stop_and_rollback(s):
    meta = json.loads((s.fixture / "metadata.json").read_text())
    replica = s.fixture / "data" / Path(meta["replica"]).relative_to("/var/lib/outpost")
    def closure():
        return {p.relative_to(replica).as_posix(): verifier.builder.digest_file(p) for folder in ("catalogs", "objects") for p in (replica / folder).rglob("*") if p.is_file()}
    before = closure()
    assert before
    for stage, old, revision in (("previous", True, 1), ("current", False, 2), ("rollback", True, 2)):
        if stage == "current":
            s.worker("config-apply", ["--input", "/run/outpost/policy-next.json"])
        name = s.create(s.old_image if old else s.image, ["worker-run", *([] if old else ["--require-isolation"]), "--bootstrap", "/run/outpost/worker.json"],
                        user=str(s.uid) + ":" + str(s.gid), mounts=s.worker_mounts())
        command(["docker", "start", name])
        time.sleep(1.2)
        running = s.inspect(name)
        assert running["State"]["Running"]
        mounts = {(m["Destination"], m["RW"]) for m in running["Mounts"] if m["Type"] == "bind"}
        assert mounts == {("/var/lib/outpost", True), ("/run/outpost", False)}
        result, _ = s.worker("worker-status", old=old)
        status = json.loads(result.stdout)["result"]
        assert status["configurationRevision"] == revision and status["node"] == meta["node"]
        command(["docker", "stop", "--time", "10", name], timeout=15)
        stopped = s.inspect(name)["State"]
        assert not stopped["Running"] and not stopped["OOMKilled"] and stopped["ExitCode"] == 0
        assert closure() == before
        write_json(s.work / (stage + "-status.json"), status)
    s.result("cached_start_upgrade_stop_and_rollback", ciphertextObjects=len(before), revision=2)


def test_compose_profile_preserves_runtime_constraints(s):
    env = dict(os.environ, OUTPOST_IMAGE=s.image, OUTPOST_UID=str(s.uid), OUTPOST_GID=str(s.gid),
               OUTPOST_DATA=str(s.fixture / "data"), OUTPOST_PRIVATE=str(s.fixture / "private"))
    config = json.loads(command(["docker", "compose", "-f", str(s.args.root / "compose.yaml"), "--profile", "commands", "--profile", "reports", "--profile", "telemetry", "config", "--format", "json"], env=env))
    assert set(config["services"]) == {"worker", "commands", "reports", "telemetry"}
    for service in config["services"].values():
        assert service["image"] == s.image and service["pull_policy"] == "never"
        assert service["user"] == str(s.uid) + ":" + str(s.gid) and service["read_only"]
        assert service["cgroup"] == "private" and service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert float(service["cpus"]) == 1 and int(service["mem_limit"]) == MEMORY and int(service["memswap_limit"]) == MEMORY and service["pids_limit"] == 128
        assert not service.get("ports") and not service.get("devices") and not service.get("privileged") and service.get("network_mode") != "host"
        assert "--require-isolation" in service["command"] and service["tmpfs"] == [TMPFS]
        assert {(m["target"], bool(m.get("read_only"))) for m in service["volumes"]} == {("/var/lib/outpost", False), ("/run/outpost", True)}
        assert all(m["type"] == "bind" and not m["bind"].get("create_host_path", False) for m in service["volumes"])
    # Configuration expansion is separate from host admission and never starts a service.
    assert config["services"]["telemetry"]["command"][0] == "worker-telemetry-loop"
    s.result("compose_profile_preserves_runtime_constraints", services=4)


def test_missing_or_readonly_volume_fails_without_fallback(s):
    before = {p.relative_to(s.fixture / "data").as_posix(): verifier.builder.digest_file(p) for p in (s.fixture / "data").rglob("*") if p.is_file()}
    for mounts in ([(s.fixture / "private", "/run/outpost", True)], s.worker_mounts(data_readonly=True)):
        result, _ = s.worker("worker-run", mounts=mounts, expected=5)
        assert json.loads(result.stderr)["error"]["code"] == "VOLUME_UNAVAILABLE"
    after = {p.relative_to(s.fixture / "data").as_posix(): verifier.builder.digest_file(p) for p in (s.fixture / "data").rglob("*") if p.is_file()}
    assert before == after
    s.result("missing_or_readonly_volume_fails_without_fallback")


def test_independent_recovery_after_source_removal(s):
    meta = json.loads((s.fixture / "metadata.json").read_text())
    receipt = json.loads((s.fixture / "seed-receipt.json").read_text())
    mounts = [(s.fixture / "data", "/var/lib/outpost", True), (s.fixture / "recovery-private", "/run/recovery", True), (s.fixture / "restored", "/restored", False)]
    s.once(s.image, ["restore-replica", "--require-isolation", "--store", meta["replica"], "--generation", receipt["generation"],
                    "--key", "/run/recovery/owner.json", "--trust", "/run/recovery/trust.json", "--output", "/restored/replica"],
           user=str(s.uid) + ":" + str(s.gid), mounts=mounts)
    s.once(s.image, ["restore", "--owner", "/run/recovery/owner.json", "--store", "/kit", "--version", meta["version"], "--dest", "/restored/standalone"],
           entrypoint="/outpost-kit", user=str(s.uid) + ":" + str(s.gid),
           mounts=[(s.fixture / "standalone-kit", "/kit", True), *mounts[1:]])
    for name in ("replica", "standalone"):
        restored = s.fixture / "restored" / name / "sample.txt"
        assert restored.stat().st_size == meta["bytes"] and verifier.builder.digest_file(restored) == meta["digest"]
    s.result("independent_recovery_after_source_removal", sha256=meta["digest"], bytes=meta["bytes"])


TESTS = [test_image_and_enforced_isolation, test_unsafe_runtime_rejected_before_profile, test_explicit_installation,
         test_cached_start_upgrade_stop_and_rollback, test_compose_profile_preserves_runtime_constraints,
         test_missing_or_readonly_volume_fails_without_fallback, test_independent_recovery_after_source_removal]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "previous-root", "work", "fixture-binary"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--previous-manifest-sha256", required=True)
    args = parser.parse_args()
    suite = Suite(args)
    try:
        for test in TESTS:
            test(suite)
        write_json(suite.work / "receipt.json", {"format": "outpost-container-check-1", "architecture": suite.arch,
                   "current": suite.current, "previous": suite.previous, "image": suite.image, "previousImage": suite.old_image,
                   "checks": suite.results, "pending": ["cold-host-boot-order", "production-infrastructure-admission", "full-product-acceptance"], "fullProductAcceptance": False})
        print("CONTAINER_PASS " + suite.arch, flush=True)
    finally:
        suite.cleanup()


if __name__ == "__main__":
    main()
