#!/usr/bin/env python3
"""Verify an uninstalled distribution against a separately retained manifest hash."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("outpost_build_release", Path(__file__).with_name("build-release.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
MAX_FILE = 128 << 20


def unique(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate JSON member")
        value[name] = item
    return value


def regular(path, maximum):
    # Refuse symlinks, FIFOs/devices and size changes before returning bytes.
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("invalid distribution file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(fd, "rb")
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        stream.close()
        raise ValueError("invalid distribution file")
    return stream


def measure(path, maximum=MAX_FILE):
    h = hashlib.sha256()
    size = 0
    with regular(path, maximum) as data:
        for block in iter(lambda: data.read(1024 * 1024), b""):
            size += len(block)
            if size > maximum:
                raise ValueError("distribution file grew")
            h.update(block)
    return {"sha256": h.hexdigest(), "bytes": size}


def verify_archive(root, architecture, files):
    expected = {name: files["linux_" + architecture + "/" + name] for name in ("outpost", "outpost-kit")}
    expected.update({name: value for name, value in files.items() if name.startswith("licenses/")})
    seen = set()
    with regular(root / ("outpost-linux-" + architecture + ".tar.gz"), MAX_FILE) as raw:
        with tarfile.open(fileobj=raw, mode="r|gz") as archive:
            for member in archive:
                if member.name not in expected or member.name in seen or not member.isfile():
                    raise ValueError("unexpected archive member")
                expected_mode = 0o755 if member.name in ("outpost", "outpost-kit") else 0o644
                if (member.mode, member.uid, member.gid, member.mtime) != (expected_mode, 0, 0, 0):
                    raise ValueError("noncanonical archive metadata")
                if member.size != expected[member.name]["bytes"] or member.size > MAX_FILE:
                    raise ValueError("unexpected archive size")
                stream = archive.extractfile(member)
                h = hashlib.sha256()
                size = 0
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    size += len(block)
                    if size > member.size:
                        raise ValueError("archive member grew")
                    h.update(block)
                if {"sha256": h.hexdigest(), "bytes": size} != expected[member.name]:
                    raise ValueError("archive payload differs")
                seen.add(member.name)
    if seen != set(expected):
        raise ValueError("missing archive member")


def verify(root, expected_hash):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash) or not root.is_absolute():
        raise ValueError("explicit trusted manifest hash and absolute root required")
    if root.resolve(strict=True) != root:
        raise ValueError("symlinked distribution root")
    with regular(root / "manifest.json", 2 << 20) as f:
        raw = f.read((2 << 20) + 1)
    if len(raw) > 2 << 20 or hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError("wrong selected manifest")
    manifest = json.loads(raw, object_pairs_hook=unique)
    if set(manifest) != {"format", "revision", "sourceDigest", "source", "goVersion", "goos", "cgo", "architectures", "files"}:
        raise ValueError("unexpected manifest fields")
    if manifest["format"] != builder.FORMAT or manifest["goos"] != "linux" or manifest["cgo"] is not False:
        raise ValueError("unsupported distribution")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|dev-[0-9a-f]{64})", manifest["revision"]):
        raise ValueError("invalid revision")
    if not re.fullmatch(r"go[0-9]+\.[0-9]+\.[0-9]+", manifest["goVersion"]):
        raise ValueError("invalid toolchain")
    source = manifest["source"]
    if not isinstance(source, dict) or not 1 <= len(source) <= 4096:
        raise ValueError("invalid source inventory")
    for name, digest in source.items():
        if not re.fullmatch(r"[A-Za-z0-9_./-]+", name) or name.startswith("/") or ".." in name.split("/") or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid source entry")
    if hashlib.sha256(builder.canonical(source)).hexdigest() != manifest["sourceDigest"]:
        raise ValueError("source digest mismatch")
    architectures = manifest["architectures"]
    if not isinstance(architectures, list) or not 1 <= len(architectures) <= 2 or len(set(architectures)) != len(architectures) or any(a not in builder.ARCHITECTURES for a in architectures):
        raise ValueError("invalid architectures")
    allowed = {"Dockerfile", "compose.yaml", ".dockerignore", "licenses/LICENSE", "licenses/THIRD_PARTY_NOTICES.md", "licenses/GO_LICENSE"}
    for architecture in architectures:
        allowed.update({"linux_" + architecture + "/outpost", "linux_" + architecture + "/outpost-kit", "outpost-linux-" + architecture + ".tar.gz"})
    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != allowed:
        raise ValueError("unexpected artifact set")
    observed = set()
    for base, directories, names in os.walk(root, followlinks=False):
        if len(directories) + len(names) > 32:
            raise ValueError("unexpected distribution tree")
        for name in directories:
            directory = Path(base) / name
            if directory.is_symlink() or directory.relative_to(root).as_posix() not in {"licenses", *["linux_" + a for a in architectures]}:
                raise ValueError("unexpected directory")
        observed.update((Path(base) / n).relative_to(root).as_posix() for n in names)
    if observed != allowed | {"manifest.json", "SHA256SUMS"}:
        raise ValueError("unlisted files in distribution")
    for name, expected in files.items():
        if not isinstance(expected, dict) or set(expected) != {"sha256", "bytes"} or type(expected["bytes"]) is not int or not 0 < expected["bytes"] <= MAX_FILE or not re.fullmatch(r"[0-9a-f]{64}", expected["sha256"]):
            raise ValueError("invalid artifact digest")
        if measure(root / name) != expected:
            raise ValueError("artifact bytes differ")
    sums = {name: value["sha256"] for name, value in files.items()}
    sums["manifest.json"] = expected_hash
    expected_sums = "".join(digest + "  " + name + "\n" for name, digest in sorted(sums.items())).encode()
    with regular(root / "SHA256SUMS", 65536) as f:
        if f.read(65537) != expected_sums:
            raise ValueError("checksum inventory differs")
    for architecture in architectures:
        for binary in ("outpost", "outpost-kit"):
            builder.verify_elf(root / ("linux_" + architecture) / binary, architecture)
        verify_archive(root, architecture, files)
    return {"format": builder.FORMAT, "revision": manifest["revision"], "sourceDigest": manifest["sourceDigest"],
            "manifestSHA256": expected_hash, "architectures": architectures, "state": "VERIFIED_ARTIFACTS", "runtimeAcceptance": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.root, args.manifest_sha256), sort_keys=True))


if __name__ == "__main__":
    main()
