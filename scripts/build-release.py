#!/usr/bin/env python3
"""Build new, source-bound Linux artifacts. Never install or publish them."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "outpost-distribution-1"
ARCHITECTURES = {"amd64": 62, "arm64": 183}


def digest_file(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def source_manifest():
    names = {"go.mod", "go.sum", "LICENSE", "THIRD_PARTY_NOTICES.md"}
    for base in ("cmd", "internal"):
        names.update(p.relative_to(ROOT).as_posix() for p in (ROOT / base).rglob("*.go"))
    for base in ("internal/management/ui", "packaging"):
        names.update(p.relative_to(ROOT).as_posix() for p in (ROOT / base).rglob("*") if p.is_file())
    names.update(p.relative_to(ROOT).as_posix() for p in (ROOT / "scripts").glob("*-release.py"))
    result = {}
    for name in sorted(names):
        p = ROOT / name
        if p.is_symlink() or not p.is_file():
            raise ValueError("nonregular build input")
        result[name] = digest_file(p)
    return result


def verify_elf(path, architecture):
    # A static ELF executable must not contain a PT_INTERP loader dependency.
    with path.open("rb") as f:
        header = f.read(64)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError("expected little-endian ELF64")
        if struct.unpack_from("<H", header, 18)[0] != ARCHITECTURES[architecture]:
            raise ValueError("wrong ELF architecture")
        offset = struct.unpack_from("<Q", header, 32)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        if size != 56 or count < 1 or count > 128 or offset + size * count > path.stat().st_size:
            raise ValueError("invalid program headers")
        f.seek(offset)
        for _ in range(count):
            if struct.unpack_from("<I", f.read(size))[0] == 3:
                raise ValueError("dynamic loader is forbidden")


def archive(output, architecture):
    files = {name: output / ("linux_" + architecture) / name for name in ("outpost", "outpost-kit")}
    files.update({"licenses/" + p.name: p for p in sorted((output / "licenses").iterdir())})
    target = output / ("outpost-linux-" + architecture + ".tar.gz")
    with target.open("xb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, path in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size = path.stat().st_size
                info.mode = 0o755 if name in ("outpost", "outpost-kit") else 0o644
                info.uid = info.gid = info.mtime = 0
                with path.open("rb") as data:
                    tar.addfile(info, data)


def build(output, architectures, revision=None):
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError("output must be a new absolute directory")
    if output.parent.resolve(strict=True) != output.parent or output.is_relative_to(ROOT):
        raise ValueError("output must be outside source and have a real existing parent")
    if not architectures or len(set(architectures)) != len(architectures) or any(a not in ARCHITECTURES for a in architectures):
        raise ValueError("unsupported, duplicate or missing architecture")
    before = source_manifest()
    source_digest = hashlib.sha256(canonical(before)).hexdigest()
    revision = revision or "dev-" + source_digest
    if not re.fullmatch(r"(?:[0-9a-f]{40}|dev-[0-9a-f]{64})", revision):
        raise ValueError("invalid revision")
    required_go = re.search(r"^go (\S+)$", (ROOT / "go.mod").read_text(), re.M).group(1)
    env = dict(os.environ, GOTOOLCHAIN="local", CGO_ENABLED="0", GOOS="linux", GOAMD64="v1", GOARM64="v8.0")
    version, goroot = subprocess.check_output(["go", "env", "GOVERSION", "GOROOT"], cwd=ROOT, env=env, text=True).splitlines()
    if version != "go" + required_go:
        raise ValueError("toolchain does not match go.mod")
    subprocess.run(["go", "mod", "verify"], cwd=ROOT, env=env, check=True)
    # No completed manifest is published if any build or source check fails.
    output.mkdir(mode=0o700)
    (output / "licenses").mkdir()
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        shutil.copyfile(ROOT / name, output / "licenses" / name)
    shutil.copyfile(Path(goroot) / "LICENSE", output / "licenses" / "GO_LICENSE")
    for name in ("Dockerfile", "compose.yaml", ".dockerignore"):
        shutil.copyfile(ROOT / "packaging" / name, output / name)
    for architecture in architectures:
        if architecture not in ARCHITECTURES:
            raise ValueError("unsupported architecture")
        folder = output / ("linux_" + architecture)
        folder.mkdir()
        target_env = dict(env, GOARCH=architecture)
        for binary in ("outpost", "outpost-kit"):
            target = folder / binary
            subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags",
                            "-s -w -buildid= -X main.revision=" + revision,
                            "-o", str(target), "./cmd/" + binary], cwd=ROOT, env=target_env, check=True)
            verify_elf(target, architecture)
            target.chmod(0o755)
        archive(output, architecture)
    if source_manifest() != before:
        raise ValueError("source changed during build; artifacts remain incomplete")
    files = {p.relative_to(output).as_posix(): {"sha256": digest_file(p), "bytes": p.stat().st_size}
             for p in sorted(output.rglob("*")) if p.is_file()}
    manifest = {"format": FORMAT, "revision": revision, "sourceDigest": source_digest,
                "source": before, "goVersion": version, "goos": "linux", "cgo": False,
                "architectures": architectures, "files": files}
    raw = json.dumps(manifest, sort_keys=True, indent=2).encode() + b"\n"
    with (output / "manifest.json").open("xb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    sums = {name: value["sha256"] for name, value in files.items()}
    sums["manifest.json"] = hashlib.sha256(raw).hexdigest()
    with (output / "SHA256SUMS").open("x", encoding="utf-8", newline="\n") as f:
        for name, value in sorted(sums.items()):
            f.write(value + "  " + name + "\n")
    return {"format": FORMAT, "revision": revision, "sourceDigest": source_digest,
            "manifestSHA256": sums["manifest.json"], "architectures": architectures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--architecture", action="append", choices=sorted(ARCHITECTURES))
    parser.add_argument("--revision", help="separately verified source commit; default binds the exact development inputs")
    args = parser.parse_args()
    result = build(args.output, args.architecture or ["amd64", "arm64"], args.revision)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
