#!/usr/bin/env python3
"""Bounded artifact checks on a selected real build; no image deployment."""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("outpost_verify_release", Path(__file__).with_name("verify-release.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
builder = verifier.builder


def replace(path, data):
    # Clones use hardlinks only for immutable inputs. Replace, never truncate,
    # so an adversarial fixture cannot corrupt the selected original build.
    temporary = path.with_name(path.name + ".replacement")
    with temporary.open("xb") as f:
        f.write(data)
    os.replace(temporary, path)


def clone(root, work):
    target = Path(tempfile.mkdtemp(prefix="artifact-case-", dir=work)) / "copy"
    shutil.copytree(root, target, copy_function=os.link)
    return target


def rebind(root):
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for name in manifest["files"]:
        manifest["files"][name] = verifier.measure(root / name)
    raw = json.dumps(manifest, sort_keys=True, indent=2).encode() + b"\n"
    replace(root / "manifest.json", raw)
    sums = {name: value["sha256"] for name, value in manifest["files"].items()}
    digest = hashlib.sha256(raw).hexdigest()
    sums["manifest.json"] = digest
    replace(root / "SHA256SUMS", "".join(value + "  " + name + "\n" for name, value in sorted(sums.items())).encode())
    return digest


def rejected(action):
    try:
        action()
    except (ValueError, OSError, tarfile.TarError):
        return
    raise AssertionError("invalid distribution accepted")


def test_selected_build_and_archives(root, digest, work):
    result = verifier.verify(root, digest)
    assert result["state"] == "VERIFIED_ARTIFACTS" and result["runtimeAcceptance"] is False
    assert result["architectures"] == ["amd64", "arm64"]


def test_wrong_manifest_never_selects_archive(root, digest, work):
    rejected(lambda: verifier.verify(root, "0" * 64))


def test_changed_payload_is_rejected(root, digest, work):
    copy = clone(root, work)
    path = copy / "linux_amd64/outpost"
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    replace(path, data)
    rejected(lambda: verifier.verify(copy, digest))


def test_wrong_elf_architecture_is_rejected_even_with_new_checksums(root, digest, work):
    copy = clone(root, work)
    path = copy / "linux_amd64/outpost"
    data = bytearray(path.read_bytes())
    data[18:20] = (183).to_bytes(2, "little")
    replace(path, data)
    selected = rebind(copy)
    rejected(lambda: verifier.verify(copy, selected))


def test_symlink_and_unlisted_files_are_rejected(root, digest, work):
    copy = clone(root, work)
    extra = copy / "unlisted-private-material"
    extra.write_bytes(b"synthetic unlisted file")
    rejected(lambda: verifier.verify(copy, digest))
    extra.unlink()
    link = copy / "licenses/GO_LICENSE"
    link.unlink()
    link.symlink_to(root / "licenses/GO_LICENSE")
    rejected(lambda: verifier.verify(copy, digest))


def test_archive_missing_dependency_and_path_injection_are_rejected(root, digest, work):
    for injected in (False, True):
        copy = clone(root, work)
        source = root / "outpost-linux-amd64.tar.gz"
        result = io.BytesIO()
        with gzip.GzipFile(fileobj=result, mode="wb", mtime=0, filename="") as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as target:
                with tarfile.open(source, "r:gz") as original:
                    for member in original:
                        if member.name == "licenses/GO_LICENSE":
                            if not injected:
                                continue
                            member.name = "../outside"
                        target.addfile(member, original.extractfile(member))
        replace(copy / source.name, result.getvalue())
        selected = rebind(copy)
        rejected(lambda: verifier.verify(copy, selected))


def test_archive_generation_is_reproducible(root, digest, work):
    copy = clone(root, work)
    for architecture in ("amd64", "arm64"):
        target = copy / ("outpost-linux-" + architecture + ".tar.gz")
        expected = builder.digest_file(target)
        target.unlink()
        builder.archive(copy, architecture)
        assert builder.digest_file(target) == expected
    verifier.verify(copy, digest)


def test_output_collision_and_failed_build_keep_original(root, digest, work):
    rejected(lambda: builder.build(root, ["amd64"]))
    rejected(lambda: builder.build(builder.ROOT / "must-not-create", ["amd64"]))
    target = work / "failed-build"
    original_run = builder.subprocess.run

    def interrupted(args, **kwargs):
        if args[:2] == ["go", "build"]:
            raise OSError("synthetic compiler interruption")
        return original_run(args, **kwargs)

    with mock.patch.object(builder.subprocess, "run", side_effect=interrupted):
        rejected(lambda: builder.build(target, ["amd64"]))
    assert target.is_dir() and not (target / "manifest.json").exists()
    assert not (target / "SHA256SUMS").exists()
    verifier.verify(root, digest)


def test_build_cli_emits_one_json_receipt(root, digest, work):
    target = work / "cli-build"
    result = subprocess.run([sys.executable, str(Path(__file__).with_name("build-release.py")),
                             "--output", str(target), "--architecture", "amd64"],
                            capture_output=True, text=True, timeout=90, check=True)
    # Parse the entire stdout, not a last line that could hide diagnostics or
    # an invalid receipt stream. Compiler/module messages belong to stderr.
    receipt = json.loads(result.stdout)
    assert receipt["architectures"] == ["amd64"] and receipt["format"] == builder.FORMAT
    assert "all modules verified" not in result.stdout
    verified = verifier.verify(target, receipt["manifestSHA256"])
    assert verified["sourceDigest"] == receipt["sourceDigest"]
    verifier.verify(root, digest)


TESTS = [test_selected_build_and_archives, test_wrong_manifest_never_selects_archive,
         test_changed_payload_is_rejected, test_wrong_elf_architecture_is_rejected_even_with_new_checksums,
         test_symlink_and_unlisted_files_are_rejected,
         test_archive_missing_dependency_and_path_injection_are_rejected,
         test_archive_generation_is_reproducible, test_output_collision_and_failed_build_keep_original,
         test_build_cli_emits_one_json_receipt]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    if not args.work.is_absolute() or args.work.exists() or args.work.parent.resolve(strict=True) != args.work.parent or args.work.is_relative_to(args.root):
        raise ValueError("new separate absolute test directory required")
    verifier.verify(args.root, args.manifest_sha256)
    args.work.mkdir(mode=0o700)
    checks = []
    for test in TESTS:
        test(args.root, args.manifest_sha256, args.work)
        checks.append({"name": test.__name__, "result": "PASS"})
        print("PASS " + test.__name__, flush=True)
    verifier.verify(args.root, args.manifest_sha256)
    print(json.dumps({"checks": checks, "sourcePreserved": True, "runtimeAcceptance": False}, sort_keys=True))


if __name__ == "__main__":
    main()
