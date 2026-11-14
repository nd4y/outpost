#!/usr/bin/env python3
"""Package allowlisted development candidates; never create a release or deploy."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tarfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("outpost_candidate_verifier", Path(__file__).with_name("verify-candidate-release.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
ROOT = Path(__file__).resolve().parents[1]


def write_archive(root, names, archive):
    with archive.open("xb") as file, gzip.GzipFile(filename="", mode="wb", fileobj=file, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name in sorted(names):
                if not verifier.safe_name(name):
                    raise ValueError("unsafe publication filename")
                path = root / name
                info = tarfile.TarInfo(name)
                info.size = path.stat().st_size
                info.mode = path.stat().st_mode & 0o777
                with verifier.distribution.regular(path, verifier.distribution.MAX_FILE) as source:
                    tar.addfile(info, source)


def package(root, manifest_hash, sbom, output, archive, selected):
    for target in (output, archive):
        if (not target.is_absolute() or target.exists() or target.is_symlink()
                or target.parent.resolve(strict=True) != target.parent or target.is_relative_to(root) or target.is_relative_to(sbom)):
            raise ValueError("new separate real absolute candidate output required")
    if archive.is_relative_to(output):
        raise ValueError("archive must remain outside candidate contents")
    checked = verifier.distribution.verify(root, manifest_hash)
    _, manifest = verifier.document(root / "manifest.json")
    if checked["revision"] != selected["commit"] or selected["nativeArchitecture"] not in checked["architectures"]:
        raise ValueError("candidate compilation does not match the selected commit")
    sbom_raw, _ = verifier.document(sbom / "sbom-manifest.json")
    sbom_hash = hashlib.sha256(sbom_raw).hexdigest()
    sbom_names = verifier.verify_sbom(sbom, checked, manifest, sbom_hash)
    inputs = {"distribution/" + name: root / name for name in set(manifest["files"]) | {"manifest.json", "SHA256SUMS"}}
    inputs.update({"sbom/" + name: sbom / name for name in sbom_names})
    inputs.update({"notes/" + lang + "/release-notes.md": ROOT / "docs" / lang / "release-notes.md" for lang in ("en", "ru")})
    output.mkdir(mode=0o700)
    records = {}
    for name, source in sorted(inputs.items()):
        target = output / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        maximum = 128 << 10 if name in verifier.NOTES else verifier.distribution.MAX_FILE
        with verifier.distribution.regular(source, maximum) as original, target.open("xb") as destination:
            shutil.copyfileobj(original, destination, 1 << 20)
        target.chmod(0o755 if source.name in ("outpost", "outpost-kit") else 0o644)
        records[name] = verifier.distribution.measure(target)
    candidate = {"format": verifier.FORMAT, "state": "DEVELOPMENT_CANDIDATE", **selected,
                 "distributionManifestSHA256": manifest_hash, "sbomManifestSHA256": sbom_hash, "files": records}
    raw = (json.dumps(candidate, indent=2, sort_keys=True) + "\n").encode()
    digest = hashlib.sha256(raw).hexdigest()
    (output / "candidate.json").write_bytes(raw)
    sums = {name: item["sha256"] for name, item in records.items()}
    sums["candidate.json"] = digest
    (output / "SHA256SUMS").write_text("".join(value + "  " + name + "\n" for name, value in sorted(sums.items())), encoding="utf-8")
    receipt = verifier.verify(output, digest, selected)
    write_archive(output, set(records) | {"candidate.json", "SHA256SUMS"}, archive)
    archive_hash = hashlib.sha256()
    with verifier.distribution.regular(archive, verifier.MAX_TOTAL) as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            archive_hash.update(block)
    receipt.update({"archiveSHA256": archive_hash.hexdigest(), "archiveBytes": archive.stat().st_size})
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--native-architecture", required=True)
    args = parser.parse_args()
    selected = verifier.selection(args.repository, args.commit, args.run_id, args.run_attempt, args.native_architecture)
    print(json.dumps(package(args.root, args.manifest_sha256, args.sbom, args.output, args.archive, selected), sort_keys=True))


if __name__ == "__main__":
    main()
