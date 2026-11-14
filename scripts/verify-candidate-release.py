#!/usr/bin/env python3
"""Verify independently selected CI candidate bytes; never install or execute them."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("outpost_distribution_verifier", Path(__file__).with_name("verify-release.py"))
distribution = importlib.util.module_from_spec(spec)
spec.loader.exec_module(distribution)
FORMAT = "outpost-ci-candidate-1"
MAX_FILES = 64
MAX_TOTAL = 512 << 20
MAX_DOCUMENT = 2 << 20
NOTES = {"notes/en/release-notes.md", "notes/ru/release-notes.md"}


def document(path, maximum=MAX_DOCUMENT):
    with distribution.regular(path, maximum) as source:
        raw = source.read(maximum + 1)
    return raw, json.loads(raw, object_pairs_hook=distribution.unique)


def safe_name(name):
    return isinstance(name, str) and bool(re.fullmatch(r"[A-Za-z0-9_./-]{1,180}", name)) and all(p not in ("", ".", "..") for p in name.split("/"))


class BoundedTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        # Validate the fixed-size header before tarfile can allocate/read a
        # PAX, GNU-longname or sparse extension body. Our packager emits USTAR
        # regular files only; richer tar dialects are not candidate formats.
        if (self.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or not safe_name(self.name)
                or not 0 < self.size <= distribution.MAX_FILE):
            raise ValueError("unsupported or oversized candidate tar header")
        return super()._proc_member(archive)


def selection(repository, commit, run_id, attempt, architecture):
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
            or not re.fullmatch(r"[0-9a-f]{40}", commit)
            or type(run_id) is not int or not 1 <= run_id < 1 << 64
            or type(attempt) is not int or not 1 <= attempt <= 1000
            or architecture not in distribution.builder.ARCHITECTURES):
        raise ValueError("explicit repository, commit, run, attempt and native architecture required")
    return {"repository": repository, "commit": commit, "runId": run_id, "runAttempt": attempt, "nativeArchitecture": architecture}


def candidate_document(raw, expected, selected):
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or len(raw) > MAX_DOCUMENT or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("wrong independently selected candidate manifest")
    d = json.loads(raw, object_pairs_hook=distribution.unique)
    if (not isinstance(d, dict) or set(d) != {"format", "state", *selected, "distributionManifestSHA256", "sbomManifestSHA256", "files"}
            or d["format"] != FORMAT or d["state"] != "DEVELOPMENT_CANDIDATE"
            or any(type(d[k]) is not type(v) or d[k] != v for k, v in selected.items())):
        raise ValueError("candidate provenance does not match the independent selection")
    if any(not isinstance(d[k], str) or not re.fullmatch(r"[0-9a-f]{64}", d[k]) for k in ("distributionManifestSHA256", "sbomManifestSHA256")):
        raise ValueError("invalid selected inner manifest")
    files = d["files"]
    if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("invalid candidate inventory")
    total = 0
    for name, item in files.items():
        if (not safe_name(name) or not (name.startswith("distribution/") or name.startswith("sbom/") or name in NOTES)
                or not isinstance(item, dict) or set(item) != {"bytes", "sha256"}
                or type(item["bytes"]) is not int or not 0 < item["bytes"] <= distribution.MAX_FILE
                or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise ValueError("invalid candidate file")
        total += item["bytes"]
    if total + len(raw) + 65536 > MAX_TOTAL:
        raise ValueError("candidate inventory exceeds byte bound")
    return d


def verify_sbom(root, selected, manifest, expected):
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise ValueError("real absolute SBOM root required")
    raw, receipt = document(root / "sbom-manifest.json")
    if (hashlib.sha256(raw).hexdigest() != expected
            or not isinstance(receipt, dict) or set(receipt) != {"format", "revision", "sourceDigest", "manifestSHA256", "generator", "files"}
            or receipt["format"] != "outpost-distribution-sbom-1"
            or receipt["revision"] != selected["revision"] or receipt["sourceDigest"] != selected["sourceDigest"]
            or receipt["manifestSHA256"] != selected["manifestSHA256"]
            or receipt["generator"] != "cyclonedx-gomod 1.12.0"):
        raise ValueError("SBOM is not bound to the selected distribution")
    allowed = {}
    for architecture in selected["architectures"]:
        for binary in ("outpost", "outpost-kit"):
            artifact = "linux_" + architecture + "/" + binary
            allowed[artifact.replace("/", "-") + ".cdx.json"] = artifact
    records = receipt["files"]
    if not isinstance(records, dict) or set(records) != set(allowed):
        raise ValueError("incomplete or unexpected binary SBOM set")
    for name, artifact in allowed.items():
        item = records[name]
        if (not isinstance(item, dict) or set(item) != {"sha256", "artifact", "artifactSHA256"}
                or item["artifact"] != artifact or item["artifactSHA256"] != manifest["files"][artifact]["sha256"]):
            raise ValueError("SBOM artifact identity differs")
        raw, bom = document(root / name, 4 << 20)
        metadata = bom.get("metadata") if isinstance(bom, dict) else None
        component = metadata.get("component") if isinstance(metadata, dict) else None
        if (hashlib.sha256(raw).hexdigest() != item["sha256"]
                or not isinstance(bom, dict)
                or bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6"
                or not isinstance(component, dict) or component.get("version") != selected["revision"]
                or not isinstance(bom.get("components"), list)
                or not any(isinstance(x, dict) and x.get("name") == "std" and x.get("version") == manifest["goVersion"] for x in bom["components"])):
            raise ValueError("invalid binary-bound CycloneDX inventory")
    observed = set()
    for item in root.iterdir():
        if item.is_symlink() or not item.is_file():
            raise ValueError("unexpected SBOM path")
        observed.add(item.name)
    if observed != set(allowed) | {"sbom-manifest.json"}:
        raise ValueError("unlisted SBOM output")
    return observed


def verify(root, expected, selected):
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise ValueError("real absolute candidate root required")
    with distribution.regular(root / "candidate.json", MAX_DOCUMENT) as source:
        raw = source.read(MAX_DOCUMENT + 1)
    d = candidate_document(raw, expected, selected)
    observed = set()
    for base, dirs, names in os.walk(root, followlinks=False):
        if len(dirs) + len(names) > MAX_FILES:
            raise ValueError("unexpected candidate tree")
        for name in dirs:
            path = Path(base) / name
            prefix = path.relative_to(root).as_posix() + "/"
            if path.is_symlink() or not any(x.startswith(prefix) for x in d["files"]):
                raise ValueError("unlisted candidate directory")
        observed.update((Path(base) / name).relative_to(root).as_posix() for name in names)
    if observed != set(d["files"]) | {"candidate.json", "SHA256SUMS"}:
        raise ValueError("unlisted or missing candidate files")
    for name, item in d["files"].items():
        if distribution.measure(root / name) != item:
            raise ValueError("candidate bytes differ")
    sums = {name: item["sha256"] for name, item in d["files"].items()}
    sums["candidate.json"] = expected
    with distribution.regular(root / "SHA256SUMS", 65536) as source:
        if source.read(65537) != "".join(value + "  " + name + "\n" for name, value in sorted(sums.items())).encode():
            raise ValueError("candidate checksum inventory differs")
    checked = distribution.verify(root / "distribution", d["distributionManifestSHA256"])
    _, manifest = document(root / "distribution/manifest.json")
    if checked["revision"] != selected["commit"] or selected["nativeArchitecture"] not in checked["architectures"]:
        raise ValueError("compiled revision or native architecture differs")
    sbom_names = verify_sbom(root / "sbom", checked, manifest, d["sbomManifestSHA256"])
    allowed = {"distribution/" + x for x in manifest["files"]} | {"distribution/manifest.json", "distribution/SHA256SUMS"}
    allowed |= {"sbom/" + x for x in sbom_names} | NOTES
    if set(d["files"]) != allowed:
        raise ValueError("candidate contains files outside the publication allowlist")
    for name in NOTES:
        with distribution.regular(root / name, 128 << 10) as source:
            if len(source.read().decode("utf-8").strip()) < 100:
                raise ValueError("missing meaningful candidate release notes")
    return {"format": FORMAT, **selected, "manifestSHA256": expected, "distributionManifestSHA256": d["distributionManifestSHA256"],
            "state": "VERIFIED_CANDIDATE_BYTES", "runtimeAcceptance": False}


def extract(archive, output, expected, selected):
    if (not archive.is_absolute() or not output.is_absolute() or output.exists() or output.is_symlink()
            or output.parent.resolve(strict=True) != output.parent):
        raise ValueError("absolute archive and new real output directory required")
    with distribution.regular(archive, MAX_TOTAL) as source, tarfile.open(fileobj=source, mode="r:gz", tarinfo=BoundedTarInfo) as tar:
        members = []
        names = set()
        total = 0
        for member in tar:
            if (not member.isfile() or member.issparse() or member.pax_headers or not safe_name(member.name)
                    or member.name in names or not 0 < member.size <= distribution.MAX_FILE):
                raise ValueError("invalid candidate archive member")
            names.add(member.name)
            total += member.size
            if len(names) > MAX_FILES + 2 or total > MAX_TOTAL:
                raise ValueError("candidate archive exceeds bounds")
            members.append(member)
        if "candidate.json" not in names:
            raise ValueError("candidate archive has no selection document")
        member = tar.getmember("candidate.json")
        if member.size > MAX_DOCUMENT:
            raise ValueError("oversized candidate selection document")
        with tar.extractfile(member) as file:
            d = candidate_document(file.read(MAX_DOCUMENT + 1), expected, selected)
        if names != set(d["files"]) | {"candidate.json", "SHA256SUMS"}:
            raise ValueError("archive differs from the selected inventory")
        for member in members:
            maximum = MAX_DOCUMENT if member.name == "candidate.json" else 65536 if member.name == "SHA256SUMS" else d["files"][member.name]["bytes"]
            if member.size > maximum:
                raise ValueError("archive member exceeds selected size")
        output.mkdir(mode=0o700)
        for member in members:
            path = output / member.name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with tar.extractfile(member) as source, path.open("xb") as target:
                shutil.copyfileobj(source, target, 1 << 20)
            path.chmod(0o755 if re.fullmatch(r"distribution/linux_(?:amd64|arm64)/outpost(?:-kit)?", member.name) else 0o644)
    return verify(output, expected, selected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--root", type=Path)
    inputs.add_argument("--archive", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--native-architecture", required=True)
    args = parser.parse_args()
    selected = selection(args.repository, args.commit, args.run_id, args.run_attempt, args.native_architecture)
    if bool(args.archive) != bool(args.output):
        parser.error("--output is required only with --archive")
    result = extract(args.archive, args.output, args.sha256, selected) if args.archive else verify(args.root, args.sha256, selected)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
