#!/usr/bin/env python3
"""Generate CycloneDX BOMs for a verified Outpost distribution on Linux."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("outpost_verify", Path(__file__).with_name("verify-release.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

TOOL_VERSION = "1.12.0"
TOOL_ARCHIVES = {
    "x86_64": (9930001, "004b9f5cc595b797fb5423e2ae4c97bcf0f18c712ed2faee1640b09e5efd6d15"),
    "aarch64": (9179402, "b6dd6424755e61c0f7fcd36074fbb78798a33c52f1bd35dd177ba62eccadf404"),
}


def extract_generator(archive, destination):
    if platform.system() != "Linux" or platform.machine() not in TOOL_ARCHIVES:
        raise ValueError("unsupported native SBOM generator platform")
    size, digest = TOOL_ARCHIVES[platform.machine()]
    with verifier.regular(archive, size) as source:
        raw = source.read(size + 1)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("CycloneDX generator archive digest mismatch")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as source:
        member = source.getmember("cyclonedx-gomod")
        if not member.isfile() or not 0 < member.size <= 32 << 20:
            raise ValueError("invalid CycloneDX generator member")
        with source.extractfile(member) as binary, destination.open("xb") as output:
            shutil.copyfileobj(binary, output)
    destination.chmod(0o700)


def generate(root, manifest_hash, generator_archive, output):
    if (not output.is_absolute() or output.parent.resolve(strict=True) != output.parent
            or output.is_relative_to(root) or output.exists() or output.is_symlink()):
        raise ValueError("SBOM output must be a new absolute directory outside the distribution")
    selected = verifier.verify(root, manifest_hash)
    with verifier.regular(root / "manifest.json", 2 << 20) as source:
        raw = source.read((2 << 20) + 1)
    if hashlib.sha256(raw).hexdigest() != manifest_hash:
        raise ValueError("selected manifest changed")
    manifest = json.loads(raw, object_pairs_hook=verifier.unique)
    records = {}
    offline = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", GOENV="off", GOWORK="off")
    with tempfile.TemporaryDirectory(prefix="outpost-sbom-") as scratch:
        work = Path(scratch)
        generator = work / "cyclonedx-gomod"
        extract_generator(generator_archive, generator)
        output.mkdir(mode=0o700)
        for architecture in selected["architectures"]:
            for name in ("outpost", "outpost-kit"):
                artifact = "linux_" + architecture + "/" + name
                binary = work / name
                with verifier.regular(root / artifact, verifier.MAX_FILE) as source, binary.open("wb") as target:
                    shutil.copyfileobj(source, target)
                if verifier.measure(binary) != manifest["files"][artifact]:
                    raise ValueError("selected binary changed before SBOM generation")
                binary.chmod(0o500)
                generated = subprocess.run(
                    [str(generator), "bin", "-json", "-output-version", "1.6", "-noserial", "-notimestamp",
                     "-std", "-version", selected["revision"], str(binary)],
                    env=offline, stdout=subprocess.PIPE, check=True, timeout=45,
                ).stdout
                binary.unlink()
                if not 0 < len(generated) <= 4 << 20:
                    raise ValueError("invalid SBOM size")
                bom = json.loads(generated, object_pairs_hook=verifier.unique)
                component = bom.get("metadata", {}).get("component", {})
                standard_library = any(item.get("name") == "std" and item.get("version") == manifest["goVersion"]
                                       for item in bom.get("components", []))
                if (bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6"
                        or component.get("version") != selected["revision"] or not standard_library):
                    raise ValueError("invalid CycloneDX output")
                inventory = artifact.replace("/", "-") + ".cdx.json"
                with (output / inventory).open("xb") as f:
                    f.write(generated)
                records[inventory] = {
                    "sha256": hashlib.sha256(generated).hexdigest(),
                    "artifact": artifact,
                    "artifactSHA256": manifest["files"][artifact]["sha256"],
                }
    receipt = {"format": "outpost-distribution-sbom-1", "revision": selected["revision"],
               "sourceDigest": selected["sourceDigest"], "manifestSHA256": manifest_hash,
               "generator": "cyclonedx-gomod " + TOOL_VERSION, "files": records}
    with (output / "sbom-manifest.json").open("x", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2, sort_keys=True)
        f.write("\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--generator-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(generate(args.root, args.manifest_sha256, args.generator_archive, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
