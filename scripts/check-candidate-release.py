#!/usr/bin/env python3
"""Adversarial checks on a real selected CI candidate; originals stay unchanged."""
import argparse
import base64
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

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("outpost_candidate_package", Path(__file__).with_name("package-release.py"))
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)
verifier = packager.verifier


def select(root):
    _, d = verifier.document(root / "candidate.json")
    return verifier.selection(d["repository"], d["commit"], d["runId"], d["runAttempt"], d["nativeArchitecture"])


def clone(root, work):
    target = Path(tempfile.mkdtemp(prefix="candidate-case-", dir=work)) / "copy"
    # Test outputs can be separate bind mounts on the same physical HDD.
    # Independent copies also keep adversarial edits away from the original.
    shutil.copytree(root, target, copy_function=shutil.copyfile)
    return target


def replace(path, raw):
    temporary = path.with_name(path.name + ".replacement")
    temporary.write_bytes(raw)
    os.replace(temporary, path)


def reject(action):
    try:
        action()
    except (ValueError, OSError, tarfile.TarError):
        return
    raise AssertionError("unproven candidate was accepted")


def test_selected_candidate_and_archive_roundtrip(root, digest, work):
    selected = select(root)
    result = verifier.verify(root, digest, selected)
    assert result["state"] == "VERIFIED_CANDIDATE_BYTES" and result["runtimeAcceptance"] is False
    archive = work / "roundtrip.tar.gz"
    packager.write_archive(root, set(verifier.document(root / "candidate.json")[1]["files"]) | {"candidate.json", "SHA256SUMS"}, archive)
    output = work / "roundtrip"
    assert verifier.extract(archive, output, digest, selected) == result
    for architecture in ("amd64", "arm64"):
        binary = output / "distribution" / ("linux_" + architecture) / "outpost"
        if binary.exists(): assert binary.stat().st_mode & 0o777 == 0o755
    second = work / "roundtrip2.tar.gz"
    packager.write_archive(root, set(verifier.document(root / "candidate.json")[1]["files"]) | {"candidate.json", "SHA256SUMS"}, second)
    assert hashlib.sha256(archive.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()


def test_independent_commit_run_architecture_and_digest_selection(root, digest, work):
    selected = select(root)
    reject(lambda: verifier.verify(root, "0" * 64, selected))
    for name, wrong in {"commit": "0" * 40, "runId": selected["runId"] + 1, "runAttempt": selected["runAttempt"] + 1,
                        "repository": "example/other", "nativeArchitecture": "arm64" if selected["nativeArchitecture"] == "amd64" else "amd64"}.items():
        changed = dict(selected, **{name: wrong})
        reject(lambda: verifier.verify(root, digest, changed))


def test_changed_unlisted_and_symlinked_candidate_files(root, digest, work):
    selected = select(root)
    for kind in ("changed", "unlisted", "link"):
        target = clone(root, work)
        note = target / "notes/en/release-notes.md"
        if kind == "changed": replace(note, b"changed candidate note")
        elif kind == "unlisted": (target / "unexpected.key").write_bytes(b"synthetic fixture marker, never upload")
        else:
            note.unlink()
            note.symlink_to(root / "notes/en/release-notes.md")
        reject(lambda: verifier.verify(target, digest, selected))


def test_sbom_and_binary_binding_cannot_be_relabelled(root, digest, work):
    target = clone(root, work)
    sbom = target / "sbom/sbom-manifest.json"
    raw, d = verifier.document(sbom)
    first = next(iter(d["files"].values()))
    first["artifactSHA256"] = "0" * 64
    # Even with a freshly selected outer digest, the inner binary binding is
    # checked. A checksum inventory alone cannot turn this into a valid SBOM.
    replace(sbom, (json.dumps(d, indent=2, sort_keys=True) + "\n").encode())
    _, candidate = verifier.document(target / "candidate.json")
    candidate["files"]["sbom/sbom-manifest.json"] = verifier.distribution.measure(sbom)
    candidate["sbomManifestSHA256"] = candidate["files"]["sbom/sbom-manifest.json"]["sha256"]
    new_digest = rebind(target, candidate)
    reject(lambda: verifier.verify(target, new_digest, select(root)))
    assert raw != sbom.read_bytes()


def rebind(root, d):
    raw = (json.dumps(d, indent=2, sort_keys=True) + "\n").encode()
    replace(root / "candidate.json", raw)
    digest = hashlib.sha256(raw).hexdigest()
    sums = {name: value["sha256"] for name, value in d["files"].items()}
    sums["candidate.json"] = digest
    replace(root / "SHA256SUMS", "".join(value + "  " + name + "\n" for name, value in sorted(sums.items())).encode())
    return digest


def test_duplicate_json_and_invalid_inventory_are_rejected(root, digest, work):
    raw, d = verifier.document(root / "candidate.json")
    duplicate = b'{"format":"duplicate",' + raw.lstrip()[1:]
    reject(lambda: verifier.candidate_document(duplicate, hashlib.sha256(duplicate).hexdigest(), select(root)))
    for wrong in (None, [], {"../escape": {"bytes": 1, "sha256": "0" * 64}},
                  {"distribution/file": {"bytes": True, "sha256": "0" * 64}},
                  {"distribution/file": {"bytes": 1, "sha256": []}}):
        changed = dict(d, files=wrong)
        value = json.dumps(changed).encode()
        reject(lambda: verifier.candidate_document(value, hashlib.sha256(value).hexdigest(), select(root)))


def test_tar_paths_links_and_duplicate_members_are_rejected(root, digest, work):
    selected = select(root)
    for i, kind in enumerate(("../escape", "/absolute", "symlink", "hardlink", "duplicate")):
        archive = work / ("bad-member-" + str(i) + ".tar.gz")
        with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
            member = tarfile.TarInfo(kind if kind.startswith(("/", ".")) else "candidate.json")
            if kind in ("symlink", "hardlink"):
                member.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                member.linkname = "../outside"
                tar.addfile(member)
            else:
                raw = (root / "candidate.json").read_bytes()
                member.size = len(raw)
                tar.addfile(member, io.BytesIO(raw))
                if kind == "duplicate": tar.addfile(member, io.BytesIO(raw))
        output = work / ("rejected-member-" + str(i))
        reject(lambda: verifier.extract(archive, output, digest, selected))
        assert not output.exists()


def test_special_tar_headers_are_refused_before_reading_bodies(root, digest, work):
    for kind in (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_SPARSE, tarfile.REGTYPE):
        header = tarfile.TarInfo("oversized-header")
        header.type, header.size = kind, verifier.distribution.MAX_FILE + 1
        archive = work / ("header-" + kind.hex() + ".tar.gz")
        # No extension/payload body is provided. EOF from trying to consume it
        # must fail this test: the fixed header must be refused first.
        with gzip.open(archive, "wb") as output: output.write(header.tobuf(format=tarfile.USTAR_FORMAT))
        try:
            verifier.extract(archive, work / ("header-output-" + kind.hex()), digest, select(root))
        except ValueError as error:
            assert str(error) == "unsupported or oversized candidate tar header", str(error)
        else: raise AssertionError("extension body was not refused at its fixed header")


def test_tar_member_count_and_aggregate_size_are_bounded(root, digest, work):
    archive = work / "many-headers.tar.gz"
    with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for i in range(verifier.MAX_FILES + 3):
            member = tarfile.TarInfo("distribution/file" + str(i)); member.size = 1
            tar.addfile(member, io.BytesIO(b"x"))
    output = work / "many-headers"
    reject(lambda: verifier.extract(archive, output, digest, select(root)))
    assert not output.exists()
    _, d = verifier.document(root / "candidate.json")
    d["files"] = {"distribution/file" + str(i): {"bytes": verifier.distribution.MAX_FILE, "sha256": "0" * 64} for i in range(5)}
    raw = json.dumps(d).encode()
    reject(lambda: verifier.candidate_document(raw, hashlib.sha256(raw).hexdigest(), select(root)))


def test_actual_verifier_cli_uses_independent_selection(root, digest, work):
    selected = select(root)
    command = [sys.executable, str(Path(__file__).with_name("verify-candidate-release.py")), "--root", str(root), "--sha256", digest,
               "--repository", selected["repository"], "--commit", selected["commit"], "--run-id", str(selected["runId"]),
               "--run-attempt", str(selected["runAttempt"]), "--native-architecture", selected["nativeArchitecture"]]
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=45)
    assert json.loads(result.stdout)["state"] == "VERIFIED_CANDIDATE_BYTES"
    bad = command.copy(); bad[bad.index("--run-id") + 1] = str(selected["runId"] + 1)
    assert subprocess.run(bad, capture_output=True, timeout=45).returncode != 0


def browser_fixture(work):
    spec = importlib.util.spec_from_file_location("outpost_browser_package", Path(__file__).with_name("package-browser-evidence.py"))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    folder = Path(tempfile.mkdtemp(prefix="browser-allowlist-", dir=work))
    import re
    names = re.findall(r'await test\(\s*"([^"\n]+)",', (module.ROOT / "scripts/browser/check.mjs").read_text())
    (folder / "result.json").write_text(json.dumps({"state": "PASS", "cases": names, "privateExtra": "SYNTHETIC_PRIVATE_SENTINEL"}))
    for language in ("en", "ru"):
        (folder / ("axe-" + language + ".json")).write_text(json.dumps({"violations": [], "url": "https://synthetic-private.invalid"}))
    # One-pixel public PNGs are packaging inputs only, never UI acceptance.
    png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j3U8AAAAASUVORK5CYII=")
    for name in module.SCREENSHOTS: (folder / name).write_bytes(png)
    (folder / "owner.key").write_text("SYNTHETIC_PRIVATE_SENTINEL")
    (folder / "ready.json").write_text("SYNTHETIC_PRIVATE_SENTINEL")
    return module, folder


def test_browser_publication_allowlist_excludes_private_fixture_files(root, digest, work):
    module, folder = browser_fixture(work)
    output, archive = work / "visual-allowlist", work / "visual-allowlist.tar.gz"
    receipt = module.package(folder, output, archive, select(root))
    assert receipt["manualAcceptance"] is False
    assert {p.name for p in output.iterdir()} == module.SCREENSHOTS | {"visual-evidence.json"}
    with tarfile.open(archive) as tar:
        assert set(tar.getnames()) == module.SCREENSHOTS | {"visual-evidence.json"}
        for member in tar:
            assert b"SYNTHETIC_PRIVATE_SENTINEL" not in tar.extractfile(member).read()
    evidence = json.loads((output / "visual-evidence.json").read_text())
    assert evidence["manualKeyboardAcceptance"] is False and evidence["productAcceptance"] is False


def test_browser_publication_refuses_failed_stale_and_linked_inputs(root, digest, work):
    for i, kind in enumerate(("failed", "stale", "link")):
        module, folder = browser_fixture(work)
        if kind in ("failed", "stale"):
            result = json.loads((folder / "result.json").read_text())
            if kind == "failed": result["state"] = "FAIL"
            else: result["cases"].pop()
            (folder / "result.json").write_text(json.dumps(result))
        else:
            screen = folder / "desktop-en.png"; screen.unlink(); screen.symlink_to(folder / "owner.key")
        reject(lambda: module.package(folder, work / ("bad-visual-" + str(i)), work / ("bad-visual-" + str(i) + ".tar.gz"), select(root)))


TESTS = [test_selected_candidate_and_archive_roundtrip, test_independent_commit_run_architecture_and_digest_selection,
         test_changed_unlisted_and_symlinked_candidate_files, test_sbom_and_binary_binding_cannot_be_relabelled,
         test_duplicate_json_and_invalid_inventory_are_rejected, test_tar_paths_links_and_duplicate_members_are_rejected,
         test_special_tar_headers_are_refused_before_reading_bodies, test_tar_member_count_and_aggregate_size_are_bounded,
         test_actual_verifier_cli_uses_independent_selection,
         test_browser_publication_allowlist_excludes_private_fixture_files,
         test_browser_publication_refuses_failed_stale_and_linked_inputs]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    if (not args.work.is_absolute() or args.work.exists() or args.work.is_symlink()
            or args.work.parent.resolve(strict=True) != args.work.parent or args.work.is_relative_to(args.root)):
        raise ValueError("new separate test directory required")
    selected = select(args.root)
    verifier.verify(args.root, args.sha256, selected)
    args.work.mkdir(mode=0o700)
    results = []
    for test in TESTS:
        test(args.root, args.sha256, args.work)
        results.append({"name": test.__name__, "state": "PASS"})
        print("PASS " + test.__name__, flush=True)
    verifier.verify(args.root, args.sha256, selected)
    print(json.dumps({"checks": results, "originalPreserved": True, "runtimeAcceptance": False}, sort_keys=True))


if __name__ == "__main__":
    main()
