#!/usr/bin/env python3
"""Publish only synthetic screenshots and sanitized successful browser results."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("outpost_candidate_package", Path(__file__).with_name("package-release.py"))
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)
verifier = packager.verifier
SCREENSHOTS = {"desktop-en.png", "desktop-viewport.png", "narrow-ru.png", "narrow-viewport.png", "text-200.png"}
ROOT = Path(__file__).resolve().parents[1]


def package(root, output, archive, selected):
    for target in (output, archive):
        if (not target.is_absolute() or target.exists() or target.is_symlink()
                or target.parent.resolve(strict=True) != target.parent or target.is_relative_to(root)):
            raise ValueError("new separate visual-evidence output required")
    if not root.is_absolute() or root.resolve(strict=True) != root or archive.is_relative_to(output):
        raise ValueError("real browser input and separate archive required")
    _, result = verifier.document(root / "result.json", 128 << 10)
    names = re.findall(r'await test\(\s*"([^"\n]+)",', (ROOT / "scripts/browser/check.mjs").read_text())
    if (not isinstance(result, dict) or result.get("state") != "PASS" or result.get("cases") != names
            or not 1 <= len(names) <= 128 or len(set(names)) != len(names)):
        raise ValueError("browser result does not cover the current declared journeys")
    for language in ("en", "ru"):
        _, axe = verifier.document(root / ("axe-" + language + ".json"), 16 << 20)
        if not isinstance(axe, dict) or axe.get("violations") != []:
            raise ValueError("browser accessibility evidence did not pass")
    output.mkdir(mode=0o700)
    files = {}
    dimensions = {}
    for name in sorted(SCREENSHOTS):
        with verifier.distribution.regular(root / name, 16 << 20) as source:
            header = source.read(24)
            if len(header) != 24 or header[:8] != b"\x89PNG\r\n\x1a\n" or header[12:16] != b"IHDR":
                raise ValueError("invalid screenshot header")
            width, height = struct.unpack(">II", header[16:24])
            if not 1 <= width <= 8192 or not 1 <= height <= 100000:
                raise ValueError("screenshot dimensions exceed bounds")
            dimensions[name] = {"width": width, "height": height}
            source.seek(0)
            with (output / name).open("xb") as target:
                shutil.copyfileobj(source, target, 1 << 20)
        files[name] = verifier.distribution.measure(output / name)
    source_files = ["scripts/browser/check.mjs", "scripts/browser/package.json", "scripts/browser/package-lock.json", "internal/management/ui_browser_linux_test.go"]
    source_files += sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "internal/management/ui").iterdir() if p.is_file())
    evidence = {"format": "outpost-browser-visual-evidence-1", **selected, "state": "AUTOMATED_PASS_VISUAL_REVIEW_PENDING",
                "cases": names, "axeViolations": {"en": 0, "ru": 0}, "screenshots": files, "dimensions": dimensions,
                "source": {name: verifier.distribution.measure(ROOT / name)["sha256"] for name in source_files},
                "manualKeyboardAcceptance": False, "productAcceptance": False}
    raw = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode()
    (output / "visual-evidence.json").write_bytes(raw)
    # No fixture directory, certificates, ready.json, logs, browser storage or
    # raw axe DOM/URL fields are traversed or included in this allowlist.
    packager.write_archive(output, SCREENSHOTS | {"visual-evidence.json"}, archive)
    return {"format": evidence["format"], **selected, "manifestSHA256": hashlib.sha256(raw).hexdigest(),
            "archiveSHA256": verifier.distribution.measure(archive)["sha256"], "cases": len(names), "manualAcceptance": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    args = parser.parse_args()
    selected = verifier.selection(args.repository, args.commit, args.run_id, args.run_attempt, "amd64")
    print(json.dumps(package(args.root, args.output, args.archive, selected), sort_keys=True))


if __name__ == "__main__":
    main()
