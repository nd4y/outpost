#!/usr/bin/env python3
"""Record independent candidate selection outside the uploaded archive."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("outpost_candidate_verifier", Path(__file__).with_name("verify-candidate-release.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    _, receipt = verifier.document(args.input)
    selected = verifier.selection(receipt["repository"], receipt["commit"], receipt["runId"], receipt["runAttempt"], receipt["nativeArchitecture"])
    if (receipt["format"] not in (verifier.FORMAT, "outpost-browser-visual-evidence-1")
            or not 1 <= args.artifact_id < 1 << 64
            or any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in (args.artifact_sha256, receipt["manifestSHA256"], receipt["archiveSHA256"]))):
        raise ValueError("invalid independent artifact selection receipt")
    record = {"format": "outpost-ci-artifact-selection-1", "kind": receipt["format"], **selected,
              "manifestSHA256": receipt["manifestSHA256"], "archiveSHA256": receipt["archiveSHA256"],
              "artifactId": args.artifact_id, "artifactSHA256": args.artifact_sha256,
              "artifactURL": "https://github.com/" + selected["repository"] + "/actions/runs/" + str(selected["runId"]) + "/artifacts/" + str(args.artifact_id)}
    with args.summary.open("a", encoding="utf-8") as output:
        output.write("\n### Downloadable development candidate\n\n")
        output.write("[Artifact](" + record["artifactURL"] + ")\n\n```json\n" + json.dumps(record, indent=2, sort_keys=True) + "\n```\n")
        output.write("\nRetain this selection outside the download. Verified bytes, native runtime checks and whole-product acceptance are separate.\n")
    print("CANDIDATE_SELECTION " + json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
