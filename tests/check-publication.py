#!/usr/bin/env python3
"""Check indexed publication files without printing potentially private values."""
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[1]
files = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
checks = {
    "credential material": [
        re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
        re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}"),
        re.compile(rb"github_pat_[A-Za-z0-9_]{30,}"),
    ],
    "personal filesystem path": [
        re.compile(rb"\b[A-Z]:[\\/](?:Users|Documents and Settings|SynologyDrive)[\\/]", re.I),
        re.compile(rb"(?:~|/(?:home|Users)/[^/\s]+)/"),
    ],
}
for name in filter(None, files):
    if any(part in ("vendor", "release", "secrets", "evidence", ".git") for part in Path(name).parts) or name == ".env":
        raise SystemExit("Private/generated path staged: " + name)
    data = subprocess.check_output(["git", "show", ":" + name], cwd=root)
    if len(data) > 1024 * 1024:
        raise SystemExit("Unexpected large staged file: " + name)
    for category, patterns in checks.items():
        if any(pattern.search(data) for pattern in patterns):
            raise SystemExit("Potential " + category + " in: " + name)
print("Git index checked: no generated/private paths, recognized credentials or personal filesystem paths")
