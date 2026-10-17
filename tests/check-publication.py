#!/usr/bin/env python3
"""Conservative pre-publication check of the actual Git index, never secret values."""
from pathlib import Path
import re,subprocess
root=Path(__file__).resolve().parents[1]
files=subprocess.check_output(["git","ls-files","-z"],cwd=root).decode().split("\0")
patterns=[
 re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
 re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}"),
 re.compile(rb"github_pat_[A-Za-z0-9_]{30,}"),
]
for name in filter(None,files):
 if any(part in ("vendor","release","secrets","evidence",".git") for part in Path(name).parts) or name==".env":
  raise SystemExit("Private/generated path staged: "+name)
 data=subprocess.check_output(["git","show",":"+name],cwd=root)
 if len(data)>1024*1024: raise SystemExit("Unexpected large staged file: "+name)
 if any(pattern.search(data) for pattern in patterns):
  raise SystemExit("Potential credential material in: "+name)
print("Git index checked: no generated/private paths or recognized credential material")
