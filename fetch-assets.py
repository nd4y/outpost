#!/usr/bin/env python3
"""Fetch pinned upstream archives; validate before replacing any local archive."""
import hashlib,json,os
from pathlib import Path
from urllib.request import Request,urlopen

root=Path(__file__).resolve().parent
manifest=json.loads((root/"sources.lock.json").read_text())
vendor=root/"vendor"
vendor.mkdir(exist_ok=True)
items=[manifest["rsync"],manifest["netbird"]["amd64"],manifest["netbird"]["arm64"]]
for item in items:
    target=vendor/item["url"].rsplit("/",1)[1]
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest()==item["sha256"]:
        print("verified",target.name)
        continue
    temporary=target.with_suffix(target.suffix+".download")
    with urlopen(Request(item["url"],headers={"User-Agent":"Outpost-build"}),timeout=45) as response, temporary.open("wb") as output:
        while chunk:=response.read(1024*1024):
            output.write(chunk)
    if hashlib.sha256(temporary.read_bytes()).hexdigest()!=item["sha256"]:
        temporary.unlink()
        raise SystemExit("CHECKSUM MISMATCH: "+target.name)
    os.replace(temporary,target)
    print("verified",target.name)
