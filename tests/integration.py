#!/usr/bin/env python3
"""Offline data-plane and hardening checks; no real setup keys or NAS data."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid

IMAGE = os.environ.get("OUTPOST_TEST_IMAGE", "outpost-hardened:0.2.0")
PREFIX = "outpost-test-" + uuid.uuid4().hex[:10]
ROOT = Path(tempfile.mkdtemp(prefix=PREFIX+"-"))
VOLUME = PREFIX+"-state"
PASSWORD = secrets.token_urlsafe(32)
ENV = dict(os.environ, RSYNC_PASSWORD=PASSWORD)
checks = []
containers = []

def call(args, good=True, **kwargs):
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, **kwargs)
    if good and p.returncode:
        raise AssertionError(f"command failed ({p.returncode}): {args[0:4]}\n{p.stderr}\n{p.stdout}")
    return p

def docker(*args, **kwargs):
    return call(["docker", *args], **kwargs)

def check(label, ok):
    if not ok:
        raise AssertionError(label)
    checks.append(label)
    print("PASS", label, flush=True)

def start(name, mode="receiver-local", extra=(), tmpdata=False):
    containers.append(name)
    args = ["run", "-d", "--name", name, "--user", "65532:65532",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", "128", "--memory", "1g", "--memory-swap", "1g", "--cpu-shares", "256",
            "--mount", ("type=tmpfs,dst=/data,tmpfs-size=524288,tmpfs-mode=0777" if tmpdata else f"type=bind,src={ROOT/'data'},dst=/data"),
            "--mount", f"type=volume,src={VOLUME},dst=/state",
            "--tmpfs", "/run/outpost:rw,noexec,nosuid,nodev,size=4m,uid=65532,gid=65532,mode=0700",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700",
            "-e", "OUTPOST_RSYNC_PASSWORD", *extra, IMAGE, mode]
    env = dict(os.environ, OUTPOST_RSYNC_PASSWORD=PASSWORD)
    return docker(*args, env=env).stdout.strip()

def rsync(name, *args, good=True, password=PASSWORD):
    return docker("run", "--rm", "--network", "container:"+name,
                  "--mount", f"type=bind,src={ROOT/'source'},dst=/source,readonly",
                  "--mount", f"type=bind,src={ROOT/'restore'},dst=/restore",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "-e", "RSYNC_PASSWORD", "--entrypoint", "/usr/bin/rsync", IMAGE,
                  *args, env=dict(os.environ, RSYNC_PASSWORD=password), good=good)

try:
    for folder in ("data", "source", "restore"):
        (ROOT/folder).mkdir()
        # Synthetic disposable test fixture only. Production permissions use UID65532.
        (ROOT/folder).chmod(0o777)
    payload = secrets.token_bytes(1024*1024+17)
    (ROOT/"source"/"payload.bin").write_bytes(payload)
    (ROOT/"source"/"русский пробел.txt").write_text("backup round-trip\n", encoding="utf-8")
    (ROOT/"source"/"nested").mkdir()
    (ROOT/"source"/"nested"/"small").write_bytes(b"one")
    start(PREFIX)
    for _ in range(50):
        p = docker("exec", PREFIX, "/usr/bin/outpost", "health", good=False)
        if p.returncode == 0:
            break
        time.sleep(.1)
    check("loopback rsync health", p.returncode == 0)
    inspect = json.loads(docker("inspect", PREFIX).stdout)[0]
    host = inspect["HostConfig"]
    check("non-root read-only zero-capabilities no-host-network", inspect["Config"]["User"]=="65532:65532"
          and host["ReadonlyRootfs"] and host["CapDrop"]==["ALL"]
          and not host["Privileged"] and host["NetworkMode"]!="host"
          and not host["Devices"] and not host["PortBindings"])
    for protocol in ("30", "31"):
        rsync(PREFIX, "--protocol="+protocol, "-a", "--no-o", "--no-g", "/source/",
              f"rsync://backup@127.0.0.1:8873/backup/p{protocol}/")
        rsync(PREFIX, "--protocol="+protocol, "-a", f"rsync://backup@127.0.0.1:8873/backup/p{protocol}/",
              f"/restore/p{protocol}/")
        check("protocol "+protocol+" upload/restore Unicode and byte identity",
              (ROOT/"restore"/("p"+protocol)/"payload.bin").read_bytes()==payload
              and (ROOT/"restore"/("p"+protocol)/"русский пробел.txt").read_bytes()==
                  (ROOT/"source"/"русский пробел.txt").read_bytes())
    p = rsync(PREFIX, "rsync://backup@127.0.0.1:8873/backup/", good=False, password="wrong-password")
    check("wrong password rejected", p.returncode != 0)
    p = rsync(PREFIX, "rsync://backup@127.0.0.1:8873/not-a-module/", good=False)
    check("unknown module rejected", p.returncode != 0)
    p = rsync(PREFIX, "rsync://backup@127.0.0.1:8873/backup/../../state/config.json", "/restore/escape", good=False)
    check("module traversal cannot read peer state", p.returncode != 0 and not (ROOT/"restore"/"escape").exists())
    (ROOT/"source"/"payload.bin").write_bytes(payload+b"changed")
    (ROOT/"source"/"nested"/"small").unlink()
    rsync(PREFIX, "-a", "--no-o", "--no-g", "--delete", "/source/",
          "rsync://backup@127.0.0.1:8873/backup/p31/")
    rsync(PREFIX, "-a", "rsync://backup@127.0.0.1:8873/backup/p31/", "/restore/update/")
    check("update and delete for HB rotation", (ROOT/"restore"/"update"/"payload.bin").read_bytes()==payload+b"changed"
          and not (ROOT/"data"/"p31"/"nested"/"small").exists())
    ip = next(iter(inspect["NetworkSettings"]["Networks"].values()))["IPAddress"]
    # A second ordinary bridge container must not reach the loopback listener.
    p = docker("run", "--rm", "--entrypoint", "/usr/bin/rsync", IMAGE, "--contimeout=2",
               f"rsync://{ip}:8873/", good=False)
    check("rsync listener unreachable on Docker LAN IP", p.returncode != 0)
    for shell in ("/bin/sh", "/bin/bash", "/bin/busybox"):
        p = docker("exec", PREFIX, shell, "-c", "exit 0", good=False)
        check("absent "+shell, p.returncode != 0)
    pid = str(inspect["State"]["Pid"])
    status = Path("/proc/"+pid+"/status").read_text()
    fields = dict(line.split(":",1) for line in status.splitlines() if ":" in line)
    check("effective caps zero and no-new-privileges set", int(fields["CapEff"].strip(),16)==0 and fields["NoNewPrivs"].strip()=="1")
    check("separate host network namespace", os.readlink("/proc/"+pid+"/ns/net") != os.readlink("/proc/self/ns/net"))
    docker("restart", PREFIX)
    for _ in range(50):
        if docker("exec", PREFIX, "/usr/bin/outpost", "health", good=False).returncode==0:
            break
        time.sleep(.1)
    rsync(PREFIX, "-a", "rsync://backup@127.0.0.1:8873/backup/p31/", "/restore/restarted/")
    check("data survives restart", (ROOT/"restore"/"restarted"/"payload.bin").read_bytes()==payload+b"changed")
    docker("stop", "--time", "15", PREFIX)
    check("graceful shutdown", json.loads(docker("inspect", PREFIX).stdout)[0]["State"]["ExitCode"]==0)
    full = PREFIX+"-full"
    start(full, tmpdata=True)
    for _ in range(50):
        if docker("exec", full, "/usr/bin/outpost", "health", good=False).returncode == 0:
            break
        time.sleep(.1)
    rsync(full, "-a", "/source/русский пробел.txt", "rsync://backup@127.0.0.1:8873/backup/")
    p = rsync(full, "-a", "/source/payload.bin", "rsync://backup@127.0.0.1:8873/backup/", good=False)
    check("full filesystem returns transfer failure", p.returncode != 0 and "No space left" in p.stderr)
    rsync(full, "-a", "rsync://backup@127.0.0.1:8873/backup/русский пробел.txt", "/restore/full-restored.txt")
    check("full filesystem preserves previous file and daemon", (ROOT/"restore"/"full-restored.txt").read_bytes() == (ROOT/"source"/"русский пробел.txt").read_bytes()
          and docker("exec", full, "/usr/bin/outpost", "health", good=False).returncode == 0)
    docker("stop", "--time", "15", full)
    # Enrollment failure must not leave a receiving daemon open.
    failed = PREFIX+"-enroll"
    start(failed, mode="run", extra=("-e","NB_MANAGEMENT_URL=https://outpost-test.invalid",
          "-e","NB_SETUP_KEY=00000000-0000-0000-0000-000000000000","-e","NB_HOSTNAME=outpost-test"))
    time.sleep(3)
    p = docker("exec", failed, "/usr/bin/outpost", "health", good=False)
    check("no ready receiver before successful NetBird enrollment", p.returncode != 0)
    live = docker("exec", failed, "/usr/bin/netbird", "--daemon-addr=unix:///state/netbird.sock", "status", "--check", "live", good=False)
    check("NetBird daemon responsive with zero capabilities and no TUN", live.returncode == 0)
    logs = docker("logs", failed, good=False).stdout + docker("logs", failed, good=False).stderr
    check("rootless daemon avoids TUN/capability failure", "operation not permitted" not in logs.lower()
          and "permission denied" not in logs.lower())
    docker("stop","--time","15",failed)
    evidence = {"image": IMAGE, "checks": checks,
                "image_id": docker("image","inspect",IMAGE,"--format","{{.Id}}").stdout.strip(),
                "limitations":["No real NetBird enrollment or ACL-direction test", "No real Hyper Backup .hbk job/restore",
                               "Docker test environment; physical DSM not tested"]}
    destination = Path(__file__).resolve().parents[1]/"evidence"
    destination.mkdir(exist_ok=True)
    arch = docker("image", "inspect", IMAGE, "--format", "{{.Architecture}}").stdout.strip()
    (destination/("integration-"+arch+".json")).write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+"\n")
    print("ALL",len(checks),"CHECKS PASSED")
finally:
    for name in reversed(containers):
        docker("rm","-f",name,good=False)
    docker("volume","rm",VOLUME,good=False)
    # Exact unique temporary fixture, never a production mount.
    shutil.rmtree(ROOT)
