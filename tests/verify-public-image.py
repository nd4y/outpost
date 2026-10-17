import json,subprocess,tempfile
from pathlib import Path
config_manager=tempfile.TemporaryDirectory(prefix="outpost-anonymous-docker-")
config=config_manager.name
image="ghcr.io/nd4y/outpost:edge"
def run(*args):
 return subprocess.check_output(["docker","--config",config,*args],text=True)
manifest=json.loads(run("manifest","inspect",image))
platforms=sorted(x["platform"]["architecture"] for x in manifest["manifests"])
assert platforms==["amd64","arm64"],platforms
for arch in platforms:
 print(run("pull","--platform","linux/"+arch,image),flush=True)
 p=run("run","--rm","--platform","linux/"+arch,"--read-only","--cap-drop","ALL","--security-opt","no-new-privileges:true","--entrypoint","/usr/bin/rsync",image,"--version")
 assert "version 3.5.1" in p,p
 print("anonymous pull and rsync startup PASS",arch,flush=True)
evidence=Path(__file__).resolve().parents[1]/"evidence"
evidence.mkdir(exist_ok=True)
(evidence/"public-manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")

config_manager.cleanup()
