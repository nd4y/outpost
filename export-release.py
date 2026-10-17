#!/usr/bin/env python3
"""Export tested local images and an explicit allowlist of non-secret project files."""
import gzip,hashlib,json,shutil,subprocess,zipfile
from pathlib import Path

root=Path(__file__).resolve().parent
destination=root/"release"
destination.mkdir(exist_ok=True)
manifest={"version":"0.2.0","images":{}}
for arch,image in (("amd64","outpost-hardened:0.2.0"),("arm64","outpost-hardened:0.2.0-arm64")):
    evidence=json.loads((root/"evidence"/("integration-"+arch+".json")).read_text())
    info=json.loads(subprocess.check_output(["docker","image","inspect",image],text=True))[0]
    assert info["Id"]==evidence["image_id"] and info["Architecture"]==arch
    target=destination/("outpost-hardened-0.2.0-"+arch+".tar.gz")
    process=subprocess.Popen(["docker","save",image],stdout=subprocess.PIPE)
    with gzip.open(target,"wb",compresslevel=6) as output:
        shutil.copyfileobj(process.stdout,output)
    process.stdout.close()
    if process.wait()!=0:
        target.unlink(missing_ok=True)
        raise SystemExit("docker save failed")
    digest=hashlib.file_digest(target.open("rb"),"sha256").hexdigest()
    manifest["images"][arch]={"file":target.name,"sha256":digest,"image_id":info["Id"],"uncompressed_image_bytes":info["Size"],"archive_bytes":target.stat().st_size}
    print("exported",arch,target.stat().st_size,"bytes",flush=True)
files=["README.md","Dockerfile","compose.yaml","docker-run.sh","install.sh",".env.example",".dockerignore",".gitignore",
       "go.mod","sources.lock.json","fetch-assets.py","export-release.py","cmd/outpost/main.go","cmd/outpost/main_test.go","cmd/outpost/bootstrap.go","cmd/outpost/metrics.go","cmd/outpost/metrics_test.go",
       "tests/integration.py","tests/installer.py","tests/validate-deploy.py","tests/check-publication.py",".github/workflows/build.yml","docs/VALIDATION.md",
       "evidence/integration-amd64.json","evidence/integration-arm64.json"]
bundle=destination/"outpost-hardened-0.2.0-source-and-deploy.zip"
with zipfile.ZipFile(bundle,"w",zipfile.ZIP_DEFLATED) as archive:
    for name in files:
        archive.write(root/name,name)
manifest["project_bundle"]={"file":bundle.name,"sha256":hashlib.file_digest(bundle.open("rb"),"sha256").hexdigest()}
(destination/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
print("release manifest saved")
