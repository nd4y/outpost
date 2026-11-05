#!/bin/sh
# Synthetic experiment only. Compiled binaries are explicit, preverified inputs.
set -eu
root=${1:?new absolute experiment directory required}
lab=${2:?compiled outpost-lab required}
restic=${3:?verified restic0.19.1 required}
case "$root" in /*) ;; *) echo 'absolute experiment directory required' >&2; exit 2;; esac
[ ! -e "$root" ] || { echo 'refuse existing directory' >&2; exit 2; }
mkdir -m 700 "$root"
mkdir "$root/context" "$root/preparation" "$root/results"
cp "$(dirname "$0")/Dockerfile" "$root/context/Dockerfile"
cp "$lab" "$root/context/outpost-lab"
cp "$restic" "$root/context/restic"
tag="outpost-g1-lab:run-$$"
name="outpost-g1-lab-$$"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker image rm "$tag" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
docker build --network none -t "$tag" "$root/context" > "$root/results/image-build.txt" 2>&1
run() {
  timeout 120 docker run --rm --name "$name" --network none --read-only \
    --cpus 1 --memory 768m --memory-swap 768m --pids-limit 64 \
    --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,nosuid,nodev,size=128m \
    -e GOMAXPROCS=1 "$@"
}
run -v "$root/preparation:/experiment:rw" "$tag" --phase prepare \
  --workdir /experiment/run --restic /tools/restic > "$root/results/prepare.json"
kit="$root/preparation/run/kit"
recovery="$root/preparation/run/recovery"
# No source, primary repo, producer cache or oracle is mounted here.
run -v "$kit:/kit:ro" -v "$recovery/password:/key:ro" -v "$root/results:/result:rw" \
  "$tag" --phase verify --kit /kit --key /key --output /result/independent \
  --restic /tools/restic > "$root/results/independent.json"
# The optional oracle validates fixture truth; it is not used to locate recovery data.
run -v "$kit:/kit:ro" -v "$recovery:/recovery:ro" -v "$root/results:/result:rw" \
  "$tag" --phase verify --kit /kit --key /recovery/password --output /result/checked \
  --expected /recovery/expected.json --restic /tools/restic > "$root/results/checked.json"
# Maintenance sees only the input kit/key and mutates a fresh disposable copy.
mkdir "$root/maintenance"
run -v "$kit:/kit:ro" -v "$recovery/password:/key:ro" -v "$root/maintenance:/maintenance:rw" \
  "$tag" --phase maintenance --kit /kit --key /key --workdir /maintenance/run \
  --restic /tools/restic > "$root/results/maintenance.json"
for checkpoint in interrupted-retirement-kit kit; do
  run -v "$root/maintenance/run/$checkpoint:/kit:ro" -v "$recovery/password:/key:ro" \
    -v "$root/maintenance/run/expected-v2.json:/expected:ro" -v "$root/results:/result:rw" \
    "$tag" --phase verify --kit /kit --key /key --versions v2 \
    --expected /expected --output "/result/retirement-$checkpoint" \
    --restic /tools/restic > "$root/results/retirement-$checkpoint.json"
done
# The original input kit must still retain both versions after maintenance.
run -v "$kit:/kit:ro" -v "$recovery/password:/key:ro" -v "$root/results:/result:rw" \
  "$tag" --phase verify --kit /kit --key /key --output /result/input-preserved \
  --restic /tools/restic > "$root/results/input-preserved.json"
printf 'incorrect-synthetic-password' > "$root/wrong-password"
status=0
run -v "$kit:/kit:ro" -v "$root/wrong-password:/key:ro" -v "$root/results:/result:rw" \
  "$tag" --phase verify --kit /kit --key /key --output /result/wrong-key \
  --restic /tools/restic > "$root/results/wrong-key.txt" 2>&1 || status=$?
[ "$status" -eq 1 ] && grep -q '^outpost-lab:' "$root/results/wrong-key.txt" || {
  echo 'wrong-key check did not produce an application rejection' >&2; exit 1;
}
cp -R "$kit" "$root/corrupt"
python3 - "$root/corrupt" <<'PY'
import pathlib, sys
pack = next(p for p in (pathlib.Path(sys.argv[1]) / 'data').rglob('*') if p.is_file())
pack.chmod(0o600)  # Only this disposable copy; native packs are read-only.
with pack.open('r+b') as f:
    first = f.read(1)
    if not first:
        raise RuntimeError('empty pack')
    f.seek(0)
    f.write(bytes([first[0] ^ 1]))
PY
status=0
run -v "$root/corrupt:/kit:ro" -v "$recovery/password:/key:ro" -v "$root/results:/result:rw" \
  "$tag" --phase verify --kit /kit --key /key --output /result/corrupt \
  --restic /tools/restic > "$root/results/corrupt.txt" 2>&1 || status=$?
[ "$status" -eq 1 ] && grep -q '^outpost-lab:' "$root/results/corrupt.txt" || {
  echo 'corruption check did not produce an application rejection' >&2; exit 1;
}
python3 - "$root" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
prep = json.loads((root/'results/prepare.json').read_text())
maintenance = json.loads((root/'results/maintenance.json').read_text())
if maintenance['packsRemoved'] < 1 or maintenance['packsAdded'] < 1:
    raise RuntimeError('physical repack not established')
if not 0 < prep['kitBytesAddedV2'] < prep['fixtureBytes']:
    raise RuntimeError('incremental kit did not reuse unchanged payload')
size = sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
if size > 1024**3:
    raise RuntimeError('experiment exceeded 1GiB disk budget')
report = {'fixture': 'PASS', 'wrongKeyRejected': True, 'corruptionRejected': True,
          'publicationFailure': 'PASS', 'physicalRepack': 'PASS',
          'retirementBoundaryRecovery': 'PASS', 'selectedVersionGC': 'PASS',
          'diskBytes': size, 'G1': 'PARTIAL_FIXTURE_ONLY', 'fullScale': 'NOT_VERIFIED'}
(root/'results/result.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report))
PY
