# G1: streaming standalone file-kit experiment

[Русский](../ru/g1-prototype.md)

This is the first executable M0 experiment, not a backup service or an accepted storage format. It evaluates a minimal native restic repository containing one file's payload versions and encrypted descriptors. The primary repository also contains another file; the kit receives only the selected stream. Neither source files nor primary repository/index/cache are mounted into the recovery container.

The trusted experiment reads each selected version through `restic dump`, then uses `backup --stdin-from-command` to create a payload snapshot in the kit. A failed producer must not publish an empty or truncated snapshot. Descriptors are encrypted by native restic and refer to exact payload snapshots, length, SHA-256 and fixture metadata. The recovery password is separate. No new cryptographic primitive, chunker or pack format is introduced.

This candidate trades simplicity for extra work: it reads the entire selected file from the primary repository for every version and duplicates encrypted storage between primary and kit. Deduplication inside the kit can reuse its unchanged chunks. These costs are measured separately; this experiment does not prove the required production traffic bound or acceptable cost. A kit's own index is a dependency contained in that kit, not the primary repository's shared index.

## Run a synthetic fixture

Requirements: Linux amd64, Go 1.27.3, Docker, Python 3, POSIX shell, curl, bzip2 and sha256sum. Use an authorized isolated development environment with sufficient free resources; do not point the tool at real sources or existing backup paths.

```sh
go test -count=1 ./...
go vet ./...
mkdir -p out
CGO_ENABLED=0 go build -trimpath -o out/outpost-lab ./cmd/outpost-lab
curl -fL -o out/restic.bz2 https://github.com/restic/restic/releases/download/v0.19.1/restic_0.19.1_linux_amd64.bz2
echo 'f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c  out/restic.bz2' | sha256sum -c -
bzip2 -dk out/restic.bz2
chmod 755 out/restic
timeout 300 sh experiments/g1/run.sh "$PWD/out/g1-run" "$PWD/out/outpost-lab" "$PWD/out/restic"
```

The destination must not exist. The script creates synthetic data and disposable containers; it removes only its own container/image and retains experiment files for inspection. Do not publish the generated password or repository. It uses one CPU, 768 MiB container memory, no network, a read-only image and scoped mounts. The 1 GiB disk condition is checked against bounded fixture inputs and actual usage; it is not an enforced filesystem quota. A compiler container needs an executable temporary filesystem for Go test binaries; the experiment container does not.

The fixture creates a 32 MiB random file, changes a 32 KiB segment and builds two versions. It checks producer failure, prunes old primary history, maintains the kit, restores independently with only kit/key and repeats with an optional truth oracle. The oracle compares output only after restoration; recovery does not depend on it. Wrong password and corrupted encrypted pack must fail. Successful output is JSON with `G1: PARTIAL_FIXTURE_ONLY`; `prepare` alone never reports recovery success.

## Evidence and remaining gates

Record toolchain/image/source identity, commands, fixture size, added kit bytes, full plaintext reads and actual disk use. A smaller incremental kit does not mean a small total read. Preserve encrypted filename behavior; generated fixture names and paths are intentionally synthetic.

Open conditions include 100 GiB/8 MiB traffic acceptance, full cost bounds, interrupted descriptor publication, deleting selected kit versions safely, general source metadata (ACL/xattr/hardlinks), signed checkpoints, keyless replication and target installation. G1 is not complete until all applicable requirements pass; G2 and G3 remain separate. The tool has fixed fixture validation and no production enrollment or arbitrary-file backup interface.

Native stream semantics are described in [restic backup](https://restic.readthedocs.io/en/stable/040_backup.html#reading-data-from-a-command) and [restic dump](https://restic.readthedocs.io/en/stable/050_restore.html#printing-files-to-stdout).
