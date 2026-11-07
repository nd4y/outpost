# Private source agent

[Русский](../ru/source-agent.md)

The Linux agent joins the [source lifecycle](source-jobs.md) to an enrolled [runtime volume](runtime-volume.md), private metadata cache and HTTPS ingress. The installed tree provider declares `best-effort` consistency. It verifies the enrolled filesystem/root inode, rejects links and overlap with runtime storage, and never deletes, unmounts or changes source files when releasing its view.

The private `outpost-source-agent-1` bootstrap contains `local` (bootstrap2 node, owner public key, volume, runtime directory and certificate/key/CA files), `profile` (opaque ID/origin, selection, bounds, consistency and copies), `tree` (the observation from `source-probe`), `dataKeyFile`, `writerKeyFile`, `authorityFile`, HTTPS `endpoint` and disk-budget `limits`. Profile `view` is empty; the agent assigns the operation ID. The writer file uses a `privateKey` JSON field. Control endpoints, listeners and cloud credentials are not source-agent inputs. Source rules and decryption keys never enter shared jobs.

Key/configuration files must be private regular files; ancestor and final symlinks are refused. The source and runtime parent must already exist. Initialization checks overlap before creating runtime state and refuses an existing destination. An interrupted initial installation needs operator inspection, not automatic reset. Missing sentinels, substituted directories, changed bootstrap/key bindings and clock rollback stop admission.

The current executable accepts one-copy best-effort profiles. A requested two-copy, filesystem-snapshot or application-consistent profile returns `CAPABILITY_UNAVAILABLE` without lowering the policy. The capture library already enforces two distinct verified copies; its authenticated network verifier is still integration work.

```sh
outpost source-probe --store /source/tree --node ORIGIN_ID --output /private/tree.json
outpost source-authority-sign --key /private/owner-key.json \
  --input /private/authority-input.json --output /private/authority.json
outpost source-init --bootstrap /private/source.json
outpost source-next --bootstrap /private/source.json
outpost source-run --bootstrap /private/source.json
outpost source-status --bootstrap /private/source.json
outpost source-checkpoint --bootstrap /private/source.json --output /private/checkpoint.json
```

`source-next` signs an operation from the durable generation head. Repeating it during a pending operation resumes that operation; after completion it prepares the next sequence and exact parent. `source-prepare --bootstrap FILE --input SIGNED_INTENT` accepts a supplied intent under the same fence. `source-run` executes/resumes the prepared operation and remains idempotent after completion; it does not schedule or create another generation.

Signed agent state fences the operation before provider preparation. Signed file results and encrypted accepted-pack progress survive restart. The source is never reopened after sealing. A lost final head update resumes the completed job and exports its verified checkpoint/lineage. The cache holds encrypted metadata/progress rather than a complete payload copy. Quotas and reconciliation preserve unaccepted files instead of deleting them.

Status exposes opaque identities, phases and copy observations without source names or keys. SIGINT/SIGTERM preserve durable progress. A joined volume monitor cancels outstanding HTTPS requests after identity loss; forcibly interrupting a filesystem call stuck inside the kernel is not promised. Checkpoint output uses a new private file without overwrite. Independent recovery also needs the file-kit recovery owner, public generation trust and complete ciphertext; a checkpoint or source cache alone is not a backup.
