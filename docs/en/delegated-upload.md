# Autonomous external planning

[Русский](../ru/delegated-upload.md)

The worker implements delegated planning without per-generation planner requests. The upload planner signs a bounded delegation containing the exact generation trust, external profile, eligible workers/classes, start, expiry and assignment-slot duration. The owner separately includes the delegation in each eligible worker's current configuration. Both checks are required. Workers receive neither planner nor data-decryption private keys.

For each locally complete generation, eligible workers derive the same canonical version-2 plan from that delegation and the writer-signed catalog. The operation binds the delegation digest and generation. Object partitioning is deterministic under the profile's hard limit. Workers describe one bounded ciphertext object at a time and persist the resulting plan before queue admission. A planning pin protects the generation until the durable upload queue owns its independent pin. Policy withdrawal stops new work and preserves pending pins.

The delegation authorizes a scope rather than signing a concrete part map. A derived map is untrusted until checked against actual object bytes: part hashes, full reconstructed-object hashes and the signed catalog closure must all match. Publication and successful receipts still require complete target readback. Honest workers derive identical plan bytes, sharing assignment/claim identities; an altered map cannot become a valid restored generation merely by carrying a valid delegation. Immutable conflicts remain explicit.

Version-1 individually signed plans remain supported. Version-2 plans require upgraded readers; unknown formats fail closed without removing old generations. Existing storage object/blob/catalog formats remain unchanged. Cached configuration and delegation validity permit autonomous work without the control plane; no delegation grants new credentials, recipients or deletion rights.

## Configuration and recovery

Sign `outpost-upload-delegation-1` with `upload-delegation-sign --key PLANNER_KEY --input DELEGATION --output NEW_SIGNED_DELEGATION`. Include its canonical signed document in `uploads` in the owner-signed configuration. Each worker must be an eligible domain holder with an explicit cloud edge to the exact profile; duplicate domain/target delegations are rejected. Target credentials remain in private local bootstrap. Changing assignment authority creates a different operation identity.

The worker discovers complete local generations and admits `outpost-external-plan-2` jobs. `worker-discovery-status` exposes discovery; `worker-status` exposes execution. The private plan cache is admitted under the shared disk budget. Cached bytes are verified on reuse; a malformed or conflicting cache blocks work and is preserved for diagnosis. Current configuration authority is compiled once per view; a cached plan cannot restore withdrawn authority. Withdrawal retains source pins, queues and evidence for an explicit recovery or maintenance decision.

Short isolated tests use three independent executors with S3-compatible and WebDAV fixtures, deterministic multipart plans, next-generation discovery without configuration updates and independent old/new recovery after stopping workers and removing the synthetic source. Four actual SIGKILL checks cover the durable planning pin, saved plan, queue admission and planning-pin release. Each restart retains generation protection, completes the upload and releases its owned pins. Scope substitution and an altered part map cannot produce successful publication.

## Remaining acceptance

Planning currently rereads the local closure for each new plan. Target publication and each executor's receipt still perform full reverse readback. These costs are not evidence of delta-bandwidth acceptance. The integration is bounded by existing catalog, object, job and plan limits. Final acceptance must measure planning reads, multipart costs, duplicate attempts, shared-link/account budgets and retained history; see the [completion map](../product-status.json). Native storage limits and long-running operation require their own admission evidence.
