# Delayed archive recovery candidate

[Русский](../ru/archive-recovery.md)

The separate M5 candidate retrieves a file version or a complete generation from an admitted S3-compatible delayed-access tier. Each deployment must pass AT-28 with its actual class, retention rules, measured retrieval time and cost. Until then its production status is unavailable and it has no ordinary-storage RTO.

## Prepare the target

Use a separate namespace and first publish the complete generation through the ordinary upload and readback path. Keep the immutable completion marker, catalog, blob descriptors, kit roots and encrypted file descriptors online for the full retention period. For every retained generation, keep the exact independently verified checkpoint, original planner-signed upload plan and plan SHA-256, public generation trust and the owner recovery kit. The planner must sign the physical part list. A worker-derived plan signs its delegation and does not meet that requirement.

Add an `archive` object to the [external recovery profile](external-upload.md#independent-external-recovery). Include the base64 Ed25519 public `planner` key and the following `policy` settings.

- `class` identifies the delayed storage class reported by HEAD. The admitted online response is a missing class header or `STANDARD`.
- `tier` is `Bulk`, `Standard` or `Expedited`, subject to target capability. `days` is the requested temporary availability period, from 1 to 30.
- `minimumWindowSeconds` is the minimum remaining time for starting recovery. Choose it from measured transfer and restore times.
- `maxParts` and `maxBytes` bound the entire selected physical closure, including metadata. One operation admits up to 32768 physical parts.
- `quote` contains `currency`, `requestMicros`, `gibMicros` and `maxBatchMicros`. Prices use millionths of one currency unit. The estimate rounds the data charge up per part and covers the retrieval request and retrieved bytes. Actual charges for metadata reads, temporary storage and egress are measured separately.

Configure and validate transitions separately. Use the `metadata` flag in each status result to protect the union of online parts across retained generations, together with the completion markers and blob descriptors. Move only eligible ciphertext payload parts. Use namespace-scoped credentials that permit read and retrieval initiation. Archive commands issue HEAD and explicit retrieval POST requests under the no-delete policy.

## Retrieve and restore

1. Run `archive-external-status --bootstrap PRIVATE_READER --trust TRUST --key OWNER --input SIGNED_PLAN --sha256 PLAN_SHA256 --generation ID`. Add `--version ID` for one file version. The command authenticates the checkpoint, physical part map and readable kit metadata before inspecting the selected parts. It reports pending, available, expiring and expired parts, the earliest temporary expiry and the estimated cost of parts requiring a request.
2. Run `archive-external-request` with the same inputs and a positive `--max-requests COUNT` to approve a batch. It reads current provider state for the whole selection before sending requests. It rejects a batch over the private cost cap. An accepted request can still be pending. If the response is lost, run status again before approving another batch. The client sends no automatic retry of a paid request.
3. Wait for a new status with `ready: true` and sufficient remaining time. Run `restore-external` with the same reader, trust, owner key, generation and optional version, and a new private output path. The standard reader verifies all hashes and authenticated ciphertext before publishing the output. If the temporary window expires, repeat status and approve retrieval again for expired parts. A failed restore leaves the destination unpublished.

The short HTTPS fixture covers authenticated metadata, a selected multipart file, a lost accepted request, a fresh status read, the cost cap, temporary expiry and a byte-for-byte second restore. A current HEAD response is an availability observation. Use a successful ciphertext audit and restore for integrity evidence. The current client creates no lifecycle rules, lists or deletes no remote objects, and does not extend a temporary window automatically.
