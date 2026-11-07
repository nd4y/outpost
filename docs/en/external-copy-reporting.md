# External copy observations

[Русский](../ru/external-copy-reporting.md)

The worker reports retained S3-compatible and WebDAV readback receipts without issuing extra requests to external storage. The operator interface shows the opaque target, exact generation, operation, verification method and original read time. Repeated observations by different workers or operations do not represent additional physical copies of one target.

`outpost-management-report-5` and `outpost-management-report-view-5` add `externalState: OBSERVED` and optional `externalCopies` (at most 4096). OBSERVED refers to inspection of local receipts, not current cloud health. Every row is bound to an UPLOAD job with the same operation and generation. Target identity is the immutable storage-profile digest; endpoint URLs and credentials are excluded. A full or cached target-readback receipt must match target, generation, operation and executor, and its observation time must not exceed the retained job's update time.

`OBSERVED_COMPLETE` means the target was completely read back at the displayed time. Cached verification preserves the oldest supporting read time. Refreshing or resending the report does not renew that time. `UNCONFIRMED` has no complete-copy claim. A completed job with a missing receipt or a receipt with invalid bindings becomes `UNAVAILABLE`, with no verification time or receipt digest. Withdrawing further work does not erase a valid historical observation. These reports do not replace an independent recovery test or establish that the external object still exists now.

The interface lists configured targets without receipts as unknown. Historical targets remain distinguishable from current placement. It clears observations when scope or access changes and marks cached views after transport failure. No aggregate count upgrades duplicate observations into distinct copies. A report without external observation support is explicitly unknown rather than an empty healthy inventory.

Upgrade the management service and its bundled UI before enabling report5 workers. The service still reads reports1-4; older readers reject version5 rather than silently misinterpreting it. Existing report signatures retain their canonical encoding when new fields are absent. Report5 also carries the existing command, recovery and unavailable-catalog observations. The OpenAPI contract defines the new fields and older-format exclusions.

Short acceptance covers wrong/missing receipts, preserved timestamps, scope, malformed/versioned reports, actual HTTPS delivery, and the existing three-worker S3/WebDAV fixture with two generations. Browser checks distinguish original verification time, unconfirmed work and legacy reports. Actual cloud-account admission, global inventory after journal loss, final scale and live monitoring remain separate acceptance gates.

Upload source caching keeps one verified object at a time. A cancelled replacement invalidates its previous identity before replacing the byte buffer, so a later assignment cannot mistake an empty or partial read for the old object. Short regression checks use an actual replica and a cancelled second-object read; protocol authorization and retry classification remain unchanged.
