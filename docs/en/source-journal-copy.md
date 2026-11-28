# Recovering the source journal

[Русский](../ru/source-journal-copy.md)

For a new source runtime, provision a separate owner-enrolled volume root with the same source node scope. Create an empty private directory beneath it. Add `journalCopy` to the private source bootstrap with that `volume` binding and the absolute `directory` path. Keep both roots outside the source tree. The bootstrap binding covers the copy configuration. Use a separate failure domain to protect against disk loss. Two directories on one disk only protect against losing the main journal file.

The source writes the signed journal copy, a signed digest anchor on the primary runtime and then the main journal. Each copy binds the exact prior journal digest and the new signed state. The copy has a fixed 32 MiB capacity budget, including a 4 MiB free-space reserve. Losing either enrolled mount fences progress. Normal restart compares the records under the source execution lease. With an intact runtime and anchor, it repairs a missing main journal or advances the exact immediate predecessor. A stale signed copy or an unrelated, corrupt or divergent main record blocks recovery and remains available for investigation.

After a restart, read `source-status` and compare the operation, receiver route, sequence and checkpoint to the last known values. For ACTIVE recovery, the runtime checks the retained capture records before restoring the main file. Continue through the ordinary source commands under the original scope and expiry. The replay preserves the existing checkpoint bytes and verification times. When the entire runtime, active capture records or journal copy are unavailable, retain all evidence for a separate recovery procedure.

The short fixture uses independently enrolled directory roots on one HDD. It interrupts initialization and the write-ahead boundary, removes the primary ACTIVE journal, verifies mount and divergence fencing and restores the completed generation byte for byte. Physical loss of the entire source volume, receiver journal recovery and migration of an existing runtime to this enrollment require separate verification.
