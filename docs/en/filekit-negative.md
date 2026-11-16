# Rejection and confidentiality of file kits

[Русский](../ru/filekit-negative.md)

The [source-bound receipt](../filekit-negative-evidence.json) records focused HDD checks for AT-05 and the file-kit part of AT-06. It complements the original [G1 acceptance](g1-acceptance.md). These are bounded format checks; distributed placement, full-size recovery and product admission retain their separate gates.

The multipart fixture contains 60,000 one-byte logical blocks and at least three encrypted descriptor parts. It first restores the valid independent kit and compares every byte. Two damaged copies must then fail without publishing the destination or leaving a plaintext restore stage:

- Delete the final physical descriptor part while preserving its signed reference.
- Exchange two distinct full-size descriptor parts and sign the changed envelope. The envelope must pass the normal length and signature checks before restoration is attempted. This exercises ordered ciphertext authentication rather than an unequal-part-length refusal.

The tamper table also seals and signs a descriptor containing a valid JSON value followed by a second value. Rejection therefore cannot be attributed to a corrupt envelope signature or ciphertext checksum. Existing cases cover a missing final payload block, truncated and appended payload, payload corruption, invalid signatures, wrong file identities, unsafe paths and special input objects. Each failed restoration checks both destination absence and staging cleanup on the functioning fixture filesystem.

The separate version and cross-file ciphertext substitution checks now require the same absence of published output. They preserve their positive guards: distinct file/version identities and equal plaintext content for the substituted block.

The confidentiality fixture places a synthetic plaintext marker at the beginning, middle and end of a 128 KiB source. It backs up that same content under two different private names. Encrypted dependency sets must be disjoint. Both stored version roots and every relative path and file in both exported kits are scanned for the private names, plaintext marker and plaintext chunk hashes. An export containing fewer than the envelope, encrypted descriptor and payload fails rather than passing an empty scan.

The receipt binds the frozen test source, test executable, exact named results, log digests and container limits. Compilation, vetting and tests use the dedicated HDD. The public record contains synthetic measurements and hashes, without owner keys, plaintext copies, private host paths or endpoint credentials.

These tests establish rejection and marker absence only for the stated corpus. They do not prove privacy of every real source, cloud access log or intermediary disk. Placement policy, hostile mounts, unavailable storage cleanup, power loss, 100 GiB recovery and the real infrastructure profile remain separate acceptance boundaries. No production format or runtime behavior changed in this increment.
