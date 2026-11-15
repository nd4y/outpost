# Source and worker executable flow

[Русский](../ru/process-flow.md)

The [source-bound HDD receipt](../cli-process-flow-evidence.json) records an actual selected executable run, four complete materialized restorations and both selection refusals. Publication CI remains a separate stage.

This opt-in acceptance check runs a separately selected distribution executable for source commands, both receiver `worker-run` processes, status and restoration. It complements library transport tests and the scratch-image installation checks. A test named "executable" is not, by itself, evidence that a distributed executable handled the data.

The fixture uses a 2 MiB random regular file with a Unicode name and a hard-link alias. It captures an initial version and an 8 KiB replacement. The owner, generation writer, source and receiver identities are separate. Receiver bootstraps contain no data-decryption, generation-signing or owner-policy key. A synthetic authenticated HTTPS center supplies unchanged owner-signed per-node configurations.

The check requires these distinct results:

- With the required initial receiver unavailable, the source command fails without releasing the view or replacing the durable operation. Retrying after the actual receiver starts completes that same capture.
- The real primary worker restarts between captures. Both source commands report complete, distinct generations and original verification milestones.
- The source tree, source runtime and source signing/transport authority are removed. The center stops before the outbound-only follower starts. That worker obtains both generations from the primary using its accepted configuration and the signed pull route. It has no listener or direct source route.
- With the source, primary and center unavailable, the follower restarts with unchanged accepted receipts and attempt counts.
- With both receiver processes stopped, the selected executable restores both versions from each holder. Each recovery input contains only immutable catalogs and objects plus the separate owner recovery material and public trust, without a mutable replica index. Full bytes, mode, UID/GID, nanosecond mtime and hard-link identity must match.

The Go process owns each child it starts, records bounded private logs and requires graceful joined shutdown. An unexpected daemon exit or missed deadline fails the test. Unknown or missing result data does not become success.

## Independent selection and execution

Verify the candidate's independently selected manifest, architecture, executable SHA-256 and commit before running it. The test checks the executable hash and its actual version response before initializing its fixture. It never rebuilds the selected executable.

Run only in an authorized isolated Linux environment with an explicit CPU, memory, temporary-space and disk-reserve profile. Set OUTPOST_CLI_PROCESS_FLOW=1, OUTPOST_FLOW_CURRENT_CLI, OUTPOST_FLOW_CURRENT_SHA256 and OUTPOST_FLOW_REVISION from the verified selection. OUTPOST_TEST_ROOT must be an existing real absolute directory in the admitted test storage. Then run:

    go test -count=1 -timeout=360s \
      -run '^TestCLIProcessSourceAndOutboundFollowerKeepIndependentHistory$' \
      -v ./cmd/outpost

Native distribution CI sets these values for each selected amd64/arm64 artifact. The optional OUTPOST_CLI_FLOW_REPORT names a new report in a real absolute output directory. Publication must preserve both the executable revision and the test-source revision.

## Scope

All processes share one synthetic fixture namespace and disk. Receiver profiles are keyless, but this fixture does not certify separate hostile-process mount isolation, physical failure domains or a real site's access rules. Immutable recovery views use hard links to the holder's ciphertext inodes; they are independent reader inputs, not additional physical copies.

This small executable workflow contributes to REQ-17/18/19/24/25/26/36/40/45/48 and AT-07/17/24/25/30. It does not replace the physical 100 GiB source, cloud or asymmetric profiles, independent full-size readers, application-provider admission, installation/isolation checks or production acceptance.

The companion selection test runs the same orchestration with a wrong executable digest and a wrong revision. Both must fail at the expected guard before identity/runtime initialization; an omitted or skipped test cannot pass this control.
