# Management interface

[Русский](../ru/management-ui.md)

The management service serves its embedded interface at `/`, with `/ui/app.js` and `/ui/app.css`. These are exact, authenticated GET routes on the configured management origin. The same client-certificate identity and local role/scope assignments apply to the interface and API. No external scripts, fonts, analytics, payload proxy or decryption keys are involved. Direct API authorization remains authoritative.

Choose an enrolled node and domain to inspect sources, placement, routes, storage targets, signed reports, generations, queues and space. A report's original observation time remains visible. Missing values mean unknown, not zero. A completed transfer is not proof of target readback or trusted restore. Refresh after an outage; changing scope clears the previous view.

An owner selects an already signed configuration file, reviews its exact digest and changes, then applies that preview against the observed revision. The browser does not sign policy. An operator chooses an available command and exact target. Restore requires an explicit generation and a locally admitted recovery preset; optional file-version identifiers come from the private recovery inventory. Omitting versions requests the selected whole generation. A maintenance command requires a separately signed permit.

Every mutation receives an operation identifier before transmission. The browser tab retains bounded operation records in session storage; it does not repeat an uncertain mutation with a new identifier. Reopen the receipt after a lost reply. Retrying configuration requires selecting the identical signed file. If session storage is unavailable/full, admission is blocked before transmission. Clearing browser storage loses this local convenience, not the service's durable audit; use the operation identifier to retrieve its result.

The English/Russian interface uses native controls, explicit labels, visible keyboard focus, status text, bounded tables and a narrow-screen layout. Loading, empty, missing, forbidden, offline, stale and invalid states remain distinct. Automated browser checks, manual accessibility inspection and installed-service acceptance are separate gates. This document defines the interface contract before its implementation and does not grant permission to expose a port or change a working service.

## Isolated checks

The [browser suite](../../scripts/browser/check.mjs) runs a real loopback mTLS management fixture with disposable identities. Seventeen journeys cover original report age, unknown space, bounded tables, keyboard focus, English/Russian accessibility scans, 320-pixel reflow and 200% text size, scope changes, offline/forbidden/empty states, role isolation and storage failure before mutation. It drops responses after actual command/configuration admission, reloads the page and verifies identical request bytes and operation identifiers. A competing signed policy publication rejects a stale browser preview.

Playwright and axe versions and integrity hashes are pinned in the [test lockfile](../../scripts/browser/package-lock.json); the [CI job](../../.github/workflows/browser.yml) pins its browser image by digest. These are test-only dependencies. The product embeds static files in its Go binary. Both languages passed the automated checks with no reported violations; contrast checks on clipped table cells remain manual-review items. Screenshots and scripted focus/text-resize checks do not claim full WCAG conformance or screen-reader acceptance. The recovery journey checks exact admission and receipt display; actual recovered bytes are covered by the separate trusted recovery checks.

Per-target external coverage, browser tracking across closed tabs, operation-record lifecycle, full manual accessibility and installed-service admission remain open. A report with no target evidence does not certify a cloud copy.

A local storage failure after remote admission reports that a receipt was received; the original request remains retained. Manual receipt lookup preserves its original replay metadata across reload. Local removal affects only a completed tracking record, never the remote operation.
