# Tasks

## Completed

- Researched Requestly's open-source browser body recorder/DevTools panel and documented the separate desktop CA requirement.
- Added a browser DevTools observation source, local pairing, bounded imports, accurate per-session counts, and the `ato observe` receiver without proxy/CA setup.
- Added the unpacked browser connector and a persistent-console launcher, with explicit setup and per-tab/completed-request limitations in BROWSER_CAPTURE.md.

- Diagnosed the browser privacy warning: the generated local mitmproxy CA was not trusted by Windows.
- Added public CA setup/removal instructions, validity/trust reporting, and a consistent mitmproxy configuration directory.
- Added automatic trust-aware HTTPS policy, explicit decryption/passthrough, and native TLS host exclusions.
- Bound the proxy/control to loopback, exposed port overrides, and reported an occupied default proxy port.
- Added capture readiness, engine exit monitoring, single-writer locking, and actual shutdown via session stop.
- Added a live host-filtered request inspector with header/body previews, byte downloads, connection metadata, origin counts, and diagnostics.
- Preserved streaming network delivery while bounding saved payloads; decoded complete captured compressed messages.
- Corrected the current mitmproxy WebSocket hook and preserved bounded messages; retained finite SSE event indexing.
- Migrated existing SQLite records additively and made native unredacted archives opt-in/per-session.
- Included viewer.html in package data, updated Windows setup/security/limitations, and added focused tests.

## Validation

- Browser data path: 10 Python tests and 6 Node adapter tests passed, including a real observer CLI receive/stop test with no CA directory created.
- Full Python suite passed with 31 cases before the final CLI case; the browser suite then passed with that added case (32 unique current Python cases).
- Browser extension files/JavaScript validated; actual browser installation and user traffic capture remain unverified because no browser was connected.

- Focused pytest suite: 22 passed on Python 3.12.1 / mitmproxy 12.2.3 on Windows.
- Real HTTP/HTTPS/gzip/SSE/WebSocket and lifecycle integration tests passed.
- Real Google HTTPS request through automatic passthrough: HTTP 200 with certificate verification enabled.
- Viewer JavaScript syntax and API/payload behavior verified; visual browser check unavailable because no browser was connected.

## Remaining limitations

- The browser connector requires manual unpacked-extension loading, pairing, DevTools open, and explicit recording of the inspected tab. It does not capture desktop/VS Code traffic, WebSocket frames, or unfinished infinite streams.
- Detached observer launch was blocked by automatic approval review; the user must keep the receiver running in their own terminal.

- Manual CA trust remains necessary for client-accepted HTTPS decryption; ATO does not install roots automatically.
- Actual native Windows capture and Chrome/Edge certificate onboarding remain unverified.
- Process attribution, non-HTTP inspection, encrypted archives, full-fidelity streaming/replay, exports, and pause/resume remain follow-up work.
- Certificate-pinned clients may require exclusions; no pinning bypass is implemented.
- No guarantee of every network request or every Windows process/protocol is made.
