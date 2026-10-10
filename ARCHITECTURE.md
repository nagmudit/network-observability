# Architecture

mitmdump is the interception engine. The CLI selects its executable from the Python environment, validates mode/ports, fixes the engine's configuration directory, and evaluates CA trust. An OS file lock prevents two gateways from recording into the same directory. Each session has an engine readiness signal and optional native archive. The viewer starts only after the addon loads; engine exit or session stop shuts the viewer down and finalizes the session.

CaptureAddon uses request/response header hooks to attach byte-preserving streaming callbacks. It keeps bounded prefixes, persists provisional records/snapshots and final exchanges, and records wire byte counts, truncation, connection metadata, errors, finite SSE events, and HTTPFlow.websocket messages. Native TLS passthrough uses mitmproxy's ignore_connection hook. TLS handshake failures are diagnostics even when no HTTP exchange exists.

Store writes an additive-migrated SQLite index and bounded payload files; updates preserve existing flow records. FastAPI provides session status, host lists/filtering, diagnostics, payload previews, and confined attachment downloads. Session creation belongs to the CLI/capture engine; the API cannot silently create a session disconnected from the running engine.

The viewer shows archived flows, per-host counts, separate connection-only rows, TLS setup guidance, and request/response details. It uses textContent for untrusted traffic. The record does not guess process identity; markers annotate operator actions and cannot prove process origin.

Browser observation is a separate ingestion source. `ato observe` runs the viewer/receiver without launching mitmdump or initializing a CA. A Chromium DevTools extension reads completed network entries and available bodies, redacts sensitive headers, bounds its queue/payload transfer, and posts them to the loopback receiver after local pairing. Browser observations use session-bound retry-safe IDs and the existing Store archive; they are labeled as browser-provided decoded bodies and browser-reported sizes. This source does not implement TLS/HTTP parsing or replace mitmproxy for gateway interception.
