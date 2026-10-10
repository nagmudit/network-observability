# Protocol support

Browser observation is also available through `ato observe` plus the DevTools extension. It receives completed HTTP(S) HAR metadata, browser-provided request text, and available decoded/base64 response content. This does not perform network interception. Bodies are capped at 128 KiB per transfer or the configured lower limit, and browser-reported sizes are labeled separately from proxy wire measurements. DevTools must remain open; unfinished/infinite streams, WebSocket frames, unavailable bodies, and non-browser processes are outside this connector's scope. See [browser capture](BROWSER_CAPTURE.md).

HTTP metadata, bounded request/response bodies, finite SSE event indexing, and WebSocket message payloads use mitmproxy hooks. HTTP/2 behavior follows mitmproxy; this test suite exercises HTTP/1.1. All HTTP bodies are forwarded as a stream of unchanged chunks, including data beyond the capture limit.

Complete captured compressed messages are decoded through mitmproxy's message API. Truncated/in-progress compressed prefixes remain encoded and are labeled accordingly. The body viewer uses text or base64 and offers byte downloads.

SSE bodies have bounded live snapshots; event rows are parsed after response completion, from the captured prefix. This is not full-fidelity live event timing. WebSocket messages have bounded files, direction, sequence, and 500-byte text previews; the API shows the latest 1,000 messages.

TLS passthrough and exclusions store destination/connection metadata only. CONNECT rows represent proxy tunnel setup, not an HTTP exchange with the origin. Client and upstream TLS failures are stored in diagnostics.

QUIC/HTTP/3, opaque TCP/UDP, DNS inspection, app-level encrypted payloads, certificate-pinned client decryption, and reliable Windows process attribution are not claimed. No guarantee of every network request is made.
