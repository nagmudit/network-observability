# Troubleshooting

## Browser payloads without installing a CA

Use `ato observe` and the DevTools extension, following [browser setup](BROWSER_CAPTURE.md). Keep the server terminal and DevTools open, pair with the current key, click Start recording, then reload the inspected tab. The viewer labels this source as Browser observation. Requests made before starting are not backfilled. A read-only browser connector can see readable HTTPS payloads supplied by the browser without decrypting TLS in a proxy.

If the viewer cannot connect, the server is not running or its port differs. A foreground server started by an agent tool may not persist after that tool/session ends. Launch it yourself using `Start-Browser-Observer.cmd` or a terminal you keep open. Loading the browser extension and activating capture are separate required steps; starting the receiver alone cannot observe an unconnected browser.

## Browser says “Your connection is not private”

Run `ato doctor`. If the local mitmproxy CA is not trusted, run `ato cert`, review the certificate and follow the printed current-user trust command. Restart the browser and gateway. Trust must be installed in the target application's intended certificate store.

Until then, use the default `--https auto` or explicit `--https passthrough` to preserve the website's original certificate. HTTPS bodies will be unavailable. Never bypass the warning or disable certificate verification to get a capture.

If Windows trusts the CA but only a particular app still fails, it may use a separate store or pin certificates. Check the viewer's Capture diagnostics. Exclude its destination using `--ignore-host '(^|.)example.com:443$'`; excluded TLS remains encrypted.

## Port already occupied / server never starts

Doctor checks both ports. Select `ato start --proxy-port 8081 --control-port 8765`, using available values. Another service may already use 8080. Startup waits for the capture addon to become ready and fails if mitmdump exits. The control server also stops if the engine exits later; it cannot silently present a healthy recording while capture is dead.

## No requests in the viewer

In explicit proxy mode, set the actual browser/application proxy to the port printed by startup. Chrome/Edge do not generally honor terminal proxy environment variables. Use the separate-profile launch command in [Windows setup](SETUP_WINDOWS.md).

In local mode, check your `--processes` filter and mitmproxy's Windows capture permissions. Explicit proxy settings are not needed. The mode and HTTPS policy in the viewer describe the running session.

CONNECT/TLS rows are connection metadata, not evidence of decrypted HTTP requests. In passthrough, that is the expected result.

## Internet stops after stopping the proxy

A client still configured to use the stopped proxy cannot connect. Close the separate capture browser, relaunch without proxy flags, or undo any manually configured Windows/application proxy. ATO never changes the global proxy automatically.

## Body preview is binary, incomplete, or truncated

Captured bodies are bounded by `ATO_MAX_BODY_BYTES`; network forwarding is not truncated. The viewer reports captured bytes, observed wire bytes, and the capture limit. Complete compressed captures are decoded; compressed prefixes that exceed the limit are kept as encoded wire bytes. Body previews are limited to 64 KiB; the download contains all saved bytes up to the configured capture limit. Existing recordings created by older versions may have wire-encoded payloads or unknown observed sizes.

SSE is forwarded live, with bounded byte snapshots. Event indexing happens when the response ends. WebSocket messages use mitmproxy's HTTPFlow.websocket API. Process origin attribution and non-HTTP protocol inspection are not implemented.
