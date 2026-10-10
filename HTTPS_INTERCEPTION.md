# HTTPS interception

The browser privacy warning occurs when the client rejects mitmproxy's generated website certificate. A proxy can log plaintext HTTP directly, but inspecting HTTPS requires the client to trust the local mitmproxy CA. This is a requirement of TLS, not a viewer or logging setting. ATO uses mitmproxy for all TLS negotiation and protocol parsing.

`ato cert` generates/reuses the CA and prints the public path, validity, fingerprint, trust status, and manual setup/removal instructions. The exact same configuration directory is passed to the capture engine. The CA is never trusted automatically; no private key is served by the API.

HTTPS choices:
- `--https auto` (default): decrypt if the CA is valid and detected in Windows' ROOT store with server-auth trust; otherwise forward TLS unchanged.
- `--https passthrough`: preserve the origin certificate, recording only TLS destination/CONNECT metadata. No encrypted request path, header, or body is available.
- `--https decrypt`: deliberately intercept TLS using mitmproxy. The target application must trust the public CA in its own store. This explicit choice also supports non-Windows/separate-store clients for which automatic detection is unavailable.

Trust is checked at startup. Restart the gateway after changing trust. Restart the browser after installing/removing a root. Windows trust detection does not prove that every browser/application's policy accepts interception.

TLS failures are persisted in diagnostics even when no HTTP request could be decoded. Pinned clients or clients with separate stores can reject the connection. Use host exclusions or passthrough for incompatible apps. Exclusions match the SNI/destination host and port and invoke mitmproxy's native ignore-connection behavior. Upstream certificate verification remains enabled; no pinning bypass is implemented.

See [mitmproxy certificate documentation](https://docs.mitmproxy.org/stable/concepts/certificates/) and [Windows setup](SETUP_WINDOWS.md).
