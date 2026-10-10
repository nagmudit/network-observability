# ATO Gateway

ATO is a local-first Windows network observability gateway built around mitmproxy. It indexes observed HTTP requests in SQLite, saves bounded request/response payloads, and provides a live host-filtered inspector at http://127.0.0.1:8765/. It does not upload traffic or automatically change certificate trust or Windows proxy settings.

## Browser payloads without a CA

Use `ato observe` (or double-click `Start-Browser-Observer.cmd`) and load the read-only extension from `browser-extension/`. Pair it in DevTools > ATO, start recording, then reload and use the inspected tab. Browser-provided HTTPS bodies appear in the same local viewer after requests complete. No proxy routing or CA installation is needed for this browser connector. Follow [the browser setup guide](BROWSER_CAPTURE.md).

This source is separate from device-wide mitmproxy interception: it captures the selected browser tab, not desktop apps or VS Code/helper processes. Keep DevTools open; unavailable bodies, infinite streams, WebSocket frames, and capture-size limits remain explicit limitations.

## Quick start

In PowerShell, from this repository:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
ato doctor
ato start --proxy-port 8081
```

Use any available proxy port. The example uses 8081 because another local service may already own the usual 8080 port. Open http://127.0.0.1:8765/ to view captures.

The default `--https auto` decrypts only when the local CA is valid and detected in Windows' trusted root store. Otherwise HTTPS passes through with the original website certificate, so browsing continues without trusting a replacement certificate. Plain HTTP payloads and HTTPS connection destinations are recorded; encrypted HTTPS headers and bodies are unavailable in passthrough.

## Connect a browser or application

Chrome and Edge do not generally pick up terminal `HTTP_PROXY` / `HTTPS_PROXY` variables. Launch a separate browser profile with an explicit proxy. See [Windows setup](SETUP_WINDOWS.md) for a copyable Edge command. For a proxy-aware test application, use http://127.0.0.1:8081 as its HTTP and HTTPS proxy.

For native capture on this device, without configuring each application's proxy:

```powershell
ato start --mode local --processes chrome,msedge
# After configuring CA trust:
ato start --mode local --https decrypt
```

The first command targets Chrome and Edge. Omitting `--processes` selects all processes supported by mitmproxy's local capture implementation; Windows may require elevation. This is active interception and can affect clients with separate trust stores or certificate pinning. Start with a targeted process.

## Inspect HTTPS payloads

```powershell
ato cert
```

This generates/reuses mitmproxy's local CA and prints its public certificate path, fingerprint, current trust status, and current-user Windows trust command. Review that certificate and run the displayed command yourself. Restart the browser, then:

```powershell
ato start --proxy-port 8081 --https decrypt
```

Open a request in the viewer to inspect its URL, headers, request/response bodies, connection metadata, and captured WebSocket/SSE data. Binary/encoded previews use base64; full saved bytes can be downloaded. Diagnostics explain TLS failures.

Clients with their own certificate stores can use explicit `--https decrypt` after trusting the public CA there. Certificate pinning may still reject interception. To preserve connectivity for such a host:

```powershell
ato start --https decrypt --ignore-host '(^|.)example.com:443$'
# Or pass all TLS through:
ato start --https passthrough
```

Exclusions match `host:port` and forward TLS unchanged using mitmproxy's native hook. They cannot reveal encrypted payloads.

Stop with Ctrl+C or `ato stop` in another terminal using the same capture directory. Stopping also terminates the engine and viewer. Remove a manually configured proxy afterward, or close the separate browser profile; a browser configured to use a stopped proxy cannot connect.

## Scope and limitations

- Explicit proxy mode only sees applications configured to use it. Native local capture covers supported targeted processes, not a guarantee of every packet/protocol on Windows.
- HTTP metadata and bounded bodies are inspectable when available to mitmproxy. Pinned apps, separate trust stores, app-level encryption, and protocols other than supported HTTP/TLS remain limitations. Process/PID attribution is not implemented.
- All request/response bodies stream to the client/server unchanged. Captured prefixes are bounded by `ATO_MAX_BODY_BYTES` (10 MiB by default); the inspector shows observed wire sizes and truncation. Complete captured compressed bodies are decoded through mitmproxy. Truncated compressed prefixes remain encoded and are labeled as wire bytes.
- SSE byte previews update during a response; event rows are indexed from the bounded body after the response ends. WebSocket messages have bounded saved payloads and text previews. There is no full-fidelity streaming timing/replay claim.
- Sensitive header values are redacted by default. Bodies and URLs can still contain private information. `ATO_SENSITIVE_MODE=true` opts into unredacted headers; archives are not encrypted.
- Native mitmproxy archives are opt-in with `--raw-flows`, unredacted, and stored per session. Because HTTP bodies are streamed, they are not included in native archives; the bounded payload files are the body archive.

Configuration: `ATO_CAPTURE_DIR`, `ATO_MITMPROXY_CONFDIR` (default `~/.mitmproxy`), `ATO_PROXY_PORT`, `ATO_CONTROL_PORT`, `ATO_CONTROL_HOST` (loopback only), `ATO_MAX_BODY_BYTES`, `ATO_SENSITIVE_MODE`. `--proxy-port` and `--control-port` override their corresponding environment settings.

## Tests

```powershell
python -m pytest -q tests/test_storage.py tests/test_capture.py tests/test_proxy_integration.py
python -m pytest -q tests/test_browser_capture.py
node --test tests/browser_capture.test.mjs
```

The integration tests launch real mitmdump and loopback HTTP/HTTPS servers using temporary CAs. They never install certificates in Windows, set a system proxy, or depend on external sites. See [test report](TEST_REPORT.md).
