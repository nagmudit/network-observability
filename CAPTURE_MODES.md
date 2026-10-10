# Capture modes

- **Browser observer:** `ato observe` plus the unpacked DevTools extension in `browser-extension/`. Records completed network entries and available readable bodies for the inspected tab. No proxy routing or CA installation. See [browser capture](BROWSER_CAPTURE.md) for pairing, installation, and limitations.

- **Explicit proxy:** `ato start --mode proxy --proxy-port 8081`. The HTTP proxy is bound to 127.0.0.1, and captures applications explicitly configured to use it. Both HTTP and HTTPS client proxy settings use an `http://` proxy URL.
- **Native local capture:** `ato start --mode local --processes chrome,msedge`. Uses mitmproxy's native `--mode local:chrome,msedge`. Names/PIDs can be comma-separated; omit the filter for supported traffic from all processes. Windows may require elevation. It does not require per-app proxy configuration. Native-driver behavior and full-device coverage remain unverified here.
- **HTTPS policy:** `--https auto` / `--https decrypt` / `--https passthrough` apply to either mode. Passthrough is active forwarding of TLS unchanged, with destination metadata logging; it is not passive packet capture.
- **Host exclusion:** repeat `--ignore-host <host:port-regex>` to exempt incompatible TLS connections. Matching happens in mitmproxy's TLS ClientHello hook using its parsed SNI/destination.
- **Passive packet diagnostics:** not implemented. Packet capture alone cannot expose HTTPS bodies.

See [mitmproxy modes](https://docs.mitmproxy.org/stable/concepts/modes/) for underlying platform limitations. Selecting a process constrains capture but does not provide process attribution on each stored flow.
