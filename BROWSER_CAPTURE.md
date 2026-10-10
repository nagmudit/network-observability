# Browser observation without installing a certificate

This is the first browser-focused Requestly-like capture path in ATO. It uses Chromium's DevTools network API to read the selected tab's already-readable request/response data and save it to the local ATO archive. It does not change the website's TLS connection or route the browser through a proxy.

## Start the observer

Keep this PowerShell terminal running:

```powershell
cd C:\Mudit\Projects\Network-interceptor
.venv\Scripts\Activate.ps1
ato observe
```

Or double-click `Start-Browser-Observer.cmd` in this repository. It runs the existing virtual-environment Python in a persistent console, without installing anything.

Open http://127.0.0.1:8765/ to view saved requests. The observer uses this port by default. A process launched through a temporary agent command is not a reliable replacement for a terminal that you keep running.

## Load the browser connector

1. In Brave, open `brave://extensions`. In Chrome use `chrome://extensions`; in Edge use `edge://extensions`.
2. Enable **Developer mode**, click **Load unpacked**, and select:

   `C:\Mudit\Projects\Network-interceptor\browser-extension`

3. Open the website you want to observe, such as https://chatgpt.com/.
4. Open DevTools with F12 or Ctrl+Shift+I. Select the **ATO** panel; it may be under the overflow menu.
5. In the local viewer, click **Reveal browser pairing key**. Copy it into the ATO DevTools panel.
6. Click **Start recording this tab**, then reload the inspected page. Requests made before recording starts are not backfilled.
7. Use the website. Keep DevTools open. After requests finish, the local viewer will show browser observations, headers, request bodies, and available response bodies.
8. Stop using the panel's **Stop** button. Stop the server with Ctrl+C or `ato stop` from the same repository/environment.

Loading this extension is a browser installation step that you perform yourself. No CA certificate is installed, no system proxy is changed, and no browser certificate validation is disabled. The extension's only host permission is the local receiver; it has no cloud service or telemetry integration.

## What is captured

The selected tab's completed DevTools network entries are recorded. The connector reads HAR request metadata/postData.text and calls the browser's response getContent API. This can provide HTTP and HTTPS payloads because the browser has already handled TLS.

Payload transfer is capped at 128 KiB per body, or the gateway's configured lower body limit. The viewer's body preview is limited to 64 KiB; downloads contain the full saved prefix. Bodies are labeled as decoded/browser-provided data. Browser-reported body sizes are not packet wire-size measurements. Sensitive header values are redacted both before transfer and in storage; bodies and URLs may still contain private data.

The queue holds at most 25 pending observations, including body reads. Its saved/dropped counters expose failures. If the receiver is unavailable or rejects pairing, recording stops visibly instead of silently discarding all future data. Stop clears unsent queued data; a request already submitted may complete. The pairing key is local, kept in server memory, and changes on restart.

## Limits of this connector

- DevTools must be open and recording must be explicitly started. It observes one tab, not every browser tab or every device process.
- Response bodies arrive after the request completes. Long-lived/infinite SSE streams remain pending; finite chat-stream responses can be observed after completion. No live SSE frame or WebSocket-frame capture is implemented here.
- Some request/response bodies are unavailable to DevTools, including certain uploads, cache/eviction cases, or browser-internal data. ATO records this absence explicitly. Multipart HAR parameters are not reconstructed into invented raw bytes.
- Browser observation does not automatically cover the ChatGPT desktop application or the VS Code/Codex extension and its helper processes. Those need their own observation connector or a compatible, explicitly trusted mitmproxy interception path.
- Duplicate headers are normalized into the existing viewer's dictionary format. This is an observability prototype, not a byte-perfect network replay/archive.
- The supplied extension connects to port 8765. A custom observer port requires updating the extension's gateway URL, host permission, and CSP.
- Local pairing/origin checks reduce accidental submissions from web pages. They do not provide isolation from malicious processes running under the same local user.

## Why Requestly can show bodies

Requestly has different mechanisms for different sources:

| Source | Mechanism | Setup/limits |
| --- | --- | --- |
| Browser | Browser extension; its current source observes fetch/XHR in the page and also provides a DevTools panel | Can read browser-side payloads without installing a proxy CA; capture coverage and size limits still apply |
| Desktop proxy | Local interception proxy; applications must connect to it | Its Windows documentation explicitly requires installing/trusting the Requestly CA for HTTPS interception |
| ATO browser connector | Read-only DevTools network observations sent to the local archive | No proxy or CA; selected tab and completed-request limits above |
| ATO mitmproxy gateway | Explicit proxy or native local capture | Traffic must reach the engine; decrypted HTTPS requires compatible client trust |

Sources: [Requestly browser body recorder](https://github.com/requestly/interceptor/blob/master/browser-extension/mv3/src/page-scripts/networkBodyRecorder.js), [Requestly DevTools panel](https://github.com/requestly/interceptor/blob/master/browser-extension/common/src/devtools/devtools.js), [Requestly Windows CA setup](https://github.com/requestly/interceptor/blob/master/documentation/troubleshoot/http-interceptor/install-certificate-windows.mdx), [Chrome DevTools network API](https://developer.chrome.com/docs/extensions/reference/api/devtools/network).

Nothing prevents building a useful local observability product. The required work is connecting each source to a place where readable data is available, making setup/status reliable, and preserving each source's limits. A proxy that receives no routed traffic cannot observe it; a passive observer outside an HTTPS client cannot infer its plaintext payloads without the necessary keys/trust/instrumentation.

## Validation

Python tests cover browser pairing, origin checks, bounded imports, HTTPS-body persistence, downloads/previews, unavailable bodies, retries, stopped sessions, and validation that does not echo payloads. Node tests cover client normalization, UTF-8/binary prefixes, redaction, body retrieval variants, and missing-body handling.

Real browser-extension loading/capture must be verified after you load the unpacked extension. Unit tests of the DevTools adapter are not proof that ChatGPT traffic was captured in your browser.
