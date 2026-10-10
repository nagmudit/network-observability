# Test report

## Browser observer addition

The current suite has 32 Python test cases. The full suite passed with 31 cases before the final observer CLI integration case was added; afterward the 10-case browser-focused suite passed, including that new case. All 6 Node adapter tests also passed. Viewer/extension JavaScript syntax and required extension file references were checked.

Browser tests verify pairing/origin restrictions, bounded JSON/body imports, decoded HTTPS observation storage, binary/text prefixes, header redaction, retry-safe IDs, unavailable bodies, session counts, and stopped-session behavior. A real `ato observe` subprocess accepted a representative browser observation, served the viewer and body inspector, then stopped through the API. Its unused CA directory remained absent throughout; no root certificate was installed and no proxy engine was started.

The browser body-provider API was tested with legacy callback and newer Promise adapters. Real browser loading, Chrome/Brave's native DevTools behavior, and actual ChatGPT request capture remain unverified: browser automation inventory returned no connected browsers. Do not interpret adapter/API tests as proof that user traffic was captured.

Detached observer startup was rejected by automatic approval review with `blocked by policy`, without a more specific reason. No workaround launch was attempted. The provided `Start-Browser-Observer.cmd` or `ato observe` command must be run in a terminal by the user to keep the receiver alive. See [browser setup](BROWSER_CAPTURE.md).

## Earlier proxy validation

Validation performed for the HTTPS/browser-connectivity fix on Windows, using Python 3.12.1 and mitmproxy 12.2.3.

Command:
```powershell
.venv\Scripts\python.exe -m pytest -q tests/test_storage.py tests/test_capture.py tests/test_proxy_integration.py
```

Result: **22 passed**. One upstream FastAPI/Starlette TestClient deprecation warning was emitted; it did not affect results.

Coverage:
- Header redaction, SQLite/payload persistence, additive migration, payload size/truncation metadata.
- CA generation/reuse, trust-aware HTTPS policy, loopback configuration, single-writer locking, failed engine startup detection.
- Native TLS passthrough hook and host exclusions, actionable client TLS diagnostics, stopped-session behavior.
- Byte-preserving streaming beyond the capture cap, decompression, multiline finite SSE event indexing, current mitmproxy WebSocket hook.
- API status/mode, body detail/download, invalid/missing records, attachment responses, payload path confinement, Host checks, and session/engine binding.
- Storage write errors in HTTP streaming do not interrupt forwarded chunks.
- Real CLI + mitmdump integration against temporary loopback HTTP/HTTPS origins: JSON request/response bodies, gzip, capped uploads/downloads, incremental SSE delivery, WebSocket echo/message capture.
- Real TLS passthrough without client trust in the interception CA, excluded-host original certificate validation, rejected untrusted client diagnostics, API stop and CLI stop terminating the running engine/viewer.

An additional live request to https://www.google.com/ through the updated gateway returned **HTTP 200** in automatic passthrough mode, with the requesting client's certificate verification enabled. No Windows root certificate or global proxy setting was changed. That smoke-test gateway was stopped afterward.

Viewer JavaScript syntax was checked with Node. The viewer API/inspector response and saved-byte downloads were verified. Visual browser QA could not run because the computer-use browser inventory had no connected browsers.

The project wheel was built successfully; viewer.html is included in the installed package.

Unverified: actual Chrome/Edge CA onboarding, Windows native local-capture driver/elevation and whole-device coverage, HTTP/2/3/QUIC behavior, pinned application decryption (unsupported), process attribution (not implemented), and full-fidelity streaming replay. Temporary test CAs were trusted only by the test clients/upstream verifier, never installed in the Windows trust store.
