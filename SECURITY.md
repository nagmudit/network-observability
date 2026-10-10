# Security

The viewer/control API and explicit proxy are restricted to loopback. Host checks guard against arbitrary browser Host headers. Captured text is displayed as text, never inserted as active HTML, and payload downloads are attachments confined to the payload directory.

Standard mode redacts sensitive HTTP header values. Bodies, query strings, WebSocket data, and SSE events can still contain private data; do not interpret header redaction as a secret-free archive. Sensitive mode (`ATO_SENSITIVE_MODE=true`) additionally preserves headers. Local archives are not encrypted. Use a protected capture directory and delete recordings after research.

Native `--raw-flows` archives are opt-in and unredacted; HTTP streamed bodies are absent. They must not be treated as sanitized exports. The API serves only the public CA certificate, never the CA key.

ATO never uploads traffic, enables cloud telemetry, automatically installs trust roots, disables upstream TLS verification, or bypasses certificate pinning. The operator may deliberately install the reviewed CA in an intended trust store using the printed command; the same certificate's removal command is provided.

Default HTTPS mode passes through TLS unless the valid CA is detected as trusted by Windows. Explicit decryption requires client trust. A Windows trust check cannot certify every application's trust policy. Use passthrough/exclusions when interception is incompatible.

The unauthenticated API is intended for a single trusted local user. Loopback is not an access-control boundary against other local processes/users; no claim of multi-user isolation is made.

Browser observation uploads require an ephemeral per-runtime pairing key and reject ordinary website origins. Pairing setup is exposed only to the local viewer/direct local client, without cross-origin reads. Imports are size-limited and schema-validated; errors do not echo captured bodies/headers. The extension has only the local receiver host permission, loads its code locally, does not inject into webpages or modify traffic, and does not persist the pairing key or use cloud telemetry. Sensitive headers are redacted before transfer as well as during storage. Browser observation is not a permission to silently capture every tab; the operator starts/stops the inspected tab explicitly in DevTools.
