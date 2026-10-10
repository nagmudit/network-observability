from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mitmproxy import http, tls

try:
    from .storage import Store, now_iso
except ImportError:
    from ato.storage import Store, now_iso


class BodyCapture:
    # mitmdump's script loader does not register the module in sys.modules;
    # a normal class also works with postponed annotations in that loader.
    def __init__(self) -> None:
        self.data = bytearray()
        self.observed = 0
        self.finished = False


class CaptureAddon:
    def __init__(self, store: Store, session_id: str, mode: str = "proxy", raw_flow_path: Path | None = None,
                 https_mode: str = "decrypt", ignore_hosts: list[str] | None = None, ready_path: Path | None = None):
        self.store, self.session_id, self.mode = store, session_id, mode
        self.raw_flow_path, self.https_mode, self.ready_path = raw_flow_path, https_mode, ready_path
        self.ignore_hosts = [re.compile(pattern, re.I) for pattern in (ignore_hosts or [])]
        self._started: dict[str, float] = {}
        self._bodies: dict[tuple[str, str], BodyCapture] = {}
        self._last_snapshot: dict[str, float] = {}
        self._last_write_warning = float("-inf")

    def running(self) -> None:
        if self.ready_path:
            self.ready_path.write_text("ready", encoding="utf-8")

    def _stream(self, flow: http.HTTPFlow, side: str) -> None:
        message = getattr(flow, side)
        body = self._bodies[(flow.id, side)] = BodyCapture()

        def capture(chunk: bytes) -> bytes:
            body.observed += len(chunk)
            body.data.extend(chunk[:max(0, self.store.max_body_bytes - len(body.data))])
            body.finished = not chunk
            if side == "response" and chunk and time.monotonic() - self._last_snapshot.get(flow.id, 0) >= 1:
                self._last_snapshot[flow.id] = time.monotonic()
                self._persist(flow, complete=False, note="Response in progress; payload preview is bounded.")
            # Forward every chunk unchanged, even when the capture limit is reached.
            return chunk

        message.stream = capture

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        self._started[flow.id] = time.perf_counter()
        self._stream(flow, "request")

    def request(self, flow: http.HTTPFlow) -> None:
        self._started.setdefault(flow.id, time.perf_counter())
        capture = self._bodies.get((flow.id, "request"))
        if capture:
            capture.finished = True
        finished = bool(flow.metadata.get("ato_response_complete"))
        self._persist(flow, complete=finished, note=None if finished else "Waiting for response.")
        if finished:
            self._cleanup(flow.id)

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        self._stream(flow, "response")
        self._persist(flow, complete=False, note="Response in progress; payload preview is bounded.")

    def _body(self, flow: http.HTTPFlow, side: str) -> dict[str, Any]:
        message = getattr(flow, side)
        capture = self._bodies.get((flow.id, side))
        raw = bytes(capture.data) if capture else bytes(message.raw_content or b"") if message else b""
        observed = capture.observed if capture else len(raw)
        truncated = observed > len(raw)
        encoding = "wire"
        body = raw
        if message and (not capture or capture.finished) and not truncated:
            copied = message.copy()
            copied.raw_content = raw
            try:
                body = copied.get_content(strict=True) or b""
                encoding = "decoded"
            except ValueError:
                pass  # Keep the original bytes and label them, never alter the forwarded message.
        return {f"{side}_body": body, f"{side}_observed_size": observed,
                f"{side}_truncated": truncated or len(body) > self.store.max_body_bytes,
                f"{side}_body_encoding": encoding}

    @staticmethod
    def _connection(flow: http.HTTPFlow) -> dict[str, Any]:
        client, server = flow.client_conn, flow.server_conn
        return {"client_address": client.peername, "server_address": server.address,
                "server_peer": server.peername, "sni": client.sni,
                "tls_version": client.tls_version, "upstream_tls_version": server.tls_version,
                "http_version": flow.request.http_version}

    def _persist(self, flow: http.HTTPFlow, complete: bool, note: str | None = None,
                 kind: str = "http", error: str | None = None) -> None:
        try:
            self._save_flow(flow, complete, note, kind, error)
        except (OSError, sqlite3.Error) as exc:
            # A disk/index failure in the stream callback must not break browsing.
            if time.monotonic() - self._last_write_warning >= 30:
                self._last_write_warning = time.monotonic()
                message = f"Capture write failed; traffic is still forwarded: {exc}"
                logging.getLogger(__name__).warning(message)
                try:
                    self.store.add_diagnostic(self.session_id, "error", "capture_write_failed", message)
                except (OSError, sqlite3.Error):
                    pass

    def _save_flow(self, flow: http.HTTPFlow, complete: bool, note: str | None,
                   kind: str, error: str | None) -> None:
        if not self.store.is_recording(self.session_id):
            return
        request, response = flow.request, flow.response
        started = self._started.get(flow.id)
        self.store.add_flow({
            "id": flow.id, "session_id": self.session_id,
            "seen_at": datetime.fromtimestamp(request.timestamp_start, timezone.utc).isoformat(),
            "mode": self.mode, "host": request.host, "method": request.method,
            "path": request.path, "url": request.pretty_url,
            "status": response.status_code if response else None,
            "duration_ms": (time.perf_counter() - started) * 1000 if started else None,
            "content_type": response.headers.get("content-type") if response else None,
            "complete": int(complete), "error": error, "capture_kind": kind, "capture_note": note,
            "request_headers": dict(request.headers.items(multi=True)),
            "response_headers": dict(response.headers.items(multi=True)) if response else {},
            "connection_info": self._connection(flow),
            **self._body(flow, "request"), **self._body(flow, "response"),
            "raw_flow_path": str(self.raw_flow_path) if self.raw_flow_path else None,
        })

    def _cleanup(self, flow_id: str) -> None:
        self._started.pop(flow_id, None)
        self._last_snapshot.pop(flow_id, None)
        self._bodies.pop((flow_id, "request"), None)
        self._bodies.pop((flow_id, "response"), None)

    def response(self, flow: http.HTTPFlow) -> None:
        flow.metadata["ato_response_complete"] = True
        capture = self._bodies.get((flow.id, "response"))
        if capture:
            capture.finished = True
        self._persist(flow, complete=True)
        if flow.response.headers.get("content-type", "").lower().startswith("text/event-stream"):
            self._record_sse(flow)
        request_capture = self._bodies.get((flow.id, "request"))
        if not request_capture or request_capture.finished:
            self._cleanup(flow.id)

    def error(self, flow: http.HTTPFlow) -> None:
        self._persist(flow, complete=False, error=flow.error.msg if flow.error else "unknown flow error")
        self._cleanup(flow.id)

    def http_connected(self, flow: http.HTTPFlow) -> None:
        self._persist(flow, complete=False, kind="tunnel", note=
                      "CONNECT tunnel setup only. HTTPS payloads require decryption; look for separate HTTP rows.")

    def http_connect_error(self, flow: http.HTTPFlow) -> None:
        self._persist(flow, complete=False, kind="tunnel", error=
                      flow.error.msg if flow.error else "CONNECT tunnel failed")

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        address = data.context.server.address
        host = data.client_hello.sni or (address[0] if address else "unknown")
        port = address[1] if address else 443
        excluded = any(pattern.search(f"{host}:{port}") for pattern in self.ignore_hosts)
        if self.https_mode == "passthrough" or excluded:
            # mitmproxy's native passthrough; we never implement TLS parsing.
            data.ignore_connection = True
            if self.store.is_recording(self.session_id):
                self.store.add_flow({
                    "id": f"{data.context.client.id}-tls", "session_id": self.session_id, "seen_at": now_iso(),
                    "mode": self.mode, "host": host, "method": "TLS", "url": f"https://{host}:{port}",
                    "complete": 0, "capture_kind": "tls", "capture_note":
                        "Encrypted passthrough (excluded host). No HTTP headers or bodies." if excluded else
                        "Encrypted passthrough. Trust the CA and restart with --https decrypt to inspect bodies.",
                    "connection_info": {"sni": host, "server_address": address,
                                        "client_address": data.context.client.peername},
                })

    def tls_failed_client(self, data: tls.TlsData) -> None:
        if self.store.is_recording(self.session_id):
            self.store.add_diagnostic(self.session_id, "error", "client_tls_failed",
                                     f"{data.context.server.address}: {data.conn.error}. "
                                     "Client may not trust the CA or may pin certificates. Run ato cert; "
                                     "use --https passthrough or --ignore-host for incompatible apps.")

    def tls_failed_server(self, data: tls.TlsData) -> None:
        if self.store.is_recording(self.session_id):
            self.store.add_diagnostic(self.session_id, "error", "upstream_tls_failed",
                                     f"{data.context.server.address}: {data.conn.error}. "
                                     "Upstream certificate verification remains enabled.")

    def _record_sse(self, flow: http.HTTPFlow) -> None:
        if not self.store.is_recording(self.session_id):
            return
        body = self._body(flow, "response")
        if (body["response_body_encoding"] != "decoded" and
                flow.response.headers.get("content-encoding", "identity").lower() != "identity"):
            return
        raw = body["response_body"][:self.store.max_body_bytes]
        with self.store._connect() as db:
            db.execute("DELETE FROM stream_events WHERE flow_id=?", (flow.id,))
            for sequence, event in enumerate(raw.replace(b"\r\n", b"\n").split(b"\n\n")[:-1], 1):
                fields: dict[str, str] = {}
                values: list[str] = []
                for line in event.decode("utf-8", errors="replace").splitlines():
                    if line.startswith(":"):
                        continue
                    key, _, value = line.partition(":")
                    value = value.removeprefix(" ")
                    if key == "data":
                        values.append(value)
                    else:
                        fields[key] = value
                if values:
                    db.execute(
                        "INSERT INTO stream_events(flow_id,sequence,event_type,event_id,data,created_at,relative_ms) "
                        "VALUES(?,?,?,?,?,?,?)", (flow.id, sequence, fields.get("event"), fields.get("id"),
                                                   "\n".join(values), now_iso(), None))

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        # Current mitmproxy passes HTTPFlow, with messages under flow.websocket.
        if flow.websocket and flow.websocket.messages and self.store.is_recording(self.session_id):
            message = flow.websocket.messages[-1]
            self.store.add_websocket_message(flow.id, len(flow.websocket.messages), message.from_client,
                                             not message.is_text, bytes(message.content))


def build_addon(store: Store, session_id: str, mode: str, raw_flow_path: Path | None = None,
                **kwargs: Any) -> CaptureAddon:
    return CaptureAddon(store, session_id, mode, raw_flow_path, **kwargs)


def _configured_addon() -> CaptureAddon:
    capture_dir = Path(os.environ["ATO_CAPTURE_DIR"])
    store = Store(capture_dir / "index.sqlite", capture_dir / "payloads",
                  int(os.getenv("ATO_MAX_BODY_BYTES", str(10 * 1024 * 1024))),
                  os.getenv("ATO_SENSITIVE_MODE", "").lower() == "true")
    raw_path = os.getenv("ATO_RAW_FLOW_PATH")
    ready_path = os.getenv("ATO_READY_PATH")
    return build_addon(store, os.environ["ATO_SESSION_ID"], os.getenv("ATO_CAPTURE_MODE", "proxy"),
                       Path(raw_path) if raw_path else None, https_mode=os.getenv("ATO_HTTPS_MODE", "passthrough"),
                       ignore_hosts=json.loads(os.getenv("ATO_IGNORE_HOSTS", "[]")),
                       ready_path=Path(ready_path) if ready_path else None)


# Importing the module in tests must not create a recording on the user's disk.
addons = [_configured_addon()] if os.getenv("ATO_SESSION_ID") else []
