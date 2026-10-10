from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SENSITIVE_HEADER = re.compile(r"authorization|cookie|set-cookie|api[-_]?key|token|secret|session", re.I)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact_headers(headers: dict[str, str], sensitive: bool) -> dict[str, str]:
    if sensitive:
        return dict(headers)
    return {key: ("<redacted>" if SENSITIVE_HEADER.search(key) else value) for key, value in headers.items()}


class Store:
    def __init__(self, db_path: Path, payload_dir: Path, max_body_bytes: int = 10 * 1024 * 1024, sensitive: bool = False):
        self.db_path = db_path
        self.payload_dir = payload_dir
        self.max_body_bytes = max_body_bytes
        self.sensitive = sensitive
        self._lock = threading.RLock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.payload_dir.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _init_db(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS capture_sessions (
                  id TEXT PRIMARY KEY, name TEXT NOT NULL, started_at TEXT NOT NULL,
                  stopped_at TEXT, status TEXT NOT NULL DEFAULT 'recording'
                );
                CREATE TABLE IF NOT EXISTS capture_markers (
                  id TEXT PRIMARY KEY, session_id TEXT NOT NULL, label TEXT NOT NULL,
                  created_at TEXT NOT NULL, FOREIGN KEY(session_id) REFERENCES capture_sessions(id)
                );
                CREATE TABLE IF NOT EXISTS network_flows (
                  id TEXT PRIMARY KEY, session_id TEXT NOT NULL, seen_at TEXT NOT NULL,
                  mode TEXT NOT NULL, host TEXT, method TEXT, path TEXT, url TEXT,
                  status INTEGER, process_name TEXT, process_pid INTEGER, duration_ms REAL,
                  request_size INTEGER, response_size INTEGER, content_type TEXT,
                  complete INTEGER NOT NULL DEFAULT 1, error TEXT, request_headers TEXT,
                  response_headers TEXT, request_body_path TEXT, response_body_path TEXT,
                  raw_flow_path TEXT, FOREIGN KEY(session_id) REFERENCES capture_sessions(id)
                );
                CREATE INDEX IF NOT EXISTS idx_flows_seen ON network_flows(seen_at);
                CREATE INDEX IF NOT EXISTS idx_flows_host ON network_flows(host);
                CREATE INDEX IF NOT EXISTS idx_flows_session ON network_flows(session_id);
                CREATE TABLE IF NOT EXISTS stream_events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id TEXT NOT NULL,
                  sequence INTEGER NOT NULL, event_type TEXT, event_id TEXT,
                  data TEXT, created_at TEXT NOT NULL, relative_ms REAL,
                  FOREIGN KEY(flow_id) REFERENCES network_flows(id)
                );
                CREATE TABLE IF NOT EXISTS websocket_messages (
                  id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id TEXT NOT NULL,
                  sequence INTEGER NOT NULL, direction TEXT NOT NULL, is_binary INTEGER NOT NULL,
                  payload_path TEXT, text_preview TEXT, created_at TEXT NOT NULL,
                  FOREIGN KEY(flow_id) REFERENCES network_flows(id)
                );
                CREATE TABLE IF NOT EXISTS diagnostics (
                  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, severity TEXT NOT NULL,
                  code TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL
                );
                """
            )
            # Additive migration preserves existing recordings.
            additions = {
                "capture_sessions": {"mode": "TEXT DEFAULT 'proxy'", "https_mode": "TEXT DEFAULT 'decrypt'",
                                     "process_filter": "TEXT"},
                "network_flows": {
                    "capture_kind": "TEXT DEFAULT 'http'", "capture_note": "TEXT", "connection_info": "TEXT",
                    "request_observed_size": "INTEGER", "response_observed_size": "INTEGER",
                    "request_truncated": "INTEGER DEFAULT 0", "response_truncated": "INTEGER DEFAULT 0",
                    "request_body_encoding": "TEXT DEFAULT 'wire'", "response_body_encoding": "TEXT DEFAULT 'wire'",
                },
                "websocket_messages": {"payload_size": "INTEGER", "observed_size": "INTEGER", "truncated": "INTEGER DEFAULT 0"},
            }
            for table, columns in additions.items():
                existing = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
                for column, definition in columns.items():
                    if column not in existing:
                        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def create_session(self, name: str, mode: str = "proxy", https_mode: str = "decrypt",
                       process_filter: str | None = None) -> dict[str, Any]:
        session_id = secrets.token_hex(8)
        with self._lock, self._connect() as db:
            db.execute("INSERT INTO capture_sessions(id,name,started_at,mode,https_mode,process_filter) VALUES(?,?,?,?,?,?)",
                       (session_id, name, now_iso(), mode, https_mode, process_filter))
        return self.session(session_id)

    def is_recording(self, session_id: str) -> bool:
        return self.session(session_id)["status"] == "recording"

    def session(self, session_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute("SELECT * FROM capture_sessions WHERE id=?", (session_id,)).fetchone()
        if row is None:
            raise KeyError(session_id)
        return dict(row)

    def current_session(self) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM capture_sessions WHERE status='recording' ORDER BY started_at DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def stop_session(self, session_id: str) -> None:
        with self._lock, self._connect() as db:
            db.execute("UPDATE capture_sessions SET status='stopped', stopped_at=? WHERE id=?", (now_iso(), session_id))

    def marker(self, session_id: str, label: str) -> dict[str, Any]:
        self.session(session_id)
        marker_id = secrets.token_hex(8)
        marker = {"id": marker_id, "session_id": session_id, "label": label, "created_at": now_iso()}
        with self._lock, self._connect() as db:
            db.execute("INSERT INTO capture_markers VALUES(?,?,?,?)", tuple(marker.values()))
        return marker

    def _write_payload(self, flow_id: str, suffix: str, body: bytes | None) -> tuple[str | None, int]:
        if not body:
            return None, 0
        limited = body[: self.max_body_bytes]
        digest = hashlib.sha256(limited).hexdigest()[:16]
        safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", flow_id)
        path = self.payload_dir / f"{safe_id}-{suffix}-{digest}.bin"
        path.write_bytes(limited)
        return str(path.relative_to(self.payload_dir.parent)), len(limited)

    def add_flow(self, flow: dict[str, Any]) -> None:
        flow = dict(flow)
        request_body, response_body = flow.pop("request_body", None), flow.pop("response_body", None)
        request_path, request_size = self._write_payload(flow["id"], "request", request_body)
        response_path, response_size = self._write_payload(flow["id"], "response", response_body)
        flow["request_body_path"], flow["response_body_path"] = request_path, response_path
        flow["request_size"], flow["response_size"] = request_size, response_size
        for side, body, size in (("request", request_body, request_size), ("response", response_body, response_size)):
            flow.setdefault(f"{side}_observed_size", len(body or b""))
            flow[f"{side}_truncated"] = int(bool(flow.get(f"{side}_truncated")) or len(body or b"") > size)
            flow.setdefault(f"{side}_body_encoding", "wire")
        flow.setdefault("capture_kind", "http")
        flow["connection_info"] = json.dumps(flow.get("connection_info", {}))
        flow["request_headers"] = json.dumps(redact_headers(flow.get("request_headers", {}), self.sensitive))
        flow["response_headers"] = json.dumps(redact_headers(flow.get("response_headers", {}), self.sensitive))
        columns = ("id", "session_id", "seen_at", "mode", "host", "method", "path", "url", "status",
                   "process_name", "process_pid", "duration_ms", "request_size", "response_size",
                   "content_type", "complete", "error", "request_headers", "response_headers",
                   "request_body_path", "response_body_path", "raw_flow_path", "capture_kind", "capture_note",
                   "connection_info", "request_observed_size", "response_observed_size", "request_truncated",
                   "response_truncated", "request_body_encoding", "response_body_encoding")
        values = [flow.get(column) for column in columns]
        with self._lock, self._connect() as db:
            updates = ",".join(f"{column}=excluded.{column}" for column in columns if column != "id")
            db.execute(f"INSERT INTO network_flows({','.join(columns)}) VALUES({','.join('?' for _ in columns)}) "
                       f"ON CONFLICT(id) DO UPDATE SET {updates}", values)

    def flow(self, flow_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute("SELECT * FROM network_flows WHERE id=?", (flow_id,)).fetchone()
            if row is None:
                raise KeyError(flow_id)
            result = dict(row)
            for field in ("request_headers", "response_headers", "connection_info"):
                result[field] = json.loads(result[field] or "{}")
            result["stream_events"] = [dict(row) for row in db.execute(
                "SELECT * FROM stream_events WHERE flow_id=? ORDER BY sequence LIMIT 1000", (flow_id,))]
            result["websocket_messages"] = [dict(row) for row in db.execute(
                "SELECT * FROM websocket_messages WHERE flow_id=? ORDER BY sequence DESC LIMIT 1000", (flow_id,))]
            result["websocket_messages"].reverse()
        return result

    def payload_path(self, flow_id: str, side: str) -> Path | None:
        if side not in {"request", "response"}:
            raise ValueError("Invalid payload side")
        flow = self.flow(flow_id)
        stored = flow[f"{side}_body_path"]
        if not stored:
            return None
        path = (self.payload_dir.parent / stored).resolve()
        if not path.is_relative_to(self.payload_dir.resolve()) or not path.is_file():
            raise FileNotFoundError("Payload unavailable")
        return path

    def origins(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT host, COUNT(*) AS flows, SUM(request_size + response_size) AS captured_bytes "
                "FROM network_flows GROUP BY host ORDER BY flows DESC LIMIT 1000")]

    def session_stats(self, session_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute("SELECT COUNT(*) AS flows, COALESCE(SUM(mode='browser'),0) AS browser_flows, "
                             "MAX(seen_at) AS last_seen_at FROM network_flows WHERE session_id=?", (session_id,)).fetchone()
        return dict(row)

    def list_diagnostics(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM diagnostics ORDER BY id DESC LIMIT ?", (limit,))]

    def add_websocket_message(self, flow_id: str, sequence: int, from_client: bool, is_binary: bool, body: bytes) -> None:
        path, size = self._write_payload(flow_id, f"ws-{sequence}", body)
        with self._lock, self._connect() as db:
            db.execute("INSERT INTO websocket_messages(flow_id,sequence,direction,is_binary,payload_path,text_preview,"
                       "created_at,payload_size,observed_size,truncated) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (flow_id, sequence, "client" if from_client else "server", int(is_binary), path,
                        body[:500].decode("utf-8", errors="replace"), now_iso(), size, len(body), int(len(body) > size)))

    def list_flows(self, host: str | None = None, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        query = "SELECT * FROM network_flows"
        args: list[Any] = []
        if host:
            query += " WHERE host LIKE ?"
            args.append(f"%{host}%")
        query += " ORDER BY seen_at DESC LIMIT ? OFFSET ?"
        args.extend((min(max(limit, 1), 1000), max(offset, 0)))
        with self._connect() as db:
            return [dict(row) for row in db.execute(query, args).fetchall()]

    def add_diagnostic(self, session_id: str | None, severity: str, code: str, message: str) -> None:
        with self._lock, self._connect() as db:
            db.execute("INSERT INTO diagnostics(session_id,severity,code,message,created_at) VALUES(?,?,?,?,?)",
                       (session_id, severity, code, message, now_iso()))
