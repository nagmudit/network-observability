"""Store browser-provided observations; this does not parse or intercept TLS/HTTP."""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator

from .storage import Store, now_iso

TRANSFER_BODY_LIMIT = 128 * 1024
MAX_IMPORT_BYTES = 1024 * 1024


class Header(BaseModel):
    name: str = Field(max_length=1024)
    value: str = Field(max_length=8192)


class BrowserObservation(BaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")
    url: str = Field(max_length=32768)
    method: str = Field(min_length=1, max_length=40)
    seen_at: datetime
    status: int = Field(ge=0, le=599)
    duration_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    tab_id: int = Field(ge=0)
    request_headers: list[Header] = Field(default_factory=list, max_length=200)
    response_headers: list[Header] = Field(default_factory=list, max_length=200)
    request_body_base64: str | None = Field(default=None, max_length=180000)
    response_body_base64: str | None = Field(default=None, max_length=180000)
    request_reported_size: int | None = Field(default=None, ge=0)
    response_reported_size: int | None = Field(default=None, ge=0)
    request_truncated: bool = False
    response_truncated: bool = False
    note: str = Field(default="", max_length=4000)
    error: str | None = Field(default=None, max_length=4000)

    @field_validator("url")
    @classmethod
    def http_url(cls, value: str) -> str:
        try:
            parsed = urlsplit(value)
            _ = parsed.port
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("Only HTTP(S) browser observations are supported")
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("URLs containing embedded credentials are not accepted")
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return value

    @field_validator("request_body_base64", "response_body_base64")
    @classmethod
    def bounded_base64(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                body = base64.b64decode(value, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("Body must be valid base64") from exc
            if len(body) > TRANSFER_BODY_LIMIT:
                raise ValueError("Body exceeds the browser transfer limit")
        return value


def import_browser_flow(store: Store, session_id: str, observation: BrowserObservation) -> str:
    parsed = urlsplit(observation.url)
    request = base64.b64decode(observation.request_body_base64) if observation.request_body_base64 is not None else b""
    response = base64.b64decode(observation.response_body_base64) if observation.response_body_base64 is not None else b""
    # Session-bound IDs make retries idempotent without overwriting other capture sources.
    flow_id = f"browser-{session_id}-{observation.id}"
    request_headers = {header.name: header.value for header in observation.request_headers}
    response_headers = {header.name: header.value for header in observation.response_headers}
    content_type = next((h.value for h in observation.response_headers if h.name.lower() == "content-type"), None)
    notes = ["Observed inside the browser via DevTools; no proxy or CA trust is required."]
    if observation.request_body_base64 is None:
        notes.append("Request body was not supplied by the browser.")
    if observation.response_body_base64 is None:
        notes.append("Response body was not supplied by the browser.")
    if observation.note:
        notes.append(observation.note)
    store.add_flow({
        "id": flow_id, "session_id": session_id, "seen_at":
            observation.seen_at.astimezone(timezone.utc).isoformat() if observation.seen_at.tzinfo else now_iso(),
        "mode": "browser", "host": parsed.hostname, "method": observation.method,
        "path": (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else ""), "url": observation.url,
        "status": observation.status or None, "duration_ms": observation.duration_ms,
        "complete": int(observation.status > 0 and not observation.error), "error": observation.error,
        "capture_kind": "http", "capture_note": " ".join(notes), "content_type": content_type,
        "request_headers": request_headers, "response_headers": response_headers,
        "request_body": request, "response_body": response,
        "request_body_encoding": "decoded", "response_body_encoding": "decoded",
        "request_observed_size": observation.request_reported_size,
        "response_observed_size": observation.response_reported_size,
        "request_truncated": observation.request_truncated, "response_truncated": observation.response_truncated,
        "connection_info": {"source": "browser-devtools", "tab_id": observation.tab_id,
                            "size_basis": "Browser/HAR-reported body sizes; not packet wire measurements",
                            "request_body_available": observation.request_body_base64 is not None,
                            "response_body_available": observation.response_body_base64 is not None},
    })
    return flow_id
