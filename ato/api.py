from __future__ import annotations

from pathlib import Path
from typing import Any
import base64
import re
import secrets

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel, ValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .certificates import certificate_status
from .browser_capture import BrowserObservation, MAX_IMPORT_BYTES, TRANSFER_BODY_LIMIT, import_browser_flow
from .config import Settings
from .storage import Store


class MarkerRequest(BaseModel):
    label: str


def create_app(settings: Settings | None = None, store: Store | None = None,
               session_id: str | None = None) -> FastAPI:
    settings = settings or Settings.from_environment()
    settings.ensure_directories()
    store = store or Store(settings.database_path, settings.payload_dir, settings.max_body_bytes, settings.sensitive_mode)
    app = FastAPI(title="ATO Gateway", version="0.1.0")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]",
                       f"[{settings.control_host}]" if ":" in settings.control_host else settings.control_host])
    app.state.settings, app.state.store = settings, store
    # Pairing is ephemeral, local-only, and never written to a recording or log.
    app.state.browser_pairing_key = secrets.token_urlsafe(24)

    def extension_origin(origin: str | None) -> bool:
        return bool(origin and re.fullmatch(r"chrome-extension://[a-p]{32}", origin))

    def active_session() -> dict[str, Any]:
        capture = store.session(session_id) if session_id else store.current_session()
        if not capture or capture["status"] != "recording":
            raise HTTPException(status_code=409, detail="No active observation session; run ato observe")
        return capture

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        capture = store.session(session_id) if session_id else store.current_session()
        return {"capture": capture, "mode": capture["mode"] if capture else None,
                "https_mode": capture["https_mode"] if capture else None,
                "sensitive_mode": settings.sensitive_mode, "max_body_bytes": settings.max_body_bytes,
                "browser_connector": True,
                "session_stats": store.session_stats(capture["id"]) if capture else None,
                "certificate": certificate_status(settings.mitmproxy_confdir),
                "proxy": f"http://127.0.0.1:{settings.proxy_port}" if not capture or capture["mode"] != "browser" else None,
                "control": settings.control_url}

    @app.get("/api/browser/setup")
    def browser_setup(request: Request) -> dict[str, Any]:
        # A website cannot read a pairing key or mint browser observations.
        if request.headers.get("origin") not in {None, settings.control_url}:
            raise HTTPException(status_code=403, detail="Open pairing setup in the local viewer")
        capture = active_session()
        return {"pairing_key": app.state.browser_pairing_key, "session_id": capture["id"],
                "max_body_bytes": min(settings.max_body_bytes, TRANSFER_BODY_LIMIT)}

    @app.options("/api/browser/connect")
    @app.options("/api/browser/flows")
    def browser_preflight(request: Request) -> Response:
        origin = request.headers.get("origin")
        if not extension_origin(origin):
            raise HTTPException(status_code=403, detail="Browser extension origin required")
        return Response(status_code=204, headers={"Access-Control-Allow-Origin": origin,
                        "Access-Control-Allow-Methods": "POST", "Vary": "Origin",
                        "Access-Control-Allow-Headers": "content-type,x-ato-pairing-key"})

    def authorize_browser(request: Request, response: Response) -> dict[str, Any]:
        origin = request.headers.get("origin")
        if origin is not None and not extension_origin(origin):
            raise HTTPException(status_code=403, detail="Website submissions are not accepted")
        if not secrets.compare_digest(request.headers.get("x-ato-pairing-key", ""), app.state.browser_pairing_key):
            raise HTTPException(status_code=403, detail="Pair with this gateway using the local viewer's pairing key")
        if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
            raise HTTPException(status_code=415, detail="JSON observation required")
        capture = active_session()
        if extension_origin(origin):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
        return capture

    @app.post("/api/browser/connect")
    def browser_connect(request: Request, response: Response) -> dict[str, Any]:
        capture = authorize_browser(request, response)
        return {"session_id": capture["id"], "max_body_bytes": min(settings.max_body_bytes, TRANSFER_BODY_LIMIT)}

    @app.post("/api/browser/flows")
    async def browser_flow(request: Request, response: Response) -> dict[str, str]:
        capture = authorize_browser(request, response)
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > MAX_IMPORT_BYTES:
                raise HTTPException(status_code=413, detail="Observation exceeds the transfer limit")
            data.extend(chunk)
        try:
            observation = BrowserObservation.model_validate_json(bytes(data))
        except ValidationError as exc:
            # Do not echo observed bodies/headers or pairing data in validation errors.
            raise HTTPException(status_code=422, detail="Invalid browser observation") from exc
        flow_id = import_browser_flow(store, capture["id"], observation)
        return {"id": flow_id}

    @app.post("/api/sessions")
    def create_session(name: str = "Research session") -> dict[str, Any]:
        raise HTTPException(status_code=409, detail="Start a capture session with ato start; the session belongs to its capture engine.")

    @app.post("/api/sessions/{session_id}/stop")
    def stop_session(session_id: str) -> dict[str, str]:
        try:
            store.session(session_id)
            store.stop_session(session_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"status": "stopped"}

    @app.post("/api/sessions/{session_id}/markers")
    def marker(session_id: str, request: MarkerRequest) -> dict[str, Any]:
        try:
            return store.marker(session_id, request.label)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="session not found") from exc

    @app.get("/api/flows")
    def flows(host: str | None = None, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)) -> list[dict[str, Any]]:
        return store.list_flows(host, limit, offset)

    def get_flow(flow_id: str) -> dict[str, Any]:
        try:
            return store.flow(flow_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Flow not found") from exc

    def body_preview(flow: dict[str, Any], side: str) -> dict[str, Any]:
        path = store.payload_path(flow["id"], side)
        if path:
            with path.open("rb") as payload:
                body = payload.read(64 * 1024)
        else:
            body = b""
        headers = flow[f"{side}_headers"]
        content_type = next((value for key, value in headers.items() if key.lower() == "content-type"), "")
        compressed = any(key.lower() == "content-encoding" and value.lower() != "identity"
                         for key, value in headers.items()) and flow[f"{side}_body_encoding"] == "wire"
        textual = not compressed and (content_type.startswith("text/") or
                    any(marker in content_type.lower() for marker in ("json", "xml", "javascript", "x-www-form-urlencoded")))
        if not content_type and not compressed:
            try:
                body.decode("utf-8")
                textual = b"\x00" not in body
            except UnicodeDecodeError:
                textual = False
        return {"captured_bytes": flow[f"{side}_size"], "observed_wire_bytes": flow[f"{side}_observed_size"],
                "truncated": bool(flow[f"{side}_truncated"]),
                "preview_limited": (flow[f"{side}_size"] or 0) > len(body),
                "body_encoding": flow[f"{side}_body_encoding"], "content_type": content_type,
                "size_source": "browser" if flow["mode"] == "browser" else "wire",
                "format": "text" if textual else "base64", "available": path is not None,
                "preview": body.decode("utf-8", errors="replace") if textual else base64.b64encode(body).decode("ascii")}

    @app.get("/api/flows/{flow_id}")
    def flow_detail(flow_id: str) -> dict[str, Any]:
        flow = get_flow(flow_id)
        try:
            flow["request_payload"] = body_preview(flow, "request")
            flow["response_payload"] = body_preview(flow, "response")
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Saved payload unavailable") from exc
        return flow

    @app.get("/api/flows/{flow_id}/payload/{side}")
    def payload(flow_id: str, side: str) -> FileResponse:
        if side not in {"request", "response"}:
            raise HTTPException(status_code=400, detail="side must be request or response")
        get_flow(flow_id)
        try:
            path = store.payload_path(flow_id, side)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Saved payload unavailable") from exc
        if path is None:
            raise HTTPException(status_code=404, detail="No saved payload")
        return FileResponse(path, media_type="application/octet-stream", filename=f"{side}-payload.bin",
                            headers={"X-Content-Type-Options": "nosniff"})

    @app.get("/api/certificate")
    def public_certificate() -> FileResponse:
        path = settings.mitmproxy_confdir / "mitmproxy-ca-cert.cer"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="Run ato cert to generate the public CA")
        return FileResponse(path, media_type="application/octet-stream", filename="mitmproxy-ca-cert.cer")

    @app.get("/api/origins")
    def origins() -> list[dict[str, Any]]:
        return store.origins()

    @app.get("/api/diagnostics")
    def diagnostics(limit: int = Query(50, ge=1, le=1000)) -> list[dict[str, Any]]:
        return store.list_diagnostics(limit)

    @app.get("/", response_class=HTMLResponse)
    def viewer() -> str:
        return (Path(__file__).with_name("viewer.html")).read_text(encoding="utf-8")

    return app
