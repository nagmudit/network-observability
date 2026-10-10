import gzip
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from mitmproxy.test import tflow

from ato.addon import CaptureAddon
from ato.api import create_app
from ato.certificates import certificate_status, initialize_ca, resolve_https_mode
from ato.config import Settings
from ato.runtime import capture_lock, wait_for_proxy
from ato.storage import Store


@pytest.fixture
def capture(tmp_path):
    store = Store(tmp_path / "index.sqlite", tmp_path / "payloads", max_body_bytes=64)
    session = store.create_session("test", "local", "passthrough", "chrome")
    return store, session, CaptureAddon(store, session["id"], "local")


def test_https_auto_requires_valid_trusted_ca():
    assert resolve_https_mode("auto", {"trusted": False, "valid": True}) == "passthrough"
    assert resolve_https_mode("auto", {"trusted": None, "valid": True}) == "passthrough"
    assert resolve_https_mode("auto", {"trusted": True, "valid": False}) == "passthrough"
    assert resolve_https_mode("auto", {"trusted": True, "valid": True}) == "decrypt"
    assert resolve_https_mode("decrypt", {"trusted": False, "valid": True}) == "decrypt"
    with pytest.raises(ValueError):
        resolve_https_mode("decrypt", {"trusted": False, "valid": False})


def test_public_ca_generation_is_stable(tmp_path):
    assert not certificate_status(tmp_path)["exists"]
    initialize_ca(tmp_path)
    first = certificate_status(tmp_path)
    initialize_ca(tmp_path)
    assert first["valid"] and first["sha256"] == certificate_status(tmp_path)["sha256"]
    assert "PRIVATE KEY" not in Path(first["path"]).read_text()


def test_local_only_settings(tmp_path):
    with pytest.raises(ValueError, match="loopback"):
        Settings(tmp_path, control_host="0.0.0.0")
    with pytest.raises(ValueError):
        Settings(tmp_path, max_body_bytes=0)


def test_streams_all_bytes_but_bounds_capture(capture):
    store, session, addon = capture
    flow = tflow.tflow(resp=True)
    flow.request.headers["Authorization"] = "test-only-value"
    addon.requestheaders(flow)
    assert flow.request.stream(b"request") == b"request"
    flow.request.stream(b"")
    addon.request(flow)
    addon.responseheaders(flow)
    original = b"x" * 400
    assert flow.response.stream(original) == original
    assert len(addon._bodies[(flow.id, "response")].data) == 64
    flow.response.stream(b"")
    addon.response(flow)
    row = store.flow(flow.id)
    assert row["complete"] == 1
    assert row["response_observed_size"] == 400
    assert row["response_truncated"] == 1 and row["response_size"] == 64
    assert row["request_headers"]["Authorization"] == "<redacted>"
    assert flow.id not in addon._started and not addon._bodies


def test_storage_failure_does_not_break_network_stream(capture, monkeypatch):
    store, _, addon = capture
    flow = tflow.tflow(resp=True)
    def fail_write(_):
        raise OSError("test disk is full")
    monkeypatch.setattr(store, "add_flow", fail_write)
    addon.responseheaders(flow)
    assert flow.response.stream(b"still forwarded") == b"still forwarded"
    assert store.list_diagnostics()[0]["code"] == "capture_write_failed"


def test_compressed_response_decodes_without_changing_forwarded_bytes(capture):
    store, _, addon = capture
    flow = tflow.tflow(resp=True)
    raw = gzip.compress(b'{"ok":true}')
    flow.response.headers["Content-Encoding"] = "gzip"
    addon.responseheaders(flow)
    assert flow.response.stream(raw) == raw
    flow.response.stream(b"")
    addon.response(flow)
    row = store.flow(flow.id)
    assert store.payload_path(flow.id, "response").read_bytes() == b'{"ok":true}'
    assert row["response_body_encoding"] == "decoded"
    assert row["response_observed_size"] == len(raw)


def test_passthrough_and_host_exclusion_use_native_tls_hook(capture):
    store, session, _ = capture
    for mode, exclusions in (("passthrough", []), ("decrypt", [r"(^|\.)example\.test:443$"])):
        addon = CaptureAddon(store, session["id"], "local", https_mode=mode, ignore_hosts=exclusions)
        flow = tflow.tflow()
        flow.server_conn.address = ("example.test", 443)
        data = SimpleNamespace(context=SimpleNamespace(client=flow.client_conn, server=flow.server_conn),
                               client_hello=SimpleNamespace(sni="example.test"), ignore_connection=False)
        addon.tls_clienthello(data)
        assert data.ignore_connection is True
        row = store.list_flows()[0]
        assert row["capture_kind"] == "tls" and row["response_size"] == 0 and row["complete"] == 0


def test_tls_failure_has_actionable_diagnostic(capture):
    store, _, addon = capture
    flow = tflow.tflow()
    flow.client_conn.error = "certificate unknown"
    addon.tls_failed_client(SimpleNamespace(conn=flow.client_conn,
                                           context=SimpleNamespace(server=flow.server_conn)))
    diagnostic = store.list_diagnostics()[0]
    assert diagnostic["code"] == "client_tls_failed" and "ato cert" in diagnostic["message"]


def test_websocket_current_mitmproxy_hook(capture):
    store, _, addon = capture
    flow = tflow.tflow(resp=True, ws=True)
    addon.response(flow)
    addon.websocket_message(flow)
    row = store.flow(flow.id)
    assert len(row["websocket_messages"]) == 1
    message = row["websocket_messages"][0]
    assert message["payload_size"] > 0 and (store.db_path.parent / message["payload_path"]).is_file()


def test_sse_multiline_events(capture):
    store, _, addon = capture
    flow = tflow.tflow(resp=True)
    flow.response.headers["content-type"] = "text/event-stream"
    flow.response.raw_content = b":comment\nevent: delta\ndata: one\ndata: two\n\n"
    addon.response(flow)
    events = store.flow(flow.id)["stream_events"]
    assert len(events) == 1 and events[0]["data"] == "one\ntwo"


def test_sse_indexes_complete_events_in_truncated_plaintext_prefix(capture):
    store, _, addon = capture
    flow = tflow.tflow(resp=True)
    flow.response.headers["content-type"] = "text/event-stream"
    addon.responseheaders(flow)
    raw = b"data: first\n\n" + b"data: " + b"x" * 100 + b"\n\n"
    assert flow.response.stream(raw) == raw
    flow.response.stream(b"")
    addon.response(flow)
    row = store.flow(flow.id)
    assert row["response_truncated"] and row["stream_events"][0]["data"] == "first"
    assert len(row["stream_events"]) == 1


def test_stopped_session_stops_recording(capture):
    store, session, addon = capture
    store.stop_session(session["id"])
    addon.response(tflow.tflow(resp=True))
    assert store.list_flows() == []


def test_api_detail_download_status_and_path_confinement(capture, tmp_path):
    store, session, addon = capture
    flow = tflow.tflow(resp=True)
    flow.response.headers["content-type"] = "application/json"
    flow.response.raw_content = b'{"message":"<script>untrusted</script>"}'
    addon.response(flow)
    settings = Settings(tmp_path, max_body_bytes=64, mitmproxy_confdir=tmp_path / "ca")
    with TestClient(create_app(settings, store, session["id"]), base_url="http://127.0.0.1") as client:
        status = client.get("/api/status").json()
        assert status["mode"] == "local" and status["https_mode"] == "passthrough"
        result = client.get(f"/api/flows/{flow.id}").json()
        assert result["response_payload"]["format"] == "text"
        assert json.loads(result["response_payload"]["preview"])["message"].startswith("<script>")
        download = client.get(f"/api/flows/{flow.id}/payload/response")
        assert download.content == flow.response.raw_content
        assert download.headers["content-disposition"].startswith("attachment")
        assert client.get("/api/flows/missing").status_code == 404
        assert client.get(f"/api/flows/{flow.id}/payload/invalid").status_code == 400
        assert client.post("/api/sessions").status_code == 409
        assert client.post("/api/sessions/missing/stop").status_code == 404
        assert client.get("/api/status", headers={"host": "untrusted.test"}).status_code == 400
        with store._connect() as db:
            db.execute("UPDATE network_flows SET response_body_path=? WHERE id=?", ("../outside.txt", flow.id))
        assert client.get(f"/api/flows/{flow.id}/payload/response").status_code == 404


def test_lock_rejects_second_gateway(tmp_path):
    with capture_lock(tmp_path):
        with pytest.raises(RuntimeError, match="already"):
            with capture_lock(tmp_path):
                pass
    with capture_lock(tmp_path):
        pass


def test_proxy_startup_failure_is_detected(tmp_path):
    with pytest.raises(RuntimeError, match="startup"):
        wait_for_proxy(SimpleNamespace(poll=lambda: 1), tmp_path / "ready", timeout=1)


def test_storage_upgrades_existing_database_and_reports_truncation(tmp_path):
    import sqlite3
    with sqlite3.connect(tmp_path / "index.sqlite") as db:
        db.execute("CREATE TABLE capture_sessions(id TEXT PRIMARY KEY,name TEXT NOT NULL,started_at TEXT NOT NULL,"
                   "stopped_at TEXT,status TEXT NOT NULL DEFAULT 'recording')")
        db.execute("INSERT INTO capture_sessions VALUES('old','old','2026-01-01',NULL,'recording')")
    store = Store(tmp_path / "index.sqlite", tmp_path / "payloads", max_body_bytes=3)
    assert store.session("old")["mode"] == "proxy"
    flow = {"id": "bounded", "session_id": "old", "seen_at": "2026-01-01", "mode": "proxy", "complete": 1,
            "request_body": b"12345", "response_body": b"abcdef"}
    store.add_flow(flow)
    assert flow["request_body"] == b"12345"
    row = store.flow("bounded")
    assert row["response_truncated"] == 1 and row["response_observed_size"] == 6
