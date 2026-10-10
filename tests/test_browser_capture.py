import base64
import os
import socket
import subprocess
import sys
import time

import httpx
from fastapi.testclient import TestClient
import pytest

from ato.api import create_app
from ato.config import Settings
from ato.storage import Store

EXTENSION = "chrome-extension://" + "a" * 32


@pytest.fixture
def observer(tmp_path):
    settings = Settings(tmp_path, max_body_bytes=8, mitmproxy_confdir=tmp_path / "unused-ca")
    store = Store(settings.database_path, settings.payload_dir, max_body_bytes=8)
    session = store.create_session("browser", "browser", "browser")
    with TestClient(create_app(settings, store, session["id"]), base_url="http://127.0.0.1") as client:
        key = client.get("/api/browser/setup").json()["pairing_key"]
        yield client, store, session, {"X-ATO-Pairing-Key": key, "Origin": EXTENSION}


def observation(**changes):
    value = {"id": "example-1", "url": "https://example.test/api?q=one", "method": "POST",
             "seen_at": "2026-10-10T10:00:00Z", "status": 200, "duration_ms": 20, "tab_id": 12,
             "request_headers": [{"name": "Authorization", "value": "test-only"}],
             "response_headers": [{"name": "Content-Type", "value": "application/json"}],
             "request_body_base64": base64.b64encode(b"request").decode(),
             "response_body_base64": base64.b64encode(b'{"ok":true}').decode(),
             "response_reported_size": 11}
    value.update(changes)
    return value


def test_browser_observation_persists_https_body_without_ca(observer):
    client, store, session, headers = observer
    connected = client.post("/api/browser/connect", json={}, headers=headers)
    assert connected.status_code == 200 and connected.json()["max_body_bytes"] == 8
    response = client.post("/api/browser/flows", json=observation(), headers=headers)
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == EXTENSION
    flow_id = response.json()["id"]
    flow = client.get(f"/api/flows/{flow_id}").json()
    assert flow["mode"] == "browser" and flow["host"] == "example.test"
    assert flow["request_headers"]["Authorization"] == "<redacted>"
    assert flow["request_payload"]["preview"] == "request"
    assert flow["response_payload"]["preview"] == '{"ok":tr'
    assert flow["response_payload"]["truncated"] and flow["response_payload"]["size_source"] == "browser"
    assert flow["connection_info"]["tab_id"] == 12
    assert not client.app.state.settings.mitmproxy_confdir.exists()
    state = client.get("/api/status").json()
    assert state["mode"] == "browser" and state["proxy"] is None
    assert state["session_stats"]["browser_flows"] == 1
    client.post("/api/browser/flows", json=observation(), headers=headers)
    assert len(store.list_flows()) == 1  # retries are idempotent


def test_pairing_key_and_origin_required(observer):
    client, _, _, headers = observer
    assert client.post("/api/browser/flows", json=observation()).status_code == 403
    assert client.post("/api/browser/flows", json=observation(), headers={**headers, "X-ATO-Pairing-Key": "wrong"}).status_code == 403
    hostile = {**headers, "Origin": "https://untrusted.test"}
    assert client.post("/api/browser/flows", json=observation(), headers=hostile).status_code == 403
    assert client.get("/api/browser/setup", headers={"Origin": EXTENSION}).status_code == 403
    assert client.options("/api/browser/flows", headers={"Origin": "https://untrusted.test"}).status_code == 403
    assert client.options("/api/browser/flows", headers={"Origin": EXTENSION}).status_code == 204


@pytest.mark.parametrize("changes", [
    {"response_body_base64": "not-base64"}, {"url": "file:///private"},
    {"url": "https://user:password@example.test/"}, {"response_reported_size": -1},
    {"response_body_base64": base64.b64encode(b"x" * (128 * 1024 + 1)).decode()},
])
def test_rejects_invalid_observations_without_echoing_data(observer, changes):
    client, store, _, headers = observer
    r = client.post("/api/browser/flows", json=observation(**changes), headers=headers)
    assert r.status_code == 422 and r.json()["detail"] == "Invalid browser observation"
    assert store.list_flows() == []


def test_enforces_import_size_and_stopped_session(observer):
    client, _, session, headers = observer
    too_large = client.post("/api/browser/flows", content=b" " * (1024 * 1024 + 1),
                            headers={**headers, "Content-Type": "application/json"})
    assert too_large.status_code == 413
    client.post(f"/api/sessions/{session['id']}/stop")
    assert client.post("/api/browser/flows", json=observation(), headers=headers).status_code == 409


def test_unavailable_body_is_explicit_and_unknown_size_stays_unknown(observer):
    client, _, _, headers = observer
    r = client.post("/api/browser/flows", json=observation(request_body_base64=None,
                    response_body_base64=None, response_reported_size=None), headers=headers)
    row = client.get("/api/flows/" + r.json()["id"]).json()
    assert not row["response_payload"]["available"]
    assert row["response_payload"]["observed_wire_bytes"] is None
    assert "not supplied" in row["capture_note"]


def test_real_observer_cli_receives_payload_and_stops_without_ca(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = os.environ.copy()
    env.update(ATO_CAPTURE_DIR=str(tmp_path / "capture"), ATO_MITMPROXY_CONFDIR=str(tmp_path / "no-ca"))
    with (tmp_path / "observer.log").open("w") as log:
        process = subprocess.Popen([sys.executable, "-m", "ato.cli", "observe", "--control-port", str(port)],
                                   env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=2) as client:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        setup = client.get("/api/browser/setup").json()
                        break
                    except httpx.HTTPError:
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise AssertionError((tmp_path / "observer.log").read_text())
                        time.sleep(0.05)
                headers = {"X-ATO-Pairing-Key": setup["pairing_key"]}
                response = client.post("/api/browser/flows", json=observation(), headers=headers)
                response.raise_for_status()
                flow = client.get("/api/flows/" + response.json()["id"]).json()
                assert flow["response_payload"]["preview"] == '{"ok":true}'
                assert not (tmp_path / "no-ca").exists()
                assert client.get("/").status_code == 200
                client.post("/api/sessions/" + setup["session_id"] + "/stop").raise_for_status()
                assert process.wait(timeout=8) == 0
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
