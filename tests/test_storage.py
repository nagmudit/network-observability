from pathlib import Path

from ato.storage import Store, redact_headers


def test_redacts_sensitive_headers() -> None:
    assert redact_headers({"Authorization": "secret", "X-Test": "ok"}, False) == {
        "Authorization": "<redacted>", "X-Test": "ok"
    }


def test_flow_persists_payloads(tmp_path: Path) -> None:
    store = Store(tmp_path / "index.sqlite", tmp_path / "payloads")
    session = store.create_session("test")
    store.add_flow({
        "id": "flow-1", "session_id": session["id"], "seen_at": "2026-01-01T00:00:00Z",
        "mode": "proxy", "host": "example.test", "method": "POST", "path": "/x",
        "url": "http://example.test/x", "status": 200, "complete": 1,
        "request_headers": {"X-Test": "ok"}, "response_headers": {},
        "request_body": b"request", "response_body": b"response",
    })
    flow = store.list_flows()[0]
    assert flow["request_size"] == 7
    assert flow["response_size"] == 8
    assert (tmp_path / flow["request_body_path"]).exists()
