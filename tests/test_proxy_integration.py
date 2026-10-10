"""Real mitmdump tests on loopback. Never install a certificate or change OS proxy settings."""
from contextlib import contextmanager
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import serialization
import httpx
from mitmproxy.certs import CertStore
import pytest
from websockets.sync.client import connect

from ato.certificates import initialize_ca
from ato.storage import Store


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_until(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except (httpx.HTTPError, ConnectionError, FileNotFoundError):
            pass
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for local test service/capture")


def cleanup(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@pytest.fixture(scope="module")
def origin(tmp_path_factory):
    root = tmp_path_factory.mktemp("origin")
    certificates = CertStore.from_store(root / "ca", "mitmproxy", 2048)
    entry = certificates.get_cert("localhost", [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    cert_path, key_path = root / "server.pem", root / "server-key.pem"
    cert_path.write_bytes(entry.cert.to_pem())
    key_path.write_bytes(entry.privatekey.private_bytes(serialization.Encoding.PEM,
                                                      serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()))
    processes = []
    ports = []
    log_handles = []
    try:
        for secure in (False, True):
            port = free_port()
            ports.append(port)
            command = [sys.executable, "-m", "uvicorn", "ato.test_server:app", "--host", "127.0.0.1",
                       "--port", str(port), "--log-level", "error"]
            if secure:
                command += ["--ssl-certfile", str(cert_path), "--ssl-keyfile", str(key_path)]
            handle = (root / f"server-{port}.log").open("w")
            log_handles.append(handle)
            processes.append(subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT))
            context = ssl.create_default_context(cafile=str(root / "ca" / "mitmproxy-ca-cert.pem"))
            url = f"{'https' if secure else 'http'}://127.0.0.1:{port}"
            with httpx.Client(verify=context, trust_env=False, timeout=1) as client:
                wait_until(lambda: client.get(url + "/test").status_code == 200)
        yield SimpleNamespace(http=f"http://127.0.0.1:{ports[0]}", https=f"https://127.0.0.1:{ports[1]}",
                              ca=root / "ca" / "mitmproxy-ca-cert.pem")
    finally:
        for process in processes:
            cleanup(process)
        for handle in log_handles:
            handle.close()


@pytest.fixture
def gateway_factory(tmp_path, origin):
    @contextmanager
    def run(https="decrypt", exclusions=()):
        root = tmp_path / f"gateway-{https}"
        root.mkdir()
        confdir = root / "ca"
        initialize_ca(confdir)
        # Keep upstream verification enabled, trusting only this test origin's CA.
        (confdir / "config.yaml").write_text(f"ssl_verify_upstream_trusted_ca: '{origin.ca.as_posix()}'\n")
        proxy_port, control_port = free_port(), free_port()
        env = os.environ.copy()
        env.update(ATO_CAPTURE_DIR=str(root / "capture"), ATO_MITMPROXY_CONFDIR=str(confdir), ATO_MAX_BODY_BYTES="1024")
        command = [sys.executable, "-m", "ato.cli", "start", "--https", https,
                   "--proxy-port", str(proxy_port), "--control-port", str(control_port)]
        for pattern in exclusions:
            command += ["--ignore-host", pattern]
        logfile = root / "gateway.log"
        with logfile.open("w") as log:
            process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                with httpx.Client(base_url=f"http://127.0.0.1:{control_port}", trust_env=False, timeout=2) as control:
                    try:
                        status = wait_until(lambda: control.get("/api/status").json())
                    except AssertionError:
                        raise AssertionError(logfile.read_text())
                    assert status["capture"]["status"] == "recording"
                    actual = status["https_mode"]
                    context = ssl.create_default_context(cafile=str(confdir / "mitmproxy-ca-cert.pem" if actual == "decrypt" else origin.ca))
                    proxy_url = f"http://127.0.0.1:{proxy_port}"
                    with httpx.Client(proxy=proxy_url, verify=context, trust_env=False, timeout=5) as client:
                        yield SimpleNamespace(client=client, control=control, proxy=proxy_url, context=context,
                                              process=process, root=root, env=env, session_id=status["capture"]["id"])
                    if process.poll() is None:
                        control.post(f"/api/sessions/{status['capture']['id']}/stop").raise_for_status()
                        assert process.wait(timeout=8) == 0, logfile.read_text()
                    store = Store(root / "capture" / "index.sqlite", root / "capture" / "payloads")
                    assert store.session(status["capture"]["id"])["status"] == "stopped"
            finally:
                cleanup(process)
    return run


def completed_flow(gateway, path):
    def found():
        rows = gateway.control.get("/api/flows").json()
        return next((row for row in rows if row["path"] == path and row["complete"]), None)
    row = wait_until(found)
    return gateway.control.get(f"/api/flows/{row['id']}").json()


def test_real_http_https_payloads_gzip_limits_sse_and_websocket(gateway_factory, origin):
    with gateway_factory() as gateway:
        assert gateway.client.get(origin.http + "/test").json() == {"status": "ok"}
        assert gateway.client.post(origin.https + "/json", json={"hello": "gateway"}).json() == {"received": {"hello": "gateway"}}
        flow = completed_flow(gateway, "/json")
        assert flow["request_payload"]["preview"] == '{"hello":"gateway"}'
        assert '"gateway"' in flow["response_payload"]["preview"]
        assert flow["connection_info"]["tls_version"] and flow["connection_info"]["upstream_tls_version"]
        assert gateway.client.get(origin.https + "/gzip").json() == {"compressed": True}
        flow = completed_flow(gateway, "/gzip")
        assert flow["response_payload"]["preview"] == '{"compressed":true}'
        assert flow["response_body_encoding"] == "decoded"
        assert len(gateway.client.get(origin.http + "/large").content) == 4096
        flow = completed_flow(gateway, "/large")
        assert flow["response_size"] == 1024 and flow["response_observed_size"] == 4096
        assert flow["response_payload"]["truncated"]
        assert gateway.client.post(origin.http + "/binary", content=b"z" * 4096).text == "4096"
        flow = completed_flow(gateway, "/binary")
        assert flow["request_size"] == 1024 and flow["request_observed_size"] == 4096
        started = time.monotonic()
        with gateway.client.stream("GET", origin.http + "/stream?delay=0.5") as response:
            chunks = response.iter_lines()
            assert next(chunks) == "event: delta"
            assert time.monotonic() - started < 0.9  # Entire response takes 1.5s: must not buffer it.
            rows = gateway.control.get("/api/flows").json()
            assert any(row["path"] == "/stream?delay=0.5" and not row["complete"] for row in rows)
            assert "data: chunk-2" in list(chunks)
        flow = completed_flow(gateway, "/stream?delay=0.5")
        assert len(flow["stream_events"]) == 3
        with connect(origin.https.replace("https:", "wss:") + "/websocket", proxy=gateway.proxy, ssl=gateway.context) as socket:
            socket.send("hello")
            assert socket.recv() == "echo:hello"
        flow = completed_flow(gateway, "/websocket")
        assert [m["text_preview"] for m in flow["websocket_messages"]] == ["hello", "echo:hello"]


def test_real_auto_passthrough_without_interception_ca_trust(gateway_factory, origin):
    with gateway_factory("auto") as gateway:
        assert gateway.control.get("/api/status").json()["https_mode"] == "passthrough"
        # This client trusts the origin CA, and has never trusted the proxy's CA.
        assert gateway.client.get(origin.https + "/test").json() == {"status": "ok"}
        wait_until(lambda: any(row["capture_kind"] == "tls" for row in gateway.control.get("/api/flows").json()))
        rows = gateway.control.get("/api/flows").json()
        assert not any(row["path"] == "/test" for row in rows)
        assert all(row["response_size"] == 0 for row in rows)


def test_real_untrusted_client_diagnostic_and_cli_stop(gateway_factory, origin):
    with gateway_factory() as gateway:
        with httpx.Client(proxy=gateway.proxy, trust_env=False, timeout=5) as untrusted:
            with pytest.raises(httpx.ConnectError):
                untrusted.get(origin.https + "/test")
        diagnostics = wait_until(lambda: gateway.control.get("/api/diagnostics").json())
        assert any(d["code"] == "client_tls_failed" for d in diagnostics)
        result = subprocess.run([sys.executable, "-m", "ato.cli", "stop"], env=gateway.env,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0
        assert gateway.process.wait(timeout=8) == 0


def test_real_excluded_host_keeps_original_certificate(gateway_factory, origin):
    with gateway_factory("decrypt", [r"^127\.0\.0\.1:\d+$"]) as gateway:
        original_context = ssl.create_default_context(cafile=str(origin.ca))
        with httpx.Client(proxy=gateway.proxy, verify=original_context, trust_env=False, timeout=5) as client:
            assert client.get(origin.https + "/test").status_code == 200
        rows = wait_until(lambda: gateway.control.get("/api/flows").json())
        assert not any(row["path"] == "/test" for row in rows)
        tls_rows = [row for row in rows if row["capture_kind"] == "tls"]
        assert tls_rows and "excluded host" in tls_rows[0]["capture_note"]
