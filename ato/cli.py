from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
from dataclasses import replace
from pathlib import Path

import typer
import uvicorn

from .api import create_app
from .certificates import certificate_status, initialize_ca, resolve_https_mode
from .config import Settings
from .runtime import capture_lock, check_port, mitmdump_executable, terminate_proxy, wait_for_proxy
from .storage import Store

app = typer.Typer(no_args_is_help=True)


def get_store() -> tuple[Settings, Store]:
    settings = Settings.from_environment()
    settings.ensure_directories()
    return settings, Store(settings.database_path, settings.payload_dir, settings.max_body_bytes, settings.sensitive_mode)


def print_certificate_setup(settings: Settings) -> None:
    ca = certificate_status(settings.mitmproxy_confdir)
    typer.echo(f"Public CA: {ca['path']}")
    typer.echo(f"CA valid: {ca['valid']}; Windows trust: {ca['trusted']}")
    if ca["sha256"]:
        typer.echo(f"SHA256 fingerprint: {ca['sha256']}")
    if sys.platform == "win32":
        public_path = settings.mitmproxy_confdir.resolve() / "mitmproxy-ca-cert.cer"
        typer.echo("For Chrome/Edge, review this local CA, then run in PowerShell to trust it for your user:")
        typer.echo(f'certutil -user -addstore Root "{public_path}"')
        typer.echo("Restart the browser and gateway after installing trust.")
        typer.echo(f"To remove this CA later: certutil -user -delstore Root {ca['sha1']}")
    typer.echo("Separate certificate stores (Firefox/Python/Java) may need their own CA setup.")
    typer.echo("With a configured explicit proxy, http://mitm.it also provides setup instructions.")
    typer.echo("ATO does not install trust roots or change Windows proxy settings.")


@app.command()
def cert() -> None:
    """Generate/reuse mitmproxy's CA and print public certificate trust instructions."""
    settings = Settings.from_environment()
    initialize_ca(settings.mitmproxy_confdir)
    print_certificate_setup(settings)


@app.command()
def doctor() -> None:
    """Check the local runtime, certificate trust, and capture prerequisites."""
    settings = Settings.from_environment()
    typer.echo(f"Python: {sys.version.split()[0]}")
    try:
        executable = mitmdump_executable()
        version = subprocess.check_output([executable, "--version"], text=True, stderr=subprocess.STDOUT).strip()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        typer.echo(f"mitmproxy unavailable: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(f"mitmproxy executable: {executable}")
    typer.echo(version)
    typer.echo(f"Capture directory: {settings.capture_dir.resolve()}")
    ca = certificate_status(settings.mitmproxy_confdir)
    typer.echo(f"Public CA: {ca['path']}; valid: {ca['valid']}; Windows trust: {ca['trusted']}")
    typer.echo(f"Default HTTPS mode: {resolve_https_mode('auto', ca)}")
    if ca["trusted"] is not True:
        typer.echo("HTTPS will pass through encrypted until CA trust is configured. Run ato cert for instructions.")
    for label, host, port in (("Control", settings.control_host, settings.control_port),
                              ("Explicit proxy", "127.0.0.1", settings.proxy_port)):
        try:
            check_port(host, port)
            typer.echo(f"{label}: {host}:{port} available")
        except RuntimeError as exc:
            typer.echo(str(exc))
    typer.echo(f"Browser proxy: launch Chrome/Edge with --proxy-server=http://127.0.0.1:{settings.proxy_port} and a separate profile.")
    typer.echo("If the proxy port is occupied, choose another with ato start --proxy-port 8081.")
    typer.echo("Local mode captures targeted processes without proxy settings; Windows may request elevation.")


def build_command(settings: Settings, mode: str, processes: str | None, raw_path: Path | None = None) -> list[str]:
    addon = Path(__file__).with_name("addon.py").resolve()
    command = [mitmdump_executable(), "--mode", f"local:{processes}" if processes else mode if mode == "local" else "regular",
               "--listen-host", "127.0.0.1", "--listen-port", str(settings.proxy_port),
               "--set", f"confdir={settings.mitmproxy_confdir.resolve()}", "--set", "ssl_insecure=false",
               "--set", "flow_detail=0", "-s", str(addon)]
    if raw_path:
        command.extend(["-w", str(raw_path)])
    return command


def run_gateway(settings: Settings, store: Store, mode: str, name: str, https: str,
                processes: str | None, ignore_hosts: list[str], raw_flows: bool) -> None:
    check_port(settings.control_host, settings.control_port)
    if mode == "proxy":
        check_port("127.0.0.1", settings.proxy_port)
    initialize_ca(settings.mitmproxy_confdir)
    https_mode = resolve_https_mode(https, certificate_status(settings.mitmproxy_confdir))
    # This directory's lock proves no older gateway is recording; recover stale session state.
    while previous := store.current_session():
        store.stop_session(previous["id"])
    session = store.create_session(name, mode, https_mode, processes)
    run_dir = settings.capture_dir.resolve() / "sessions" / session["id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    ready_path = run_dir / "ready"
    raw_path = run_dir / "traffic.mitm" if raw_flows else None
    env = os.environ.copy()
    env.update({
        "ATO_CAPTURE_DIR": str(settings.capture_dir.resolve()), "ATO_SESSION_ID": session["id"],
        "ATO_CAPTURE_MODE": mode, "ATO_HTTPS_MODE": https_mode,
        "ATO_SENSITIVE_MODE": str(settings.sensitive_mode).lower(), "ATO_MAX_BODY_BYTES": str(settings.max_body_bytes),
        "ATO_IGNORE_HOSTS": json.dumps(ignore_hosts), "ATO_READY_PATH": str(ready_path),
        "ATO_RAW_FLOW_PATH": str(raw_path) if raw_path else "",
    })
    # Ensure the addon imports the same installed package/source even when cwd changes.
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent) + os.pathsep + env.get("PYTHONPATH", "")
    proxy = None
    monitor_done = threading.Event()
    try:
        typer.echo(f"HTTPS: {https_mode}")
        if https_mode == "passthrough":
            typer.echo("HTTPS browsing keeps the original server certificate. Only connection metadata is captured.")
            typer.echo("For HTTPS payloads, run ato cert, configure trust, then restart with --https decrypt.")
        elif certificate_status(settings.mitmproxy_confdir)["trusted"] is not True:
            typer.echo("Decryption explicitly selected: the target client must trust the CA in its own store.")
        typer.echo(f"Capture mode: {mode}" + (f" ({processes})" if processes else ""))
        if mode == "proxy":
            typer.echo(f"Configure the browser/app proxy as http://127.0.0.1:{settings.proxy_port}.")
        if raw_flows:
            typer.echo("Native archives are unredacted, and streamed bodies are absent; protect the capture directory.")
        proxy = subprocess.Popen(build_command(settings, mode, processes, raw_path), env=env)
        wait_for_proxy(proxy, ready_path)
        server = uvicorn.Server(uvicorn.Config(create_app(settings, store, session["id"]),
                                               host=settings.control_host, port=settings.control_port))

        def monitor() -> None:
            while not monitor_done.wait(0.5):
                if proxy.poll() is not None:
                    store.add_diagnostic(session["id"], "error", "proxy_exited",
                                         f"mitmdump exited (code {proxy.returncode}); capture stopped.")
                    server.should_exit = True
                    return
                if not store.is_recording(session["id"]):
                    server.should_exit = True
                    return

        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        typer.echo(f"Session {session['id']} ready. Viewer: {settings.control_url}/")
        typer.echo("Stop with Ctrl+C or ato stop. Remove any manually configured proxy after stopping.")
        try:
            server.run()
        finally:
            monitor_done.set()
            thread.join(timeout=2)
        if proxy.poll() is not None:
            raise RuntimeError(f"Capture engine exited unexpectedly (code {proxy.returncode})")
    except (OSError, RuntimeError) as exc:
        store.add_diagnostic(session["id"], "error", "capture_failed", str(exc))
        raise
    finally:
        monitor_done.set()
        if proxy is not None:
            terminate_proxy(proxy)
        ready_path.unlink(missing_ok=True)
        store.stop_session(session["id"])


@app.command()
def start(mode: str = typer.Option("proxy", help="proxy or local"),
          name: str = "Research session",
          https: str = typer.Option("auto", help="auto (trust-aware), decrypt, or passthrough"),
          processes: str | None = typer.Option(None, help="Local mode process names/PIDs, comma separated; e.g. chrome,msedge"),
          ignore_host: list[str] | None = typer.Option(None, help=r"Repeatable host:port regex for TLS passthrough; e.g. (^|\.)example\.com:443$"),
          raw_flows: bool = typer.Option(False, help="Also write an unredacted native mitmproxy archive"),
          proxy_port: int | None = typer.Option(None, min=1, max=65535, help="Explicit proxy port; overrides ATO_PROXY_PORT"),
          control_port: int | None = typer.Option(None, min=1, max=65535, help="Viewer port; overrides ATO_CONTROL_PORT")) -> None:
    """Start a local capture engine and request/payload viewer."""
    if mode not in {"proxy", "local"}:
        raise typer.BadParameter("--mode must be proxy or local")
    if https not in {"auto", "decrypt", "passthrough"}:
        raise typer.BadParameter("--https must be auto, decrypt, or passthrough")
    if processes is not None and (mode != "local" or not processes.strip()):
        raise typer.BadParameter("--processes requires --mode local and a nonempty process filter")
    for pattern in ignore_host or []:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise typer.BadParameter(f"Invalid --ignore-host regex: {exc}") from exc
    try:
        settings, store = get_store()
        settings = replace(settings, proxy_port=proxy_port or settings.proxy_port,
                           control_port=control_port or settings.control_port)
        with capture_lock(settings.capture_dir):
            run_gateway(settings, store, mode, name, https, processes, ignore_host or [], raw_flows)
    except (OSError, ValueError, RuntimeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc


@app.command()
def observe(name: str = "Browser observation", control_port: int | None = typer.Option(None, min=1, max=65535)) -> None:
    """Run the browser connector/viewer without a proxy, TLS interception, or CA setup."""
    try:
        settings, store = get_store()
        settings = replace(settings, control_port=control_port or settings.control_port)
        with capture_lock(settings.capture_dir):
            check_port(settings.control_host, settings.control_port)
            while previous := store.current_session():
                store.stop_session(previous["id"])
            session = store.create_session(name, "browser", "browser")
            server = uvicorn.Server(uvicorn.Config(create_app(settings, store, session["id"]),
                                                   host=settings.control_host, port=settings.control_port))
            finished = threading.Event()

            def monitor() -> None:
                while not finished.wait(0.5):
                    if not store.is_recording(session["id"]):
                        server.should_exit = True
                        return

            thread = threading.Thread(target=monitor, daemon=True)
            thread.start()
            typer.echo(f"Browser observer ready. Viewer: {settings.control_url}/")
            typer.echo("Load the browser extension, open DevTools > ATO, pair, and start recording the inspected tab.")
            typer.echo("No CA installation or proxy routing. Stop with ato stop or Ctrl+C.")
            try:
                server.run()
            finally:
                finished.set()
                thread.join(timeout=2)
                store.stop_session(session["id"])
    except (OSError, ValueError, RuntimeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc


@app.command()
def marker(label: str) -> None:
    """Add a marker to the active session."""
    _, store = get_store()
    session = store.current_session()
    if not session:
        raise typer.BadParameter("no active capture session")
    typer.echo(store.marker(session["id"], label)["id"])


@app.command()
def stop() -> None:
    """Stop the active recording and its capture engine/control server."""
    _, store = get_store()
    session = store.current_session()
    if session:
        store.stop_session(session["id"])
        typer.echo(f"Stopping {session['id']}; the running gateway will exit.")
    else:
        typer.echo("No active session")


@app.command()
def status() -> None:
    """Show capture status."""
    _, store = get_store()
    typer.echo(store.current_session() or "No active session")


if __name__ == "__main__":
    app()
