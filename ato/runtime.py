from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


def mitmdump_executable() -> str:
    sibling = Path(sys.executable).with_name("mitmdump.exe" if os.name == "nt" else "mitmdump")
    executable = str(sibling) if sibling.is_file() else shutil.which("mitmdump")
    if not executable:
        raise RuntimeError("mitmdump is unavailable; install the project dependencies in this Python environment")
    return executable


def check_port(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind((host, port))
        except OSError as exc:
            raise RuntimeError(f"Cannot listen on {host}:{port}; another server may already be running") from exc


def wait_for_proxy(proxy: subprocess.Popen, ready_path: Path, timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        code = proxy.poll()
        if code is not None:
            raise RuntimeError(f"mitmdump exited during startup (code {code}); see the error above")
        if ready_path.is_file():
            return
        time.sleep(0.1)
    raise RuntimeError("mitmdump did not become ready; check local-capture permissions and proxy errors")


def terminate_proxy(proxy: subprocess.Popen) -> None:
    if proxy.poll() is None:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.wait(timeout=5)


@contextmanager
def capture_lock(capture_dir: Path) -> Iterator[None]:
    """OS releases this lock even after a crash; recordings must have a single writer."""
    with (capture_dir / ".gateway.lock").open("a+b") as handle:
        handle.seek(0, 2)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError("A gateway is already using this capture directory") from exc
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
