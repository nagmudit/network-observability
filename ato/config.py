from __future__ import annotations

import os
from dataclasses import dataclass
from dataclasses import field
import ipaddress
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    capture_dir: Path
    control_host: str = "127.0.0.1"
    control_port: int = 8765
    proxy_port: int = 8080
    max_body_bytes: int = 10 * 1024 * 1024
    sensitive_mode: bool = False
    mitmproxy_confdir: Path = field(default_factory=lambda: Path.home() / ".mitmproxy")

    def __post_init__(self) -> None:
        if self.control_host != "localhost" and not ipaddress.ip_address(self.control_host).is_loopback:
            raise ValueError("ATO_CONTROL_HOST must be a loopback address")
        if not all(1 <= port <= 65535 for port in (self.control_port, self.proxy_port)):
            raise ValueError("Ports must be between 1 and 65535")
        if self.max_body_bytes < 1:
            raise ValueError("ATO_MAX_BODY_BYTES must be positive")

    @property
    def control_url(self) -> str:
        host = f"[{self.control_host}]" if ":" in self.control_host else self.control_host
        return f"http://{host}:{self.control_port}"

    @property
    def database_path(self) -> Path:
        return self.capture_dir / "index.sqlite"

    @property
    def payload_dir(self) -> Path:
        return self.capture_dir / "payloads"

    @property
    def flow_path(self) -> Path:
        return self.capture_dir / "traffic.mitm"

    @classmethod
    def from_environment(cls, capture_dir: Path | None = None) -> "Settings":
        root = capture_dir or Path(os.getenv("ATO_CAPTURE_DIR", "captures/current"))
        return cls(
            capture_dir=root,
            control_host=os.getenv("ATO_CONTROL_HOST", "127.0.0.1"),
            control_port=int(os.getenv("ATO_CONTROL_PORT", "8765")),
            proxy_port=int(os.getenv("ATO_PROXY_PORT", "8080")),
            max_body_bytes=int(os.getenv("ATO_MAX_BODY_BYTES", str(10 * 1024 * 1024))),
            sensitive_mode=os.getenv("ATO_SENSITIVE_MODE", "").lower() == "true",
            mitmproxy_confdir=Path(os.getenv("ATO_MITMPROXY_CONFDIR", str(Path.home() / ".mitmproxy"))),
        )

    def ensure_directories(self) -> None:
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.payload_dir.mkdir(parents=True, exist_ok=True)
