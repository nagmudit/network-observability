"""Public CA information only; trust installation remains an operator action."""
from __future__ import annotations

import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from mitmproxy.certs import CertStore


def initialize_ca(confdir: Path) -> None:
    # Use mitmproxy's own certificate store, exactly as mitmdump does.
    CertStore.from_store(confdir, "mitmproxy", 2048)


def certificate_status(confdir: Path) -> dict[str, Any]:
    path = confdir.resolve() / "mitmproxy-ca-cert.pem"
    result: dict[str, Any] = {
        "path": str(path), "exists": path.is_file(), "trusted": None,
        "valid": False, "sha256": None, "sha1": None,
        "trust_scope": "Windows ROOT store" if sys.platform == "win32" else "application-specific",
    }
    if not path.is_file():
        return result
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        now = datetime.now(timezone.utc)
        result.update(valid=cert.not_valid_before_utc <= now <= cert.not_valid_after_utc,
                      sha256=cert.fingerprint(hashes.SHA256()).hex().upper(),
                      sha1=cert.fingerprint(hashes.SHA1()).hex().upper())
        if sys.platform == "win32":
            der = cert.public_bytes(serialization.Encoding.DER)
            result["trusted"] = any(
                encoding == "x509_asn" and value == der and (trust is True or "1.3.6.1.5.5.7.3.1" in trust)
                for value, encoding, trust in ssl.enum_certificates("ROOT")
            )
    except (ValueError, OSError) as exc:
        result["error"] = str(exc)
    return result


def resolve_https_mode(requested: str, ca: dict[str, Any]) -> str:
    if requested not in {"auto", "decrypt", "passthrough"}:
        raise ValueError("--https must be auto, decrypt, or passthrough")
    if requested == "auto":
        return "decrypt" if ca["trusted"] is True and ca["valid"] else "passthrough"
    if requested == "decrypt" and not ca["valid"]:
        raise ValueError("The mitmproxy CA is missing or expired. Run ato cert, then review its setup instructions.")
    # Explicit decrypt supports clients that trust this CA in a separate store.
    return requested
