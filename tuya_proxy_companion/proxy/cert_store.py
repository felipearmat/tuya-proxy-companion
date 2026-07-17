"""TLS certificate generation and caching for the MITM proxy."""

from __future__ import annotations

import datetime
import logging
from pathlib import Path

_LOGGER = logging.getLogger(__name__)
_CERT_DIR = Path("/data/proxy_certs")


def get_or_create_cert(domain: str) -> tuple[str, str]:
    """Return (cert_path, key_path) for domain, generating if missing. Blocking."""
    _CERT_DIR.mkdir(parents=True, exist_ok=True)
    safe = domain.replace(".", "_").replace("*", "wildcard")
    cert_path = _CERT_DIR / f"{safe}.crt"
    key_path = _CERT_DIR / f"{safe}.key"
    if not cert_path.exists() or not key_path.exists():
        _generate(domain, cert_path, key_path)
    return str(cert_path), str(key_path)


def _generate(domain: str, cert_path: Path, key_path: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    _LOGGER.info("cert_store: generated TLS cert for %s", domain)
