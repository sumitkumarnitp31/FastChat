"""
gen_dev_certs.py
================
Generates a self-signed TLS certificate for LOCAL DEVELOPMENT ONLY, using
the `cryptography` package instead of shelling out to the `openssl` CLI.

Why this exists alongside gen_dev_certs.sh: on Windows, `openssl` usually
isn't on PATH by default (it ships with Git Bash / WSL, but not a stock
Windows 11 install), so the bash script fails for a lot of Windows users.
This does the exact same thing in pure Python, which I have already
installed as part of this project's dependencies.

Usage:
    python deployment/gen_dev_certs.py

Produces:
    server/certs/server.key
    server/certs/server.crt
"""

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUT_DIR = Path(__file__).resolve().parent.parent / "server" / "certs"


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    key_path = OUT_DIR / "server.key"
    cert_path = OUT_DIR / "server.crt"

    if key_path.exists() and cert_path.exists():
        # Idempotent on purpose: this script is also invoked as a one-shot
        # Docker service (see docker-compose.yml's `cert-init`) that runs
        # every `docker compose up`. Without this check, a restart would
        # silently regenerate a new cert every time, which is harmless for
        # local dev but pointless churn -- and if we ever wire in a real
        # CA-issued cert to these same paths, we don't want this script
        # clobbering it.
        print(f"Certs already exist at {OUT_DIR} -- skipping generation.")
        print("Delete server/certs/ if we want a fresh self-signed cert.")
        return

    # Generate a 4096-bit RSA keypair for the server's TLS certificate.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)   # self-signed: issuer == subject
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated {key_path}")
    print(f"Generated {cert_path}")
    print("These paths already match CERT_FILE/KEY_FILE in tcp_server.py and "
          "CA_CERT_FILE in client.py -- no further edits needed.")


if __name__ == "__main__":
    main()
