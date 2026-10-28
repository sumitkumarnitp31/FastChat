"""
identity_store.py
==================
Persists a client's long-term E2E identity keypair, plus any peer shared
keys it has already derived, to local disk -- so a user doesn't get a
brand-new (and therefore incompatible) keypair every time they restart
`client.py`.

WHY THIS MATTERS: without this, every client run calls
`e2e_crypto.generate_keypair()` fresh, meaning:
  - Every restart requires re-running `/addkey` with every peer, forever.
  - Worse: if BOTH sides eventually restart, the public key a peer has
    cached for you no longer matches any key you actually hold anymore --
    messages encrypted against your old public key become permanently
    undecryptable, including ones queued for offline delivery.

Real E2E systems (Signal, WhatsApp, iMessage) all generate a long-term
identity keypair ONCE per device/account and reuse it indefinitely. This
module does the same thing, scoped to `username` since multiple users may
run `client.py` from the same machine/checkout.

STORAGE FORMAT: plain JSON files under `server/.fastchat_identities/`,
containing base64-encoded key material. `os.chmod(..., 0o600)` is applied
on creation so at least only the owning OS user can read the file.

Security Note For Production: private keys here are stored unencrypted at
rest. A real deployment should encrypt this file with a user-supplied
passphrase (e.g. via `cryptography`'s `Scrypt` KDF + Fernet) rather than
storing the raw private key in plaintext on disk.
"""

import json
import os
from pathlib import Path
from typing import Optional

from e2e_crypto import generate_keypair, b64, unb64

STORE_DIR = Path(__file__).resolve().parent / ".fastchat_identities"


def _identity_path(username: str) -> Path:
    return STORE_DIR / f"{username}.identity.json"


def _peers_path(username: str) -> Path:
    return STORE_DIR / f"{username}.peers.json"


def load_or_create_identity(username: str) -> tuple[bytes, bytes, bool]:
    """
    Returns (private_key_bytes, public_key_bytes, was_newly_created).
    Loads the existing identity for this username if one exists on disk;
    otherwise generates one and persists it before returning.
    """
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    path = _identity_path(username)

    if path.exists():
        data = json.loads(path.read_text())
        return unb64(data["private_key"]), unb64(data["public_key"]), False

    private_key, public_key = generate_keypair()
    path.write_text(json.dumps({
        "private_key": b64(private_key),
        "public_key": b64(public_key),
    }))
    try:
        os.chmod(path, 0o600)   # best-effort; no-op on some platforms (e.g. Windows)
    except Exception:
        pass
    return private_key, public_key, True


def load_peer_keys(username: str) -> dict[int, bytes]:
    """Returns {peer_user_id: shared_aes_key_bytes} previously established, if any."""
    path = _peers_path(username)
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {int(peer_id): unb64(key_b64) for peer_id, key_b64 in data.items()}


def save_peer_key(username: str, peer_user_id: int, shared_key: bytes) -> None:
    """Persists one derived shared key so future sessions don't need /addkey again."""
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    path = _peers_path(username)
    data = {}
    if path.exists():
        data = json.loads(path.read_text())
    data[str(peer_user_id)] = b64(shared_key)
    path.write_text(json.dumps(data))
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
