"""
e2e_crypto.py
=============
IMPORTANT DISTINCTION:

  TLS (what tcp_server.py / client.py set up via `ssl.SSLContext`) encrypts
  data IN TRANSIT between a client and the server. The server terminates
  that TLS connection, so the server itself sees plaintext bytes. That is
  "encryption in transit," not "end-to-end encryption" -- a compromised or
  subpoenaed server can still read message content.

  TRUE end-to-end encryption (E2E) means the server only ever handles
  ciphertext it cannot decrypt -- only the two conversing clients hold the
  keys. This module implements that layer:

    - Each client generates a long-term X25519 keypair on first run.
    - Public keys are published via the FastAPI auth API (users.public_key) so
      peers can look each other up.
    - For a conversation between Alice and Bob, both sides independently
      compute the same shared secret via X25519 Diffie-Hellman
      (Alice's private + Bob's public == Bob's private + Alice's public).
    - That shared secret is fed through HKDF to derive an AES-256-GCM key.
    - Message bodies are encrypted with that key before ever touching the
      socket. The server relays/stores only ciphertext + nonce.

  Use TLS AND this module together: TLS protects metadata/framing and
  prevents tampering/MITM on the wire; this module protects the message
  body itself even from the server operator.
"""

import os
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_keypair() -> tuple[bytes, bytes]:
    """Returns (private_key_bytes, public_key_bytes), both raw 32-byte X25519 keys."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def derive_shared_key(my_private_bytes: bytes, their_public_bytes: bytes) -> bytes:
    """
    Diffie-Hellman: both parties call this with their own private key and the
    other party's public key and arrive at the identical 32-byte AES key.
    """
    private_key = X25519PrivateKey.from_private_bytes(my_private_bytes)
    peer_public_key = X25519PublicKey.from_public_bytes(their_public_bytes)
    shared_secret = private_key.exchange(peer_public_key)

    # HKDF turns the raw DH output into a uniformly random, fixed-length AES key.
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"fastchat-e2e-v1",
    ).derive(shared_secret)


def encrypt_message(key: bytes, plaintext: str) -> tuple[bytes, bytes]:
    """Returns (ciphertext, nonce). AES-GCM nonce must never repeat for a given key."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return ciphertext, nonce


def decrypt_message(key: bytes, ciphertext: bytes, nonce: bytes) -> str:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))
