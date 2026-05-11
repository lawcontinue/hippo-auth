"""Ed25519 key management: generate, load, serialize."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass
class KeyPair:
    private_key: Ed25519PrivateKey
    keyid: str  # URL where public key can be resolved

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def public_bytes_raw(self) -> bytes:
        return self.public_key.public_bytes_raw()

    def public_bytes_b64(self) -> str:
        return base64.b64encode(self.public_bytes_raw()).decode()

    def to_dict(self) -> dict:
        """Export public key info for keyid resolution endpoint."""
        return {
            "address": self.keyid,
            "public_key": self.public_bytes_b64(),
        }


def generate_keypair(keyid: str) -> KeyPair:
    """Generate a new Ed25519 keypair."""
    return KeyPair(private_key=Ed25519PrivateKey.generate(), keyid=keyid)


def save_keypair(kp: KeyPair, path: str | Path, *, password: str | None = None) -> None:
    """Save private key to PEM file. Keyid stored in JSON sidecar.

    ⚠️  If *password* is ``None`` the private key is written **unencrypted**.
        Always pass a password for production use.
    """
    path = Path(path)
    if password is not None:
        enc = serialization.BestAvailableEncryption(password.encode())
    else:
        enc = serialization.NoEncryption()
    pem = kp.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    path.write_bytes(pem)
    meta_path = path.with_suffix(".keyid.json")
    meta_path.write_text(json.dumps({"keyid": kp.keyid}))


def load_keypair(path: str | Path, *, password: str | None = None) -> KeyPair:
    """Load keypair from PEM file + keyid sidecar."""
    path = Path(path)
    pem = path.read_bytes()
    pwd = password.encode() if password is not None else None
    private_key = serialization.load_pem_private_key(pem, password=pwd)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError(f"Expected Ed25519PrivateKey, got {type(private_key).__name__}")
    meta_path = path.with_suffix(".keyid.json")
    if meta_path.exists():
        keyid = json.loads(meta_path.read_text())["keyid"]
    else:
        keyid = path.stem
    return KeyPair(private_key=private_key, keyid=keyid)


def load_public_key_b64(b64: str) -> Ed25519PublicKey:
    """Load public key from base64 raw bytes."""
    raw = base64.b64decode(b64)
    return Ed25519PublicKey.from_public_bytes(raw)
