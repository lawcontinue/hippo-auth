"""JSON-RPC message signing for A2A protocol."""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .keys import KeyPair, load_public_key_b64
from .signatures import NonceCache


@dataclass
class SignedRPC:
    """A signed JSON-RPC message."""

    jsonrpc: str
    method: str
    params: dict
    id: str | int
    signature: str  # base64 signature
    signature_input: dict  # what was signed

    def to_dict(self) -> dict:
        return {
            "jsonrpc": self.jsonrpc,
            "method": self.method,
            "params": self.params,
            "id": self.id,
            "signature": self.signature,
            "signature_input": self.signature_input,
        }


def sign_rpc(kp: KeyPair, method: str, params: dict, *, rpc_id: str | int | None = None, tag: str | None = None) -> SignedRPC:
    """Sign a JSON-RPC message for A2A."""
    if rpc_id is None:
        rpc_id = os.urandom(8).hex()

    created = int(time.time())
    nonce = os.urandom(16).hex()

    # Build canonical message for signing
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": rpc_id,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    # Signature input includes metadata
    sig_input = {
        "created": created,
        "nonce": nonce,
        "keyid": kp.keyid,
    }
    if tag:
        sig_input["tag"] = tag

    # Sign canonical payload
    message = canonical.encode("utf-8")
    raw_sig = kp.private_key.sign(message)
    sig_b64 = base64.b64encode(raw_sig).decode()

    return SignedRPC(
        jsonrpc="2.0",
        method=method,
        params=params,
        id=rpc_id,
        signature=sig_b64,
        signature_input=sig_input,
    )


def verify_rpc(
    message: dict,
    public_key_b64: str,
    *,
    max_age: int = 300,
    nonce_cache: NonceCache | None = None,
) -> bool:
    """Verify a signed JSON-RPC message."""
    sig = message.get("signature")
    sig_input = message.get("signature_input", {})
    if not sig:
        return False

    # P0-5: validate created and nonce from sig_input
    created = sig_input.get("created", 0)
    nonce = sig_input.get("nonce", "")

    now = int(time.time())
    if now - created > max_age:
        return False
    if created > now + 60:
        return False

    if nonce_cache is not None and nonce and not nonce_cache.check(nonce):
        return False

    # Reconstruct canonical payload (everything except signature fields)
    payload = {k: v for k, v in message.items() if k not in ("signature", "signature_input")}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    pub = load_public_key_b64(public_key_b64)
    try:
        pub.verify(base64.b64decode(sig), canonical.encode("utf-8"))
        return True
    except InvalidSignature:
        return False
