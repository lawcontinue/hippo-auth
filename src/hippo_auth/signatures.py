"""RFC 9421 HTTP Message Signatures — hand-rolled, minimal dependencies."""

from __future__ import annotations

import base64
import logging
import os
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .digest import compute_digest, verify_digest
from .keys import KeyPair, load_public_key_b64

logger = logging.getLogger(__name__)


class NonceCache:
    """TTL + LRU nonce deduplication cache.

    Pass an instance to verify_signature / verify_rpc to enforce nonce uniqueness.
    """

    def __init__(self, max_size: int = 10_000, ttl: int = 600) -> None:
        self._max_size = max_size
        self._ttl = ttl
        self._store: OrderedDict[str, float] = OrderedDict()

    def check(self, nonce: str) -> bool:
        """Return True if nonce is new (and register it), False if already seen."""
        now = time.time()
        # Evict expired entries
        expired = [k for k, t in self._store.items() if now - t > self._ttl]
        for k in expired:
            del self._store[k]
        if nonce in self._store:
            return False
        # Evict oldest if at capacity
        while len(self._store) >= self._max_size:
            self._store.popitem(last=False)
        self._store[nonce] = now
        return True


def _sf_escape(value: str) -> str:
    """Escape a string for Structured Fields (RFC 9421 / RFC 8941).

    Escapes ``\\`` and ``"`` inside a quoted string.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')

# Signature components
BUILT_INS = {"@method", "@path", "@target-uri", "@authority", "@scheme", "@query", "@query-param"}
DEFAULT_COMPONENTS = ("@method", "@path", "content-digest", "created", "nonce", "keyid")


@dataclass
class SignatureParams:
    """Parameters that go into the signature input string."""

    keyid: str
    created: int
    nonce: str
    components: tuple[str, ...] = DEFAULT_COMPONENTS
    tag: str | None = None

    @classmethod
    def new(cls, keyid: str, *, tag: str | None = None, components: tuple[str, ...] | None = None) -> "SignatureParams":
        return cls(
            keyid=keyid,
            created=int(time.time()),
            nonce=os.urandom(16).hex(),
            components=components or DEFAULT_COMPONENTS,
            tag=tag,
        )

    def to_header_value(self, label: str = "sig1") -> str:
        """Build the signature-input header value (e.g. ``sig1=(...);created=...``)."""
        params_parts = [f'"{c}"' for c in self.components]
        param_items = [
            f'({" ".join(params_parts)})',
            f'created={self.created}',
            f'nonce="{_sf_escape(self.nonce)}"',
            f'keyid="{_sf_escape(self.keyid)}"',
        ]
        if self.tag:
            param_items.append(f'tag="{_sf_escape(self.tag)}"')
        return f'{label}={";".join(param_items)}'

    def signature_input(self, method: str, path: str, digest_value: str) -> str:
        """Build the signature base per RFC 9421 §2.3."""
        lines: list[str] = []
        for comp in self.components:
            if comp == "@method":
                lines.append(f'"@method": {method.upper()}')
            elif comp == "@path":
                lines.append(f'"@path": {path}')
            elif comp == "content-digest":
                lines.append(f'"content-digest": {digest_value}')
            elif comp == "created":
                lines.append(f'"created": {self.created}')
            elif comp == "nonce":
                lines.append(f'"nonce": {self.nonce}')
            elif comp == "keyid":
                lines.append(f'"keyid": {self.keyid}')
            else:
                logger.warning("Unknown signature component: %r", comp)
                raise ValueError(f"Unknown signature component: {comp!r}")
        # Signature params line
        params_parts = []
        for comp in self.components:
            params_parts.append(f'"{comp}"')
        param_items = [
            f'({" ".join(params_parts)})',
            f'created={self.created}',
            f'nonce="{_sf_escape(self.nonce)}"',
            f'keyid="{_sf_escape(self.keyid)}"',
        ]
        if self.tag:
            param_items.append(f'tag="{_sf_escape(self.tag)}"')
        lines.append('"@signature-params": ' + ";".join(param_items))
        return "\n".join(lines)


def sign_request(
    kp: KeyPair,
    method: str,
    path: str,
    body: bytes,
    *,
    tag: str | None = None,
    components: tuple[str, ...] | None = None,
) -> dict[str, str]:
    """Sign an HTTP request. Returns headers to add.

    Returns dict with: content-digest, signature-input, signature
    """
    digest_value = compute_digest(body)
    params = SignatureParams.new(kp.keyid, tag=tag, components=components)
    sig_base = params.signature_input(method, path, digest_value)
    raw_sig = kp.private_key.sign(sig_base.encode("utf-8"))
    sig_b64 = base64.b64encode(raw_sig).decode()

    return {
        "content-digest": digest_value,
        "signature-input": params.to_header_value(),
        "signature": f'sig1=:{sig_b64}:',
    }


@dataclass
class VerifyRequest:
    """Bundle of parameters for signature verification."""

    public_key_b64: str
    method: str
    path: str
    body: bytes
    signature: str  # sig1=:base64:
    signature_input: str  # sig1=(...)
    content_digest: str


def verify_signature(
    public_key_b64: str,
    method: str,
    path: str,
    body: bytes,
    signature: str,  # sig1=:base64:
    signature_input: str,  # sig1=(...)
    content_digest: str,
    *,
    max_age: int = 300,
    nonce_cache: NonceCache | None = None,
) -> bool:
    """Verify an RFC 9421 signature.

    Parameters map to the HTTP header values.
    """
    # Delegate to the dataclass-based implementation
    req = VerifyRequest(
        public_key_b64=public_key_b64,
        method=method,
        path=path,
        body=body,
        signature=signature,
        signature_input=signature_input,
        content_digest=content_digest,
    )
    return _verify(req, max_age=max_age, nonce_cache=nonce_cache)


def _verify(
    req: VerifyRequest,
    *,
    max_age: int = 300,
    nonce_cache: NonceCache | None = None,
) -> bool:
    """Internal verification using VerifyRequest."""
    # Extract base64 from sig1=:...:
    if not req.signature.startswith("sig1=:") or not req.signature.endswith(":"):
        return False
    sig_b64 = req.signature[6:-1]
    raw_sig = base64.b64decode(sig_b64)

    # Parse signature-input to reconstruct params
    # Format: sig1=("@method" "@path" ...);created=...;nonce="...";keyid="..."
    if not req.signature_input.startswith("sig1="):
        return False
    si_val = req.signature_input[5:]

    # P1-4: wrap parsing in try/except
    try:
        paren_end = si_val.index(")")
        components_str = si_val[1:paren_end]  # inside parens
        components = tuple(c.strip().strip('"') for c in components_str.split())

        rest = si_val[paren_end + 1:].lstrip(";")
        created = 0
        nonce = ""
        keyid = ""
        tag = None
        for part in rest.split(";"):
            k, _, v = part.partition("=")
            k = k.strip()
            v = v.strip().strip('"')
            if k == "created":
                created = int(v)
            elif k == "nonce":
                nonce = v
            elif k == "keyid":
                keyid = v
            elif k == "tag":
                tag = v
    except (IndexError, ValueError):
        return False

    # P0-1: reject expired / future signatures
    now = int(time.time())
    if now - created > max_age:
        return False
    if created > now + 60:
        return False

    # P0-2: nonce dedup
    if nonce_cache is not None and nonce and not nonce_cache.check(nonce):
        return False

    params = SignatureParams(
        keyid=keyid, created=created, nonce=nonce,
        components=components, tag=tag,
    )
    sig_base = params.signature_input(req.method, req.path, req.content_digest)

    if not verify_digest(req.body, req.content_digest):
        return False

    pub = load_public_key_b64(req.public_key_b64)
    try:
        pub.verify(raw_sig, sig_base.encode("utf-8"))
        return True
    except InvalidSignature:
        return False
