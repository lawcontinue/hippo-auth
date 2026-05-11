"""Content-Digest header with SHA-256 default and auto-promotion to SHA-512."""

from __future__ import annotations

import base64
import hashlib
import hmac

THRESHOLD = 4096  # bytes — auto-promote to SHA-512 above this


def compute_digest(body: bytes) -> str:
    """Compute content-digest value. Returns the header value string.

    Uses SHA-256 by default, SHA-512 if body >= 4KB.
    Format: ``sha-256=:base64:`` or ``sha-512=:base64:``
    """
    if len(body) >= THRESHOLD:
        algo = "sha-512"
        digest = hashlib.sha512(body).digest()
    else:
        algo = "sha-256"
        digest = hashlib.sha256(body).digest()
    return f"{algo}=:{base64.b64encode(digest).decode()}:"


def verify_digest(body: bytes, digest_header: str) -> bool:
    """Verify content-digest header against body."""
    expected = compute_digest(body)
    # Use constant-time comparison to prevent timing attacks
    if hmac.compare_digest(digest_header, expected):
        return True
    # Try both algos explicitly
    for algo, fn in [("sha-256", hashlib.sha256), ("sha-512", hashlib.sha512)]:
        val = f"{algo}=:{base64.b64encode(fn(body).digest()).decode()}:"
        if hmac.compare_digest(val, digest_header):
            return True
    return False
