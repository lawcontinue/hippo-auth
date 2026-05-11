"""Keyid resolution: fetch public key from a flat JSON endpoint."""

from __future__ import annotations

from typing import Optional


def resolve_keyid(keyid_url: str, *, timeout: float = 10.0, allow_http: bool = False) -> dict:
    """Resolve a keyid URL to {address, public_key}.

    The endpoint should return a flat JSON object:
    ``{"address": "...", "public_key": "<base64>"}``

    By default only HTTPS URLs are allowed.  Pass ``allow_http=True`` to
    opt into plain HTTP (e.g. for local development).
    """
    if not keyid_url.startswith("https://") and not allow_http:
        if keyid_url.startswith("http://"):
            raise ValueError(
                "Plain HTTP keyid URLs are not allowed by default. "
                "Pass allow_http=True to opt in."
            )
        raise ValueError(f"Invalid keyid URL scheme: {keyid_url!r}")
    try:
        import httpx
    except ImportError:
        raise ImportError(
            "httpx is required for keyid resolution. "
            "Install it with: pip install hippo-auth[resolver]"
        )
    resp = httpx.get(keyid_url, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    if "public_key" not in data:
        raise ValueError(f"No public_key in response from {keyid_url}")
    return data


def build_well_known(public_key_b64: str, address: str) -> dict:
    """Build the JSON response for a keyid resolution endpoint."""
    return {"address": address, "public_key": public_key_b64}
