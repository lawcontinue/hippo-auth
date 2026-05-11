"""Tests for digest module."""

from hippo_auth.digest import compute_digest, verify_digest


def test_sha256_small_body():
    body = b"hello"
    d = compute_digest(body)
    assert d.startswith("sha-256=:")
    assert verify_digest(body, d)


def test_sha512_large_body():
    body = b"x" * 4096
    d = compute_digest(body)
    assert d.startswith("sha-512=:")
    assert verify_digest(body, d)


def test_wrong_body_fails():
    d = compute_digest(b"hello")
    assert not verify_digest(b"world", d)
