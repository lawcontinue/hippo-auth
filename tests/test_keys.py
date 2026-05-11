"""Tests for keys module."""

import tempfile
from hippo_auth.keys import generate_keypair, save_keypair, load_keypair, load_public_key_b64


def test_generate_keypair():
    kp = generate_keypair("https://example.com/keys/alice")
    assert kp.keyid == "https://example.com/keys/alice"
    assert len(kp.public_bytes_raw()) == 32


def test_save_load_roundtrip():
    kp = generate_keypair("https://example.com/keys/bob")
    with tempfile.TemporaryDirectory() as td:
        path = f"{td}/bob.pem"
        save_keypair(kp, path)
        kp2 = load_keypair(path)
        assert kp2.keyid == kp.keyid
        assert kp2.public_bytes_raw() == kp.public_bytes_raw()


def test_public_key_b64_roundtrip():
    kp = generate_keypair("test")
    b64 = kp.public_bytes_b64()
    pub = load_public_key_b64(b64)
    assert pub.public_bytes_raw() == kp.public_bytes_raw()
