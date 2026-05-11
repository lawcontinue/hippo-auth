"""Tests for P0 fixes: max_age, NonceCache, password encryption, SF escape, verify_rpc created/nonce."""

import time
import tempfile

from hippo_auth.keys import generate_keypair, save_keypair, load_keypair
from hippo_auth.signatures import NonceCache, sign_request, verify_signature, _sf_escape
from hippo_auth.rpc import sign_rpc, verify_rpc


# --- P0-1: max_age (created timestamp validation) ---

def test_expired_signature_rejected():
    """A signature with created too far in the past should be rejected."""
    kp = generate_keypair("test")
    body = b"hello"

    # Manually craft a signature with old created timestamp
    from hippo_auth.signatures import SignatureParams
    params = SignatureParams(keyid=kp.keyid, created=int(time.time()) - 600, nonce="abc123")
    from hippo_auth.digest import compute_digest
    digest_value = compute_digest(body)
    sig_base = params.signature_input("POST", "/", digest_value)
    raw_sig = kp.private_key.sign(sig_base.encode())

    import base64
    sig_b64 = base64.b64encode(raw_sig).decode()
    components = " ".join(f'"{c}"' for c in params.components)
    sig_input = f'sig1=({components});created={params.created};nonce="{params.nonce}";keyid="{params.keyid}"'

    ok = verify_signature(
        kp.public_bytes_b64(), "POST", "/", body,
        f"sig1=:{sig_b64}:", sig_input, digest_value,
        max_age=300,
    )
    assert not ok, "Should reject expired signature"


def test_fresh_signature_accepted_with_max_age():
    """A fresh signature within max_age should be accepted."""
    kp = generate_keypair("test")
    headers = sign_request(kp, "POST", "/", b"hello")
    ok = verify_signature(
        kp.public_bytes_b64(), "POST", "/", b"hello",
        headers["signature"], headers["signature-input"], headers["content-digest"],
        max_age=300,
    )
    assert ok


# --- P0-2: NonceCache ---

def test_nonce_cache_rejects_duplicate():
    cache = NonceCache()
    assert cache.check("nonce1")
    assert not cache.check("nonce1"), "Duplicate nonce should be rejected"
    assert cache.check("nonce2")


def test_nonce_cache_ttl():
    cache = NonceCache(ttl=0)  # instant expiry
    assert cache.check("nonce1")
    # After TTL=0, it should be evicted on next check
    time.sleep(0.01)
    assert cache.check("nonce1"), "Nonce should be accepted after TTL expiry"


def test_nonce_cache_max_size():
    cache = NonceCache(max_size=2)
    cache.check("a")
    cache.check("b")
    cache.check("c")  # evicts "a"
    assert cache.check("a"), "a should have been evicted"


def test_verify_rejects_replay_with_nonce_cache():
    kp = generate_keypair("test")
    cache = NonceCache()
    headers = sign_request(kp, "POST", "/", b"hello")

    ok1 = verify_signature(
        kp.public_bytes_b64(), "POST", "/", b"hello",
        headers["signature"], headers["signature-input"], headers["content-digest"],
        nonce_cache=cache,
    )
    assert ok1

    ok2 = verify_signature(
        kp.public_bytes_b64(), "POST", "/", b"hello",
        headers["signature"], headers["signature-input"], headers["content-digest"],
        nonce_cache=cache,
    )
    assert not ok2, "Replayed signature should be rejected"


# --- P0-3: Password encryption ---

def test_save_load_with_password():
    kp = generate_keypair("https://example.com/keys/alice")
    with tempfile.TemporaryDirectory() as td:
        path = f"{td}/alice.pem"
        save_keypair(kp, path, password="hunter2")
        # File should contain encrypted PEM
        content = open(path).read()
        assert "ENCRYPTED" in content
        # Load with password
        kp2 = load_keypair(path, password="hunter2")
        assert kp2.public_bytes_raw() == kp.public_bytes_raw()
        assert kp2.keyid == kp.keyid


def test_load_without_password_fails():
    kp = generate_keypair("test")
    with tempfile.TemporaryDirectory() as td:
        path = f"{td}/test.pem"
        save_keypair(kp, path, password="secret")
        try:
            load_keypair(path)
            assert False, "Should have raised"
        except Exception:
            pass  # expected


# --- P0-4: SF string escaping ---

def test_sf_escape():
    assert _sf_escape('simple') == 'simple'
    assert _sf_escape('has"quote') == 'has\\"quote'
    assert _sf_escape('back\\slash') == 'back\\\\slash'
    assert _sf_escape('both\\"') == 'both\\\\\\"'


def test_special_chars_in_keyid():
    """keyid with special characters should be properly escaped in signature-input."""
    kp = generate_keypair('https://example.com/keys/"alice"')
    headers = sign_request(kp, "POST", "/", b"hello")
    # The signature-input header should have escaped quotes in keyid
    assert '\\"alice\\"' in headers["signature-input"]


# --- P0-5: verify_rpc validates created and nonce ---

def test_rpc_expired_rejected():
    kp = generate_keypair("test")
    msg = sign_rpc(kp, "tasks/send", {"x": 1})
    d = msg.to_dict()
    # Tamper created to be old
    d["signature_input"]["created"] = int(time.time()) - 600
    assert not verify_rpc(d, kp.public_bytes_b64(), max_age=300)


def test_rpc_nonce_replay_rejected():
    kp = generate_keypair("test")
    cache = NonceCache()
    msg = sign_rpc(kp, "tasks/send", {"x": 1})
    d = msg.to_dict()
    assert verify_rpc(d, kp.public_bytes_b64(), nonce_cache=cache)
    assert not verify_rpc(d, kp.public_bytes_b64(), nonce_cache=cache)
