"""Tests for signatures module."""

from hippo_auth.keys import generate_keypair
from hippo_auth.signatures import sign_request, verify_signature


def test_sign_and_verify():
    kp = generate_keypair("https://example.com/keys/alice")
    body = b'{"jsonrpc":"2.0","method":"tasks/send","id":"1"}'
    headers = sign_request(kp, "POST", "/a2a", body)

    assert "content-digest" in headers
    assert "signature-input" in headers
    assert "signature" in headers

    ok = verify_signature(
        public_key_b64=kp.public_bytes_b64(),
        method="POST",
        path="/a2a",
        body=body,
        signature=headers["signature"],
        signature_input=headers["signature-input"],
        content_digest=headers["content-digest"],
    )
    assert ok


def test_sign_with_tag():
    kp = generate_keypair("test")
    headers = sign_request(kp, "POST", "/", b'{}', tag="task")
    assert 'tag="task"' in headers["signature-input"]


def test_tampered_body_fails():
    kp = generate_keypair("test")
    headers = sign_request(kp, "POST", "/", b"original")
    ok = verify_signature(
        kp.public_bytes_b64(), "POST", "/", b"tampered",
        headers["signature"], headers["signature-input"], headers["content-digest"],
    )
    assert not ok


def test_wrong_key_fails():
    kp1 = generate_keypair("alice")
    kp2 = generate_keypair("bob")
    body = b"hello"
    headers = sign_request(kp1, "POST", "/", body)
    ok = verify_signature(
        kp2.public_bytes_b64(), "POST", "/", body,
        headers["signature"], headers["signature-input"], headers["content-digest"],
    )
    assert not ok
