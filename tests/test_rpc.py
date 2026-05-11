"""Tests for RPC signing."""

from hippo_auth.keys import generate_keypair
from hippo_auth.rpc import sign_rpc, verify_rpc


def test_sign_and_verify_rpc():
    kp = generate_keypair("https://example.com/keys/alice")
    msg = sign_rpc(kp, "tasks/send", {"task": "hello"}, tag="task")
    d = msg.to_dict()
    assert d["jsonrpc"] == "2.0"
    assert d["method"] == "tasks/send"
    assert verify_rpc(d, kp.public_bytes_b64())


def test_tampered_rpc_fails():
    kp = generate_keypair("test")
    msg = sign_rpc(kp, "tasks/send", {"task": "hello"})
    d = msg.to_dict()
    d["params"]["task"] = "tampered"
    assert not verify_rpc(d, kp.public_bytes_b64())


def test_wrong_key_rpc_fails():
    kp1 = generate_keypair("alice")
    kp2 = generate_keypair("bob")
    msg = sign_rpc(kp1, "tasks/send", {"x": 1})
    assert not verify_rpc(msg.to_dict(), kp2.public_bytes_b64())
