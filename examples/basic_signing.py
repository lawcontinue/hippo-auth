"""Example: basic signing with hippo-auth."""

from hippo_auth.keys import generate_keypair
from hippo_auth.signatures import sign_request, verify_signature
from hippo_auth.rpc import sign_rpc, verify_rpc

# Generate a keypair
kp = generate_keypair("https://example.com/.well-known/a2a-keys/alice")
print(f"KeyID: {kp.keyid}")
print(f"Public key (b64): {kp.public_bytes_b64()}")

# --- HTTP request signing ---
body = b'{"jsonrpc":"2.0","method":"tasks/send","params":{"task":"hello"},"id":"1"}'
headers = sign_request(kp, "POST", "/a2a", body, tag="task")
print(f"\nSigned headers:\n  content-digest: {headers['content-digest']}\n  signature-input: {headers['signature-input']}\n  signature: {headers['signature']}")

ok = verify_signature(
    kp.public_bytes_b64(), "POST", "/a2a", body,
    headers["signature"], headers["signature-input"], headers["content-digest"],
)
print(f"\nVerify: {'PASS' if ok else 'FAIL'}")

# --- JSON-RPC signing ---
rpc = sign_rpc(kp, "tasks/send", {"task": "hello"}, tag="task")
d = rpc.to_dict()
print(f"\nSigned RPC: {d}")
print(f"RPC verify: {'PASS' if verify_rpc(d, kp.public_bytes_b64()) else 'FAIL'}")
