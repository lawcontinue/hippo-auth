# hippo-auth

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml) [![Tests](https://img.shields.io/badge/tests-35%20passing-brightgreen.svg)](tests/)

Ed25519 + RFC 9421 HTTP Message Signatures for A2A protocol. A minimal, dependency-light reference implementation.

## Why?

For [a2aproject/A2A #1829](https://github.com/a2aproject/A2A/issues/1829) — proving that A2A identity can be grounded in Ed25519 keypairs with RFC 9421 signatures, no X.509 needed.

## Features

- **Ed25519 key management** — generate, save, load keypairs
- **RFC 9421 HTTP signatures** — hand-rolled, no external signing library needed
- **Content-Digest** — SHA-256 by default, auto-promotes to SHA-512 for bodies ≥ 4KB
- **JSON-RPC signing** — sign/verify A2A JSON-RPC messages directly
- **Keyid resolution** — flat JSON endpoint (`{address, public_key}`)
- **Replay protection** — `created` timestamp + random `nonce`
- **Tag parameter** — distinguish signature purpose (`task`, `heartbeat`, `delegation`)

## Install

```bash
pip install -e .
```

## Quick Start

```python
from hippo_auth.keys import generate_keypair
from hippo_auth.signatures import sign_request, verify_signature

# Generate keypair
kp = generate_keypair("https://example.com/.well-known/a2a-keys/alice")

# Sign an HTTP request
body = b'{"jsonrpc":"2.0","method":"tasks/send","params":{},"id":"1"}'
headers = sign_request(kp, "POST", "/a2a", body, tag="task")

# Verify
ok = verify_signature(
    kp.public_bytes_b64(), "POST", "/a2a", body,
    headers["signature"], headers["signature-input"], headers["content-digest"],
)
assert ok
```

### JSON-RPC Signing

```python
from hippo_auth.rpc import sign_rpc, verify_rpc

msg = sign_rpc(kp, "tasks/send", {"task": "hello"}, tag="task")
assert verify_rpc(msg.to_dict(), kp.public_bytes_b64())
```

### Key Persistence

```python
from hippo_auth.keys import save_keypair, load_keypair

save_keypair(kp, "alice.pem")
kp2 = load_keypair("alice.pem")
```

## Project Structure

```
src/hippo_auth/
├── keys.py          # Ed25519 key generation, save/load
├── signatures.py    # RFC 9421 HTTP request signing/verification
├── digest.py        # Content-Digest with auto SHA-256→SHA-512
├── rpc.py           # JSON-RPC message signing for A2A
└── resolver.py      # Keyid URL → public key resolution
```

## Run Tests

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
