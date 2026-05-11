"""hippo-auth: Ed25519 + RFC 9421 HTTP Message Signatures for A2A."""

__version__ = "0.1.0"

from .keys import generate_keypair, save_keypair, load_keypair
from .signatures import sign_request, verify_signature, NonceCache, VerifyRequest
from .rpc import sign_rpc, verify_rpc

__all__ = [
    "generate_keypair",
    "save_keypair",
    "load_keypair",
    "sign_request",
    "verify_signature",
    "sign_rpc",
    "verify_rpc",
    "NonceCache",
    "VerifyRequest",
]
