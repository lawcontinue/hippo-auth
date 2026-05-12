# Hippo RFC 9421 Test Vectors

Canonical test vectors for `hippo-auth`'s Ed25519 + RFC 9421 HTTP Message Signatures implementation.

## Files

| File | Description |
|------|-------------|
| `vectors.json` | 3 test vectors with full signature bases, public key, and verification data |
| `byte-match-report.json` | Verification report: 3/3 byte-match confirmed |

## Vectors

| # | Description | Body Size | Digest | Tag |
|---|-------------|-----------|--------|-----|
| 1 | Basic A2A message | 68 B | SHA-256 | `a2a-message` |
| 2 | Agent card GET (backward compat) | 0 B | SHA-256 | none |
| 3 | Large message (≥4KB) | 4210 B | SHA-512 | `a2a-message` |

## Cross-Implementation Byte-Match

To verify byte-match with another RFC 9421 implementation:

1. Load `vectors.json`
2. For each vector, reconstruct `signature_base` from the provided fields
3. Verify the Ed25519 signature using `public_key_b64`
4. Compare your computed `signature_base` byte-for-byte against the provided one

All three vectors use the **same Ed25519 keypair** (public key only, private key not included).

## Key

- **Algorithm**: Ed25519 (RFC 8032 §7.1)
- **Signature Format**: RFC 9421 HTTP Message Signatures
- **Components**: `@method`, `@path`, `content-digest`, `created`, `nonce`, `keyid`
- **Tag**: Optional `tag` parameter per A2A-IDF §6 discussion

## Relation to A2A Ecosystem

- **Canonical home** (planned): `opena2a-org/a2a-idf-conformance`
- **Development source**: `lawcontinue/hippo-auth/fixtures/hippo-rfc9421/`
- **Mirror** (planned): `aeoess/aps-conformance-suite/fixtures/composition/hippo-rfc9421/`

These vectors are designed to byte-match against `envoys-rfc9421` test vectors when using the same keypair and message content.
