# Prekey Model

## Key Types
- **Identity Key** (ED25519): permanent, signs everything
- **Signed Prekey** (X25519): rotated weekly, signed by identity key
- **One-Time Prekeys** (X25519): consumed once, replenished in batches

## Session Establishment (Async)
1. Recipient publishes prekey bundle to relay
2. Sender fetches bundle, verifies signed prekey
3. Sender creates ephemeral X25519, derives shared secret
4. If OTK available: additional DH for extra forward secrecy
5. HKDF derives channel keys
6. Sender encrypts first message, submits to relay
7. Relay queues (recipient offline)
8. Recipient comes online, fetches pending, decrypts

## Security Properties
- Confidentiality: ChaCha20-Poly1305 AEAD
- Authenticity: ED25519 signatures
- Relay blindness: cannot read content
- Basic forward secrecy: ephemeral keys per session
- OTK consumption: each one-time key used exactly once

## Prekey Bundle Contents

```
{
  identity_pub:       ED25519 public key (hex)
  signed_prekey_pub:  X25519 public key (hex), rotated weekly
  signed_prekey_sig:  ED25519 signature over SHA-256(signed_prekey_pub)
  otk_pub:            X25519 one-time key (hex), optional
}
```

## Verification Flow

When a sender fetches a prekey bundle:

1. Compute `hash = SHA-256(signed_prekey_pub)`
2. Verify `signed_prekey_sig` against `identity_pub` using ED25519
3. If verification fails, abort — the prekey may have been tampered with
4. If OTK present, it is consumed (used exactly once)

## Key Rotation

Signed prekeys should be rotated on a weekly basis. The rotation check
compares the prekey's `created_at` timestamp against its
`rotation_interval`. Expired prekeys still verify cryptographically but
should be replaced.

One-time prekeys are consumed on use. Clients should replenish them in
batches when the relay reports low OTK count.
