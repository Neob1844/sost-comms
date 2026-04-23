# Session Bootstrap

How asynchronous session establishment works in SOST Comms.

## Problem

Standard key agreement (like the Phase XIII handshake) requires both
parties to be online simultaneously. For a gold exchange protocol,
participants may be in different time zones or intermittently connected.

Session bootstrap solves this by allowing a sender to establish an
encrypted channel with a recipient who is currently offline.

## Solution: Prekey Bundles

The recipient publishes a prekey bundle to the relay ahead of time. The
sender can then establish a session at any point, without the recipient
being online.

### Bundle Structure

```
PrekeyBundle {
  identity_pub:       ED25519 public key (permanent identity)
  signed_prekey_pub:  X25519 public key (rotated weekly)
  signed_prekey_sig:  ED25519 sig over SHA-256(signed_prekey_pub)
  otk_pub:            X25519 one-time key (optional, consumed once)
}
```

## Key Derivation

### Without OTK (basic)

```
Sender:
  ephemeral = X25519.generate()
  shared    = DH(ephemeral.priv, signed_prekey_pub)
  keys      = HKDF-SHA256(shared, deal_id)

Recipient:
  shared    = DH(signed_prekey.priv, ephemeral.pub)
  keys      = HKDF-SHA256(shared, deal_id)
```

Both sides derive the same shared secret because:
`DH(a, B) == DH(b, A)` (Diffie-Hellman commutativity)

### With OTK (enhanced forward secrecy)

```
Sender:
  ephemeral = X25519.generate()
  dh1       = DH(ephemeral.priv, signed_prekey_pub)
  dh2       = DH(ephemeral.priv, otk_pub)
  combined  = SHA-256(dh1 || dh2)
  keys      = HKDF-SHA256(combined, deal_id)

Recipient:
  dh1       = DH(signed_prekey.priv, ephemeral.pub)
  dh2       = DH(otk.priv, ephemeral.pub)
  combined  = SHA-256(dh1 || dh2)
  keys      = HKDF-SHA256(combined, deal_id)
```

The OTK adds an extra DH computation. Since OTKs are consumed once,
this provides additional forward secrecy: even if the signed prekey
is later compromised, sessions that used an OTK remain secure (the
OTK private key was deleted after use).

## Channel Key Directionality

HKDF produces two 32-byte keys from the shared secret:

```
HKDF(shared, deal_id, "sost-deal-key-a") → key_a
HKDF(shared, deal_id, "sost-deal-key-b") → key_b

Initiator (sender):   send_key = key_a, recv_key = key_b
Responder (recipient): send_key = key_b, recv_key = key_a
```

This ensures that each direction uses a different symmetric key.

## Session ID

```
session_id = SHA-256(shared_secret || deal_id)[0:16].hex()
```

The session ID is included in every encrypted envelope header for
message correlation.

## Compared to Phase XIII Handshake

| | Phase XIII Handshake | Phase XIV Bootstrap |
|---|---|---|
| Both online? | Yes | No |
| Round trips | 3-step | 0 (async) |
| Forward secrecy | Ephemeral per deal | Ephemeral + optional OTK |
| Key source | X25519 from key bundle | Prekey bundle + ephemeral |
| Relay role | Routes handshake messages | Stores prekey bundles |

## Relay Blindness

The relay stores prekey bundles but cannot use them to decrypt messages:

- The relay has `signed_prekey_pub` but not `signed_prekey_priv`
- The relay has `otk_pub` but not `otk_priv`
- The relay never sees ephemeral private keys
- Without any private key, the relay cannot compute the shared secret
- Without the shared secret, HKDF output is unknown
- Without channel keys, ChaCha20-Poly1305 decryption fails

The relay is a blind store-and-forward node.
