# E2E Crypto Model

End-to-end encryption for SOST deal channels. The relay is a blind
transport layer that routes encrypted envelopes without reading them.

## Identity Layer

Each participant has a long-lived **ED25519** keypair.

- Signs all protocol messages (trade offers, accepts, cancels, settlements)
- Public key serves as the participant's identity (`sender_id` / `receiver_id`)
- The relay verifies ED25519 signatures on envelope headers for routing auth

## Key Agreement (per deal)

Each deal creates a fresh **X25519** ephemeral keypair on both sides.

1. The initiator generates an X25519 keypair and includes the public key
   in the handshake offer.
2. The responder generates their own X25519 keypair and derives the shared
   secret using Diffie-Hellman:
   `shared_secret = X25519(our_private, their_public)`
3. Both sides derive the same 32-byte shared secret because X25519 DH
   is commutative.

Ephemeral keys are discarded after the deal concludes. Compromise of one
deal's keys does not affect any other deal.

## Channel Key Derivation

From the shared secret, two directional keys are derived using **HKDF-SHA256**:

```
key_a = HKDF-SHA256(shared_secret, salt=deal_id, label="sost-deal-key-a", len=32)
key_b = HKDF-SHA256(shared_secret, salt=deal_id, label="sost-deal-key-b", len=32)
```

The initiator uses `key_a` for sending and `key_b` for receiving.
The responder uses `key_b` for sending and `key_a` for receiving.

A session ID is derived as:
```
session_id = SHA-256(shared_secret || deal_id)[0..16]  (hex-encoded)
```

## Payload Encryption

Each message payload is encrypted with **ChaCha20-Poly1305** AEAD:

- **Key**: the sender's `sendKey` (32 bytes, from HKDF derivation above)
- **Nonce**: 12 random bytes, unique per message
- **Plaintext**: the serialized trade message JSON
- **Output**: ciphertext + 16-byte authentication tag

## Encrypted Envelope

The encrypted envelope contains both routing metadata (cleartext header)
and the encrypted payload:

```
{
  version:      1,
  deal_id:      string,      // routing
  session_id:   string,      // session binding
  sender_id:    string,      // ED25519 public key hex
  receiver_id:  string,      // ED25519 public key hex
  msg_type:     string,      // "trade_offer" | "trade_accept" | etc.
  seq_no:       number,      // monotonic sequence number
  timestamp:    number,      // unix epoch seconds
  nonce:        string,      // 12-byte random, hex
  ciphertext:   string,      // ChaCha20-Poly1305 output, hex
  tag:          string,      // Poly1305 auth tag, hex
  signature:    string       // ED25519 sig over header (routing auth)
}
```

## Relay Blindness

The relay:

- **CAN** read: version, deal_id, session_id, sender_id, receiver_id,
  msg_type, seq_no, timestamp, signature
- **CANNOT** read: the plaintext content inside ciphertext
- **DOES** verify the ED25519 signature on the header for routing auth
- **DOES NOT** decrypt or inspect the payload

The relay stores envelopes as opaque JSON blobs and returns them as-is
to the intended recipient.

## Replay Protection

- Each message carries a monotonically increasing `seq_no`
- The relay enforces a sequence window (currently 256) to reject messages
  that jump too far ahead
- Out-of-order delivery within the window is allowed
- Endpoints should track received seq_nos to detect duplicates

## Header Signature

The header signature provides routing authentication:

1. Serialize all header fields (excluding `signature`) in sorted key order as JSON
2. SHA-256 hash the serialized string
3. Sign the hash with the sender's ED25519 private key

This ensures:
- Only the declared sender could have created the envelope
- The routing metadata has not been tampered with
- The relay can verify routing authority without reading the payload

## Future: Phase XIV

Phase XIV will add:
- **Prekey bundles** for asynchronous key exchange
- **Double-ratchet** for forward secrecy on every message
- Key rotation within a deal session
- Ephemeral key advertisement via the relay
