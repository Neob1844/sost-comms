# Deal Channel E2E Flow

Step-by-step flow for an end-to-end encrypted deal, from handshake
through settlement.

## Prerequisites

- Both parties have long-lived ED25519 identity keypairs
- The relay is running and accessible via HTTP

## Flow

### 1. Seller generates ephemeral X25519 keypair

```
seller_x25519 = generateX25519KeyPair()
```

A fresh keypair is created for this specific deal. The private key
never leaves the seller's machine.

### 2. Seller creates HandshakeOffer

The seller broadcasts a signed trade offer that includes their
X25519 encryption public key:

```
{
  type: "trade_offer",
  offer_id: "...",
  pair: "SOST/XAUT",
  side: "sell",
  amount_sost: "100.00000000",
  encryption_pubkey: seller_x25519.publicKey (hex),
  ...
}
```

This offer is submitted to the relay via `POST /submit` (plaintext,
signed with ED25519 identity key).

### 3. Buyer receives offer and generates own X25519

```
buyer_x25519 = generateX25519KeyPair()
```

### 4. Both derive shared secret via X25519

```
// Seller side:
shared = X25519(seller_x25519.privateKey, buyer_x25519.publicKey)

// Buyer side:
shared = X25519(buyer_x25519.privateKey, seller_x25519.publicKey)

// Both produce the same 32-byte shared secret
```

### 5. HKDF derives send/recv channel keys

```
key_a = HKDF-SHA256(shared, salt=deal_id, label="sost-deal-key-a", 32)
key_b = HKDF-SHA256(shared, salt=deal_id, label="sost-deal-key-b", 32)

// Seller (initiator):
sendKey = key_a, recvKey = key_b

// Buyer (responder):
sendKey = key_b, recvKey = key_a
```

### 6. Seller encrypts trade_offer details

```
nonce = random(12 bytes)
{ciphertext, tag} = ChaCha20-Poly1305(
  key = seller.sendKey,
  nonce = nonce,
  plaintext = JSON.stringify(trade_offer_details)
)
```

### 7. Seller submits encrypted envelope to relay

```
POST /submit/encrypted
{
  version: 1,
  deal_id: "deal_...",
  session_id: "...",
  sender_id: seller_ed25519_pubkey_hex,
  receiver_id: buyer_ed25519_pubkey_hex,
  msg_type: "trade_offer",
  seq_no: 0,
  timestamp: unix_now(),
  nonce: nonce_hex,
  ciphertext: ciphertext_hex,
  tag: tag_hex,
  signature: ED25519_sign(header)
}
```

### 8. Relay stores envelope (cannot read content)

The relay validates the header signature and sequence number, then
stores the full envelope as an opaque JSON blob. The relay never
sees the plaintext trade details.

### 9. Buyer fetches encrypted messages

```
GET /deals/:deal_id/encrypted
```

Returns all stored encrypted envelopes for this deal.

### 10. Buyer decrypts with channel keys

```
plaintext = ChaCha20-Poly1305_decrypt(
  key = buyer.recvKey,
  nonce = envelope.nonce,
  ciphertext = envelope.ciphertext,
  tag = envelope.tag
)
trade_offer = JSON.parse(plaintext)
```

### 11. Buyer encrypts trade_accept

```
accept_envelope = encrypt(buyer.sendKey, trade_accept_details)
POST /submit/encrypted (seq_no: 1)
```

### 12. Deal continues through settlement

Each subsequent message (cancel, settlement_notice, etc.) follows
the same pattern:

1. Encrypt with sender's channel key
2. Submit to relay via `POST /submit/encrypted`
3. Recipient fetches via `GET /deals/:id/encrypted`
4. Decrypt with recipient's channel key

## What the relay sees

| Field | Relay can read? |
|---|---|
| deal_id | Yes (routing) |
| sender_id / receiver_id | Yes (routing) |
| msg_type | Yes (metadata) |
| seq_no / timestamp | Yes (ordering) |
| ciphertext | No (opaque bytes) |
| tag | No (auth token) |
| nonce | Yes (but useless without key) |

## Error cases

- **Wrong key**: ChaCha20-Poly1305 decryption fails with auth error
- **Tampered header**: ED25519 signature verification fails at relay
- **Replay**: seq_no outside window rejected by relay
- **Man-in-the-middle**: cannot forge ED25519 signature or derive
  X25519 shared secret without the private keys
