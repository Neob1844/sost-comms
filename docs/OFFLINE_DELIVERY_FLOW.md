# Offline Delivery Flow

Step-by-step walkthrough of how messages are delivered when the recipient
is offline.

## Flow

```
1. Recipient publishes prekey bundle
   POST /prekeys/:identity
   Body: { identity_pub, signed_prekey_pub, signed_prekey_sig, otk_pub? }

2. Sender fetches recipient's prekey bundle
   GET /prekeys/:recipientId
   Response: { identity, bundle }

3. Sender initiates async session (no recipient interaction needed)
   - Verify signed_prekey_sig against identity_pub
   - Generate ephemeral X25519 keypair
   - DH: ephemeral_priv x signed_prekey_pub → shared_secret
   - If OTK: DH: ephemeral_priv x otk_pub → dh2, combine
   - HKDF(shared_secret, deal_id) → send_key, recv_key

4. Sender encrypts trade_offer
   - ChaCha20-Poly1305 with send_key
   - Header signed with ED25519 identity key
   - Envelope contains cleartext routing metadata

5. Sender submits encrypted envelope
   POST /submit/encrypted
   Body: EncryptedEnvelope
   - Relay validates header fields and signature
   - Relay queues for offline recipient

6. ... time passes, recipient is offline ...

7. Recipient comes online

8. Recipient fetches pending messages
   GET /pending/:recipientId
   Response: { recipient_id, messages: QueuedMessage[] }

9. Recipient processes session init
   - Extract sender's ephemeral public key from envelope
   - DH: signed_prekey_priv x ephemeral_pub → shared_secret
   - If OTK was used: DH: otk_priv x ephemeral_pub → dh2, combine

10. Recipient derives channel keys
    - HKDF(shared_secret, deal_id) → send_key, recv_key
    - recv_key matches sender's send_key (directional)

11. Recipient decrypts message
    - ChaCha20-Poly1305 with recv_key
    - Verify header signature against sender's identity key
    - Parse plaintext trade_offer

12. Recipient acknowledges receipt
    POST /ack/:messageId
    - Relay updates delivery state to "acknowledged"

13. Recipient encrypts trade_accept, submits
    POST /submit/encrypted
    - Uses their send_key (sender's recv_key)
    - Deal continues normally
```

## Delivery States

```
queued → delivered → acknowledged
  │
  └→ expired (after TTL, default 7 days)
```

## Endpoints Summary

| Method | Path | Purpose |
|--------|------|---------|
| POST | /prekeys/:identity | Publish prekey bundle |
| GET | /prekeys/:identity | Fetch prekey bundle |
| POST | /submit/encrypted | Submit encrypted envelope |
| GET | /pending/:recipientId | Fetch pending offline messages |
| POST | /ack/:messageId | Acknowledge delivery |
| GET | /delivery/:dealId | Get delivery status for deal |

## Security Guarantees

- The relay never sees plaintext content
- The relay cannot forge messages (lacks signing keys)
- Messages expire after 7 days by default (configurable TTL)
- Each OTK is consumed exactly once
- Delivery acknowledgment is explicit (not automatic)
