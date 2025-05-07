# Message Sending (src/send.ts)

This module assumes that both sender and recipient identity keys have been exchanged via on-chain `Handshake` events.  
The recipient's identity key must be known and passed explicitly.


```ts
await initiateHandshake({
  contract,
  recipientAddress: '0xBob...',
  identityPubKey: myIdentityKey.publicKey, // sender's long-term x25519 key
  ephemeralPubKey: myEphemeral.publicKey, // generated per-handshake
  plaintextPayload: 'Hi Bob, ping from Alice'
});

```