# VerbEth SDK

End-to-end encrypted messaging over Ethereum logs, using the blockchain as the only transport layer. Uses `tweetnacl.box` to encrypt/decrypt messages with ephemeral keys and optional sender identity. Ensures forward secrecy and compatibility with smart accounts.

## How It Works: Alice & Bob (Handshake Flow)

👩‍💻 Alice wants to initiate a secure chat with Bob 👨‍💻 using only the blockchain.

1. Alice generates a new **ephemeral keypair**.
2. She emits a `Handshake` event:
   - Includes her ephemeral public key
   - Includes her long-term X25519 identity key (derived from Ethereum address)
   - Plaintext payload like: `"Hi Bob, respond if you're online"`
3. Bob watches logs for `Handshake` events addressed to him:
   - Looks for `keccak256("contact:0xMyAddress")` in `recipientHash`
   - Verifies if he's the recipient
4. If interested, Bob responds with a `HandshakeResponse`:
   - Contains a payload encrypted to Alice's ephemeral key
   - Includes his own ephemeral key and optional identity key
5. Once handshake is complete, both use their shared secret to exchange `MessageSent` logs:
   - Encrypted payloads using `NaCl.box` and fresh ephemeral keys
   - Bob and Alice filter messages using topics, timestamp, or sender

✅ If the sender does not yet know the recipient's long-term public key (X25519), 
they must emit a `Handshake` event. This allows the recipient to reply with their key.

If the recipient’s public key is already known (from a past `HandshakeResponse`, 
on-chain announcement, or static mapping), the sender may skip the handshake.
```
Alice (Initiator)                    Bob (Responder)
├─ deriva X25519 + Ed25519          ├─ deriva X25519 + Ed25519
│  da firma Ethereum                │  da firma Ethereum  
│                                   │
├─ Handshake Event ──────────────→  ├─ riceve handshake
│  • X25519 identity key            │  • valida identity key
│  • Ed25519 signing key            │  • salva entrambe le chiavi
│  • ephemeral key                  │
│  • plaintext payload              │
│                                   │
│ ←─────────────── HandshakeResponse├─ 
│  • X25519 identity key            │
│  • Ed25519 signing key            │
│  • ephemeral key (encrypted)      │
│  • note (encrypted)               │
│                                   │
├─ MessageSent ────────────────────→├─ riceve messaggio
│  • encrypted con X25519           │  • decrypta con X25519
│  • signed con Ed25519             │  • verifica con Ed25519 
```


## Features

- Stateless encrypted messaging via logs
- Ephemeral keys & forward secrecy
- Handshake-based key exchange (no prior trust)
- Minimal metadata via `recipientHash`
- Fully on-chain: no servers, no relays
- Compatible with EOAs and smart contract accounts

## Usage (WIP)

```ts
import { decryptLog, initiateHandshake } from '@verbeth/sdk'

// Receive and decrypt a message
const msg = decryptLog(eventLog, mySecretKey);

// Start a handshake
await initiateHandshake({
  contract,
  recipientAddress: '0xBob...',
  ephemeralPubKey: myEphemeral.publicKey,
  plaintextPayload: 'Hi Bob, ping from Alice'
});
