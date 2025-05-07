# VerbEth SDK

End-to-end encrypted messaging over Ethereum logs, using the blockchain as the only transport layer. Uses `tweetnacl.box` to encrypt/decrypt messages with ephemeral keys and optional sender identity. Ensures forward secrecy and compatibility with smart accounts.

## How It Works: Alice & Bob (Handshake Flow)

👩‍💻 Alice wants to initiate a secure chat with Bob 👨‍💻 using only the blockchain.

1. Alice generates a new **ephemeral keypair**.
2. She emits a `Handshake` event:
   - Includes her ephemeral public key
   - Optionally includes her long-term identity key
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
