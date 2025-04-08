# VerbEth SDK

End-to-end encrypted messaging over Ethereum logs, using the blockchain as the only transport layer. Uses tweetnacl.box to encrypt/decrypt messages with ephemeral keys and optional sender signatures. Ensures forward secrecy (ephemeral key) and authenticity (optional signature with sender's long-term key).

## How It Works: Alice & Bob

👩‍💻 Alice wants to send Bob 👨‍💻 a private message over Ethereum logs — without knowing Bob personally.

1. Alice opens her dapp that uses VerbEth SDK
2. The SDK asks Bob (via ethers.Signer) to sign a fallback message — from that, it derives Bob's x25519 pubkey
3. Alice's browser generates a new ephemeral keypair
4. Alice encrypts her message using NaCl and adds a detached signature with her long-term signing key
5. The encrypted payload is JSON-wrapped and sent to the blockchain as a MessageSent event
6. Bob watches logs using filters (topic, sender)
7. When Bob sees a message:
   - He extracts the ciphertext
   - Verifies Alice's signature (optional)
   - Decrypts the message using his x25519 secret key


## Features

- Stateless encrypted messaging
- Ephemeral keys & forward secrecy
- Minimal on-chain interface
- No centralized server or database
- Private communication via public blockchain

## Usage (WIP)

```ts
import { decryptLog } from '@verbeth/sdk'

const msg = decryptLog(eventLog, mySecretKey);
```