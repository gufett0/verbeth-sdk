# Message Decryption

This flow is triggered when reading on-chain logs.

## Logs Module (`src/logs.ts`)
- Accepts a decoded `LogMessage` struct from the blockchain.
- Validates if it's a duplicate (using nonce).
- Calls `decryptMessage()` from `crypto.ts`.

## Crypto Module (`src/crypto.ts`)
- Uses NaCl's `box.open` with:
  - Ephemeral pubkey from sender
  - Recipient's x25519 secret key
- Verifies signature if present.

Returns the plaintext message or `null` if decryption fails.
