# Message Sending (src/send.ts)

This module encrypts a message using:
- Recipient's x25519 public key (derived or resolved)
- Ephemeral keypair (generated per message)
- Optional static signing key (Ed25519)

## Steps
1. Resolve recipient key (from Signer or address).
2. Generate ephemeral keypair.
3. Encrypt the message and (optionally) sign it.
4. Encode ciphertext payload into a JSON blob.
5. Emit it on-chain via `LogChain.sendMessage()`.

Uses nonce from `utils/nonce.ts` for replay protection.
