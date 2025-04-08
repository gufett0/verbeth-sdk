# Keys and Signatures

## Sender Key
- Optional signing with Ed25519
- Signature is detached over `(epk || nonce || ciphertext)`

## Recipient Key
- Derived from Ethereum key (via signature over a known message)
- Uses `@noble/secp256k1` to recover `pubkey`
- Then hashed and truncated to 32 bytes to produce x25519-compatible key