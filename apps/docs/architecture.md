# VerbEth Architecture

VerbEth enables stateless end-to-end encrypted messaging over Ethereum logs using ephemeral keys and authenticated encryption.

## Modules

- `contracts/`: Solidity contract emitting encrypted message events.
- `src/`: Core logic for encryption, log parsing, payload encoding.
- `utils/`: Key derivation, nonce tracking, Ethereum-specific helpers.
- `test/`: Unit tests to validate contract and SDK behavior.

## Core Design Principles

- Ethereum logs are the only transport.
- AEAD (NaCl box) for confidentiality and authenticity.
- Handshake required for key exchange; stateless after that.
- Optional signature for sender authenticity.


## 🔑 Key Establishment via Handshake

Users emit an on-chain `Handshake` event:

```solidity
event Handshake(
  bytes32 indexed recipientHash,  // keccak256("contact:" + lowercaseAddress)
  address indexed sender,
  bytes identityPubKey,  // sender's long-term identity key (X25519, 32 bytes)
  bytes ephemeralPubKey,  // fresh per-handshake public key
  bytes plaintextPayload
);
```

Responders may reply via HandshakeResponse, allowing bidirectional key visibility.