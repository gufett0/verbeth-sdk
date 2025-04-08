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
- Stateless, no handshake or session required.
- Optional signature for sender authenticity.
