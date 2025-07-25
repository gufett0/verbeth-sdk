# VerbEth SDK

End-to-end encrypted messaging over Ethereum logs, using the blockchain as the only transport layer. Uses `tweetnacl.box` to encrypt/decrypt messages with ephemeral keys and optional sender identity. Ensures forward secrecy and compatibility with smart accounts.

## How It Works: Alice & Bob (High-level Flow)

Alice wants to initiate a secure chat with Bob using only the blockchain.

1. Alice generates a new **ephemeral keypair**.
2. She emits a `Handshake` event:
   - Includes her ephemeral public key
   - Includes her long-term unified keys (X25519 identity + Ed25519 signing, derived from Ethereum address)
   - Plaintext payload like: `"Hi Bob, respond if you're online"` with derivation proof
3. Bob watches logs for `Handshake` events addressed to him:
   - Looks for `keccak256("contact:0xMyAddress")` in `recipientHash`
   - Verifies Alice's identity using her derivation proof
4. If interested, Bob responds with a `HandshakeResponse`:
   - Contains a payload encrypted to Alice's **ephemeral key** (not identity key)
   - Includes his own ephemeral key, identity keys, and derivation proof
5. Once handshake is complete, both use Bob's identity key for future `MessageSent` logs:
   - Alice encrypts messages using Bob's **identity key** + **fresh ephemeral keys per message**
   - Alice signs messages using her **signing key**
   - Bob and Alice filter messages using topics, timestamp, or sender

--> **Forward Secrecy**: Every message uses fresh ephemeral keys, providing forward secrecy for all communication.

If the sender does not yet know the recipient's long-term public key (X25519), 
they must emit a `Handshake` event. This allows the recipient to reply with their key.

If the recipient's public key is already known (from a past `HandshakeResponse`, 
on-chain announcement, or static mapping), the sender may skip the handshake.

```
ALICE (Initiator)              BLOCKCHAIN               BOB (Responder)
      |                            |                            |
      |----------------------------|                            |
      |  PHASE 0: Identity Key Derivation (Proof)               |
      |--------------------------->|                            |
      |  Sign derivation msg       |                            |
      |  Derive unified keys       |                            |
      |  Create DerivationProof    |                            |
      |                            |<---------------------------|
      |                            |  Bob: Sign/derive keys     |
      |                            |  Create DerivationProof    |
      |                            |                            |
      |  PHASE 1: Alice Initiates Handshake                     |
      |--------------------------->|                            |
      |  Generate ephemeral keypair|                            |
      |  Prepare HandshakeContent  |                            |
      |  Encode unified pubKeys    |                            |
      |  initiateHandshake()       |--------------------------->|
      |                            |  Emit Handshake event      |
      |                            |--------------------------->|
      |                            |  PHASE 2: Bob Receives     |
      |                            |  Listen for event          |
      |                            |  Parse unified pubKeys     |
      |                            |  Extract DerivationProof   |
      |                            |  Verify Alice's identity   |
      |                            |                            |
      |                            |  PHASE 3: Bob Responds     |
      |                            |--------------------------->|
      |                            |  If valid:                 |
      |                            |   - Generate ephemeral key |
      |                            |   - Prepare response       |
      |                            |   - Encrypt w/ Alice's     |
      |                            |     EPHEMERAL key          |
      |                            |  respondToHandshake()      |
      |                            |  Emit HandshakeResponse    |
      |                            |--------------------------->|
      |                            |  Else: reject handshake    |
      |                            |                            |
      |  PHASE 4: Alice Receives Response                       |
      |<--------------------------|                             |
      |  Listen for HandshakeResponse event                     |
      |  Decrypt response w/ own ephemeral secret               |
      |  Extract Bob's keys & proof                             |
      |  Verify Bob's identity                                  |
      |                                                         |
      |  PHASE 5: Secure Communication Established              |
      |--------------------------->|                            |
      |  Store Bob's keys          |                            |
      |  Ongoing:                  |                            |
      |   - Generate fresh         |                            |
      |     ephemeral keys         |                            |
      |   - Encrypt w/ Bob's       |                            |
      |     IDENTITY key +         |                            |
      |     fresh ephemeral        |                            |
      |   - Sign w/ Alice's key    |                            |
      |   - sendMessage()          |--------------------------->|
      |                            |  Message event received    |
      |                            |  Decrypt w/ Bob's          |
      |                            |    IDENTITY key +          |
      |                            |    ephemeral from msg      |
      |                            |  Verify signature          |
      |                            |  Secure message delivered  |
      |----------------------------|----------------------------|
      |  Key Security:                                          |
      |   - Forward Secrecy (fresh ephemeral keys per message) |
      |   - Identity Verification (derivation proofs)          |
      |   - Address Binding                                     |
      |   - Unified Key Management                              |
```

## Features

- Stateless encrypted messaging via logs
- Ephemeral keys & forward secrecy
- Handshake-based key exchange (no prior trust)
- Minimal metadata via `recipientHash`
- Fully on-chain: no servers, no relays
- Compatible with EOAs and smart contract accounts

## Example Usage (WIP)

```ts
import {
  decryptLog,
  initiateHandshake,
  sendEncryptedMessage,
  deriveIdentityKeyPairWithProof,
} from '@verbeth/sdk';

// 1. Generate or load your long-term identity keypair
const { publicKey, secretKey } = await deriveIdentityKeyPairWithProof(walletClient);

// 2. Receive and decrypt a message from an on-chain log event
const decrypted = decryptLog(eventLog, secretKey);

// 3. Start a handshake with another user
await initiateHandshake({
  contract,                       // LogChainV1
  recipientAddress: '0xBob...',   
  ephemeralPubKey: ephemeralKey.publicKey, 
  plaintextPayload: 'Hi Bob, ping from Alice', // (optional) plaintext handshake message
});

// 4. Send an encrypted message (after handshake is established)
await sendEncryptedMessage({
  contract,                        
  recipientAddress: '0xBob...',
  message: 'Hello again, Bob!',
  senderEphemeralKeyPair: ephemeralKey, // ephemeral keypair used for forward secrecy
  recipientPublicKey,              
});
```


## ⚠️ Smart Account Handshake Limitation
 
[ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) lets a smart-contract wallet prove ownership by exposing `isValidSignature`.  
Because the code that implements that function lives *inside* the contract, the check is impossible until the wallet is actually deployed. Any counter-factual (pre-deploy) account therefore fails a plain ERC-1271 test.

In the current [demo](apps/demo), if a user signs the initial handshake with a **fresh** Smart Account, the sdk can’t verify it yet, so the handshake appears to hang. Deployed accounts work fine.

**Solution in Progress:** A new [`UniversalSigValidator`](packages/contracts/contracts/UniversalSigValidator.sol) contract to fully support [ERC-6492](https://eips.ethereum.org/EIPS/eip-6492) signatures.

**Incoming fix — ERC-6492**  
[ERC-6492](https://eips.ethereum.org/EIPS/eip-6492) standardises a workaround: you wrap the signature together with the account’s `initCode` and send it to a singleton validator that *simulates* the deployment plus the ERC-1271 call in one `eth_call`. For now, I’ve deployed that singleton—[`UniversalSigValidator`](packages/contracts/contracts/UniversalSigValidator.sol)—at  
0x1964A76a7C76C9483f056244c1065Aa0A3a9802d // Base mainnet.

Our client workflow will soon:

1. **Try ERC-1271** on the account (works once it’s live).  
2. **If that reverts**, wrap the signature in an ERC-6492 envelope and ask `UniversalSigValidator` to verify it.

Once integrated, handshake verification will just work regardless of smart account deployment status.

> **Until that release, unverified handshake for undeployed accounts are expected behaviour.**
