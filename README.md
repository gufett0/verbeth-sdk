# VerbEth SDK

End-to-end encrypted messaging over Ethereum logs, using the blockchain as the only transport layer. Uses `tweetnacl.box` to encrypt/decrypt messages with ephemeral keys and optional sender identity. Ensures forward secrecy and compatibility with smart accounts.

## How It Works: Alice & Bob (High-level Flow)

Alice wants to initiate a secure chat with Bob using only the blockchain.

1. Alice generates a new **ephemeral keypair**.
2. She emits a `Handshake` event:
   - Includes her ephemeral public key
   - Includes her long-term unified keys (X25519 + Ed25519)
   - Plaintext payload like: `"Hi Bob, respond if you're online"` with identity proof
3. Bob watches logs for `Handshake` events addressed to him:
   - Looks for `keccak256("contact:0xMyAddress")` in `recipientHash`
   - Verifies Alice's identity using her identity proof
4. If interested, Bob responds with a `HandshakeResponse`:
   - Contains a payload encrypted to Alice's **ephemeral key** (not identity key)
   - Includes his own ephemeral key, identity keys, and identity proof
5. Once handshake is complete, both use Bob's identity key for future `MessageSent` logs:
   - Alice encrypts messages using Bob's **identity key** + **fresh ephemeral keys per message**
   - Alice signs messages using her **signing key**
   - Bob and Alice filter messages using topics, timestamp, or sender



```
ALICE (Initiator)              BLOCKCHAIN               BOB (Responder)
      |                            |                            |
      |----------------------------|----------------------------|
      |                          PHASE 0:                       |
      |                 Identity and Key Derivation             |
      |--------------------------->|                            |
      |  Generate identity keys     |                           |
      | Sign identity-binding msg  |                            |                            
      |  Create IdentityProof      |                            |
      |                            |<---------------------------|
      |                            |  Generate identity keys    |                            
      |                            | Sign identity-binding msg  |                         
      |                            |   Create IdentityProof     |
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
      |                            |  Extract IdentityProof     |
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
      |   - Forward Secrecy (fresh ephemeral keys per message)  |
      |   - Identity Verification                               |
      |   - Address Binding                                     |
      |   - Unified Key Management                              |
```


## Contract

/// We include `sender` (= msg.sender) as an indexed event field to bind each log to the
/// actual caller account (EOA or smart account) and make it Bloom-filterable. A tx receipt/log
/// does not expose the immediate caller of this contract—it only contains the emitter address
/// (this contract) and the topics/data—so recovering `msg.sender` would require execution traces.
/// Under ERC-4337 this is even harder: the outer tx targets EntryPoint and tx.from is the bundler,
/// not the smart account. Without `sender` in the event, reliably linking a log to the originating
/// account requires correlating EntryPoint internals or traces, which is non-standard and costly.

### Deployed Addresses

LogChainV1 `0x41a3eaC0d858028E9228d1E2092e6178fc81c4f0`

ERC1967Proxy `0x62720f39d5Ec6501508bDe4D152c1E13Fd2F6707`

## Features

- Stateless encrypted messaging via logs
- Ephemeral keys & forward secrecy
- Handshake-based key exchange (no prior trust)
- Minimal metadata via `recipientHash`
- Fully on-chain: no servers, no relays
- Compatible with EOAs and smart contract accounts

The SDK now verifies handshakes and handshake responses using [viem.verifyMessage](https://viem.sh/docs/actions/public/verifyMessage).  
It supports both EOAs and Smart Contract Accounts — whether they’re already deployed or still counterfactual/pre-deployed — by leveraging:

- ERC-1271: for verifying signatures from smart contract wallets that are deployed.
- ERC-6492: a wrapper standard that lets smart contract accounts sign and be verified before deployment.

### Notes on the current model

**Discoverability**: If the sender does not yet know the recipient’s long-term public key (X25519), the sender must emit a `Handshake` event. The recipient replies with their keys and identity proof, after which the sender caches the verified mapping. If the key is already known (from a past `HandshakeResponse`, an on-chain announcement, or a static mapping), the handshake can be skipped.

**Identity key binding**: The message (es. “VerbEth Key Binding v1\nAddress: …\nPkEd25519: …\nPkX25519: …\nContext: …\nVersion: …”) is signed by the evm account directly binding its address to the long-term keys (i.e. preventing impersonation).

**Non-repudiation**: By default, confidentiality and integrity are guaranteed by AEAD with NaCl box. Additionally, the sender can attach a detached Ed25519 signature over (epk || nonce || ciphertext) using the Ed25519 key bound in the handshake. This effectively provides per-message origin authentication that is verifiable: a recipient (or any third party) can prove the message was produced by the holder of that specific Ed25519 key. Otherwise, attribution relies on context, making sender spoofing at the application layer harder to detect.

**Forward secrecy**: Each message uses a fresh sender ephemeral key. This provides sender-side forward secrecy for sent messages: once the sender deletes the ephemeral secret, a future compromise of their long-term keys does not expose past ciphertexts. Handshake responses also use ephemeral↔ephemeral, enjoying the same property. However, if a recipient’s long-term X25519 key is compromised, all past messages addressed to them remain decryptable. A double-ratchet (or ephemeral↔ephemeral messaging) can extend forward secrecy to the recipient side (see [here](#improvement-ideas)).


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
## Improvement ideas
| Title                                              | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Refs                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Bidirectional Forward Secrecy (session ratchet)    | Achieve **end-to-end, bilateral FS** even if the **recipient’s long-term X25519** is later compromised. Two options: (1) switch messaging to **ephemeral↔ephemeral** (derive per-message DH and discard secrets), or (2) derive a **symmetric session ratchet** from the handshake (e.g., **Double Ratchet** for 1:1; **MLS** for 1\:many) so every message advances sending/receiving chains and old keys are irrecoverable. | Signal **Double Ratchet** spec (post-X3DH): [https://signal.org/docs/specifications/doubleratchet/](https://signal.org/docs/specifications/doubleratchet/) ; **MLS** (RFC 9420): [https://www.rfc-editor.org/rfc/rfc9420](https://www.rfc-editor.org/rfc/rfc9420) ; Matrix **Olm/Megolm** (Double Ratchet for 1:1 / group): [https://gitlab.matrix.org/matrix-org/olm](https://gitlab.matrix.org/matrix-org/olm) ; **Status/Waku** Double Ratchet transport: [https://specs.status.im/spec/5](https://specs.status.im/spec/5) and Waku X3DH/DR notes: [https://rfc.vac.dev/waku/standards/application/53/x3dh/](https://rfc.vac.dev/waku/standards/application/53/x3dh/) ; **XMTP** (MLS-based): [https://docs.xmtp.org/protocol/overview](https://docs.xmtp.org/protocol/overview) |
| Passkeys & WebAuthn PRF for encryption of messages | Let smart accounts encrypt messages with the same passkey used for UserOps. Use the WebAuthn **PRF** extension to derive an AEAD key at auth time (plus per-message salt/nonce) so users only manage the passkey—gaining stronger security (hardware/biometric protection) and portability/recovery (OS-synced passkeys or hardware keys).                                                                                                                                                                 | [Corbado: Passkeys & PRF](https://www.corbado.com/blog/passkeys-prf-webauthn), [W3C WebAuthn L3: PRF extension](https://www.w3.org/TR/webauthn-3/), [Chrome: Intent to Ship (PRF)](https://groups.google.com/a/chromium.org/g/blink-dev/c/iTNOgLwD2bI), [SimpleWebAuthn: PRF docs](https://simplewebauthn.dev/docs/advanced/prf)                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
