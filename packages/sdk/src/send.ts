// packages/sdk/src/send.ts

import { 
  keccak256,
  toUtf8Bytes,
  hexlify,
  Signer
} from "ethers";
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";
import { getNextNonce } from './utils/nonce';
import { encryptMessage, encryptStructuredPayload } from './crypto';
import { 
  HandshakeContent, 
  serializeHandshakeContent,
  encodeUnifiedPubKeys,
  createHandshakeResponseContent
} from './payload';
import { IdentityKeyPair, DerivationProof } from './types';  
import nacl from 'tweetnacl';

/**
 * Sends an encrypted message assuming recipient's keys were already obtained via handshake
 */
export async function sendEncryptedMessage({
  contract,
  topic,
  message,
  recipientPubKey,
  senderAddress,
  senderSignKeyPair,
  timestamp
}: {
  contract: LogChainV1;
  topic: string;
  message: string;
  recipientPubKey: Uint8Array;          // X25519 key for encryption
  senderAddress: string;
  senderSignKeyPair: nacl.SignKeyPair;  // Ed25519 keys for signing
  timestamp: number;
}) {
  const ephemeralKeyPair = nacl.box.keyPair();

  const ciphertext = encryptMessage(
    message,
    recipientPubKey,                      // X25519 for encryption
    ephemeralKeyPair.secretKey,
    ephemeralKeyPair.publicKey,
    senderSignKeyPair.secretKey,          // Ed25519 for signing
    senderSignKeyPair.publicKey
  );

  const nonce = getNextNonce(senderAddress, topic);

  return contract.sendMessage(toUtf8Bytes(ciphertext), topic, timestamp, nonce);
}

/**
 * Initiates an on-chain handshake with unified keys and mandatory identity proof
 */
export async function initiateHandshake({
  contract,
  recipientAddress,
  identityKeyPair,
  ephemeralPubKey,
  plaintextPayload,
  derivationProof,         // 🆕 Using type from types.ts
  signer
}: {
  contract: LogChainV1;
  recipientAddress: string;
  identityKeyPair: IdentityKeyPair;
  ephemeralPubKey: Uint8Array;
  plaintextPayload: string;
  derivationProof: DerivationProof;  // 🆕 Using type from types.ts
  signer: Signer;
}) {
  const recipientHash = keccak256(
    toUtf8Bytes('contact:' + recipientAddress.toLowerCase())
  );

  // 🆕 Sempre include derivation proof (obbligatorio)
  const handshakeContent: HandshakeContent = {
    plaintextPayload,
    derivationProof
  };

  const serializedPayload = serializeHandshakeContent(handshakeContent);

  // 🆕 Create unified pubKeys (65 bytes: version + X25519 + Ed25519)
  const unifiedPubKeys = encodeUnifiedPubKeys(
    identityKeyPair.publicKey,        // X25519 for encryption
    identityKeyPair.signingPublicKey  // Ed25519 for signing
  );

  // Contract call with unified keys
  return await contract.initiateHandshake(
    recipientHash,
    hexlify(unifiedPubKeys),            // 🆕 65 bytes unified field
    hexlify(ephemeralPubKey),
    toUtf8Bytes(serializedPayload)
  );
}

/**
 * Responds to a handshake with unified keys and mandatory identity proof
 */
export async function respondToHandshake({
  contract,
  inResponseTo,
  initiatorPubKey,
  responderIdentityKeyPair,
  responderEphemeralKeyPair,
  note,
  derivationProof,         // 🆕 Using type from types.ts
  signer
}: {
  contract: LogChainV1;
  inResponseTo: string;
  initiatorPubKey: Uint8Array;
  responderIdentityKeyPair: IdentityKeyPair;
  responderEphemeralKeyPair?: nacl.BoxKeyPair;
  note?: string;
  derivationProof: DerivationProof;  // 🆕 Using type from types.ts
  signer: Signer;
}) {
  const ephemeralKeyPair = responderEphemeralKeyPair || nacl.box.keyPair();
  
  // 🆕 Sempre include derivation proof
  const responseContent = createHandshakeResponseContent(
    responderIdentityKeyPair.publicKey,        // X25519
    responderIdentityKeyPair.signingPublicKey, // Ed25519
    ephemeralKeyPair.publicKey,
    note,
    derivationProof         // 🆕 Include derivation proof invece di identityProof
  );
  
  // Encrypt the response for the initiator
  const payload = encryptStructuredPayload(
    responseContent,
    initiatorPubKey,              // Encrypt to initiator's X25519 key
    ephemeralKeyPair.secretKey,
    ephemeralKeyPair.publicKey
  );
  
  return contract.respondToHandshake(inResponseTo, toUtf8Bytes(payload));
}