// packages/sdk/src/crypto.ts - Aggiornamenti per unified keys

import nacl from 'tweetnacl';
import { 
  encodePayload, 
  decodePayload, 
  encodeStructuredContent,
  decodeStructuredContent,
  MessagePayload,
  HandshakeResponseContent,
  extractKeysFromHandshakeResponse
} from './payload';
import { DerivationProof } from './types';  // 🆕 Import from types

/**
 * Encrypts a structured payload (JSON-serializable objects)
 */
export function encryptStructuredPayload<T>(
  payload: T,
  recipientPublicKey: Uint8Array,
  ephemeralSecretKey: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  staticSigningSecretKey?: Uint8Array,
  staticSigningPublicKey?: Uint8Array
): string {
  // Encode payload as binary JSON
  const plaintext = encodeStructuredContent(payload);
  
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const box = nacl.box(plaintext, nonce, recipientPublicKey, ephemeralSecretKey);

  let sig;
  if (staticSigningSecretKey && staticSigningPublicKey) {
    const dataToSign = Buffer.concat([ephemeralPublicKey, nonce, box]);
    sig = nacl.sign.detached(dataToSign, staticSigningSecretKey);
  }

  return encodePayload(ephemeralPublicKey, nonce, box, sig);
}

/**
 * Decrypts a structured payload with converter function
 */
export function decryptStructuredPayload<T>(
  payloadJson: string,
  recipientSecretKey: Uint8Array,
  converter: (obj: any) => T,
  staticSigningPublicKey?: Uint8Array
): T | null {
  const { epk, nonce, ciphertext, sig } = decodePayload(payloadJson);

  if (sig && staticSigningPublicKey) {
    const dataToVerify = Buffer.concat([epk, nonce, ciphertext]);
    const valid = nacl.sign.detached.verify(dataToVerify, sig, staticSigningPublicKey);
    if (!valid) return null;
  }

  const box = nacl.box.open(ciphertext, nonce, epk, recipientSecretKey);
  if (!box) return null;
  
  return decodeStructuredContent(box, converter);
}

// Convenience wrappers for encrypting and decrypting messages
export function encryptMessage(
  message: string,
  recipientPublicKey: Uint8Array,
  ephemeralSecretKey: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  staticSigningSecretKey?: Uint8Array,
  staticSigningPublicKey?: Uint8Array
): string {
  const payload: MessagePayload = { content: message };
  return encryptStructuredPayload(
    payload,
    recipientPublicKey,
    ephemeralSecretKey,
    ephemeralPublicKey,
    staticSigningSecretKey,
    staticSigningPublicKey
  );
}

export function decryptMessage(
  payloadJson: string,
  recipientSecretKey: Uint8Array,
  staticSigningPublicKey?: Uint8Array
): string | null {
  const result = decryptStructuredPayload(
    payloadJson,
    recipientSecretKey,
    (obj) => obj as MessagePayload,
    staticSigningPublicKey
  );
  return result ? result.content : null;
}

/**
 * Decrypts handshake response and extracts individual keys from unified format
 */
export function decryptHandshakeResponse(
  payloadJson: string,
  initiatorEphemeralSecretKey: Uint8Array
): HandshakeResponseContent | null {
  return decryptStructuredPayload(
    payloadJson,
    initiatorEphemeralSecretKey,
    (obj) => {
      if (!obj.derivationProof) {
        throw new Error("Invalid handshake response: missing derivationProof");
      }
      return {
        unifiedPubKeys: Uint8Array.from(Buffer.from(obj.unifiedPubKeys, 'base64')),
        ephemeralPubKey: Uint8Array.from(Buffer.from(obj.ephemeralPubKey, 'base64')),
        note: obj.note,
        derivationProof: obj.derivationProof
      };
    }
  );
}

/**
 * 🆕 Convenience function to decrypt handshake response and extract individual keys
 */
export function decryptAndExtractHandshakeKeys(
  payloadJson: string,
  initiatorEphemeralSecretKey: Uint8Array
): {
  identityPubKey: Uint8Array;
  signingPubKey: Uint8Array;
  ephemeralPubKey: Uint8Array;
  note?: string;
  derivationProof: DerivationProof;  // 🆕 Using type from types.ts
} | null {
  const decrypted = decryptHandshakeResponse(payloadJson, initiatorEphemeralSecretKey);
  if (!decrypted) return null;
  
  const extracted = extractKeysFromHandshakeResponse(decrypted);
  if (!extracted) return null;
  
  return {
    identityPubKey: extracted.identityPubKey,
    signingPubKey: extracted.signingPubKey,
    ephemeralPubKey: extracted.ephemeralPubKey,
    note: decrypted.note,
    derivationProof: decrypted.derivationProof
  };
}