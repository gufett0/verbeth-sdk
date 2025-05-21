import nacl from 'tweetnacl';
import { 
  encodePayload, 
  decodePayload, 
  encodeStructuredContent,
  decodeStructuredContent,
  MessagePayload,
  HandshakeResponseContent
} from './payload';

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

export function decryptHandshakeResponse(
  payloadJson: string,
  initiatorEphemeralSecretKey: Uint8Array
): HandshakeResponseContent | null {
  return decryptStructuredPayload(
    payloadJson,
    initiatorEphemeralSecretKey,
    (obj) => ({
      identityPubKey: Uint8Array.from(Buffer.from(obj.identityPubKey, 'base64')),
      ephemeralPubKey: Uint8Array.from(Buffer.from(obj.ephemeralPubKey, 'base64')),
      note: obj.note,
      identityProof: obj.identityProof
    })
  );
}