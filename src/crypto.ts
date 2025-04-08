import nacl from 'tweetnacl';
import { decodeUTF8, encodeUTF8 } from 'tweetnacl-util';
import { encodePayload, decodePayload } from './payload';

export function encryptMessage(message: string, recipientPublicKey: Uint8Array, senderSecretKey: Uint8Array, senderPublicKey: Uint8Array): string {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const box = nacl.box(
    decodeUTF8(message),
    nonce,
    recipientPublicKey,
    senderSecretKey
  );
  return encodePayload(senderPublicKey, nonce, box);
}

export function decryptMessage(payloadJson: string, recipientSecretKey: Uint8Array): string | null {
  const { epk, nonce, ciphertext } = decodePayload(payloadJson);
  const box = nacl.box.open(ciphertext, nonce, epk, recipientSecretKey);
  if (!box) return null;
  return encodeUTF8(box);
}
