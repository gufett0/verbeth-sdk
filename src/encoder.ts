import nacl from 'tweetnacl';
import { decodeUTF8 } from 'tweetnacl-util';

export function encryptMessage(message: string, recipientPublicKey: Uint8Array, senderSecretKey: Uint8Array) {
  const nonce = nacl.randomBytes(24);
  const box = nacl.box(
    decodeUTF8(message),
    nonce,
    recipientPublicKey,
    senderSecretKey
  );

  return { box, nonce };
}
