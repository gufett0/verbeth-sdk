import nacl from 'tweetnacl';
import { decodeUTF8, encodeUTF8 } from 'tweetnacl-util';
import { encodePayload, decodePayload } from './payload';

export function encryptMessage(
  message: string,
  recipientPublicKey: Uint8Array,
  ephemeralSecretKey: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  staticSigningSecretKey?: Uint8Array,
  staticSigningPublicKey?: Uint8Array
): string {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const box = nacl.box(
    decodeUTF8(message),
    nonce,
    recipientPublicKey,
    ephemeralSecretKey
  );

  let sig;
  if (staticSigningSecretKey && staticSigningPublicKey) {
    const dataToSign = Buffer.concat([ephemeralPublicKey, nonce, box]);
    sig = nacl.sign.detached(dataToSign, staticSigningSecretKey);
  }

  return encodePayload(ephemeralPublicKey, nonce, box, sig);
}


export function decryptMessage(
  payloadJson: string,
  recipientSecretKey: Uint8Array,
  staticSigningPublicKey?: Uint8Array
): string | null {
  const { epk, nonce, ciphertext, sig } = decodePayload(payloadJson);

  if (sig && staticSigningPublicKey) {
    const dataToVerify = Buffer.concat([epk, nonce, ciphertext]);
    const valid = nacl.sign.detached.verify(dataToVerify, sig, staticSigningPublicKey);
    if (!valid) return null;
  }

  const box = nacl.box.open(ciphertext, nonce, epk, recipientSecretKey);
  if (!box) return null;
  return encodeUTF8(box);
}