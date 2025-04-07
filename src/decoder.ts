import nacl from 'tweetnacl';

export function decryptMessage(box: Uint8Array, nonce: Uint8Array, senderPublicKey: Uint8Array, recipientSecretKey: Uint8Array): string | null {
  const decrypted = nacl.box.open(box, nonce, senderPublicKey, recipientSecretKey);
  if (!decrypted) return null;
  return new TextDecoder().decode(decrypted);
}
