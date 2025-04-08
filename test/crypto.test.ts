import { expect } from 'chai';
import nacl from 'tweetnacl';
import { encryptMessage, decryptMessage } from '../src/crypto';

describe('Crypto Payload Encoding', () => {
  it('should encrypt and decrypt a message successfully', () => {
    const senderKeyPair = nacl.box.keyPair();
    const recipientKeyPair = nacl.box.keyPair();
    const message = 'Hello VerbEth!';

    const payload = encryptMessage(
      message,
      recipientKeyPair.publicKey,
      senderKeyPair.secretKey,
      senderKeyPair.publicKey
    );

    const decrypted = decryptMessage(payload, recipientKeyPair.secretKey);
    expect(decrypted).to.equal(message);
  });

  it('should return null on decryption with wrong recipient key', () => {
    const senderKeyPair = nacl.box.keyPair();
    const recipientKeyPair = nacl.box.keyPair();
    const wrongRecipient = nacl.box.keyPair();
    const message = 'Sensitive Info';

    const payload = encryptMessage(
      message,
      recipientKeyPair.publicKey,
      senderKeyPair.secretKey,
      senderKeyPair.publicKey
    );

    const decrypted = decryptMessage(payload, wrongRecipient.secretKey);
    expect(decrypted).to.be.null;
  });

  it('should fail to decrypt if payload is tampered', () => {
    const senderKeyPair = nacl.box.keyPair();
    const recipientKeyPair = nacl.box.keyPair();
    const message = 'tamper test';

    let payload = encryptMessage(
      message,
      recipientKeyPair.publicKey,
      senderKeyPair.secretKey,
      senderKeyPair.publicKey
    );

    const parsed = JSON.parse(payload);
    parsed.ct = Buffer.from('00'.repeat(32), 'hex').toString('base64'); // corrupted ciphertext
    const tampered = JSON.stringify(parsed);

    const decrypted = decryptMessage(tampered, recipientKeyPair.secretKey);
    expect(decrypted).to.be.null;
  });
});
