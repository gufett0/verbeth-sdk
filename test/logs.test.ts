import { expect } from 'chai';
import nacl from 'tweetnacl';
import { decryptLog, LogMessage } from '../src/logs';
import { encryptMessage } from '../src/crypto';

describe('Log decoding', () => {
  it('should decode and decrypt a log message', () => {
    const senderKey = nacl.box.keyPair();
    const recipientKey = nacl.box.keyPair();
    const message = 'from on-chain log';

    const ciphertext = encryptMessage(
      message,
      recipientKey.publicKey,
      senderKey.secretKey,
      senderKey.publicKey
    );

    const mockLog: LogMessage = {
      sender: '0xabc123...',
      ciphertext,
      timestamp: Math.floor(Date.now() / 1000),
      topic: '0xdeadbeef...', // arbitrary
      nonce: 1n
    };

    const decrypted = decryptLog(mockLog, recipientKey.secretKey);
    expect(decrypted).to.equal(message);
  });
});
