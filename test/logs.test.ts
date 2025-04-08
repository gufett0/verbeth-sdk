import { expect } from 'chai';
import nacl from 'tweetnacl';
import { decryptLog, LogMessage } from '../src/logs';
import { encryptMessage } from '../src/crypto';

describe('Log decoding', () => {
  it('should decode and decrypt a log message', () => {
    const senderBoxKey = nacl.box.keyPair();
    const senderSignKey = nacl.sign.keyPair(); 

    const recipientKey = nacl.box.keyPair();
    
    const message = 'from on-chain log';

    const ciphertext = encryptMessage(
      message,
      recipientKey.publicKey,
      senderBoxKey.secretKey,
      senderBoxKey.publicKey,
      senderSignKey.secretKey,
      senderSignKey.publicKey
    );

    const mockLog: LogMessage = {
      sender: '0xabc123...',
      ciphertext,
      timestamp: Math.floor(Date.now() / 1000),
      topic: '0xdeadbeef...',
      nonce: 1n
    };

    const decrypted = decryptLog(mockLog, recipientKey.secretKey, senderSignKey.publicKey);
    expect(decrypted).to.equal(message);
  });
});
