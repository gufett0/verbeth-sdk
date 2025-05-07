import { expect } from 'chai';
import nacl from 'tweetnacl';
import { decryptLog, LogMessage, HandshakeLog, HandshakeResponseLog } from '../src/logs';
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


describe('HandshakeLog structure', () => {
  it('should decode a HandshakeLog from event fields', () => {
    const example: HandshakeLog = {
      recipientHash: '0x' + 'a'.repeat(64),
      sender: '0x' + 'b'.repeat(40),
      identityPubKey: '0x' + 'c'.repeat(64),    
      ephemeralPubKey: '0x' + 'd'.repeat(64),
      plaintextPayload: 'hi there'
    };

    expect(example.recipientHash).to.match(/^0x[a-f0-9]{64}$/);
    expect(example.identityPubKey).to.match(/^0x[a-f0-9]{64}$/); 
    expect(example.ephemeralPubKey).to.have.length.greaterThan(10);
  });

  it('should decode a HandshakeResponseLog', () => {
    const response: HandshakeResponseLog = {
      inResponseTo: '0x' + 'd'.repeat(64),
      responder: '0x' + 'b'.repeat(40),
      ciphertext: '0x' + 'e'.repeat(64)
    };

    expect(response.ciphertext).to.match(/^0x[a-f0-9]{64}$/);
  });
});

