import { expect } from 'chai';
import nacl from 'tweetnacl';
import { 
  encryptMessage, 
  decryptMessage,
  encryptStructuredPayload,
  decryptStructuredPayload,
  decryptHandshakeResponse
} from '../src/crypto';
import { 
  HandshakePayload, 
  encodeHandshakePayload, 
  decodeHandshakePayload,
  encodeHandshakeResponseContent, 
  decodeHandshakeResponseContent,
  MessagePayload,
  HandshakeResponseContent
} from '../src/payload';
import type { LogMessage } from '../src/types';

describe('Encryption/Decryption', () => {
  describe('Message Encryption', () => {
    it('should encrypt and decrypt a message successfully', () => {
      const senderBoxKey = nacl.box.keyPair();
      const senderSignKey = nacl.sign.keyPair();
      const recipientKey = nacl.box.keyPair();
      const message = 'Hello VerbEth!';

      const encrypted = encryptMessage(
        message,
        recipientKey.publicKey,
        senderBoxKey.secretKey,
        senderBoxKey.publicKey,
        senderSignKey.secretKey,
        senderSignKey.publicKey
      );

      const decrypted = decryptMessage(encrypted, recipientKey.secretKey, senderSignKey.publicKey);
      expect(decrypted).to.equal(message);
    });

    it('should return null on decryption with wrong recipient key', () => {
      const senderBoxKey = nacl.box.keyPair();
      const senderSignKey = nacl.sign.keyPair();
      const recipientKey = nacl.box.keyPair();
      const wrongKey = nacl.box.keyPair();
      const message = 'Sensitive Info';

      const encrypted = encryptMessage(
        message,
        recipientKey.publicKey,
        senderBoxKey.secretKey,
        senderBoxKey.publicKey,
        senderSignKey.secretKey,
        senderSignKey.publicKey
      );

      const decrypted = decryptMessage(encrypted, wrongKey.secretKey, senderSignKey.publicKey);
      expect(decrypted).to.be.null;
    });

    it('should fail to decrypt if payload is tampered', () => {
      const senderBoxKey = nacl.box.keyPair();
      const senderSignKey = nacl.sign.keyPair();
      const recipientKey = nacl.box.keyPair();
      const message = 'tamper test';

      let encrypted = encryptMessage(
        message,
        recipientKey.publicKey,
        senderBoxKey.secretKey,
        senderBoxKey.publicKey,
        senderSignKey.secretKey,
        senderSignKey.publicKey
      );

      const parsed = JSON.parse(encrypted);
      parsed.ct = Buffer.from('00'.repeat(32), 'hex').toString('base64');
      const tampered = JSON.stringify(parsed);

      const decrypted = decryptMessage(tampered, recipientKey.secretKey, senderSignKey.publicKey);
      expect(decrypted).to.be.null;
    });

    it('should work with the structured message format', () => {
      const senderBoxKey = nacl.box.keyPair();
      const senderSignKey = nacl.sign.keyPair();
      const recipientKey = nacl.box.keyPair();
      
      const messagePayload: MessagePayload = {
        content: 'Hello structured VerbEth!',
        timestamp: Date.now(),
        messageType: 'text'
      };

      const encrypted = encryptStructuredPayload(
        messagePayload,
        recipientKey.publicKey,
        senderBoxKey.secretKey,
        senderBoxKey.publicKey,
        senderSignKey.secretKey,
        senderSignKey.publicKey
      );

      const decrypted = decryptStructuredPayload(
        encrypted,
        recipientKey.secretKey,
        (obj) => obj as MessagePayload,
        senderSignKey.publicKey
      );

      expect(decrypted).to.deep.equal(messagePayload);
    });
  });

  describe('Handshake Response Encryption', () => {
    it('should encrypt and decrypt handshake response content', () => {
      const initiatorEphemeralKey = nacl.box.keyPair();
      const responderEphemeralKey = nacl.box.keyPair();
      const identityPubKey = new Uint8Array(32).fill(3);
      const ephemeralPubKey = new Uint8Array(32).fill(4);
      const note = 'here is my response';

      const responseContent: HandshakeResponseContent = {
        identityPubKey,
        ephemeralPubKey,
        note
      };

      const encrypted = encryptStructuredPayload(
        responseContent,
        initiatorEphemeralKey.publicKey,
        responderEphemeralKey.secretKey,
        responderEphemeralKey.publicKey
      );

      const decrypted = decryptHandshakeResponse(
        encrypted,
        initiatorEphemeralKey.secretKey
      );

      expect(decrypted).to.not.be.null;
      expect(decrypted!.identityPubKey).to.deep.equal(identityPubKey);
      expect(decrypted!.ephemeralPubKey).to.deep.equal(ephemeralPubKey);
      expect(decrypted!.note).to.equal(note);
    });

    it('should handle handshake response with identity proof', () => {
      const initiatorEphemeralKey = nacl.box.keyPair();
      const responderEphemeralKey = nacl.box.keyPair();
      const identityPubKey = new Uint8Array(32).fill(5);
      const ephemeralPubKey = new Uint8Array(32).fill(6);
      const identityProof = {
        signature: '0x' + '1'.repeat(130),
        message: '0x' + '2'.repeat(64)
      };

      const responseContent: HandshakeResponseContent = {
        identityPubKey,
        ephemeralPubKey,
        note: 'with proof',
        identityProof
      };

      const encrypted = encryptStructuredPayload(
        responseContent,
        initiatorEphemeralKey.publicKey,
        responderEphemeralKey.secretKey,
        responderEphemeralKey.publicKey
      );

      const decrypted = decryptHandshakeResponse(
        encrypted,
        initiatorEphemeralKey.secretKey
      );

      expect(decrypted).to.not.be.null;
      expect(decrypted!.identityProof).to.deep.equal(identityProof);
    });
  });

  describe('Payload Encoding/Decoding', () => {
    it('should encode and decode handshake payload correctly', () => {
      const payload: HandshakePayload = {
        identityPubKey: new Uint8Array(32).fill(1),
        ephemeralPubKey: new Uint8Array(32).fill(2),
        plaintextPayload: 'hello bob'
      };

      const encoded = encodeHandshakePayload(payload);
      const decoded = decodeHandshakePayload(encoded);

      expect(decoded.identityPubKey).to.deep.equal(payload.identityPubKey);
      expect(decoded.ephemeralPubKey).to.deep.equal(payload.ephemeralPubKey);
      expect(decoded.plaintextPayload).to.equal('hello bob');
    });

    it('should encode and decode response content correctly', () => {
      const identityPubKey = new Uint8Array(32).fill(3);
      const ephemeralPubKey = new Uint8Array(32).fill(4);
      const note = 'here is my response';

      const content: HandshakeResponseContent = {
        identityPubKey,
        ephemeralPubKey,
        note
      };

      const encoded = encodeHandshakeResponseContent(content);
      const decoded = decodeHandshakeResponseContent(encoded);

      expect(decoded.identityPubKey).to.deep.equal(identityPubKey);
      expect(decoded.ephemeralPubKey).to.deep.equal(ephemeralPubKey);
      expect(decoded.note).to.equal(note);
    });
  });

  describe('Log Message Structure', () => {
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
        sender: '0x' + 'a'.repeat(40),
        ciphertext,
        timestamp: Math.floor(Date.now() / 1000),
        topic: '0x' + 'd'.repeat(64),
        nonce: 1n
      };

      const decrypted = decryptMessage(mockLog.ciphertext, recipientKey.secretKey, senderSignKey.publicKey);
      expect(decrypted).to.equal(message);
    });
  });
});