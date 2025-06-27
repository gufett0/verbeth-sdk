import { describe, it, expect } from 'vitest';
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
  HandshakeResponseContent,
  encodeUnifiedPubKeys 
} from '../src/payload';
import { DerivationProof } from '../src/types';
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
      expect(decrypted).toBe(message);
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
      expect(decrypted).toBeNull();
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
      expect(decrypted).toBeNull();
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

      expect(decrypted).toEqual(messagePayload);
    });
  });

  describe('Handshake Response Encryption', () => {
    it('should encrypt and decrypt handshake response content', () => {
      const initiatorEphemeralKey = nacl.box.keyPair();
      const responderEphemeralKey = nacl.box.keyPair();
      
      const identityPubKey = new Uint8Array(32).fill(3);
      const signingPubKey = new Uint8Array(32).fill(7);
      const unifiedPubKeys = encodeUnifiedPubKeys(identityPubKey, signingPubKey);
      
      const ephemeralPubKey = new Uint8Array(32).fill(4);
      const note = 'here is my response';
      
      const derivationProof: DerivationProof = {
        message: 'VerbEth Identity Key Derivation v1\nAddress: 0x1234...',
        signature: '0x' + '1'.repeat(130)
      };

      const responseContent: HandshakeResponseContent = {
        unifiedPubKeys,      
        ephemeralPubKey,
        note,
        derivationProof     
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

      expect(decrypted).not.toBeNull();
      expect(decrypted!.unifiedPubKeys).toEqual(unifiedPubKeys);  
      expect(decrypted!.ephemeralPubKey).toEqual(ephemeralPubKey);
      expect(decrypted!.note).toBe(note);
      expect(decrypted!.derivationProof).toEqual(derivationProof); 
    });

    it('should handle handshake response with derivation proof', () => {
      const initiatorEphemeralKey = nacl.box.keyPair();
      const responderEphemeralKey = nacl.box.keyPair();
      
      const identityPubKey = new Uint8Array(32).fill(5);
      const signingPubKey = new Uint8Array(32).fill(8);
      const unifiedPubKeys = encodeUnifiedPubKeys(identityPubKey, signingPubKey);
      
      const ephemeralPubKey = new Uint8Array(32).fill(6);
      
      const derivationProof: DerivationProof = {
        message: 'VerbEth Identity Key Derivation v1\nAddress: 0xabcd...',
        signature: '0x' + '2'.repeat(130)
      };

      const responseContent: HandshakeResponseContent = {
        unifiedPubKeys,    
        ephemeralPubKey,
        note: 'with derivation proof',
        derivationProof      
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

      expect(decrypted).not.toBeNull();
      expect(decrypted!.derivationProof).toEqual(derivationProof);  
    });
  });

  describe('Payload Encoding/Decoding', () => {
    it('should encode and decode handshake payload correctly', () => {
      const identityPubKey = new Uint8Array(32).fill(1);
      const signingPubKey = new Uint8Array(32).fill(9);
      const unifiedPubKeys = encodeUnifiedPubKeys(identityPubKey, signingPubKey);
      
      const payload: HandshakePayload = {
        unifiedPubKeys,     
        ephemeralPubKey: new Uint8Array(32).fill(2),
        plaintextPayload: 'hello bob'
      };

      const encoded = encodeHandshakePayload(payload);
      const decoded = decodeHandshakePayload(encoded);

      expect(decoded.unifiedPubKeys).toEqual(payload.unifiedPubKeys);  
      expect(decoded.ephemeralPubKey).toEqual(payload.ephemeralPubKey);
      expect(decoded.plaintextPayload).toBe('hello bob');
    });

    it('should encode and decode response content correctly', () => {
      const identityPubKey = new Uint8Array(32).fill(3);
      const signingPubKey = new Uint8Array(32).fill(10);
      const unifiedPubKeys = encodeUnifiedPubKeys(identityPubKey, signingPubKey);
      
      const ephemeralPubKey = new Uint8Array(32).fill(4);
      const note = 'here is my response';
      
      const derivationProof: DerivationProof = {
        message: 'VerbEth Identity Key Derivation v1\nAddress: 0xtest...',
        signature: '0x' + '3'.repeat(130)
      };

      const content: HandshakeResponseContent = {
        unifiedPubKeys,      
        ephemeralPubKey,
        note,
        derivationProof    
      };

      const encoded = encodeHandshakeResponseContent(content);
      const decoded = decodeHandshakeResponseContent(encoded);

      expect(decoded.unifiedPubKeys).toEqual(unifiedPubKeys); 
      expect(decoded.ephemeralPubKey).toEqual(ephemeralPubKey);
      expect(decoded.note).toBe(note);
      expect(decoded.derivationProof).toEqual(derivationProof);  
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
      expect(decrypted).toBe(message);
    });
  });
});