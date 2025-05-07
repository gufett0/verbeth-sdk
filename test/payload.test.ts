import { expect } from 'chai';
import nacl from 'tweetnacl';
import { encryptMessage, decryptMessage } from '../src/crypto';
import { HandshakePayload, encodeHandshakePayload, decodeHandshakePayload,
  encodeHandshakeResponseContent, decodeHandshakeResponseContent 
 } from '../src/payload';

describe('Crypto Payload Encoding', () => {
  it('should encrypt and decrypt a message successfully', () => {
    const senderBoxKey = nacl.box.keyPair();
    const senderSignKey = nacl.sign.keyPair();
    const recipientKey = nacl.box.keyPair();
    const message = 'Hello VerbEth!';

    const payload = encryptMessage(
      message,
      recipientKey.publicKey,
      senderBoxKey.secretKey,
      senderBoxKey.publicKey,
      senderSignKey.secretKey,
      senderSignKey.publicKey
    );

    const decrypted = decryptMessage(payload, recipientKey.secretKey, senderSignKey.publicKey);
    expect(decrypted).to.equal(message);
  });

  it('should return null on decryption with wrong recipient key', () => {
    const senderBoxKey = nacl.box.keyPair();
    const senderSignKey = nacl.sign.keyPair();
    const recipientKey = nacl.box.keyPair();
    const wrongKey = nacl.box.keyPair();
    const message = 'Sensitive Info';

    const payload = encryptMessage(
      message,
      recipientKey.publicKey,
      senderBoxKey.secretKey,
      senderBoxKey.publicKey,
      senderSignKey.secretKey,
      senderSignKey.publicKey
    );

    const decrypted = decryptMessage(payload, wrongKey.secretKey, senderSignKey.publicKey);
    expect(decrypted).to.be.null;
  });

  it('should fail to decrypt if payload is tampered', () => {
    const senderBoxKey = nacl.box.keyPair();
    const senderSignKey = nacl.sign.keyPair();
    const recipientKey = nacl.box.keyPair();
    const message = 'tamper test';

    let payload = encryptMessage(
      message,
      recipientKey.publicKey,
      senderBoxKey.secretKey,
      senderBoxKey.publicKey,
      senderSignKey.secretKey,
      senderSignKey.publicKey
    );

    const parsed = JSON.parse(payload);
    parsed.ct = Buffer.from('00'.repeat(32), 'hex').toString('base64');
    const tampered = JSON.stringify(parsed);

    const decrypted = decryptMessage(tampered, recipientKey.secretKey, senderSignKey.publicKey);
    expect(decrypted).to.be.null;
  });
});


describe('HandshakePayload', () => {
  it('should encode and decode a handshake payload correctly', () => {
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
});

describe('HandshakeResponseContent', () => {
  it('should encode and decode response content correctly', () => {
    const identityPubKey = new Uint8Array(32).fill(3);
    const ephemeralPubKey = new Uint8Array(32).fill(4);
    const note = 'here is my response';

    const encoded = encodeHandshakeResponseContent({ identityPubKey, ephemeralPubKey, note });
    const decoded = decodeHandshakeResponseContent(encoded);

    expect(decoded.identityPubKey).to.deep.equal(identityPubKey);
    expect(decoded.ephemeralPubKey).to.deep.equal(ephemeralPubKey);
    expect(decoded.note).to.equal(note);
  });
});

