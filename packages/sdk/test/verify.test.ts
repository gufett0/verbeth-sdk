import { describe, it, expect } from 'vitest';
import {
  Wallet,
  Transaction,
  SigningKey,
  keccak256,
  toUtf8Bytes,
  hexlify,
  getBytes,
} from 'ethers';
import nacl from 'tweetnacl';

import { verifyEOAIdentity } from '../src/utils';
import {
  verifyHandshakeIdentity,
  verifyHandshakeResponseIdentity,
} from '../src/verify';
import { convertPublicKeyToX25519 } from '../src/utils/x25519';
import { encryptStructuredPayload } from '../src/crypto';
import { HandshakeResponseContent } from '../src/payload';


async function signedTxAndKey() {
  const wallet = Wallet.createRandom();

  const rawTx = await wallet.signTransaction({
    to: Wallet.createRandom().address,
    value: 0n,
    nonce: 0,
    gasLimit: 21_000n,
    gasPrice: 1n,
    chainId: 1,
  });

  const txObj = Transaction.from(rawTx);
  const expandedPubKey = SigningKey.recoverPublicKey(
    txObj.unsignedHash,
    txObj.signature!
  );

  const rawBytes = getBytes(expandedPubKey).slice(1);
  const identityPubKey = convertPublicKeyToX25519(rawBytes);

  return { wallet, rawTx, identityPubKey };
}

describe('Verify identity & handshake (only EOA)', () => {
  it('verifyEOAIdentity - OK with correct pubkey', async () => {
    const { rawTx, identityPubKey } = await signedTxAndKey();
    expect(verifyEOAIdentity(rawTx, identityPubKey)).toBe(true);
  });

  it('verifyEOAIdentity - KO with wrong pubkey', async () => {
    const { rawTx } = await signedTxAndKey();
    const wrong = new Uint8Array(32).fill(0xaa);
    expect(verifyEOAIdentity(rawTx, wrong)).toBe(false);
  });

  it('verifyHandshakeIdentity (EOA flow) → true', async () => {
    const { wallet, rawTx, identityPubKey } = await signedTxAndKey();

    const handshakeEvent = {
      recipientHash: keccak256(toUtf8Bytes('contact:0xdead')),
      sender: wallet.address,
      identityPubKey: hexlify(identityPubKey),
      ephemeralPubKey: hexlify(nacl.box.keyPair().publicKey),
      plaintextPayload: 'Hi VerbEth',
    };

    const ok = await verifyHandshakeIdentity(handshakeEvent, rawTx);
    expect(ok).toBe(true);
  });

  it('verifyHandshakeResponseIdentity (EOA flow) → true', async () => {
    const { wallet, rawTx, identityPubKey } = await signedTxAndKey();

    const aliceEphemeral = nacl.box.keyPair(); // initiator

    const responseContent: HandshakeResponseContent = {
      identityPubKey,
      ephemeralPubKey: nacl.box.keyPair().publicKey,
      note: 'pong',
    };

    const payload = encryptStructuredPayload(
      responseContent,
      aliceEphemeral.publicKey,
      nacl.box.keyPair().secretKey, // responder's secret
      nacl.box.keyPair().publicKey
    );

    const responseEvent = {
      inResponseTo: keccak256(toUtf8Bytes('test-handshake')),
      responder: wallet.address,
      ciphertext: hexlify(toUtf8Bytes(payload)),
    };

    const ok = await verifyHandshakeResponseIdentity(
      rawTx,
      responseEvent,
      identityPubKey,
      aliceEphemeral.secretKey
    );

    expect(ok).toBe(true);
  });
});
