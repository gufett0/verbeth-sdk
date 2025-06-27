import { describe, it, expect, vi } from 'vitest';
import {
  Wallet,
  HDNodeWallet,  
  keccak256,
  toUtf8Bytes,
  hexlify,
  JsonRpcProvider,
} from 'ethers';
import nacl from 'tweetnacl';

import { 
  verifyEOADerivationProof,
  verifySmartAccountDerivationProof,
  isSmartContract 
} from '../src/utils';
import {
  verifyHandshakeIdentity,
  verifyHandshakeResponseIdentity,
} from '../src/verify';
import { encryptStructuredPayload } from '../src/crypto';
import { 
  HandshakeResponseContent, 
  encodeUnifiedPubKeys,
  parseHandshakeKeys 
} from '../src/payload';
import { 
  DerivationProof, 
  HandshakeLog, 
  HandshakeResponseLog 
} from '../src/types';
import { deriveIdentityKeyPairWithProof } from '../src/identity'; 


const mockProvider = {
  async getCode(address: string) {
    // assume all addresses starting with '0xCc' are contracts
    return address.startsWith('0xCc') ? '0x60016000' : '0x';
  },
  async call() {
    return '0x1626ba7e' + '0'.repeat(56); 
  }
} as unknown as JsonRpcProvider;


async function createSDKDerivationProof(wallet: HDNodeWallet): Promise<{
  derivationProof: DerivationProof;
  identityPubKey: Uint8Array;
  signingPubKey: Uint8Array;
  unifiedPubKeys: Uint8Array;
}> {
 
  const result = await deriveIdentityKeyPairWithProof(wallet, wallet.address);
  
  const unifiedPubKeys = encodeUnifiedPubKeys(
    result.keyPair.publicKey,        // X25519
    result.keyPair.signingPublicKey  // Ed25519
  );
  
  return {
    derivationProof: result.derivationProof,
    identityPubKey: result.keyPair.publicKey,
    signingPubKey: result.keyPair.signingPublicKey,
    unifiedPubKeys
  };
}

describe('Verify Identity & Handshake (Updated for Unified Keys)', () => {
  describe('EOA Derivation Proof Verification', () => {
    it('verifyEOADerivationProof - OK with correct unified keys', async () => {
      const wallet: HDNodeWallet = Wallet.createRandom();  
      const { derivationProof, identityPubKey, signingPubKey } = await createSDKDerivationProof(wallet);
      
      const result = verifyEOADerivationProof(
        derivationProof,
        wallet.address,
        { identityPubKey, signingPubKey }
      );
      
      expect(result).toBe(true);
    });

    it('verifyEOADerivationProof - KO with wrong address', async () => {
      const wallet1: HDNodeWallet = Wallet.createRandom();  
      const wallet2: HDNodeWallet = Wallet.createRandom();  
      const { derivationProof, identityPubKey, signingPubKey } = await createSDKDerivationProof(wallet1);
      
      const result = verifyEOADerivationProof(
        derivationProof,
        wallet2.address, 
        { identityPubKey, signingPubKey }
      );
      
      expect(result).toBe(false);
    });

    it('verifyEOADerivationProof - KO with wrong keys', async () => {
      const wallet: HDNodeWallet = Wallet.createRandom(); 
      const { derivationProof } = await createSDKDerivationProof(wallet);
      
      const wrongKeys = {
        identityPubKey: new Uint8Array(32).fill(0xaa),
        signingPubKey: new Uint8Array(32).fill(0xbb)
      };
      
      const result = verifyEOADerivationProof(
        derivationProof,
        wallet.address,
        wrongKeys
      );
      
      expect(result).toBe(false);
    });
  });

  describe('Smart Contract Verification', () => {
    it('isSmartContract detects contracts correctly', async () => {
      expect(await isSmartContract('0xCcCcCc...', mockProvider)).toBe(true);
      expect(await isSmartContract('0xEeeEee...', mockProvider)).toBe(false);
    });

    it('verifySmartAccountDerivationProof - handles EIP-1271 correctly', async () => {
      const contractAddress = '0xCcCcCc1234567890123456789012345678901234';
      
      // mock derivation proof for smart account
      const message = `VerbEth Identity Key Derivation v1\nAddress: ${contractAddress}`;
      const derivationProof: DerivationProof = {
        message,
        signature: '0x' + '1'.repeat(130)
      };
      
      const identityKeyPair = nacl.box.keyPair();
      const signingKeyPair = nacl.sign.keyPair();
      
      const expectedKeys = {
        identityPubKey: identityKeyPair.publicKey,
        signingPubKey: signingKeyPair.publicKey
      };
      
      // In a real scenario, we'd need proper EIP-1271 implementation
      // The function should handle the message hashing internally
      const result = await verifySmartAccountDerivationProof(
        derivationProof,
        contractAddress,
        expectedKeys,
        mockProvider
      );
      
      expect(typeof result).toBe('boolean');
      expect(result).toBe(false); 
    });
  });

  describe('Handshake Verification', () => {
    it('verifyHandshakeIdentity - EOA flow with unified keys', async () => {
      const wallet: HDNodeWallet = Wallet.createRandom();  
      const { derivationProof, unifiedPubKeys } = await createSDKDerivationProof(wallet);
      
      const handshakeEvent: HandshakeLog = {
        recipientHash: keccak256(toUtf8Bytes('contact:0xdead')),
        sender: wallet.address,
        pubKeys: hexlify(unifiedPubKeys),  
        ephemeralPubKey: hexlify(nacl.box.keyPair().publicKey),
        plaintextPayload: JSON.stringify({ 
          plaintextPayload: 'Hi VerbEth',
          derivationProof
        })
      };

      const result = await verifyHandshakeIdentity(handshakeEvent, mockProvider);
      expect(result).toBe(true);
    });

    it('verifyHandshakeIdentity - fails with invalid derivation proof', async () => {
      const wallet: HDNodeWallet = Wallet.createRandom(); 
      const { unifiedPubKeys } = await createSDKDerivationProof(wallet);
      
      // create invalid derivation proof with different wallet signature
      const differentWallet: HDNodeWallet = Wallet.createRandom();
      const invalidMessage = 'Invalid message for verification';
      const invalidSignature = await differentWallet.signMessage(invalidMessage);
      
      const invalidDerivationProof: DerivationProof = {
        message: invalidMessage, 
        signature: invalidSignature 
      };
      
      const handshakeEvent: HandshakeLog = {
        recipientHash: keccak256(toUtf8Bytes('contact:0xdead')),
        sender: wallet.address,  
        pubKeys: hexlify(unifiedPubKeys),
        ephemeralPubKey: hexlify(nacl.box.keyPair().publicKey),
        plaintextPayload: JSON.stringify({
          plaintextPayload: 'Hi VerbEth',
          derivationProof: invalidDerivationProof
        })
      };

      const result = await verifyHandshakeIdentity(handshakeEvent, mockProvider);
      expect(result).toBe(false);
    });
  });

  describe('Handshake Response Verification', () => {
    it('verifyHandshakeResponseIdentity - EOA flow with unified keys', async () => {
      const responderWallet: HDNodeWallet = Wallet.createRandom();  
      const { derivationProof, identityPubKey, unifiedPubKeys } = await createSDKDerivationProof(responderWallet);

      const aliceEphemeral = nacl.box.keyPair(); // initiator
      const responderEphemeral = nacl.box.keyPair();

      const responseContent: HandshakeResponseContent = {
        unifiedPubKeys,     
        ephemeralPubKey: responderEphemeral.publicKey,
        note: 'pong',
        derivationProof    
      };

      const payload = encryptStructuredPayload(
        responseContent,
        aliceEphemeral.publicKey,
        responderEphemeral.secretKey,
        responderEphemeral.publicKey
      );

      const responseEvent: HandshakeResponseLog = {
        inResponseTo: keccak256(toUtf8Bytes('test-handshake')),
        responder: responderWallet.address,
        ciphertext: payload,  
      };

      const result = await verifyHandshakeResponseIdentity(
        responseEvent,
        identityPubKey,    
        aliceEphemeral.secretKey,
        mockProvider
      );

      expect(result).toBe(true);
    });

    it('verifyHandshakeResponseIdentity - fails with wrong identity key', async () => {
      const responderWallet: HDNodeWallet = Wallet.createRandom();  
      const { derivationProof, unifiedPubKeys } = await createSDKDerivationProof(responderWallet);

      const aliceEphemeral = nacl.box.keyPair();
      const responderEphemeral = nacl.box.keyPair();

      const responseContent: HandshakeResponseContent = {
        unifiedPubKeys,
        ephemeralPubKey: responderEphemeral.publicKey,
        note: 'pong',
        derivationProof
      };

      const payload = encryptStructuredPayload(
        responseContent,
        aliceEphemeral.publicKey,
        responderEphemeral.secretKey,
        responderEphemeral.publicKey
      );

      const responseEvent: HandshakeResponseLog = {
        inResponseTo: keccak256(toUtf8Bytes('test-handshake')),
        responder: responderWallet.address,
        ciphertext: payload,  
      };

      const wrongIdentityKey = new Uint8Array(32).fill(0xff);

      const result = await verifyHandshakeResponseIdentity(
        responseEvent,
        wrongIdentityKey,
        aliceEphemeral.secretKey,
        mockProvider
      );

      expect(result).toBe(false);
    });
  });

  describe('Key Parsing', () => {
    it('parseHandshakeKeys extracts unified keys correctly', () => {
      const identityPubKey = new Uint8Array(32).fill(1);
      const signingPubKey = new Uint8Array(32).fill(2);
      const unifiedPubKeys = encodeUnifiedPubKeys(identityPubKey, signingPubKey);
      
      const event = {
        pubKeys: hexlify(unifiedPubKeys)
      };
      
      const parsed = parseHandshakeKeys(event);
      
      expect(parsed).not.toBeNull();
      expect(parsed!.identityPubKey).toEqual(identityPubKey);
      expect(parsed!.signingPubKey).toEqual(signingPubKey);
    });

    it('parseHandshakeKeys returns null for invalid keys', () => {
      const event = {
        pubKeys: '0x1234' 
      };
      
      const parsed = parseHandshakeKeys(event);
      expect(parsed).toBeNull();
    });
  });
});