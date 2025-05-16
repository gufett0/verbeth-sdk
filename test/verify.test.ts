import { expect } from "chai";
import { ethers, Wallet, Provider, Signer } from "../utils/ethers"; 
import { verifyHandshakeResponseIdentity, verifyEOAHandshakeResponse } from "../src/verify";
import { convertPublicKeyToX25519 } from "../utils/x25519";
import { LogChain, TestSmartAccount } from "../typechain-types";
import { encryptStructuredPayload } from "../src/crypto";
import { HandshakeResponseContent } from "../src/payload";
import nacl from 'tweetnacl';

describe("Handshake Response Verification", function () {
  let provider: Provider;

  beforeEach(async () => {
    const [signer] = await ethers.getSigners();
    provider = signer.provider!;
  });

  describe("EOA Verification", function () {
    let logChain: LogChain;

    beforeEach(async () => {
      const factory = await ethers.getContractFactory("LogChain");
      logChain = await factory.deploy();
      await logChain.waitForDeployment();
    });

    it("should verify EOA identity from transaction signature", async function () {
      // Create a random wallet 
      const [fundedSigner] = await ethers.getSigners();
      const wallet = new Wallet(Wallet.createRandom().privateKey).connect(provider);

      await fundedSigner.sendTransaction({
        to: wallet.address,
        value: ethers.parseEther("1.0"),
      });

      // Derive x25519 key from wallet signature
      const testMessage = "VerbEth-test";
      const signature = await wallet.signMessage(testMessage);
      const expandedPubKey = ethers.SigningKey.recoverPublicKey(
        ethers.hashMessage(testMessage),
        signature
      );
      const rawBytes = ethers.getBytes(expandedPubKey).slice(1);
      const x25519PubKey = convertPublicKeyToX25519(rawBytes);

      // Create a transaction
      const tx = await logChain
        .connect(wallet)
        .respondToHandshake(
          ethers.keccak256(ethers.toUtf8Bytes("test")),
          ethers.hexlify(ethers.randomBytes(64))
        );
      
      const receipt = await tx.wait();
      const minedTx = await provider.getTransaction(receipt!.hash);
      const serializedTx = ethers.Transaction.from(minedTx!).serialized;
      
      // Test verification
      const verified = verifyEOAHandshakeResponse(serializedTx, x25519PubKey);
      expect(verified).to.be.true;
    });

    it("should reject verification with wrong public key", async function () {
      const [wallet] = await ethers.getSigners();
      const wrongKey = new Uint8Array(32).fill(0x99);
      
      const tx = await logChain
        .connect(wallet)
        .respondToHandshake(
          ethers.keccak256(ethers.toUtf8Bytes("test")),
          ethers.hexlify(ethers.randomBytes(64))
        );
      
      const receipt = await tx.wait();
      const minedTx = await provider.getTransaction(receipt!.hash);
      const serializedTx = ethers.Transaction.from(minedTx!).serialized;
      
      const verified = verifyEOAHandshakeResponse(serializedTx, wrongKey);
      expect(verified).to.be.false;
    });
  });

  describe("Smart Account Verification", function () {
    let testSmartAccount: TestSmartAccount;
    let owner: Signer;

    beforeEach(async function () {
      [owner] = (await ethers.getSigners()) as unknown as Signer[];
      const AccountFactory = await ethers.getContractFactory("TestSmartAccount");
      testSmartAccount = await AccountFactory.deploy(await owner.getAddress());
      await testSmartAccount.waitForDeployment();
    });

    it("should verify valid EIP-1271 signature", async function () {
      const message = "VerbEth-HSResponse-test";
      const messageHash = ethers.hashMessage(message);
      const signature = await owner.signMessage(message);
      
      const result = await testSmartAccount.isValidSignature(messageHash, signature);
      expect(result).to.equal("0x1626ba7e");
    });

    it("should reject invalid EIP-1271 signature", async function () {
      const [, attacker] = await ethers.getSigners();
      const message = "VerbEth-HSResponse-test";
      const messageHash = ethers.hashMessage(message);
      const signature = await attacker.signMessage(message);
      
      const result = await testSmartAccount.isValidSignature(messageHash, signature);
      expect(result).to.equal("0xffffffff");
    });
  });

  describe("Unified verifyHandshakeResponseIdentity", function () {
    let logChain: LogChain;
    let testSmartAccount: TestSmartAccount;
    let owner: Signer;

    beforeEach(async function () {
      [owner] = (await ethers.getSigners()) as unknown as Signer[];
      const logChainFactory = await ethers.getContractFactory("LogChain");
      logChain = await logChainFactory.deploy();
      await logChain.waitForDeployment();
      
      const accountFactory = await ethers.getContractFactory("TestSmartAccount");
      testSmartAccount = await accountFactory.deploy(await owner.getAddress());
      await testSmartAccount.waitForDeployment();
      
    });

    it("should correctly detect and verify EOA", async function () {
      const [fundedSigner] = await ethers.getSigners();
      const eoaWallet = new Wallet(Wallet.createRandom().privateKey).connect(provider);
      
      await fundedSigner.sendTransaction({
        to: eoaWallet.address,
        value: ethers.parseEther("1.0"),
      });

      // Derive identity key
      const msg = "VerbEth-HSResponse-v1";
      const sig = await eoaWallet.signMessage(msg);
      const expandedPubKey = ethers.SigningKey.recoverPublicKey(
        ethers.hashMessage(msg),
        sig
      );
      const rawBytes = ethers.getBytes(expandedPubKey).slice(1);
      const identityPubKey = convertPublicKeyToX25519(rawBytes);

      const tx = await logChain
        .connect(eoaWallet)
        .respondToHandshake(
          ethers.keccak256(ethers.toUtf8Bytes("test")),
          ethers.hexlify(ethers.randomBytes(64))
        );
      
      const receipt = await tx.wait();
      const minedTx = await provider.getTransaction(receipt!.hash);
      const serializedTx = ethers.Transaction.from(minedTx!).serialized;
      
      // Mock response event
      const responseEvent = {
        responder: eoaWallet.address,
        ciphertext: ethers.hexlify(ethers.randomBytes(64))
      };
      
      // Test unified verification - should detect EOA and verify correctly
      const verified = await verifyHandshakeResponseIdentity(
        serializedTx,
        responseEvent,
        identityPubKey,
        nacl.box.keyPair().secretKey, // Dummy ephemeral key
        provider
      );
      
      expect(verified).to.be.true;
    });

    it("should correctly detect and verify Smart Account", async function () {
      // Generate keys for test
      const bobIdentityPubKey = nacl.box.keyPair().publicKey;
      const aliceEphemeral = nacl.box.keyPair();
      const bobEphemeral = nacl.box.keyPair();
      
      // Create identity proof
      const inResponseTo = ethers.keccak256(ethers.toUtf8Bytes("test-handshake"));
      const bindingMessage = ethers.solidityPacked(
        ['bytes32', 'bytes32', 'string'],
        [bobIdentityPubKey, inResponseTo, 'VerbEth-HSResponse-v1']
      );
      
      const messageHash = ethers.hashMessage(bindingMessage);
      const signature = await owner.signMessage(bindingMessage);
      
      // Create response content
      const responseContent: HandshakeResponseContent = {
        identityPubKey: bobIdentityPubKey,
        ephemeralPubKey: bobEphemeral.publicKey,
        note: 'Test response',
        identityProof: {
          signature,
          message: messageHash
        }
      };
      
      // Encrypt response
      const encryptedPayload = encryptStructuredPayload(
        responseContent,
        aliceEphemeral.publicKey,
        bobEphemeral.secretKey,
        bobEphemeral.publicKey
      );
      
      // Mock response event from smart account
      const responseEvent = {
        responder: await testSmartAccount.getAddress(),
        ciphertext: ethers.hexlify(ethers.toUtf8Bytes(encryptedPayload))
      };
      
      // Test unified verification - should detect smart account and verify via EIP-1271
      const verified = await verifyHandshakeResponseIdentity(
        "", // Empty txHex since we're testing smart account path
        responseEvent,
        bobIdentityPubKey,
        aliceEphemeral.secretKey,
        provider
      );
      
      expect(verified).to.be.true;
    });

    it("should reject smart account with invalid identity proof", async function () {
      const [, attacker] = await ethers.getSigners();
      
      const bobIdentityPubKey = nacl.box.keyPair().publicKey;
      const aliceEphemeral = nacl.box.keyPair();
      const bobEphemeral = nacl.box.keyPair();
      
      // Create invalid identity proof (signed by attacker)
      const inResponseTo = ethers.keccak256(ethers.toUtf8Bytes("test-handshake"));
      const bindingMessage = ethers.solidityPacked(
        ['bytes32', 'bytes32', 'string'],
        [bobIdentityPubKey, inResponseTo, 'VerbEth-HSResponse-v1']
      );
      
      const messageHash = ethers.hashMessage(bindingMessage);
      const invalidSignature = await attacker.signMessage(bindingMessage);
      
      const responseContent: HandshakeResponseContent = {
        identityPubKey: bobIdentityPubKey,
        ephemeralPubKey: bobEphemeral.publicKey,
        note: 'Malicious response',
        identityProof: {
          signature: invalidSignature,
          message: messageHash
        }
      };
      
      const encryptedPayload = encryptStructuredPayload(
        responseContent,
        aliceEphemeral.publicKey,
        bobEphemeral.secretKey,
        bobEphemeral.publicKey
      );
      
      const responseEvent = {
        responder: await testSmartAccount.getAddress(),
        ciphertext: ethers.hexlify(ethers.toUtf8Bytes(encryptedPayload))
      };
      
      // Should reject invalid proof
      const verified = await verifyHandshakeResponseIdentity(
        "",
        responseEvent,
        bobIdentityPubKey,
        aliceEphemeral.secretKey,
        provider
      );
      
      expect(verified).to.be.false;
    });

    it("should reject smart account without identity proof", async function () {
      // Generate keys
      const bobIdentityPubKey = nacl.box.keyPair().publicKey;
      const aliceEphemeral = nacl.box.keyPair();
      const bobEphemeral = nacl.box.keyPair();
      
      const responseContent: HandshakeResponseContent = {
        identityPubKey: bobIdentityPubKey,
        ephemeralPubKey: bobEphemeral.publicKey,
        note: 'Response without proof'
        // identityProof is undefined
      };
      
      const encryptedPayload = encryptStructuredPayload(
        responseContent,
        aliceEphemeral.publicKey,
        bobEphemeral.secretKey,
        bobEphemeral.publicKey
      );
      
      const responseEvent = {
        responder: await testSmartAccount.getAddress(),
        ciphertext: ethers.hexlify(ethers.toUtf8Bytes(encryptedPayload))
      };
      
      const verified = await verifyHandshakeResponseIdentity(
        "",
        responseEvent,
        bobIdentityPubKey,
        aliceEphemeral.secretKey,
        provider
      );
      
      expect(verified).to.be.false;
    });
  });
});