import { expect } from "chai";
import { ethers, Wallet, Provider, Signer } from "../utils/ethers"; 
import { verifyHandshakeResponseIdentity, verifyHandshakeIdentity } from "../src/verify";
import { verifyEOAIdentity } from "../src/utils";
import { convertPublicKeyToX25519 } from "../utils/x25519";
import { LogChainV1, TestSmartAccount } from "../typechain-types";
import { encryptStructuredPayload } from "../src/crypto";
import { HandshakeResponseContent } from "../src/payload";
import nacl from 'tweetnacl';

describe("Handshake Identity Verification", function () {
  let testSmartAccount: TestSmartAccount;
  let owner: Signer;
  let provider: Provider;

  beforeEach(async function () {
    [owner] = (await ethers.getSigners()) as unknown as Signer[];
    provider = owner.provider!;
    const AccountFactory = await ethers.getContractFactory("TestSmartAccount");
    testSmartAccount = await AccountFactory.deploy(await owner.getAddress());
    await testSmartAccount.waitForDeployment();
  });

  it("should verify EOA handshake identity with proper tx", async function () {
    const [fundedSigner] = await ethers.getSigners();
    const aliceEOA = new Wallet(Wallet.createRandom().privateKey).connect(provider);
    
    await fundedSigner.sendTransaction({
      to: aliceEOA.address,
      value: ethers.parseEther("1.0"),
    });
  
    const testMessage = "VerbEth-test";
    const signature = await aliceEOA.signMessage(testMessage);
    const expandedPubKey = ethers.SigningKey.recoverPublicKey(
      ethers.hashMessage(testMessage),
      signature
    );
    const rawBytes = ethers.getBytes(expandedPubKey).slice(1);
    const identityPubKey = convertPublicKeyToX25519(rawBytes);
  
    const logChain = await ethers.getContractFactory("LogChainV1").then(f => f.deploy());
    const tx = await logChain
      .connect(aliceEOA)
      .initiateHandshake(
        ethers.keccak256(ethers.toUtf8Bytes("test")),
        ethers.hexlify(identityPubKey),
        ethers.hexlify(nacl.box.keyPair().publicKey),
        ethers.toUtf8Bytes("Hi Bob, this is Alice")
      );
    
    const receipt = await tx.wait();
    const minedTx = await provider.getTransaction(receipt!.hash);
    const serializedTx = ethers.Transaction.from(minedTx!).serialized;
    
    const handshakeEvent = {
      recipientHash: ethers.keccak256(ethers.toUtf8Bytes("test")),
      sender: aliceEOA.address,
      identityPubKey: ethers.hexlify(identityPubKey),
      ephemeralPubKey: ethers.hexlify(nacl.box.keyPair().publicKey),
      plaintextPayload: "Hi Bob, this is Alice"
    };
  
    const verified = await verifyHandshakeIdentity(
      handshakeEvent,
      serializedTx,
      provider
    );
    
    expect(verified).to.be.true;
  });


  it("should verify Smart Account handshake identity with proof", async function () {
    const aliceIdentityPubKey = nacl.box.keyPair().publicKey;
    const aliceEphemeralPubKey = nacl.box.keyPair().publicKey;
    const recipientHash = ethers.keccak256(ethers.toUtf8Bytes("test"));
    
    const bindingMessage = ethers.solidityPacked(
      ['bytes32', 'bytes32', 'string'],
      [aliceIdentityPubKey, recipientHash, 'VerbEth-Handshake-v1']
    );
    
    const messageHash = ethers.hashMessage(bindingMessage);
    const signature = await owner.signMessage(bindingMessage);
    
    const handshakeContent = {
      plaintextPayload: "Hi Bob, I'm Alice (Smart Account)",
      identityProof: {
        signature,
        message: messageHash
      }
    };
    
    const handshakeEvent = {
      recipientHash,
      sender: await testSmartAccount.getAddress(),
      identityPubKey: ethers.hexlify(aliceIdentityPubKey),
      ephemeralPubKey: ethers.hexlify(aliceEphemeralPubKey),
      plaintextPayload: JSON.stringify(handshakeContent)
    };
    
    const verified = await verifyHandshakeIdentity(
      handshakeEvent,
      undefined,
      provider
    );
    
    expect(verified).to.be.true;
  });

  it("should reject Smart Account handshake with invalid identity proof", async function () {
    const [, attacker] = await ethers.getSigners();
    const aliceIdentityPubKey = nacl.box.keyPair().publicKey;
    const aliceEphemeralPubKey = nacl.box.keyPair().publicKey;
    const recipientHash = ethers.keccak256(ethers.toUtf8Bytes("test"));
    
    const bindingMessage = ethers.solidityPacked(
      ['bytes32', 'bytes32', 'string'],
      [aliceIdentityPubKey, recipientHash, 'VerbEth-Handshake-v1']
    );
    
    const messageHash = ethers.hashMessage(bindingMessage);
    const invalidSignature = await attacker.signMessage(bindingMessage);
    
    const handshakeContent = {
      plaintextPayload: "Hi Bob, I'm a malicious actor",
      identityProof: {
        signature: invalidSignature,
        message: messageHash
      }
    };
    
    const handshakeEvent = {
      recipientHash,
      sender: await testSmartAccount.getAddress(),
      identityPubKey: ethers.hexlify(aliceIdentityPubKey),
      ephemeralPubKey: ethers.hexlify(aliceEphemeralPubKey),
      plaintextPayload: JSON.stringify(handshakeContent)
    };
    
    const verified = await verifyHandshakeIdentity(
      handshakeEvent,
      undefined,
      provider
    );
    
    expect(verified).to.be.false;
  });

  it("should reject Smart Account claiming to be EOA", async function () {
    const aliceIdentityPubKey = nacl.box.keyPair().publicKey;
    const aliceEphemeralPubKey = nacl.box.keyPair().publicKey;
    
    const handshakeEvent = {
      recipientHash: ethers.keccak256(ethers.toUtf8Bytes("test")),
      sender: await testSmartAccount.getAddress(), 
      identityPubKey: ethers.hexlify(aliceIdentityPubKey),
      ephemeralPubKey: ethers.hexlify(aliceEphemeralPubKey),
      plaintextPayload: "Hi Bob, I'm totally an EOA"
    };
    

    const verified = await verifyHandshakeIdentity(
      handshakeEvent,
      undefined,
      provider
    );
    
    expect(verified).to.be.false;
  });
});

describe("Handshake Response Verification", function () {
  let provider: Provider;

  beforeEach(async () => {
    const [signer] = await ethers.getSigners();
    provider = signer.provider!;
  });

  describe("EOA Verification", function () {
    let logChain: LogChainV1;

    beforeEach(async () => {
      const factory = await ethers.getContractFactory("LogChainV1");
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
      
      const verified = verifyEOAIdentity(serializedTx, x25519PubKey);
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
      
      const verified = verifyEOAIdentity(serializedTx, wrongKey);
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
    let logChain: LogChainV1;
    let testSmartAccount: TestSmartAccount;
    let owner: Signer;

    beforeEach(async function () {
      [owner] = (await ethers.getSigners()) as unknown as Signer[];
      const logChainFactory = await ethers.getContractFactory("LogChainV1");
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
      
      // Mock response event with proper HandshakeResponseLog structure
      const responseEvent = {
        inResponseTo: ethers.keccak256(ethers.toUtf8Bytes("test")),
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
      
      const responseContent: HandshakeResponseContent = {
        identityPubKey: bobIdentityPubKey,
        ephemeralPubKey: bobEphemeral.publicKey,
        note: 'Test response',
        identityProof: {
          signature,
          message: messageHash
        }
      };
      
      const encryptedPayload = encryptStructuredPayload(
        responseContent,
        aliceEphemeral.publicKey,
        bobEphemeral.secretKey,
        bobEphemeral.publicKey
      );
      
      // Mock response event from smart account with proper structure
      const responseEvent = {
        inResponseTo,
        responder: await testSmartAccount.getAddress(),
        ciphertext: ethers.hexlify(ethers.toUtf8Bytes(encryptedPayload))
      };
      
      // Test unified verification - should detect smart account and verify via EIP-1271
      const verified = await verifyHandshakeResponseIdentity(
        "", 
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
        inResponseTo,
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
      
      const inResponseTo = ethers.keccak256(ethers.toUtf8Bytes("test-handshake"));
      const responseEvent = {
        inResponseTo,
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