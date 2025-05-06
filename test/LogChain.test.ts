import { expect } from 'chai';
import { ethers } from '../utils/ethers';
import { LogChain } from '../typechain-types';
import { resolveRecipientKey } from '../utils/recipient';

describe('LogChain', () => {
  let logChain: LogChain;

  beforeEach(async () => {
    const factory = await ethers.getContractFactory('LogChain');
    logChain = await factory.deploy();
    await logChain.waitForDeployment();
  });

  it('should emit a MessageSent event', async () => {
    const [sender] = await ethers.getSigners();

    const msg = ethers.encodeBytes32String('Hello');
    const topic = ethers.keccak256(ethers.toUtf8Bytes('chat:dev'));
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = 1;

    await expect(logChain.sendMessage(msg, topic, timestamp, nonce))
      .to.emit(logChain, 'MessageSent')
      .withArgs(await sender.getAddress(), msg, timestamp, topic, nonce);
  });

  it('should allow duplicate nonce (no on-chain check)', async () => {
    const [] = await ethers.getSigners();
  
    const msg = ethers.encodeBytes32String('Hello');
    const topic = ethers.keccak256(ethers.toUtf8Bytes('chat:dev'));
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = 42;
  
    await logChain.sendMessage(msg, topic, timestamp, nonce);
    await logChain.sendMessage(msg, topic, timestamp + 1, nonce); // re-use same nonce, no revert
  });

  it('should resolve recipient pubkey from address using signer fallback', async () => {
    const [signer] = await ethers.getSigners();
  
    // Skip test if running under Hardhat, which returns non-recoverable signatures
    if ((ethers.provider as any)._isHardhatNetwork) {
      console.warn('⚠ Skipping signer fallback test (Hardhat does not support recoverable signatures)');
      return;
    }
  
    const pubkey = await resolveRecipientKey(signer);
    expect(pubkey).to.be.instanceOf(Uint8Array);
    expect(pubkey.length).to.equal(32);
  });
  

  it('should resolve pubkey from address via tx history', async () => {
    const [sender] = await ethers.getSigners();

    if ((ethers.provider as any)._isHardhatNetwork) {
      console.warn('⚠ Skipping tx history test (Hardhat signatures not recoverable)');
      return;
    }

    const tx = await sender.sendTransaction({
      to: await sender.getAddress(),
      data: ethers.toUtf8Bytes('warmup')
    });
    await tx.wait();

    const resolved = await resolveRecipientKey(await sender.getAddress(), ethers.provider);

    expect(resolved).to.be.instanceOf(Uint8Array);
    expect(resolved.length).to.equal(32);
  });
  
  
  it('should emit a Handshake event', async () => {
    const [alice] = await ethers.getSigners();
    const recipient = await alice.getAddress();
    const recipientHash = ethers.keccak256(ethers.toUtf8Bytes("contact:" + recipient.toLowerCase()));

    const identityPubKey = '0x'; // EOA, no pubkey needed
    const ephemeralPubKey = ethers.hexlify(ethers.randomBytes(32));
    const plaintextPayload = ethers.toUtf8Bytes("Hi Bob, respond pls");

    await expect(logChain.initiateHandshake(
      recipientHash,
      identityPubKey,
      ephemeralPubKey,
      plaintextPayload
    )).to.emit(logChain, 'Handshake')
      .withArgs(recipientHash, recipient, identityPubKey, ephemeralPubKey, plaintextPayload);
  });
  
  it('should emit a HandshakeResponse event', async () => {
    const [bob] = await ethers.getSigners();
    const inResponseTo = ethers.keccak256(ethers.toUtf8Bytes("handshakeFromAlice"));
    const responseCiphertext = ethers.hexlify(ethers.randomBytes(64));

    await expect(logChain.respondToHandshake(inResponseTo, responseCiphertext))
      .to.emit(logChain, 'HandshakeResponse')
      .withArgs(inResponseTo, await bob.getAddress(), responseCiphertext);
  });
});
