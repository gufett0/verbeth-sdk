import { expect } from 'chai';
import { ethers } from '../utils/ethers';
import { LogChain } from '../typechain-types';

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

  it('should reject a message with the same nonce', async () => {
    const msg = ethers.encodeBytes32String('Hello');
    const topic = ethers.keccak256(ethers.toUtf8Bytes('chat:dev'));
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = 1;
  
    await logChain.sendMessage(msg, topic, timestamp, nonce);
  
    await expect(
      logChain.sendMessage(msg, topic, timestamp + 1, nonce)
    ).to.be.revertedWith('Replay or stale nonce');
  });
  
});
