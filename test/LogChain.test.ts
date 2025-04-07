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

    await expect(logChain.sendMessage(msg, topic, timestamp))
      .to.emit(logChain, 'MessageSent')
      .withArgs(await sender.getAddress(), msg, timestamp, topic);
  });
});
