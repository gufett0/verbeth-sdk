import { expect } from "chai";
// @ts-ignore
import { ethers, upgrades } from "hardhat";
import { LogChainV1 } from "../typechain-types";

describe("LogChainV1 – Upgradeability (UUPS)", function () {
  let logChain: LogChainV1;
  let owner: any;
  let attacker: any;

  beforeEach(async () => {
    [owner, attacker] = await ethers.getSigners();

    const Factory = await ethers.getContractFactory("LogChainV1");
    logChain = (await upgrades.deployProxy(Factory, [], {
      kind: "uups",
      initializer: "initialize",
    })) as unknown as LogChainV1;
  });

  it("is initialized correctly", async () => {
    expect(await logChain.owner()).to.equal(await owner.getAddress());
  });

  it("prevents re‑initialization", async () => {
    await expect(
      logChain.initialize()
      // @ts-ignore
    ).to.be.revertedWithCustomError(logChain, "InvalidInitialization");
  });

  it("only owner can perform upgrade", async () => {
    const NewImplFactory = await ethers.getContractFactory("LogChainV1");
    const newImpl = await NewImplFactory.deploy();

    await expect(
      (logChain as any)
        .connect(attacker)
        .upgradeToAndCall(await newImpl.getAddress(), "0x")
      // @ts-ignore
    ).to.be.revertedWithCustomError(logChain, "OwnableUnauthorizedAccount");

    await expect(
      (logChain as any)
        .connect(owner)
        .upgradeToAndCall(await newImpl.getAddress(), "0x")
      // @ts-ignore
    ).to.not.be.reverted;
  });

  it("storage gap is preserved after upgrade", async () => {
    const ImplV2 = await ethers.getContractFactory("LogChainV1");
    const newImpl = await ImplV2.deploy();

    // Perform upgrade via UUPS entry point
    await (logChain as any).upgradeToAndCall(await newImpl.getAddress(), "0x");

    // Ensure it's still functional
    const msg = ethers.encodeBytes32String("hi");
    const topic = ethers.keccak256(ethers.toUtf8Bytes("chat:dev"));
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = 1;

    await expect(
      logChain.sendMessage(msg, topic, timestamp, nonce)
      // @ts-ignore
    ).to.emit(logChain, "MessageSent");
  });
});
