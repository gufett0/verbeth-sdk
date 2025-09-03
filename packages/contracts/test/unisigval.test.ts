// packages/contracts/test/unisigval.test.ts
// @ts-ignore
import { ethers } from "hardhat";
import { expect } from "chai";
import { UniversalSigValidator } from "../typechain-types";

/**
 * @dev
 *   These tests ensure that UniversalSigValidator behaves correctly
 *   with already deployed accounts (EOA + ERC-1271).
 *   They do not yet cover ERC-6492 pre-deploy simulation.
 *
 * @todo
 * Once ERC-6492 support is integrated, add tests that:
 *   1. Wrap a signature in a 6492 envelope with the account initCode.
 *   2. Call UniversalSigValidator using that envelope.
 *   3. Assert that verification succeeds even if the smart account
 *      is not deployed on-chain yet.
 */
describe("UniversalSigValidator (minimal)", () => {
  let validator: UniversalSigValidator;

  beforeEach(async () => {
    const Factory = await ethers.getContractFactory("UniversalSigValidator");
    validator = (await Factory.deploy()) as UniversalSigValidator;
    await validator.waitForDeployment();
  });

  it("validates an EOA signature via ecrecover", async () => {
    const [signer] = await ethers.getSigners();

    const message = ethers.randomBytes(32);
    const digest = ethers.hashMessage(message);
    const signature = await signer.signMessage(message);

    const ok = await validator.isValidSig.staticCall(
      await signer.getAddress(),
      digest,
      signature
    );
    expect(ok).to.equal(true);
  });

  it("returns false if the signer address does not match the signature", async () => {
    const [signer, other] = await ethers.getSigners();

    const message = ethers.randomBytes(32);
    const digest = ethers.hashMessage(message);
    const signature = await signer.signMessage(message);

    const ok = await validator.isValidSig.staticCall(
      await other.getAddress(),
      digest,
      signature
    );
    expect(ok).to.equal(false);
  });

  it("reverts on invalid signature length (must be 65 bytes)", async () => {
    const [signer] = await ethers.getSigners();

    const message = ethers.randomBytes(32);
    const digest = ethers.hashMessage(message);
    const badSig = ethers.hexlify(ethers.randomBytes(64)); // 64, not 65

    await expect(
      validator.isValidSig(await signer.getAddress(), digest, badSig)
      // @ts-ignore
    ).to.be.reverted;
  });

  it("reverts on invalid v value (must be 27 or 28)", async () => {
    const [signer] = await ethers.getSigners();

    const message = ethers.randomBytes(32);
    const digest = ethers.hashMessage(message);
    const goodSig = await signer.signMessage(message);

    const bytes = ethers.getBytes(goodSig);
    bytes[64] = 0; // force v = 0 (invalid)
    const badSig = ethers.hexlify(bytes);

    await expect(
      validator.isValidSig(await signer.getAddress(), digest, badSig)
      // @ts-ignore
    ).to.be.reverted;
  });

  it("isValidSigWithSideEffects behaves like isValidSig for EOA signatures", async () => {
    const [signer] = await ethers.getSigners();

    const message = ethers.randomBytes(32);
    const digest = ethers.hashMessage(message);
    const signature = await signer.signMessage(message);

    const ok = await validator.isValidSigWithSideEffects.staticCall(
      await signer.getAddress(),
      digest,
      signature
    );
    expect(ok).to.equal(true);
  });

  // ----------------------------------------
  // ERC-1271 path using TestSmartAccount.sol
  // ----------------------------------------

  it("validates via ERC-1271 when signer is a smart account", async () => {
    const [owner] = await ethers.getSigners();

    const Factory = await ethers.getContractFactory("TestSmartAccount");
    const wallet1271 = await Factory.deploy(
      ethers.ZeroAddress,
      await owner.getAddress()
    );
    await wallet1271.waitForDeployment();

    const message = ethers.randomBytes(32);
    const digest = ethers.hashMessage(message);
    const signature = await owner.signMessage(message);

    const ok = await validator.isValidSig.staticCall(
      await wallet1271.getAddress(),
      digest,
      signature
    );
    expect(ok).to.equal(true);

    const okSide = await validator.isValidSigWithSideEffects.staticCall(
      await wallet1271.getAddress(),
      digest,
      signature
    );
    expect(okSide).to.equal(true);
  });

  it("returns false via ERC-1271 if signature does not recover to the wallet's owner", async () => {
    const [owner, other] = await ethers.getSigners();

    const Factory = await ethers.getContractFactory("TestSmartAccount");
    const wallet1271 = await Factory.deploy(
      ethers.ZeroAddress,
      await owner.getAddress()
    );
    await wallet1271.waitForDeployment();

    const message = ethers.randomBytes(32);
    const digest = ethers.hashMessage(message);
    const wrongSig = await other.signMessage(message);

    const ok = await validator.isValidSig.staticCall(
      await wallet1271.getAddress(),
      digest,
      wrongSig
    );
    expect(ok).to.equal(false);
  });

  it("returns false if ERC-1271 wallet returns a non-magic value (invalid sig)", async () => {
    const [owner, other] = await ethers.getSigners();

    const Factory = await ethers.getContractFactory("TestSmartAccount");
    const wallet1271 = await Factory.deploy(
      ethers.ZeroAddress,
      await owner.getAddress()
    );
    await wallet1271.waitForDeployment();

    const message = ethers.randomBytes(32);
    const digest = ethers.hashMessage(message);
    const nonMagicSig = await other.signMessage(message);

    const ok = await validator.isValidSig.staticCall(
      await wallet1271.getAddress(),
      digest,
      nonMagicSig
    );
    expect(ok).to.equal(false);
  });
});
