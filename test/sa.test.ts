// import { expect } from "chai";
// import { ethers } from "hardhat";
// import { Signer } from "ethers";
// import { TestSmartAccount } from "../typechain-types";

// describe("TestSmartAccount EIP-1271", function () {
//   let account: TestSmartAccount;
//   let owner: Signer;
//   let attacker: Signer;

//   beforeEach(async function () {
//     [owner, attacker] = (await ethers.getSigners()) as unknown as Signer[];

//     // Deploy TestSmartAccount
//     const AccountFactory = await ethers.getContractFactory("TestSmartAccount");
//     account = await AccountFactory.deploy(await owner.getAddress());
//     await account.waitForDeployment();
//   });

//   it("should verify EIP-1271 signature correctly", async function () {
//     const message = "VerbEth-HSResponse-test";
//     const messageHash = ethers.hashMessage(message);
//     const signature = await owner.signMessage(message);
    
//     const result = await account.isValidSignature(messageHash, signature);
//     expect(result).to.equal("0x1626ba7e");
//   });

//   it("should reject invalid EIP-1271 signature", async function () {
//     const message = "VerbEth-HSResponse-test";
//     const messageHash = ethers.hashMessage(message);
//     const signature = await attacker.signMessage(message);
    
//     const result = await account.isValidSignature(messageHash, signature);
//     expect(result).to.equal("0xffffffff");
//   });

//   it("should reject signatures from zero address recovery", async function () {
//     const messageHash = ethers.keccak256(ethers.toUtf8Bytes("test"));
//     const invalidSignature = "0x" + "00".repeat(65);
    
//     const result = await account.isValidSignature(messageHash, invalidSignature);
//     expect(result).to.equal("0xffffffff");
//   });
// });