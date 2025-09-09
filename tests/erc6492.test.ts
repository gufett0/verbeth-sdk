// tests/erc6492.test.ts
import { expect, describe, it, beforeAll, afterAll } from "vitest";
import {
  Wallet,
  NonceManager,
  parseEther,
  AbiCoder,
  concat,
  hashMessage,
  keccak256,
  getCreate2Address,
  Interface,
  Signature,
  getBytes,
  hexlify,
} from "ethers";

import {
  UniversalSigValidator__factory,
  type UniversalSigValidator,
  TestSmartAccount__factory,
  type TestSmartAccount,
} from "../packages/contracts/typechain-types/index.js";
import {
  verifyERC6492WithSingleton,
  ERC6492_SUFFIX,
  DEFAULT_UNI_SIG_VALIDATOR,
} from "../packages/sdk/src/utils.js";

import { AnvilSetup } from "./setup.js";

const ENTRYPOINT_ADDR = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const CREATE_X_ADDR = "0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed";

describe("UniversalSigValidator — ERC-6492 integration", () => {
  let anvil: AnvilSetup;
  let deployer: Wallet;
  let deployerNM: NonceManager;
  let smartAccountOwner: Wallet;
  let validator: UniversalSigValidator;

  beforeAll(async () => {
    anvil = new AnvilSetup();
    const forkUrl = "https://base-rpc.publicnode.com";
    await anvil.start(forkUrl);

    const provider = anvil.provider;
    const testPrivateKeys = [
      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
      "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    ];
    deployer = new Wallet(testPrivateKeys[0], provider);
    deployerNM = new NonceManager(deployer);
    smartAccountOwner = new Wallet(testPrivateKeys[1], provider);

    await deployerNM.sendTransaction({
      to: smartAccountOwner.address,
      value: parseEther("1"),
    });

    validator = UniversalSigValidator__factory.connect(
      DEFAULT_UNI_SIG_VALIDATOR,
      anvil.provider
    );
  }, 60000);

  afterAll(async () => {
    await anvil.stop();
  });

  // ----------------------------------------------------------------------
  describe("Deployed account (graceful 6492 acceptance)", () => {
    let sa: TestSmartAccount;

    beforeAll(async () => {
      sa = await new TestSmartAccount__factory(deployerNM).deploy(
        ENTRYPOINT_ADDR,
        smartAccountOwner.address
      );
      await sa.waitForDeployment();
    }, 30000);

    it("accepts wrapped signature with suffix", async () => {
      const msg = new Uint8Array(32);
      // just the raw hash, bc hashMessage adds the personal sign prefix
      const digest = keccak256(msg);
      const sig = Signature.from(smartAccountOwner.signingKey.sign(digest));
      const rawSig = sig.serialized;

      const coder = new AbiCoder();
      const prefix = coder.encode(
        ["address", "bytes", "bytes"],
        [await validator.getAddress(), "0x", rawSig]
      );
      const wrapped = concat([prefix, ERC6492_SUFFIX]);

      const ok = await validator.isValidSig.staticCall(
        await sa.getAddress(),
        digest,
        wrapped
      );
      expect(ok).toBe(true);
    });
  });

  // ----------------------------------------------------------------------
  describe("Pre-deployed (counterfactual) account", () => {
    it("validates via 6492 envelope with no side effects (direct initCode, Base CreateX + guarded salt)", async () => {
      // build direct initCode for my TestSmartAccount
      const ctorArgs = new AbiCoder().encode(
        ["address", "address"],
        [ENTRYPOINT_ADDR, smartAccountOwner.address]
      );
      const initCode = (TestSmartAccount__factory.bytecode +
        ctorArgs.slice(2)) as `0x${string}`;
      const initCodeHash = keccak256(initCode);

      // the salt as expected by CreateX (guarded with msg.sender)
      const validatorAddr = await validator.getAddress();
      // build a 32b salt: [ first 20b = validatorAddr ][ 0x00 ][ 11b zeros ]
      const addr20 = getBytes(validatorAddr);
      const flag = Uint8Array.of(0x00); // RedeployProtection.False
      const entropy = new Uint8Array(11);
      const saltBytes = concat([addr20, flag, entropy]);
      const salt = hexlify(saltBytes) as `0x${string}`;

      // pad the address to 32b
      const addr32 = new AbiCoder().encode(["address"], [validatorAddr]);
      const guardedSalt = keccak256(concat([addr32, salt]));

      // predict the actual address CreateX will deploy to
      const predictedAddr = getCreate2Address(
        CREATE_X_ADDR,
        guardedSalt,
        initCodeHash
      );

      const msg = new Uint8Array(32);
      const digest = hashMessage(msg);
      const rawSig = await smartAccountOwner.signMessage(msg);

      // for the envelope we must pass the original salt bc CreateX will guard it internally
      const createXInterface = new Interface([
        "function deployCreate2(bytes32 salt, bytes initCode) returns (address)",
      ]);
      const factoryCalldata = createXInterface.encodeFunctionData(
        "deployCreate2",
        [salt, initCode]
      );

      const prefix = new AbiCoder().encode(
        ["address", "bytes", "bytes"],
        [CREATE_X_ADDR, factoryCalldata, rawSig]
      );
      const wrapped = concat([prefix, ERC6492_SUFFIX]);

      // no-side-effects path: validator should simulate deploy+1271 and then revert(bool)
      const ok = await validator.isValidSig.staticCall(
        predictedAddr,
        digest,
        wrapped
      );
      expect(ok).toBe(true);

      const code = await anvil.provider.getCode(predictedAddr);
      expect(code).toBe("0x");
    }, 60000);
  });

  // ----------------------------------------------------------------------

  describe("SDK utils — verifyERC6492WithSingleton (Base CreateX)", () => {
    it("returns true for counterfactual SA via 6492 envelope (no side effects)", async () => {
      // 1) Build direct initCode for TestSmartAccount(ENTRYPOINT_ADDR, owner)
      const ctorArgs = new AbiCoder().encode(
        ["address", "address"],
        [ENTRYPOINT_ADDR, smartAccountOwner.address]
      );
      const initCode = (TestSmartAccount__factory.bytecode +
        ctorArgs.slice(2)) as `0x${string}`;
      const initCodeHash = keccak256(initCode);

      // 2) Use the locally deployed validator address instead of Base mainnet
      const validatorAddr = (await validator.getAddress()) as `0x${string}`;
      console.log("DEBUG - using validator address:", validatorAddr);
      const addr20 = getBytes(validatorAddr).slice(0, 20);
      const flag = Uint8Array.of(0x00);
      const entropy = new Uint8Array(11);
      const salt = hexlify(concat([addr20, flag, entropy]));

      const addr32 = new AbiCoder().encode(["address"], [validatorAddr]); // 32-byte padded
      const guardedSalt = keccak256(concat([addr32, salt])); // _efficientHash(a,b)

      const predictedAddr = getCreate2Address(
        CREATE_X_ADDR,
        guardedSalt,
        initCodeHash
      );

      const singletonCode = await anvil.provider.getCode(validatorAddr);
      expect(singletonCode).not.toBe("0x");
      console.log(
        "DEBUG - validator singleton code size:",
        (singletonCode.length - 2) / 2
      );

      // 3) Message + signature (owner)
      const msg = new Uint8Array(32);
      const digest = hashMessage(msg);
      const rawSig = await smartAccountOwner.signMessage(msg);

      // 4) CreateX calldata + 6492 envelope
      const createXInterface = new Interface([
        "function deployCreate2(bytes32 salt, bytes initCode) returns (address)",
      ]);
      const factoryCalldata = createXInterface.encodeFunctionData(
        "deployCreate2",
        [salt, initCode] // unguarded salt; CreateX guards internally
      );
      const prefix = new AbiCoder().encode(
        ["address", "bytes", "bytes"],
        [CREATE_X_ADDR, factoryCalldata, rawSig]
      );
      const wrapped = concat([prefix, ERC6492_SUFFIX]) as `0x${string}`;

      // 5) Call verbeth util
      const ok = await verifyERC6492WithSingleton({
        account: predictedAddr,
        messageHash: digest,
        sig6492Envelope: wrapped,
        provider: anvil.provider,
        validator: validatorAddr,
      });
      expect(ok).toBe(true);

      // 6) No side effects: account is still undeployed
      const code = await anvil.provider.getCode(predictedAddr);
      expect(code).toBe("0x");
    }, 60000);
  });
});