// packages/sdk/test/handshake.anvil.test.ts
import { expect, describe, it, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcess } from "child_process";
import {
  JsonRpcProvider,
  Wallet,
  Contract,
  parseEther,
  keccak256,
  toUtf8Bytes,
  AbiCoder,
  formatEther,
  NonceManager,
  SigningKey,
  concat,
  toBeHex,
  Signer,
  Interface,
  BaseContract
} from "ethers";

import nacl from "tweetnacl";
import {
  ExecutorFactory,
  initiateHandshake,
  DirectEntryPointExecutor,
  deriveIdentityKeyPairWithProof,
  split128x128,
} from "./packages/sdk/src/index.js";
import {
  ERC1967Proxy__factory,
  EntryPoint__factory,
  type EntryPoint,
  LogChainV1__factory,
  type LogChainV1,
  TestSmartAccount__factory,
  type TestSmartAccount,
} from "./packages/contracts/typechain-types/index.js";

// Canonical EntryPoint address (deployed on mainnet)
const ENTRYPOINT_ADDR = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

class AnvilSetup {
  private process: ChildProcess | null = null;
  public provider: JsonRpcProvider;

  constructor(private port: number = 8545) {
    this.provider = new JsonRpcProvider(`http://localhost:${port}`);
  }

  async start(forkUrl: string, forkBlock?: number): Promise<void> {
    console.log("🚀 Starting Anvil (mainnet-fork)…");

    const params = [
      "--port",
      this.port.toString(),
      "--fork-url",
      forkUrl,
      "--chain-id",
      "8453",
      "--accounts",
      "10",
      "--balance",
      "1000",
      "--gas-limit",
      "30000000",
    ];

    if (forkBlock) {
      params.push("--fork-block-number", forkBlock.toString());
    }

    this.process = spawn("anvil", params);

    this.process.stdout?.on("data", (d) => process.stdout.write(`Anvil: ${d}`));
    this.process.stderr?.on("data", (d) =>
      process.stderr.write(`Anvil ❌ ${d}`)
    );

    await new Promise<void>((resolve, reject) => {
      const t = setTimeout(
        () => reject(new Error("Anvil start timeout")),
        20_000
      );

      const ping = async () => {
        try {
          await this.provider.getBlockNumber();
          clearTimeout(t);
          console.log("✅ Anvil ready (mainnet fork)!");
          resolve();
        } catch {
          setTimeout(ping, 300);
        }
      };
      ping();
    });
  }

  async stop(): Promise<void> {
    if (this.process) {
      console.log("⏹️ Stopping Anvil…");
      this.process.kill();
      this.process = null;
    }
  }
}

describe("Smart Account Handshake via Direct EntryPoint", () => {
  let anvil: AnvilSetup;
  let provider: JsonRpcProvider;
  let entryPoint: EntryPoint;
  let logChain: LogChainV1;
  let testSmartAccount: TestSmartAccount;
  let executor: DirectEntryPointExecutor;

  // Test accounts
  let deployer: Wallet;
  let smartAccountOwner: Wallet;
  let recipient: Wallet;

  // Test keys
  let ownerIdentityKeys: any;

  beforeAll(async () => {
    // Start Anvil with mainnet fork
    anvil = new AnvilSetup();
    const forkUrl = "https://base-rpc.publicnode.com";

    await anvil.start(forkUrl);
    provider = anvil.provider;

    // Create test accounts using private keys from Anvil's deterministic accounts
    const testPrivateKeys = [
      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
      "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
      "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    ];

    deployer = new Wallet(testPrivateKeys[0], provider);
    const deployerNM = new NonceManager(deployer);
    smartAccountOwner = new Wallet(testPrivateKeys[1], provider);
    recipient = new Wallet(testPrivateKeys[2], provider);

    console.log("🔑 Test accounts:");
    console.log(`  Deployer: ${deployer.address}`);
    console.log(`  Smart Account Owner: ${smartAccountOwner.address}`);
    console.log(`  Recipient: ${recipient.address}`);

    // Connect to canonical EntryPoint (already deployed on mainnet fork)
    entryPoint = EntryPoint__factory.connect(ENTRYPOINT_ADDR, provider);
    console.log(`📍 Connected to EntryPoint: ${entryPoint.target}`);

    // Deploy LogChain contract with proxy (using TypeChain factory)
    console.log("📦 Deploying LogChain...");

    // Deploy implementation
    const logChainFactory = new LogChainV1__factory(deployerNM);
    const logChainImpl = await logChainFactory.deploy();
    await logChainImpl.waitForDeployment();

    console.log(
      `📦 LogChain implementation deployed at: ${await logChainImpl.getAddress()}`
    );

    // Prepare initialize call data
    const initData = logChainFactory.interface.encodeFunctionData(
      "initialize",
      []
    );

    // Deploy ERC1967Proxy using the factory
    const proxyFactory = new ERC1967Proxy__factory(deployerNM);
    const proxy = await proxyFactory.deploy(
      await logChainImpl.getAddress(),
      initData
    );
    await proxy.waitForDeployment();

    // Connect to proxy using LogChain interface
    logChain = LogChainV1__factory.connect(
      await proxy.getAddress(),
      deployerNM
    );

    console.log(`⛓️ LogChain deployed at: ${await logChain.getAddress()}`);

    // Deploy test smart account
    console.log("🤖 Deploying TestSmartAccount...");
    const testSmartAccountFactory = new TestSmartAccount__factory(deployerNM);
    testSmartAccount = await testSmartAccountFactory.deploy(
      ENTRYPOINT_ADDR, // Use canonical EntryPoint
      smartAccountOwner.address
    );

    await testSmartAccount.waitForDeployment();
    console.log(
      `🤖 TestSmartAccount deployed at: ${await testSmartAccount.getAddress()}`
    );

    // Fund smart account for gas
    await deployerNM.sendTransaction({
      to: await testSmartAccount.getAddress(),
      value: parseEther("1"),
    });
    console.log("💰 Smart account funded with 1 ETH");

    // Generate identity keys for smart account owner
    ownerIdentityKeys = await deriveIdentityKeyPairWithProof(
      smartAccountOwner,
      await testSmartAccount.getAddress() // Use smart account address for derivation
    );
    console.log("🔑 Identity keys generated for smart account");

    // Create Direct EntryPoint executor
    executor = ExecutorFactory.createDirectEntryPoint(
      await testSmartAccount.getAddress(),
      entryPoint.connect(deployer) as unknown as Contract,
      await logChain.getAddress(),
      createMockSmartAccountClient(testSmartAccount, smartAccountOwner),
      deployerNM // Signer for EntryPoint transactions
    ) as DirectEntryPointExecutor;

    console.log("🚀 DirectEntryPointExecutor created");
  }, 60000); // 60s timeout for setup

  afterAll(async () => {
    await anvil.stop();
  });

  it("should initiate handshake from smart account via canonical EntryPoint", async () => {
    const ephemeralKeys = nacl.box.keyPair();

    console.log("🤝 Initiating handshake...");

    // Initiate handshake from smart account to recipient
    const tx = await initiateHandshake({
      executor,
      recipientAddress: recipient.address,
      identityKeyPair: ownerIdentityKeys.keyPair,
      ephemeralPubKey: ephemeralKeys.publicKey,
      plaintextPayload: "Hello from smart account handshake!",
      derivationProof: ownerIdentityKeys.derivationProof,
      signer: smartAccountOwner,
    });

    console.log("⏳ Waiting for transaction...");
    const receipt = await tx.wait();

console.log("Receipt", receipt);
console.log("Logs in receipt", receipt.logs);

    expect(receipt.status).toBe(1);
    console.log(`✅ Handshake transaction successful: ${receipt.hash}`);

    // Verify handshake event was emitted
    // const currentBlock = await provider.getBlockNumber();
    // const handshakeFilter = logChain.filters.Handshake();
    // const events = await logChain.queryFilter(
    //   handshakeFilter,
    //   Math.max(currentBlock - 100, 0), // Only last 100 blocks
    //   currentBlock
    // );

    const handshakeFilter = logChain.filters.Handshake();

    // (v6) assicurati che `latest` abbia raggiunto quel blocco
    while ((await provider.getBlockNumber()) < receipt.blockNumber) {
      await new Promise((r) => setTimeout(r, 10));
    }

    const events = await logChain.queryFilter(
      handshakeFilter,
      receipt.blockNumber,
      receipt.blockNumber
    );

    expect(events).toHaveLength(1);

    const handshakeEvent = events[0];
    expect(handshakeEvent.args.sender).toBe(
      await testSmartAccount.getAddress()
    );

    // Verify recipient hash
    const expectedRecipientHash = keccak256(
      toUtf8Bytes("contact:" + recipient.address.toLowerCase())
    );
    expect(handshakeEvent.args.recipientHash).toBe(expectedRecipientHash);

    console.log("🎉 Handshake event verified!");
    console.log(`  Sender: ${handshakeEvent.args.sender}`);
    console.log(`  Recipient Hash: ${handshakeEvent.args.recipientHash}`);
    console.log(`  PubKeys Length: ${handshakeEvent.args.pubKeys.length}`);
    console.log(
      `  Ephemeral Key Length: ${handshakeEvent.args.ephemeralPubKey.length}`
    );
  }, 30000);

  it("should handle multiple handshakes from same smart account", async () => {
  const recipients = [
    "0x" + "11".repeat(20),
    "0x" + "22".repeat(20),
    "0x" + "33".repeat(20),
  ];

  console.log("🤝 Initiating multiple handshakes...");

  const receipts: Array<{ blockNumber: number }> = [];

  for (let i = 0; i < recipients.length; i++) {
    const ephemeralKeys = nacl.box.keyPair();

    const tx = await initiateHandshake({
      executor,
      recipientAddress: recipients[i],
      identityKeyPair: ownerIdentityKeys.keyPair,
      ephemeralPubKey: ephemeralKeys.publicKey,
      plaintextPayload: `Batch handshake ${i + 1}`,
      derivationProof: ownerIdentityKeys.derivationProof,
      signer: smartAccountOwner,
    });

    const receipt = await tx.wait();
    receipts.push(receipt);

    console.log(
      `  ✅ Handshake ${i + 1}/${recipients.length} completed (block ${receipt.blockNumber})`
    );
  }

  // -------- verify all handshakes --------
  const handshakeFilter = logChain.filters.Handshake(
    undefined,
    await testSmartAccount.getAddress()
  );

  const fromBlock = receipts[0].blockNumber;
  const toBlock   = receipts[receipts.length - 1].blockNumber;

  // ethers v6: attendi che il provider abbia indicizzato fino a toBlock
  while ((await provider.getBlockNumber()) < toBlock) {
    await new Promise((r) => setTimeout(r, 10));
  }

  const events = await logChain.queryFilter(handshakeFilter, fromBlock, toBlock);

  expect(events.length).toBeGreaterThanOrEqual(recipients.length);
  console.log(`🎉 All ${recipients.length} handshakes completed successfully!`);
}, 45_000);


  it("should estimate gas correctly for handshake operations", async () => {
    const ephemeralKeys = nacl.box.keyPair();

    // Create a test handshake to estimate gas
    const testRecipient = "0x" + "99".repeat(20);

    console.log("⛽ Testing gas estimation...");

    const tx = await initiateHandshake({
      executor,
      recipientAddress: testRecipient,
      identityKeyPair: ownerIdentityKeys.keyPair,
      ephemeralPubKey: ephemeralKeys.publicKey,
      plaintextPayload: "Gas estimation test",
      derivationProof: ownerIdentityKeys.derivationProof,
      signer: smartAccountOwner,
    });

    const receipt = await tx.wait();

    expect(receipt.status).toBe(1);
    expect(Number(receipt.gasUsed)).toBeGreaterThan(0);

    console.log(`⛽ Gas used for handshake: ${receipt.gasUsed} gas`);
    console.log(
      `💰 Gas cost at 20 gwei: ~${formatEther(
        receipt.gasUsed * 20_000_000_000n
      )} ETH`
    );

    // Gas usage should be reasonable (less than 1M gas)
    expect(Number(receipt.gasUsed)).toBeLessThan(1_000_000);
  }, 30000);

  it("should fail gracefully with invalid recipient address", async () => {
    const ephemeralKeys = nacl.box.keyPair();
    const invalidRecipient = "0x0000000000000000000000000000000000000000";

    console.log("❌ Testing invalid recipient handling...");

    // This should still succeed (contract doesn't validate recipient address)
    // but we can test that the event is emitted correctly
    const tx = await initiateHandshake({
      executor,
      recipientAddress: invalidRecipient,
      identityKeyPair: ownerIdentityKeys.keyPair,
      ephemeralPubKey: ephemeralKeys.publicKey,
      plaintextPayload: "Invalid recipient test",
      derivationProof: ownerIdentityKeys.derivationProof,
      signer: smartAccountOwner,
    });

    const receipt = await tx.wait();
    expect(receipt.status).toBe(1);

    // Verify the event was emitted with the invalid recipient hash
    const handshakeFilter = logChain.filters.Handshake();

    // (v6) assicurati che `latest` abbia raggiunto quel blocco
    while ((await provider.getBlockNumber()) < receipt.blockNumber) {
      await new Promise((r) => setTimeout(r, 10));
    }

    const events = await logChain.queryFilter(
      handshakeFilter,
      receipt.blockNumber,
      receipt.blockNumber
    );
    const newEvents = events.filter((e) => e.transactionHash === receipt.hash);
    expect(newEvents).toHaveLength(1);

    const expectedHash = keccak256(
      toUtf8Bytes("contact:" + invalidRecipient.toLowerCase())
    );
    expect(newEvents[0].args.recipientHash).toBe(expectedHash);

    console.log("✅ Invalid recipient handled correctly");
  }, 30000);
});

// Helper function to detect UserOp format based on available fields
function detectUserOpFormat(userOp: any): "v0.6" | "v0.7" {
  // v0.7 has packed fields, v0.6 has separate fields
  if ("accountGasLimits" in userOp && "gasFees" in userOp) {
    return "v0.7";
  } else if (
    "callGasLimit" in userOp &&
    "verificationGasLimit" in userOp &&
    "maxFeePerGas" in userOp
  ) {
    return "v0.6";
  }
  // Default to v0.7 if uncertain
  return "v0.7";
}

// Mock Smart Account Client for testing (compatible with both v0.6 and v0.7)
function createMockSmartAccountClient(
  smartAccount: TestSmartAccount,
  owner: Wallet
) {
  return {
    address: smartAccount.getAddress(),

    async getNonce(): Promise<bigint> {
      try {
        // Call the contract's getNonce method correctly
        const nonce = await smartAccount["getNonce"]();
        return nonce;
      } catch (error) {
        console.warn("Failed to get nonce from SmartAccount, using 0:", error);
        return 0n;
      }
    },


    

    async signUserOperation(userOp: any): Promise<any> {
      // Create proper UserOp hash according to EIP-4337
      if (!owner.provider) {
        throw new Error("Owner wallet has no provider attached");
      }
      const chainId = (await owner.provider.getNetwork()).chainId;

      // Auto-detect UserOp format and extract gas values accordingly
      const format = detectUserOpFormat(userOp);
      let callGasLimit: bigint;
      let verificationGasLimit: bigint;
      let maxFeePerGas: bigint;
      let maxPriorityFeePerGas: bigint;

      if (format === "v0.7") {
  // Gestisci sia BigInt che hex string
  let accountGasLimits = userOp.accountGasLimits;
  let gasFees = userOp.gasFees;
  
  // Se sono hex string, convertili a BigInt
  if (typeof accountGasLimits === 'string') {
    accountGasLimits = BigInt(accountGasLimits);
  }
  if (typeof gasFees === 'string') {
    gasFees = BigInt(gasFees);
  }
  
  // Ora puoi fare split128x128
  [verificationGasLimit, callGasLimit] = split128x128(accountGasLimits);
  [maxFeePerGas, maxPriorityFeePerGas] = split128x128(gasFees);
  
  console.log("🔧 UserOp v0.7 format detected");
  console.log("  accountGasLimits:", userOp.accountGasLimits.toString());
  console.log("  gasFees:", userOp.gasFees.toString());
} else {
  // v0.6 format: usa i valori direttamente
  callGasLimit = typeof userOp.callGasLimit === 'string' ? BigInt(userOp.callGasLimit) : userOp.callGasLimit;
  verificationGasLimit = typeof userOp.verificationGasLimit === 'string' ? BigInt(userOp.verificationGasLimit) : userOp.verificationGasLimit;
  maxFeePerGas = typeof userOp.maxFeePerGas === 'string' ? BigInt(userOp.maxFeePerGas) : userOp.maxFeePerGas;
  maxPriorityFeePerGas = typeof userOp.maxPriorityFeePerGas === 'string' ? BigInt(userOp.maxPriorityFeePerGas) : userOp.maxPriorityFeePerGas;
  
  console.log("🔧 UserOp v0.6 format detected");
  console.log("  callGasLimit:", callGasLimit.toString());
  console.log("  verificationGasLimit:", verificationGasLimit.toString());
  console.log("  maxFeePerGas:", maxFeePerGas.toString());
  console.log("  maxPriorityFeePerGas:", maxPriorityFeePerGas.toString());
}

      // Pack UserOp for hashing (EIP-4337 standard)
      const abiCoder = new AbiCoder();

      console.log("📦 Encoding UserOp for signing:");
      console.log("  sender:", userOp.sender);
      console.log("  nonce:", userOp.nonce.toString());
      console.log(
        "  preVerificationGas:",
        userOp.preVerificationGas.toString()
      );
      console.log("  callGasLimit:", callGasLimit.toString());
      console.log("  verificationGasLimit:", verificationGasLimit.toString());
      console.log("  maxFeePerGas:", maxFeePerGas.toString());
      console.log("  maxPriorityFeePerGas:", maxPriorityFeePerGas.toString());

      const packedUserOp = abiCoder.encode(
  [
    "address",
    "uint256", 
    "bytes32",
    "bytes32",
    "bytes32", // accountGasLimits (packed)
    "uint256",
    "bytes32", // gasFees (packed)  
    "bytes32",
  ],
  [
    userOp.sender,
    userOp.nonce,
    keccak256(userOp.initCode || "0x"),
    keccak256(userOp.callData),
    userOp.accountGasLimits, // Usa il valore packed direttamente
    userOp.preVerificationGas,
    userOp.gasFees, // Usa il valore packed direttamente
    keccak256(userOp.paymasterAndData || "0x"),
  ]
);

console.log("📦 Using v0.7 packed format for hash calculation");

      console.log("✅ UserOp encoded successfully");

      const userOpHash = keccak256(
        abiCoder.encode(
          ["bytes32", "address", "uint256"],
          [keccak256(packedUserOp), ENTRYPOINT_ADDR, chainId]
        )
      );

      console.log("🔐 UserOpHash created:", userOpHash);

console.log("🔐 Hash calculated on values:");
console.log("  callGasLimit:", callGasLimit.toString());
console.log("  verificationGasLimit:", verificationGasLimit.toString());
console.log("  maxFeePerGas:", maxFeePerGas.toString());
console.log("  maxPriorityFeePerGas:", maxPriorityFeePerGas.toString());

      // Sign the hash
      const sk =
        (owner as any).signingKey ?? // se già esposto dal wallet
        new SigningKey(owner.privateKey); // fallback

      // 2. firma del digest RAW (no prefisso)
      const sig = sk.sign(userOpHash); // { r, s, yParity, v }

      // 3. v in formato 27 / 28
      const v = sig.v ?? 27 + sig.yParity;
      const vHex = toBeHex(v, 1);

      // 4. serializzazione 65-byte r||s||v
      const signature = concat([sig.r, sig.s, vHex]);

      console.log("✍️ Signature created:", signature);

      return {
        ...userOp,
        signature,
      };
    },
  };
}
