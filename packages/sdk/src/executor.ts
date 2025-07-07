// packages/sdk/src/executor.ts

import {
  Signer,
  Contract,
  Interface,
  BaseContract,
  toBeHex,
  zeroPadValue,
} from "ethers";
import {
  AASpecVersion,
  UserOpV06,
  UserOpV07,
  PackedUserOperation,
} from "./types";
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";

function pack128x128(high: bigint, low: bigint): bigint {
  return (high << 128n) | (low & ((1n << 128n) - 1n));
}

// Unpack a packed 256-bit value into two 128-bit values
export function split128x128(word: bigint): readonly [bigint, bigint] {
  const lowMask = (1n << 128n) - 1n;
  return [word >> 128n, word & lowMask] as const;
}

/* -------------------------------------------------------------------------- */
/*    Helpers for compatibility between AA spec v0.6 and v0.7                 */
/* -------------------------------------------------------------------------- */

// ► Detects the version from the EntryPoint ABI (v0.7 introduces getAccountGasLimits)
const detectSpecVersion = (iface: Interface): AASpecVersion => {
  try {
    iface.getFunction("getAccountGasLimits");
    return "v0.7";
  } catch {
    return "v0.6";
  }
};

// ► Automatically transforms all bigints into padded bytes32 (uint256)
const padBigints = <T extends Record<string, any>>(op: T): T => {
  const out: any = { ...op };
  for (const [k, v] of Object.entries(out)) {
    if (typeof v === "bigint") {
      out[k] = zeroPadValue(toBeHex(v), 32);
    }
  }
  return out as T;
};

export interface IExecutor {
  sendMessage(
    ciphertext: Uint8Array,
    topic: string,
    timestamp: number,
    nonce: bigint
  ): Promise<any>;

  initiateHandshake(
    recipientHash: string,
    pubKeys: string,
    ephemeralPubKey: string,
    plaintextPayload: Uint8Array
  ): Promise<any>;

  respondToHandshake(
    inResponseTo: string,
    ciphertext: Uint8Array
  ): Promise<any>;
}

// EOA Executor - Direct contract calls via wallet signer
export class EOAExecutor implements IExecutor {
  constructor(private contract: LogChainV1) {}

  async sendMessage(
    ciphertext: Uint8Array,
    topic: string,
    timestamp: number,
    nonce: bigint
  ): Promise<any> {
    return this.contract.sendMessage(ciphertext, topic, timestamp, nonce);
  }

  async initiateHandshake(
    recipientHash: string,
    pubKeys: string,
    ephemeralPubKey: string,
    plaintextPayload: Uint8Array
  ): Promise<any> {
    return this.contract.initiateHandshake(
      recipientHash,
      pubKeys,
      ephemeralPubKey,
      plaintextPayload
    );
  }

  async respondToHandshake(
    inResponseTo: string,
    ciphertext: Uint8Array
  ): Promise<any> {
    return this.contract.respondToHandshake(inResponseTo, ciphertext);
  }
}

// UserOp Executor - Account Abstraction via bundler
export class UserOpExecutor implements IExecutor {
  private logChainInterface: Interface;
  private smartAccountInterface: Interface;

  constructor(
    private smartAccountAddress: string,
    private logChainAddress: string,
    private bundlerClient: any,
    private smartAccountClient: any
  ) {
    this.logChainInterface = new Interface([
      "function sendMessage(bytes calldata ciphertext, bytes32 topic, uint256 timestamp, uint256 nonce)",
      "function initiateHandshake(bytes32 recipientHash, bytes pubKeys, bytes ephemeralPubKey, bytes plaintextPayload)",
      "function respondToHandshake(bytes32 inResponseTo, bytes ciphertext)",
    ]);

    // Smart account interface for executing calls to other contracts
    this.smartAccountInterface = new Interface([
      "function execute(address target, uint256 value, bytes calldata data) returns (bytes)",
    ]);
  }

  async sendMessage(
    ciphertext: Uint8Array,
    topic: string,
    timestamp: number,
    nonce: bigint
  ): Promise<any> {
    const logChainCallData = this.logChainInterface.encodeFunctionData(
      "sendMessage",
      [ciphertext, topic, timestamp, nonce]
    );

    const smartAccountCallData = this.smartAccountInterface.encodeFunctionData(
      "execute",
      [
        this.logChainAddress,
        0, // value
        logChainCallData,
      ]
    );

    return this.executeUserOp(smartAccountCallData);
  }

  async initiateHandshake(
    recipientHash: string,
    pubKeys: string,
    ephemeralPubKey: string,
    plaintextPayload: Uint8Array
  ): Promise<any> {
    const logChainCallData = this.logChainInterface.encodeFunctionData(
      "initiateHandshake",
      [recipientHash, pubKeys, ephemeralPubKey, plaintextPayload]
    );

    const smartAccountCallData = this.smartAccountInterface.encodeFunctionData(
      "execute",
      [
        this.logChainAddress,
        0, // value
        logChainCallData,
      ]
    );

    return this.executeUserOp(smartAccountCallData);
  }

  async respondToHandshake(
    inResponseTo: string,
    ciphertext: Uint8Array
  ): Promise<any> {
    const logChainCallData = this.logChainInterface.encodeFunctionData(
      "respondToHandshake",
      [inResponseTo, ciphertext]
    );

    const smartAccountCallData = this.smartAccountInterface.encodeFunctionData(
      "execute",
      [
        this.logChainAddress,
        0, // value
        logChainCallData,
      ]
    );

    return this.executeUserOp(smartAccountCallData);
  }

  private async executeUserOp(callData: string): Promise<any> {
    const callGasLimit = 1_000_000n;
    const verificationGasLimit = 1_000_000n;
    const maxFeePerGas = 1_000_000_000n;
    const maxPriorityFeePerGas = 1_000_000_000n;

    const userOp: PackedUserOperation = {
      sender: this.smartAccountAddress,
      nonce: await this.smartAccountClient.getNonce(),
      initCode: "0x", // No init code for existing accounts
      callData,

      accountGasLimits: pack128x128(verificationGasLimit, callGasLimit),
      preVerificationGas: 100_000n,
      gasFees: pack128x128(maxFeePerGas, maxPriorityFeePerGas),

      paymasterAndData: "0x",
      signature: "0x",
    };

    const signedUserOp = await this.smartAccountClient.signUserOperation(
      userOp
    );
    const userOpHash = await this.bundlerClient.sendUserOperation(signedUserOp);

    const receipt = await this.bundlerClient.waitForUserOperationReceipt(
      userOpHash
    );
    return receipt;
  }
}

// Direct EntryPoint Executor - for local testing (bypasses bundler)
export class DirectEntryPointExecutor implements IExecutor {
  private logChainInterface: Interface;
  private smartAccountInterface: Interface;
  private entryPointContract: Contract;
  private spec: AASpecVersion;

  constructor(
    private smartAccountAddress: string,
    entryPointContract: Contract | BaseContract,
    private logChainAddress: string,
    private smartAccountClient: any,
    private signer: Signer // direct signer for test transactions
  ) {
    this.logChainInterface = new Interface([
      "function sendMessage(bytes calldata ciphertext, bytes32 topic, uint256 timestamp, uint256 nonce)",
      "function initiateHandshake(bytes32 recipientHash, bytes pubKeys, bytes ephemeralPubKey, bytes plaintextPayload)",
      "function respondToHandshake(bytes32 inResponseTo, bytes ciphertext)",
    ]);

    // Smart account interface for executing calls to other contracts
    this.smartAccountInterface = new Interface([
      "function execute(address target, uint256 value, bytes calldata data) returns (bytes)",
    ]);

    this.entryPointContract = entryPointContract.connect(signer) as Contract;
    // Auto-detect AA spec version (v0.6 / v0.7)
    this.spec = detectSpecVersion(this.entryPointContract.interface);
  }

  async sendMessage(
    ciphertext: Uint8Array,
    topic: string,
    timestamp: number,
    nonce: bigint
  ): Promise<any> {

    const logChainCallData = this.logChainInterface.encodeFunctionData(
      "sendMessage",
      [ciphertext, topic, timestamp, nonce]
    );

    const smartAccountCallData = this.smartAccountInterface.encodeFunctionData(
      "execute",
      [
        this.logChainAddress,
        0, // value
        logChainCallData,
      ]
    );

    return this.executeDirectUserOp(smartAccountCallData);
  }

  
  async initiateHandshake(
    recipientHash: string,
    pubKeys: string,
    ephemeralPubKey: string,
    plaintextPayload: Uint8Array
  ): Promise<any> {

    const logChainCallData = this.logChainInterface.encodeFunctionData(
      "initiateHandshake",
      [recipientHash, pubKeys, ephemeralPubKey, plaintextPayload]
    );

    const smartAccountCallData = this.smartAccountInterface.encodeFunctionData(
      "execute",
      [
        this.logChainAddress,
        0, // value
        logChainCallData,
      ]
    );

    return this.executeDirectUserOp(smartAccountCallData);
  }

  

  async respondToHandshake(
    inResponseTo: string,
    ciphertext: Uint8Array
  ): Promise<any> {

    const logChainCallData = this.logChainInterface.encodeFunctionData(
      "respondToHandshake",
      [inResponseTo, ciphertext]
    );

    const smartAccountCallData = this.smartAccountInterface.encodeFunctionData(
      "execute",
      [
        this.logChainAddress,
        0, // value
        logChainCallData,
      ]
    );

    return this.executeDirectUserOp(smartAccountCallData);
  }

  private async executeDirectUserOp(callData: string) {
    const callGasLimit = 1_000_000n;
    const verificationGasLimit = 1_000_000n;
    const maxFeePerGas = 1_000_000_000n;
    const maxPriorityFeePerGas = 1_000_000_000n;

    // Build UserOperation
    let userOp: UserOpV06 | UserOpV07;

    if (this.spec === "v0.6") {
      userOp = {
        sender: this.smartAccountAddress,
        nonce: await this.smartAccountClient.getNonce(),
        initCode: "0x",
        callData,
        callGasLimit,
        verificationGasLimit,
        preVerificationGas: 100_000n,
        maxFeePerGas,
        maxPriorityFeePerGas,
        paymasterAndData: "0x",
        signature: "0x",
      } as UserOpV06;
    } else {
      userOp = {
        sender: this.smartAccountAddress,
        nonce: await this.smartAccountClient.getNonce(),
        initCode: "0x",
        callData,
        accountGasLimits: pack128x128(verificationGasLimit, callGasLimit),
        preVerificationGas: 100_000n,
        gasFees: pack128x128(maxFeePerGas, maxPriorityFeePerGas),
        paymasterAndData: "0x",
        signature: "0x",
      } as UserOpV07;
    }

    // Pad bigints → bytes32 before signing
    const paddedUserOp = padBigints(userOp);
    //console.log("Padded UserOp:", paddedUserOp);

    const signed = await this.smartAccountClient.signUserOperation(
      paddedUserOp
    );

    // Direct submit to EntryPoint
    const tx = await this.entryPointContract.handleOps(
      [signed],
      await this.signer.getAddress()
    );
    return tx;
  }
}

export class ExecutorFactory {
  static createEOA(contract: LogChainV1): IExecutor {
    return new EOAExecutor(contract);
  }

  static createUserOp(
    smartAccountAddress: string,
    _entryPointAddress: string,
    logChainAddress: string,
    bundlerClient: any,
    smartAccountClient: any
  ): IExecutor {
    return new UserOpExecutor(
      smartAccountAddress,
      logChainAddress,
      bundlerClient,
      smartAccountClient
    );
  }

  static createDirectEntryPoint(
    smartAccountAddress: string,
    entryPointContract: Contract | BaseContract,
    logChainAddress: string,
    smartAccountClient: any,
    signer: Signer
  ): IExecutor {
    return new DirectEntryPointExecutor(
      smartAccountAddress,
      entryPointContract,
      logChainAddress,
      smartAccountClient,
      signer
    );
  }

  // Auto-detect executor based on environment and signer type
  static async createAuto(
    signerOrAccount: any,
    contract: LogChainV1,
    options?: {
      entryPointAddress?: string;
      entryPointContract?: Contract | BaseContract;
      logChainAddress?: string;
      bundlerClient?: any;
      isTestEnvironment?: boolean;
    }
  ): Promise<IExecutor> {
    if (
      signerOrAccount.address &&
      (options?.bundlerClient || options?.entryPointContract)
    ) {
      if (
        options.isTestEnvironment &&
        options.entryPointContract &&
        options.logChainAddress
      ) {
        return new DirectEntryPointExecutor(
          signerOrAccount.address,
          options.entryPointContract,
          options.logChainAddress,
          signerOrAccount,
          signerOrAccount.signer || signerOrAccount
        );
      }

      if (
        options.bundlerClient &&
        options.entryPointAddress &&
        options.logChainAddress
      ) {
        return new UserOpExecutor(
          signerOrAccount.address,
          options.logChainAddress,
          options.bundlerClient,
          signerOrAccount
        );
      }
    }

    return new EOAExecutor(contract);
  }
}