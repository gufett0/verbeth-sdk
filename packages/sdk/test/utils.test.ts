import { describe, it, expect, beforeEach, vi } from "vitest";
import nacl from "tweetnacl";
import { JsonRpcProvider } from "ethers";

import { MessageDeduplicator, sendEncryptedMessage } from "../src/index.js";
import { getNextNonce } from "../src/utils/nonce.js";
import { convertPublicKeyToX25519 } from "../src/utils/x25519.js";
import { isSmartContract1271, verifyEIP1271Signature } from "../src/utils.js";
import { ExecutorFactory } from "../src/index.js";
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";

const fakeProvider = {
  async getCode(addr: string) {
    return addr === "0xCc…Cc" ? "0x60016000" : "0x";
  },
  async call() {
    return "0x1626ba7e" + "0".repeat(56);
  },
  async resolveName(name: string) {
    return name;
  },
} as unknown as JsonRpcProvider;

// --- mock ethers.Contract to control behavior per ABI variant ---
let behavior4: (() => Promise<any>) | null = null;
let behavior3: (() => Promise<any>) | null = null;

describe("MessageDeduplicator", () => {
  it("detects duplicates and enforces maxSize", () => {
    const dedup = new MessageDeduplicator(2);
    expect(dedup.isDuplicate("A", "T", 1n)).toBe(false);
    expect(dedup.isDuplicate("A", "T", 1n)).toBe(true);
    expect(dedup.isDuplicate("A", "T", 2n)).toBe(false);
    expect(dedup.isDuplicate("A", "T", 3n)).toBe(false);
    expect(dedup.isDuplicate("A", "T", 1n)).toBe(false); // not duplicate anymore
  });
});

describe("getNextNonce", () => {
  it("increments per (sender, topic) and returns bigint", () => {
    const n1 = getNextNonce("0xAlice", "topic");
    const n2 = getNextNonce("0xAlice", "topic");
    const nOther = getNextNonce("0xBob", "topic");
    expect(n2).toBe(n1 + 1n);
    expect(nOther).toBe(1n);
  });
});

describe("Utils Functions", () => {
  it("isSmartContract1271 returns true for contract bytecode", async () => {
    expect(await isSmartContract1271("0xCc…Cc", fakeProvider)).toBe(true);
    expect(await isSmartContract1271("0xEe…Ee", fakeProvider)).toBe(false);
  });

  it("verifyEIP1271Signature returns true on magic value", async () => {
    const validHash = "0x" + "aa".repeat(32);
    const validSig = "0x" + "bb".repeat(65);

    const ok = await verifyEIP1271Signature(
      "0xCc…Cc",
      validHash,
      validSig,
      fakeProvider
    );

    expect(ok).toBe(true);
  });

  it("convertPublicKeyToX25519 returns 32-byte key", () => {
    const raw = new Uint8Array(64).fill(1);
    const out = convertPublicKeyToX25519(raw);
    expect(out).toHaveLength(32);
  });
});

describe("sendEncryptedMessage", () => {
  it("calls contract.sendMessage with expected parameters", async () => {
    const mockSendMessage = vi.fn().mockResolvedValue("txHash");
    const fakeContract = {
      sendMessage: mockSendMessage,
    } as unknown as LogChainV1;

    const executor = ExecutorFactory.createEOA(fakeContract);
    const recipientKey = nacl.box.keyPair();
    const senderSign = nacl.sign.keyPair();

    await sendEncryptedMessage({
      executor: executor,
      topic: "0x" + "ab".repeat(32),
      message: "hi",
      recipientPubKey: recipientKey.publicKey,
      senderAddress: "0xAlice",
      senderSignKeyPair: senderSign,
      timestamp: 42,
    });

    expect(mockSendMessage).toHaveBeenCalledTimes(1);

    const callArgs = mockSendMessage.mock.calls[0];
    expect(callArgs).toHaveLength(4); // ciphertext, topic, timestamp, nonce
    expect(typeof callArgs[1]).toBe("string");
    expect(typeof callArgs[2]).toBe("number");
    expect(typeof callArgs[3]).toBe("bigint");
  });

  it("generates different nonces for different calls", async () => {
    const mockSendMessage = vi.fn().mockResolvedValue("txHash");
    const fakeContract = {
      sendMessage: mockSendMessage,
    } as unknown as LogChainV1;

    const executor = ExecutorFactory.createEOA(fakeContract);
    const recipientKey = nacl.box.keyPair();
    const senderSign = nacl.sign.keyPair();

    // send two messages from same sender
    await sendEncryptedMessage({
      executor: executor,
      topic: "0x" + "ab".repeat(32),
      message: "message 1",
      recipientPubKey: recipientKey.publicKey,
      senderAddress: "0xAlice",
      senderSignKeyPair: senderSign,
      timestamp: 42,
    });

    await sendEncryptedMessage({
      executor: executor,
      topic: "0x" + "ab".repeat(32),
      message: "message 2",
      recipientPubKey: recipientKey.publicKey,
      senderAddress: "0xAlice",
      senderSignKeyPair: senderSign,
      timestamp: 43,
    });

    expect(mockSendMessage).toHaveBeenCalledTimes(2);

    const firstNonce = mockSendMessage.mock.calls[0][3];
    const secondNonce = mockSendMessage.mock.calls[1][3];
    expect(secondNonce).toBe(firstNonce + 1n);
  });
});

describe("Unified Keys Utilities", () => {
  it("should handle unified key operations", () => {
    // just verify the basic imports work
    expect(typeof isSmartContract1271).toBe("function");
    expect(typeof verifyEIP1271Signature).toBe("function");
    expect(typeof sendEncryptedMessage).toBe("function");
  });
});

// --------------------------------------------------------------------
// verifyERC6492WithSingleton unit tests
// --------------------------------------------------------------------

const DUMMY = {
  account: "0x0000000000000000000000000000000000000001",
  messageHash: "0x" + "11".repeat(32),
  sig6492Envelope: "0x" + "22".repeat(64),
  provider: {} as any,
};

describe("utils.verifyERC6492WithSingleton (unit)", () => {
  let verifyERC6492WithSingleton: typeof import("../src/utils.js").verifyERC6492WithSingleton;

  beforeEach(async () => {
    behavior4 = null;
    behavior3 = null;

    vi.resetModules();
    vi.doMock("ethers", async () => {
      const actual = await vi.importActual<any>("ethers");
      class Contract {
        address: string;
        abi: any;
        provider: any;
        isValidSig: { staticCall: (...args: any[]) => Promise<any> };

        constructor(address: string, abi: any, provider: any) {
          this.address = address;
          this.abi = abi;
          this.provider = provider;

          const sig = Array.isArray(abi) ? String(abi[0] ?? "") : "";
          const uses4 = sig.includes("(address,bytes32,bytes,bool)");
          const uses3 = sig.includes("(address,bytes32,bytes)");

          this.isValidSig = {
            staticCall: async () => {
              if (uses4 && behavior4) return behavior4();
              if (uses3 && behavior3) return behavior3();
              throw Object.assign(new Error("no behavior"), { data: "0x" });
            },
          };
        }
      }
      return { ...actual, Contract };
    });

    ({ verifyERC6492WithSingleton } = await import("../src/utils.js"));
  });

  it("returns true via 4-arg ABI (direct)", async () => {
    behavior4 = async () => true;
    const ok = await verifyERC6492WithSingleton(DUMMY);
    expect(ok).toBe(true);
  });

  it("falls back to 3-arg ABI and returns true", async () => {
    behavior4 = async () => {
      throw Object.assign(new Error("no 4-arg"), { data: "0x" });
    };
    behavior3 = async () => true;
    const ok = await verifyERC6492WithSingleton(DUMMY);
    expect(ok).toBe(true);
  });

  it("decodes revert(bool)=true from revert data", async () => {
    const revertTrue = "0x" + "00".repeat(31) + "01";
    behavior4 = async () => {
      throw Object.assign(new Error("revert-true"), { data: revertTrue });
    };
    const ok = await verifyERC6492WithSingleton(DUMMY);
    expect(ok).toBe(true);
  });

  it("decodes revert(bool)=false from revert data", async () => {
    const revertFalse = "0x" + "00".repeat(32);
    behavior4 = async () => {
      throw Object.assign(new Error("revert-false"), { data: revertFalse });
    };
    const ok = await verifyERC6492WithSingleton(DUMMY);
    expect(ok).toBe(false);
  });

  // enforce low-s form to prevent ECDSA malleability (r,s) vs (r, n−s) duplicates
  it("rejects ECDSA signatures with high-s values (inside 6492 envelope)", async () => {
    // make a fake 65-byte signature with s > secp256k1n/2
    const r = "0x" + "11".repeat(32);
    const highS = "0x" + "ff".repeat(32); 
    const v = "1b";
    const badSig = r + highS.slice(2) + v;

    // build ERC-6492 envelope: (factory, calldata, signature) + suffix
    const dummyFactory = "0x" + "00".repeat(20);
    const dummyCalldata = "0x";
    const abiCoder = new (await import("ethers")).AbiCoder();
    const prefix = abiCoder.encode(
      ["address", "bytes", "bytes"],
      [dummyFactory, dummyCalldata, badSig]
    );

    const suffix = "0x" + "6492".repeat(8); // 32-byte detection suffix
    const envelope = prefix + suffix.slice(2);

    const { verifyERC6492WithSingleton } = await import("../src/utils.js");

    const ok = await verifyERC6492WithSingleton({
      ...DUMMY,
      sig6492Envelope: envelope,
    });

    expect(ok).toBe(false);
  });
});
