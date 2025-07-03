import { describe, it, expect, vi } from "vitest";
import nacl from "tweetnacl";
import { JsonRpcProvider } from "ethers";

import { MessageDeduplicator, sendEncryptedMessage } from "../src";
import { getNextNonce } from "../src/utils/nonce";
import { convertPublicKeyToX25519 } from "../src/utils/x25519";
import { 
  isSmartContract, 
  verifyEIP1271Signature 
} from "../src/utils";  
import { ExecutorFactory } from "../src";
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
  }
} as unknown as JsonRpcProvider;

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
  it("isSmartContract returns true for contract bytecode", async () => {
    expect(await isSmartContract("0xCc…Cc", fakeProvider)).toBe(true);
    expect(await isSmartContract("0xEe…Ee", fakeProvider)).toBe(false);
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
    expect(typeof callArgs[1]).toBe('string'); 
    expect(typeof callArgs[2]).toBe('number'); 
    expect(typeof callArgs[3]).toBe('bigint'); 
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
    expect(typeof isSmartContract).toBe('function');
    expect(typeof verifyEIP1271Signature).toBe('function');
    expect(typeof sendEncryptedMessage).toBe('function');
  });
});