import { describe, it, expect, vi } from "vitest";
import nacl from "tweetnacl";
import { JsonRpcProvider } from "ethers";

import { MessageDeduplicator } from "../src";
import { getNextNonce } from "../src/utils/nonce";
import { convertPublicKeyToX25519 } from "../src/utils/x25519";
import { isSmartContract, verifyEIP1271Signature, sendEncryptedMessage } from "../src";
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

//
describe("MessageDeduplicator", () => {
  it("detects duplicates and enforces maxSize", () => {
    const dedup = new MessageDeduplicator(2);
    expect(dedup.isDuplicate("A", "T", 1n)).toBe(false); // first time
    expect(dedup.isDuplicate("A", "T", 1n)).toBe(true);  // duplicate
    expect(dedup.isDuplicate("A", "T", 2n)).toBe(false); // new
    expect(dedup.isDuplicate("A", "T", 3n)).toBe(false); // evicts 1
    expect(dedup.isDuplicate("A", "T", 1n)).toBe(false); // not duplicate anymore
  });
});


//
describe("getNextNonce", () => {
  it("increments per (sender, topic) and returns bigint", () => {
    const n1 = getNextNonce("0xAlice", "topic");
    const n2 = getNextNonce("0xAlice", "topic");
    const nOther = getNextNonce("0xBob", "topic");
    expect(n2).toBe(n1 + 1n);
    expect(nOther).toBe(1n);
  });
});

//
describe("Utils", () => {
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

//
describe("sendEncryptedMessage", () => {
  it("calls contract.sendMessage with expected parameters", async () => {
    const fakeContract = {
      sendMessage: vi.fn().mockResolvedValue("txHash"),
    } as unknown as LogChainV1;

    const recipientKey = nacl.box.keyPair();
    const senderSign = nacl.sign.keyPair();

    await sendEncryptedMessage({
      contract: fakeContract,
      topic: "0x" + "ab".repeat(32),
      message: "hi",
      recipientPubKey: recipientKey.publicKey,
      senderAddress: "0xAlice",
      senderSignKeyPair: senderSign,
      timestamp: 42,
    });

    expect(fakeContract.sendMessage).toHaveBeenCalledTimes(1);
  });
});
