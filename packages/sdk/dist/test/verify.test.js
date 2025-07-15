import { describe, it, expect } from "vitest";
import { Wallet, keccak256, toUtf8Bytes, hexlify, } from "ethers";
import nacl from "tweetnacl";
import { sha256 } from "@noble/hashes/sha256";
import { hkdf } from "@noble/hashes/hkdf";
import { verifyEOADerivationProof, verifySmartAccountDerivationProof, verifyEIP1271Signature, } from "../src/utils.js";
import { verifyHandshakeIdentity, verifyHandshakeResponseIdentity, } from "../src/verify.js";
import { encryptStructuredPayload } from "../src/crypto.js";
import { encodeUnifiedPubKeys, parseHandshakeKeys, } from "../src/payload.js";
import { deriveIdentityWithUnifiedKeys } from "../src/identity.js";
const mockProvider = {
    async getCode(address) {
        // assume all addresses starting with '0xCc' are contracts
        return address.startsWith("0xCc") ? "0x60016000" : "0x";
    },
    async call() {
        return "0x1626ba7e" + "0".repeat(56);
    },
};
describe("Verify Identity & Handshake (Updated for Unified Keys)", () => {
    describe("EOA Derivation Proof Verification", () => {
        it("verifyEOADerivationProof - OK with correct unified keys", async () => {
            const wallet = Wallet.createRandom();
            const { derivationProof, identityPubKey, signingPubKey } = await deriveIdentityWithUnifiedKeys(wallet, wallet.address);
            const result = verifyEOADerivationProof(derivationProof, wallet.address, {
                identityPubKey,
                signingPubKey,
            });
            expect(result).toBe(true);
        });
        it("verifyEOADerivationProof - KO with wrong address", async () => {
            const wallet1 = Wallet.createRandom();
            const wallet2 = Wallet.createRandom();
            const { derivationProof, identityPubKey, signingPubKey } = await deriveIdentityWithUnifiedKeys(wallet1, wallet1.address);
            const result = verifyEOADerivationProof(derivationProof, wallet2.address, { identityPubKey, signingPubKey });
            expect(result).toBe(false);
        });
        it("verifyEOADerivationProof - KO with wrong keys", async () => {
            const wallet = Wallet.createRandom();
            const { derivationProof } = await deriveIdentityWithUnifiedKeys(wallet, wallet.address);
            const wrongKeys = {
                identityPubKey: new Uint8Array(32).fill(0xaa),
                signingPubKey: new Uint8Array(32).fill(0xbb),
            };
            const result = verifyEOADerivationProof(derivationProof, wallet.address, wrongKeys);
            expect(result).toBe(false);
        });
    });
    describe("Smart Contract Verification", () => {
        it("verifyEIP1271Signature - handles both success and failure cases", async () => {
            const contractAddress = "0xCcCcCc1234567890123456789012345678901234";
            const messageHash = "0x" + "aa".repeat(32);
            const signature = "0x" + "bb".repeat(65);
            const failingProvider = {
                async getCode() {
                    return "0x60016000";
                },
                async call() {
                    throw new Error("Contract call failed");
                },
            };
            const result = await verifyEIP1271Signature(contractAddress, messageHash, signature, failingProvider);
            const result2 = await verifyEIP1271Signature(contractAddress, messageHash, signature, mockProvider);
            expect(result).toBe(false);
            expect(result2).toBe(true);
        });
        it("verifySmartAccountDerivationProof - handles EIP-1271 correctly", async () => {
            const contractAddress = "0xCcCcCc1234567890123456789012345678901234";
            const tempWallet = Wallet.createRandom();
            const message = `VerbEth Identity Key Derivation v1\nAddress: ${contractAddress}`;
            const signature = await tempWallet.signMessage(message);
            const derivationProof = {
                message,
                signature,
            };
            const ikm = sha256(signature);
            const salt = new Uint8Array(32);
            // Derive X25519 keys
            const info_x25519 = new TextEncoder().encode("verbeth-x25519-v1");
            const keyMaterial_x25519 = hkdf(sha256, ikm, salt, info_x25519, 32);
            const boxKeyPair = nacl.box.keyPair.fromSecretKey(keyMaterial_x25519);
            // Derive Ed25519 keys
            const info_ed25519 = new TextEncoder().encode("verbeth-ed25519-v1");
            const keyMaterial_ed25519 = hkdf(sha256, ikm, salt, info_ed25519, 32);
            const signKeyPair = nacl.sign.keyPair.fromSeed(keyMaterial_ed25519);
            const expectedKeys = {
                identityPubKey: boxKeyPair.publicKey,
                signingPubKey: signKeyPair.publicKey,
            };
            const enhancedMockProvider = {
                async getCode(address) {
                    return address.startsWith("0xCc") ? "0x60016000" : "0x";
                },
                async call(request) {
                    // EIP-1271 mock: a simulation of a contract that always returns a valid signature
                    return "0x1626ba7e" + "0".repeat(56);
                },
            };
            const result = await verifySmartAccountDerivationProof(derivationProof, contractAddress, expectedKeys, enhancedMockProvider);
            expect(result).toBe(true);
        });
    });
    describe("Handshake Verification", () => {
        it("verifyHandshakeIdentity - EOA flow with unified keys", async () => {
            const wallet = Wallet.createRandom();
            const { derivationProof, unifiedPubKeys } = await deriveIdentityWithUnifiedKeys(wallet, wallet.address);
            const handshakeEvent = {
                recipientHash: keccak256(toUtf8Bytes("contact:0xdead")),
                sender: wallet.address,
                pubKeys: hexlify(unifiedPubKeys),
                ephemeralPubKey: hexlify(nacl.box.keyPair().publicKey),
                plaintextPayload: JSON.stringify({
                    plaintextPayload: "Hi VerbEth",
                    derivationProof,
                }),
            };
            const result = await verifyHandshakeIdentity(handshakeEvent, mockProvider);
            expect(result).toBe(true);
        });
        it("verifyHandshakeIdentity - fails with invalid derivation proof", async () => {
            const wallet = Wallet.createRandom();
            const { unifiedPubKeys } = await deriveIdentityWithUnifiedKeys(wallet, wallet.address);
            // create invalid derivation proof with different wallet signature
            const differentWallet = Wallet.createRandom();
            const invalidMessage = "Invalid message for verification";
            const invalidSignature = await differentWallet.signMessage(invalidMessage);
            const invalidDerivationProof = {
                message: invalidMessage,
                signature: invalidSignature,
            };
            const handshakeEvent = {
                recipientHash: keccak256(toUtf8Bytes("contact:0xdead")),
                sender: wallet.address,
                pubKeys: hexlify(unifiedPubKeys),
                ephemeralPubKey: hexlify(nacl.box.keyPair().publicKey),
                plaintextPayload: JSON.stringify({
                    plaintextPayload: "Hi VerbEth",
                    derivationProof: invalidDerivationProof,
                }),
            };
            const result = await verifyHandshakeIdentity(handshakeEvent, mockProvider);
            expect(result).toBe(false);
        });
    });
    describe("Handshake Response Verification", () => {
        it("verifyHandshakeResponseIdentity - EOA flow with unified keys", async () => {
            const responderWallet = Wallet.createRandom();
            const { derivationProof, identityPubKey, unifiedPubKeys } = await deriveIdentityWithUnifiedKeys(responderWallet, responderWallet.address);
            const aliceEphemeral = nacl.box.keyPair(); // initiator
            const responderEphemeral = nacl.box.keyPair();
            const responseContent = {
                unifiedPubKeys,
                ephemeralPubKey: responderEphemeral.publicKey,
                note: "pong",
                derivationProof,
            };
            const payload = encryptStructuredPayload(responseContent, aliceEphemeral.publicKey, responderEphemeral.secretKey, responderEphemeral.publicKey);
            const responseEvent = {
                inResponseTo: keccak256(toUtf8Bytes("test-handshake")),
                responder: responderWallet.address,
                ciphertext: payload,
            };
            const result = await verifyHandshakeResponseIdentity(responseEvent, identityPubKey, aliceEphemeral.secretKey, mockProvider);
            expect(result).toBe(true);
        });
        it("verifyHandshakeResponseIdentity - fails with wrong identity key", async () => {
            const responderWallet = Wallet.createRandom();
            const { derivationProof, unifiedPubKeys } = await deriveIdentityWithUnifiedKeys(responderWallet, responderWallet.address);
            const aliceEphemeral = nacl.box.keyPair();
            const responderEphemeral = nacl.box.keyPair();
            const responseContent = {
                unifiedPubKeys,
                ephemeralPubKey: responderEphemeral.publicKey,
                note: "pong",
                derivationProof,
            };
            const payload = encryptStructuredPayload(responseContent, aliceEphemeral.publicKey, responderEphemeral.secretKey, responderEphemeral.publicKey);
            const responseEvent = {
                inResponseTo: keccak256(toUtf8Bytes("test-handshake")),
                responder: responderWallet.address,
                ciphertext: payload,
            };
            const wrongIdentityKey = new Uint8Array(32).fill(0xff);
            const result = await verifyHandshakeResponseIdentity(responseEvent, wrongIdentityKey, aliceEphemeral.secretKey, mockProvider);
            expect(result).toBe(false);
        });
    });
    describe("Key Parsing", () => {
        it("parseHandshakeKeys extracts unified keys correctly", () => {
            const identityPubKey = new Uint8Array(32).fill(1);
            const signingPubKey = new Uint8Array(32).fill(2);
            const unifiedPubKeys = encodeUnifiedPubKeys(identityPubKey, signingPubKey);
            const event = {
                pubKeys: hexlify(unifiedPubKeys),
            };
            const parsed = parseHandshakeKeys(event);
            expect(parsed).not.toBeNull();
            expect(parsed.identityPubKey).toEqual(identityPubKey);
            expect(parsed.signingPubKey).toEqual(signingPubKey);
        });
        it("parseHandshakeKeys returns null for invalid keys", () => {
            const event = {
                pubKeys: "0x1234",
            };
            const parsed = parseHandshakeKeys(event);
            expect(parsed).toBeNull();
        });
    });
});
