import { ethers, Provider } from "../utils/ethers";
import { convertPublicKeyToX25519 } from "../utils/x25519";
import { decryptHandshakeResponse } from "./crypto";

/**
 * Verifies the identity of a handshake responder (EOA or Smart Account)
 */
export async function verifyHandshakeResponseIdentity(
  rawTxHex: string,
  responseEvent: {
    responder: string;
    ciphertext: string;
  },
  responderIdentityPubKey: Uint8Array,
  initiatorEphemeralSecretKey: Uint8Array,
  provider?: Provider
): Promise<boolean> {
  // First try EOA verification
  const eoaResult = verifyEOAHandshakeResponse(
    rawTxHex,
    responderIdentityPubKey
  );
  
  // If EOA verification succeeds, no need to check smart account
  if (eoaResult) {
    return true;
  }

  // If provider is available, check if it's a smart account
  if (provider) {
    const code = await provider.getCode(responseEvent.responder);
    if (code !== '0x') {
      return verifySmartAccountHandshakeResponse(
        responseEvent,
        responderIdentityPubKey,
        initiatorEphemeralSecretKey,
        provider
      );
    }
  }
  return false;
}

/**
 * Verifies EOA handshake response by checking the signature
 * against the responder's public key derived from the transaction
 * @param rawTxHex - The raw transaction hex string
 * @param responderIdentityPubKey - The responder's identity public key
 * @returns true if the verification is successful, false otherwise
 */
export function verifyEOAHandshakeResponse(
  rawTxHex: string,
  responderIdentityPubKey: Uint8Array
): boolean {
  try {
    // Early return if rawTxHex is empty or invalid
    if (!rawTxHex || rawTxHex.trim() === "" || rawTxHex === "0x") {
      return false;
    }

    const parsedTx = ethers.Transaction.from(rawTxHex);
    const digest = parsedTx.unsignedHash;

    const sig = parsedTx.signature;
    if (!sig) {
      throw new Error("Invalid or missing signature in parsed transaction");
    }

    const secpPubKey = ethers.SigningKey.recoverPublicKey(digest, sig);
    if (!secpPubKey || !secpPubKey.startsWith("0x04")) {
      throw new Error("Invalid or missing public key in parsed transaction");
    }

    const pubkeyBytes = ethers.getBytes(secpPubKey).slice(1);
    if (pubkeyBytes.length !== 64) {
      throw new Error(
        `Expected 64 bytes after removing prefix, got ${pubkeyBytes.length}`
      );
    }
    const derivedX25519 = convertPublicKeyToX25519(pubkeyBytes);
    return Buffer.from(derivedX25519).equals(
      Buffer.from(responderIdentityPubKey)
    );
  } catch (err) {
    // Only log errors that are not expected (like empty rawTxHex)
    if (rawTxHex && rawTxHex.trim() !== "" && rawTxHex !== "0x") {
      console.error("verifyEOAHandshakeResponse error:", err);
    }
    return false;
  }
}

/**
 * Verifies smart account handshake response using EIP-1271
 * @param responseEvent - The response event containing responder address and ciphertext
 * @param responderIdentityPubKey - The responder's identity public key
 * @param initiatorEphemeralSecretKey - The ephemeral secret key of the initiator
 * @param provider - The ethers provider for interacting with the blockchain
 * @returns true if the verification is successful, false otherwise
 */
async function verifySmartAccountHandshakeResponse(
  responseEvent: {
    responder: string;
    ciphertext: string;
  },
  responderIdentityPubKey: Uint8Array,
  initiatorEphemeralSecretKey: Uint8Array,
  provider: Provider
): Promise<boolean> {
  try {
    // Convert hex string to UTF-8 string
    // responseEvent.ciphertext is a hex string ("0x1234...") from Solidity bytes
    // We need to convert it to a UTF-8 string to get the JSON payload
    const bytesData = ethers.getBytes(responseEvent.ciphertext);
    const jsonString = new TextDecoder().decode(bytesData);
    
    // Now decrypt the JSON string
    const responseContent = decryptHandshakeResponse(
      jsonString,
      initiatorEphemeralSecretKey
    );

    if (!responseContent) {
      console.error("Failed to decrypt handshake response");
      return false;
    }

    // Verify the identity key matches what's in the decrypted content
    if (
      !Buffer.from(responseContent.identityPubKey).equals(
        Buffer.from(responderIdentityPubKey)
      )
    ) {
      console.error("Identity public key mismatch");
      return false;
    }

    // For smart accounts, we need the identity proof
    if (!responseContent.identityProof) {
      console.log("No identity proof found for smart account");
      return false;
    }

    // Verify the signature using EIP-1271
    const accountContract = new ethers.Contract(
      responseEvent.responder,
      [
        "function isValidSignature(bytes32, bytes) external view returns (bytes4)",
      ],
      provider
    );

    const result = await accountContract.isValidSignature(
      responseContent.identityProof.message,
      responseContent.identityProof.signature
    );

    // EIP-1271 magic value
    return result === "0x1626ba7e";
  } catch (err) {
    console.error("verifySmartAccountHandshakeResponse error:", err);
    return false;
  }
}