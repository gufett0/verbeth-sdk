import { ethers, Provider } from "../utils/ethers";
import { decryptHandshakeResponse } from "./crypto";
import { HandshakeLog, HandshakeResponseLog } from "./types";
import { parseHandshakePayload } from "./payload";
import { verifyEIP1271Signature, isSmartContract, verifyEOAIdentity } from "./utils";

// ============= Handshake Verification =============

/**
 * Unified handshake identity verification (supports both EOA and Smart Account)
 */
export async function verifyHandshakeIdentity(
  handshakeEvent: HandshakeLog,
  rawTxHex?: string,
  provider?: Provider
): Promise<boolean> {
  // Parse payload to check for identity proof
  const content = parseHandshakePayload(handshakeEvent.plaintextPayload);
  
  // Verify identity key matches sender's pubkey derived from transaction
  const identityPubKey = ethers.getBytes(handshakeEvent.identityPubKey);
  
  // If no proof provided, assume EOA and verify via transaction
  if (!content.identityProof) {
    if (!rawTxHex) {
      console.warn("No raw transaction provided for EOA verification");
      return false;
    }
    return verifyEOAIdentity(rawTxHex, identityPubKey);
  }
  
  if (!provider) {
    console.warn("No provider provided for Smart Account verification");
    return false;
  }
  
  const isContract = await isSmartContract(handshakeEvent.sender, provider);
  if (!isContract) {
    console.error("Identity proof provided but sender is not a smart contract");
    return false;
  }
  
  return verifyEIP1271Signature(
    handshakeEvent.sender,
    content.identityProof.message,
    content.identityProof.signature,
    provider
  );
}

// ============= HandshakeResponse Verification =============

/**
 * Unified handshake response identity verification
 */
export async function verifyHandshakeResponseIdentity(
  rawTxHex: string,
  responseEvent: HandshakeResponseLog,
  responderIdentityPubKey: Uint8Array,
  initiatorEphemeralSecretKey: Uint8Array,
  provider?: Provider
): Promise<boolean> {
  // First try EOA verification
  const eoaResult = verifyEOAIdentity(rawTxHex, responderIdentityPubKey);
  
  if (eoaResult) {
    return true;
  }

  if (!provider) {
    return false;
  }
  
  const isContract = await isSmartContract(responseEvent.responder, provider);
  if (!isContract) {
    return false;
  }

  // Verify Smart Account response
  return verifySmartAccountHandshakeResponse(
    responseEvent,
    responderIdentityPubKey,
    initiatorEphemeralSecretKey,
    provider
  );
}

/**
 * Verifies smart account handshake response using EIP-1271
 */
async function verifySmartAccountHandshakeResponse(
  responseEvent: HandshakeResponseLog,
  responderIdentityPubKey: Uint8Array,
  initiatorEphemeralSecretKey: Uint8Array,
  provider: Provider
): Promise<boolean> {
  try {
    const bytesData = ethers.getBytes(responseEvent.ciphertext);
    const jsonString = new TextDecoder().decode(bytesData);
    const responseContent = decryptHandshakeResponse(
      jsonString,
      initiatorEphemeralSecretKey
    );

    if (!responseContent) {
      console.error("Failed to decrypt handshake response");
      return false;
    }

    // Verify the identity key matches
    if (!Buffer.from(responseContent.identityPubKey).equals(Buffer.from(responderIdentityPubKey))) {
      console.error("Identity public key mismatch");
      return false;
    }

    if (!responseContent.identityProof) {
      console.warn("No identity proof found for smart account");
      return false;
    }

    return verifyEIP1271Signature(
      responseEvent.responder,
      responseContent.identityProof.message,
      responseContent.identityProof.signature,
      provider
    );
  } catch (err) {
    console.error("verifySmartAccountHandshakeResponse error:", err);
    return false;
  }
}