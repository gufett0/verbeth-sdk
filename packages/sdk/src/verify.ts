// packages/sdk/src/verify.ts - Mandatory derivation proof verification

import { 
  JsonRpcProvider
} from "ethers";
import { decryptAndExtractHandshakeKeys } from "./crypto";
import { HandshakeLog, HandshakeResponseLog } from "./types";
import { parseHandshakePayload, parseHandshakeKeys } from "./payload";
import { 
  verifyEOADerivationProof, 
  verifySmartAccountDerivationProof, 
  isSmartContract 
} from "./utils";

// ============= Handshake Verification =============

/**
 * 🆕 Simplified handshake verification with mandatory derivation proof
 */
export async function verifyHandshakeIdentity(
  handshakeEvent: HandshakeLog,
  provider: JsonRpcProvider
): Promise<boolean> {
  try {
    // Parse handshake payload - now always requires derivationProof
    const content = parseHandshakePayload(handshakeEvent.plaintextPayload);
    
    // Extract unified keys from event
    const parsedKeys = parseHandshakeKeys(handshakeEvent);
    if (!parsedKeys) {
      console.error("Failed to parse unified pubKeys from handshake event");
      return false;
    }
    
    // Check if sender is a smart contract
    const isContract = await isSmartContract(handshakeEvent.sender, provider);
    
    if (isContract) {
      // Smart Account verification
      return await verifySmartAccountDerivationProof(
        content.derivationProof,
        handshakeEvent.sender,
        parsedKeys,
        provider
      );
    } else {
      // EOA verification
      return verifyEOADerivationProof(
        content.derivationProof,
        handshakeEvent.sender,
        parsedKeys
      );
    }
    
  } catch (err) {
    console.error("verifyHandshakeIdentity error:", err);
    return false;
  }
}

// ============= HandshakeResponse Verification =============

/**
 * 🆕 Simplified handshake response verification with mandatory derivation proof
 */
export async function verifyHandshakeResponseIdentity(
  responseEvent: HandshakeResponseLog,
  responderIdentityPubKey: Uint8Array,
  initiatorEphemeralSecretKey: Uint8Array,
  provider: JsonRpcProvider
): Promise<boolean> {
  try {
    // Decrypt and extract handshake response
    const extractedResponse = decryptAndExtractHandshakeKeys(
      responseEvent.ciphertext,
      initiatorEphemeralSecretKey
    );

    if (!extractedResponse) {
      console.error("Failed to decrypt handshake response");
      return false;
    }

    // Verify the identity key matches expected
    if (!Buffer.from(extractedResponse.identityPubKey).equals(Buffer.from(responderIdentityPubKey))) {
      console.error("Identity public key mismatch in handshake response");
      return false;
    }

    // Check if responder is a smart contract
    const isContract = await isSmartContract(responseEvent.responder, provider);
    
    const expectedKeys = {
      identityPubKey: extractedResponse.identityPubKey,
      signingPubKey: extractedResponse.signingPubKey
    };
    
    if (isContract) {
      // Smart Account verification
      return await verifySmartAccountDerivationProof(
        extractedResponse.derivationProof,
        responseEvent.responder,
        expectedKeys,
        provider
      );
    } else {
      // EOA verification
      return verifyEOADerivationProof(
        extractedResponse.derivationProof,
        responseEvent.responder,
        expectedKeys
      );
    }
    
  } catch (err) {
    console.error("verifyHandshakeResponseIdentity error:", err);
    return false;
  }
}

// ============= Utility Functions =============

/**
 * 🆕 Convenience function to verify both handshake and extract keys
 */
export async function verifyAndExtractHandshakeKeys(
  handshakeEvent: HandshakeLog,
  provider: JsonRpcProvider
): Promise<{
  isValid: boolean;
  keys?: {
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
  };
}> {
  const isValid = await verifyHandshakeIdentity(handshakeEvent, provider);
  
  if (!isValid) {
    return { isValid: false };
  }
  
  const parsedKeys = parseHandshakeKeys(handshakeEvent);
  if (!parsedKeys) {
    return { isValid: false };
  }
  
  return {
    isValid: true,
    keys: parsedKeys
  };
}

/**
 * 🆕 Convenience function to verify handshake response and extract keys
 */
export async function verifyAndExtractHandshakeResponseKeys(
  responseEvent: HandshakeResponseLog,
  initiatorEphemeralSecretKey: Uint8Array,
  provider: JsonRpcProvider
): Promise<{
  isValid: boolean;
  keys?: {
    identityPubKey: Uint8Array;
    signingPubKey: Uint8Array;
    ephemeralPubKey: Uint8Array;
    note?: string;
  };
}> {
  const extractedResponse = decryptAndExtractHandshakeKeys(
    responseEvent.ciphertext,
    initiatorEphemeralSecretKey
  );

  if (!extractedResponse) {
    return { isValid: false };
  }

  const isValid = await verifyHandshakeResponseIdentity(
    responseEvent,
    extractedResponse.identityPubKey,
    initiatorEphemeralSecretKey,
    provider
  );
  
  if (!isValid) {
    return { isValid: false };
  }
  
  return {
    isValid: true,
    keys: {
      identityPubKey: extractedResponse.identityPubKey,
      signingPubKey: extractedResponse.signingPubKey,
      ephemeralPubKey: extractedResponse.ephemeralPubKey,
      note: extractedResponse.note
    }
  };
}