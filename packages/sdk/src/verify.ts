// packages/sdk/src/verify.ts
import { 
  JsonRpcProvider
} from "ethers";
import { decryptAndExtractHandshakeKeys } from "./crypto.js";
import { HandshakeLog, HandshakeResponseLog } from "./types.js";
import { parseHandshakePayload, parseHandshakeKeys } from "./payload.js";
import { 
  verifyEOADerivationProof, 
  verifySmartAccountDerivationProof, 
  isSmartContract 
} from "./utils.js";

// ============= Handshake Verification =============

/**
 * handshake verification with mandatory derivation proof
 */
export async function verifyHandshakeIdentity(
  handshakeEvent: HandshakeLog,
  provider: JsonRpcProvider
): Promise<boolean> {
  try {
    let plaintextPayload = handshakeEvent.plaintextPayload;
    
    if (typeof plaintextPayload === 'string' && plaintextPayload.startsWith('0x')) {
      try {
        const bytes = new Uint8Array(Buffer.from(plaintextPayload.slice(2), 'hex'));
        plaintextPayload = new TextDecoder().decode(bytes);
      } catch (err) {
        console.error("Failed to decode hex payload:", err);
        return false;
      }
    }
    
    const content = parseHandshakePayload(plaintextPayload);
    
    const parsedKeys = parseHandshakeKeys(handshakeEvent);
    if (!parsedKeys) {
      console.error("Failed to parse unified pubKeys from handshake event");
      return false;
    }
    
    const isContract = await isSmartContract(handshakeEvent.sender, provider);
    
    if (isContract) {
      return await verifySmartAccountDerivationProof(
        content.derivationProof,
        handshakeEvent.sender,
        parsedKeys,
        provider
      );
    } else {
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
 * handshake response verification with mandatory derivation proof
 */
export async function verifyHandshakeResponseIdentity(
  responseEvent: HandshakeResponseLog,
  responderIdentityPubKey: Uint8Array,
  initiatorEphemeralSecretKey: Uint8Array,
  provider: JsonRpcProvider
): Promise<boolean> {
  try {
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

    const isContract = await isSmartContract(responseEvent.responder, provider);

    const expectedKeys = {
      identityPubKey: extractedResponse.identityPubKey,
      signingPubKey: extractedResponse.signingPubKey
    };
    
    if (isContract) {
      return await verifySmartAccountDerivationProof(
        extractedResponse.derivationProof,
        responseEvent.responder,
        expectedKeys,
        provider
      );
    } else {
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