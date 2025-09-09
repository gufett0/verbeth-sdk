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
  isSmartContract1271,
  hasERC6492Suffix 
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

    // 6492 awareness
    const dp: any = content.derivationProof;
    const sigPrimary: string = dp.signature;                       
    const sig6492: string | undefined = dp.signature6492 ?? dp.erc6492; // optional: allow duck-typing
    const uses6492 = hasERC6492Suffix(sigPrimary) || !!sig6492;
    console.log("DEBUG verifyHSidentity - uses6492():", uses6492);
    
    const isContract1271 = await isSmartContract1271(handshakeEvent.sender, provider);
    console.log("DEBUG verifyHSidentity - isSmartContract1271():", isContract1271);
    
    if (isContract1271 || uses6492) {
      // smart-account path: verify via 1271 (deployed) OR ERC-6492 (undeployed)
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

    // 6492 awareness
    const dpAny: any = extractedResponse.derivationProof;
    if (!dpAny) {
      console.error("Missing derivationProof in handshake response payload");
      return false;
    }
    const sigPrimary: string = dpAny.signature;
    const sig6492: string | undefined = dpAny.signature6492 ?? dpAny.erc6492;
    const uses6492 = hasERC6492Suffix(sigPrimary) || !!sig6492;
    console.log("DEBUG verifyHSRESPidentity - uses6492():", uses6492);

    const isContract1271 = await isSmartContract1271(responseEvent.responder, provider);
    console.log("DEBUG verifyHSRESPidentity - isSmartContract1271():", isContract1271);

    const expectedKeys = {
      identityPubKey: extractedResponse.identityPubKey,
      signingPubKey: extractedResponse.signingPubKey
    };
    
    if (isContract1271 || uses6492) {
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