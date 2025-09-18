// packages/sdk/src/verify.ts
import { JsonRpcProvider, getAddress, hexlify } from "ethers";
import { decryptAndExtractHandshakeKeys } from "./crypto.js";
import { HandshakeLog, HandshakeResponseLog, IdentityProof } from "./types.js";
import { parseHandshakePayload, parseHandshakeKeys } from "./payload.js";
import {
  isSmartContract1271,
  hasERC6492Suffix,
  Rpcish,
  makeViemPublicClient,
  parseBindingMessage,
} from "./utils.js";

// ============= Handshake Verification =============

/**
 * handshake verification with mandatory identity proof
 */
export async function verifyHandshakeIdentity(
  handshakeEvent: HandshakeLog,
  provider: JsonRpcProvider
): Promise<boolean> {
  try {
    let plaintextPayload = handshakeEvent.plaintextPayload;

    if (
      typeof plaintextPayload === "string" &&
      plaintextPayload.startsWith("0x")
    ) {
      try {
        const bytes = new Uint8Array(
          Buffer.from(plaintextPayload.slice(2), "hex")
        );
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

    // // 6492 awareness
    // const dp: any = content.identityProof;
    // const sigPrimary: string = dp.signature;
    // const sig6492: string | undefined = dp.signature6492 ?? dp.erc6492;
    // const uses6492 = hasERC6492Suffix(sigPrimary) || !!sig6492;

    // const isContract1271 = await isSmartContract1271(handshakeEvent.sender, provider);

    return await verifyIdentityProof(
      content.identityProof,
      handshakeEvent.sender,
      parsedKeys,
      provider
    );
  } catch (err) {
    console.error("verifyHandshakeIdentity error:", err);
    return false;
  }
}

// ============= HandshakeResponse Verification =============

/**
 * handshake response verification with mandatory identity proof
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
    if (
      !Buffer.from(extractedResponse.identityPubKey).equals(
        Buffer.from(responderIdentityPubKey)
      )
    ) {
      console.error("Identity public key mismatch in handshake response");
      return false;
    }

    // 6492 awareness
    const dpAny: any = extractedResponse.identityProof;
    if (!dpAny) {
      console.error("Missing identityProof in handshake response payload");
      return false;
    }
    // const sigPrimary: string = dpAny.signature;
    // const sig6492: string | undefined = dpAny.signature6492 ?? dpAny.erc6492;
    // const uses6492 = hasERC6492Suffix(sigPrimary) || !!sig6492;

    // const isContract1271 = await isSmartContract1271(responseEvent.responder,provider);

    const expectedKeys = {
      identityPubKey: extractedResponse.identityPubKey,
      signingPubKey: extractedResponse.signingPubKey,
    };

    return await verifyIdentityProof(
      extractedResponse.identityProof,
      responseEvent.responder,
      expectedKeys,
      provider
    );
  } catch (err) {
    console.error("verifyHandshakeResponseIdentity error:", err);
    return false;
  }
}

/**
 * Verifica "IdentityProof" per EOA e smart accounts.
 * - Verifica la firma con viem (EOA / ERC-1271 / ERC-6492).
 * - Parsa e confronta Address e pk attese con il contenuto del message.
 */
export async function verifyIdentityProof(
  identityProof: IdentityProof,
  smartAccountAddress: string,
  expectedUnifiedKeys: {
    identityPubKey: Uint8Array; // X25519 (nacl.box)
    signingPubKey: Uint8Array; // Ed25519 (nacl.sign)
  },
  provider: Rpcish
): Promise<boolean> {
  try {
    const client = await makeViemPublicClient(provider);
    const address = smartAccountAddress as `0x${string}`;

    // 1) Verifica firma sul binding message
    const okSig = await client.verifyMessage({
      address,
      message: identityProof.message,
      signature: identityProof.signature as `0x${string}`,
    });
    if (!okSig) {
      console.error("Binding signature invalid for address");
      return false;
    }

    // 2) Parsare il message e confrontare i campi attesi
    const parsed = parseBindingMessage(identityProof.message);

    // Header opzionale ma utile
    if (parsed.header && parsed.header !== "VerbEth Key Binding v1") {
      console.error("Unexpected binding header:", parsed.header);
      return false;
    }

    // Address nel messaggio deve combaciare

    if (
      !parsed.address ||
      getAddress(parsed.address) !== getAddress(smartAccountAddress)
    ) {
      console.error("Binding message address mismatch");
      return false;
    }

    // Confronto chiavi pubbliche
    const expectedPkX = hexlify(
      expectedUnifiedKeys.identityPubKey
    ) as `0x${string}`;
    const expectedPkEd = hexlify(
      expectedUnifiedKeys.signingPubKey
    ) as `0x${string}`;

    if (!parsed.pkX25519 || hexlify(parsed.pkX25519) !== expectedPkX) {
      console.error("PkX25519 mismatch");
      return false;
    }
    if (!parsed.pkEd25519 || hexlify(parsed.pkEd25519) !== expectedPkEd) {
      console.error("PkEd25519 mismatch");
      return false;
    }

    // 3) (opzionali) enforce di context/version, se le hai incluse
    if (parsed.context && parsed.context !== "verbeth") {
      console.error("Unexpected context:", parsed.context);
      return false;
    }
    if (parsed.version && parsed.version !== "1") {
      console.error("Unexpected version:", parsed.version);
      return false;
    }

    // (opzionale) chainId/rpId checks se presenti nel tuo message
    // if (typeof parsed.chainId === 'number' && parsed.chainId !== currentChainId) return false;

    return true;
  } catch (err) {
    console.error("verifyIdentityProof error:", err);
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
    keys: parsedKeys,
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
      note: extractedResponse.note,
    },
  };
}
