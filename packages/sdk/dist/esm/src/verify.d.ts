import { JsonRpcProvider } from "ethers";
import { HandshakeLog, HandshakeResponseLog } from "./types.js";
/**
 * handshake verification with mandatory derivation proof
 */
export declare function verifyHandshakeIdentity(handshakeEvent: HandshakeLog, provider: JsonRpcProvider): Promise<boolean>;
/**
 * handshake response verification with mandatory derivation proof
 */
export declare function verifyHandshakeResponseIdentity(responseEvent: HandshakeResponseLog, responderIdentityPubKey: Uint8Array, initiatorEphemeralSecretKey: Uint8Array, provider: JsonRpcProvider): Promise<boolean>;
export declare function verifyAndExtractHandshakeKeys(handshakeEvent: HandshakeLog, provider: JsonRpcProvider): Promise<{
    isValid: boolean;
    keys?: {
        identityPubKey: Uint8Array;
        signingPubKey: Uint8Array;
    };
}>;
export declare function verifyAndExtractHandshakeResponseKeys(responseEvent: HandshakeResponseLog, initiatorEphemeralSecretKey: Uint8Array, provider: JsonRpcProvider): Promise<{
    isValid: boolean;
    keys?: {
        identityPubKey: Uint8Array;
        signingPubKey: Uint8Array;
        ephemeralPubKey: Uint8Array;
        note?: string;
    };
}>;
//# sourceMappingURL=verify.d.ts.map