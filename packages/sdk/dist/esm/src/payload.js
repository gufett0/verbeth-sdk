export function parseHandshakePayload(plaintextPayload) {
    try {
        const parsed = JSON.parse(plaintextPayload);
        if (typeof parsed === 'object' && parsed.plaintextPayload && parsed.derivationProof) {
            return parsed;
        }
    }
    catch (e) {
    }
    throw new Error("Invalid handshake payload: missing derivationProof");
}
export function serializeHandshakeContent(content) {
    return JSON.stringify(content);
}
export function encodePayload(ephemeralPubKey, nonce, ciphertext, sig) {
    const payload = {
        v: 1,
        epk: Buffer.from(ephemeralPubKey).toString('base64'),
        n: Buffer.from(nonce).toString('base64'),
        ct: Buffer.from(ciphertext).toString('base64'),
        ...(sig && { sig: Buffer.from(sig).toString('base64') })
    };
    return JSON.stringify(payload);
}
export function decodePayload(json) {
    let actualJson = json;
    if (typeof json === 'string' && json.startsWith('0x')) {
        try {
            const bytes = new Uint8Array(Buffer.from(json.slice(2), 'hex'));
            actualJson = new TextDecoder().decode(bytes);
        }
        catch (err) {
            throw new Error(`Hex decode error: ${err instanceof Error ? err.message : String(err)}`);
        }
    }
    try {
        const { epk, n, ct, sig } = JSON.parse(actualJson);
        return {
            epk: Buffer.from(epk, 'base64'),
            nonce: Buffer.from(n, 'base64'),
            ciphertext: Buffer.from(ct, 'base64'),
            ...(sig && { sig: Buffer.from(sig, 'base64') })
        };
    }
    catch (parseError) {
        throw new Error(`JSON parse error: ${parseError instanceof Error ? parseError.message : String(parseError)}`);
    }
}
// Unified function for encoding any structured content as Uint8Array
export function encodeStructuredContent(content) {
    const serialized = JSON.stringify(content, (key, value) => {
        if (value instanceof Uint8Array) {
            return Buffer.from(value).toString('base64');
        }
        return value;
    });
    return new TextEncoder().encode(serialized);
}
// Unified function for decoding structured content
export function decodeStructuredContent(encoded, converter) {
    const decoded = JSON.parse(new TextDecoder().decode(encoded));
    return converter(decoded);
}
// ========== UNIFIED KEYS MANAGEMENT ==========
/**
 * Encodes X25519 + Ed25519 keys into a single 65-byte array with versioning
 */
export function encodeUnifiedPubKeys(identityPubKey, // X25519 - 32 bytes
signingPubKey // Ed25519 - 32 bytes  
) {
    const version = new Uint8Array([0x01]); // v1
    return new Uint8Array([
        ...version,
        ...identityPubKey,
        ...signingPubKey
    ]); // 65 bytes total
}
/**
 * Decodes unified pubKeys back to individual X25519 and Ed25519 keys
 */
export function decodeUnifiedPubKeys(pubKeys) {
    if (pubKeys.length === 64) {
        // Legacy
        return {
            version: 0,
            identityPubKey: pubKeys.slice(0, 32),
            signingPubKey: pubKeys.slice(32, 64)
        };
    }
    if (pubKeys.length === 65 && pubKeys[0] === 0x01) {
        // V1: with versioning
        return {
            version: 1,
            identityPubKey: pubKeys.slice(1, 33),
            signingPubKey: pubKeys.slice(33, 65)
        };
    }
    return null;
}
export function encodeHandshakePayload(payload) {
    return new TextEncoder().encode(JSON.stringify({
        unifiedPubKeys: Buffer.from(payload.unifiedPubKeys).toString('base64'),
        ephemeralPubKey: Buffer.from(payload.ephemeralPubKey).toString('base64'),
        plaintextPayload: payload.plaintextPayload
    }));
}
export function decodeHandshakePayload(encoded) {
    const json = new TextDecoder().decode(encoded);
    const parsed = JSON.parse(json);
    return {
        unifiedPubKeys: Uint8Array.from(Buffer.from(parsed.unifiedPubKeys, 'base64')),
        ephemeralPubKey: Uint8Array.from(Buffer.from(parsed.ephemeralPubKey, 'base64')),
        plaintextPayload: parsed.plaintextPayload
    };
}
export function encodeHandshakeResponseContent(content) {
    return new TextEncoder().encode(JSON.stringify({
        unifiedPubKeys: Buffer.from(content.unifiedPubKeys).toString('base64'),
        ephemeralPubKey: Buffer.from(content.ephemeralPubKey).toString('base64'),
        note: content.note,
        derivationProof: content.derivationProof
    }));
}
export function decodeHandshakeResponseContent(encoded) {
    const json = new TextDecoder().decode(encoded);
    const parsed = JSON.parse(json);
    if (!parsed.derivationProof) {
        throw new Error("Invalid handshake response: missing derivationProof");
    }
    return {
        unifiedPubKeys: Uint8Array.from(Buffer.from(parsed.unifiedPubKeys, 'base64')),
        ephemeralPubKey: Uint8Array.from(Buffer.from(parsed.ephemeralPubKey, 'base64')),
        note: parsed.note,
        derivationProof: parsed.derivationProof
    };
}
/**
 * Creates HandshakePayload from separate identity keys
 */
export function createHandshakePayload(identityPubKey, signingPubKey, ephemeralPubKey, plaintextPayload) {
    return {
        unifiedPubKeys: encodeUnifiedPubKeys(identityPubKey, signingPubKey),
        ephemeralPubKey,
        plaintextPayload
    };
}
/**
 * Creates HandshakeResponseContent from separate identity keys
 */
export function createHandshakeResponseContent(identityPubKey, signingPubKey, ephemeralPubKey, note, derivationProof) {
    if (!derivationProof) {
        throw new Error("Derivation proof is now mandatory for handshake responses");
    }
    return {
        unifiedPubKeys: encodeUnifiedPubKeys(identityPubKey, signingPubKey),
        ephemeralPubKey,
        note,
        derivationProof
    };
}
/**
 * Extracts individual keys from HandshakePayload
 */
export function extractKeysFromHandshakePayload(payload) {
    const decoded = decodeUnifiedPubKeys(payload.unifiedPubKeys);
    if (!decoded)
        return null;
    return {
        identityPubKey: decoded.identityPubKey,
        signingPubKey: decoded.signingPubKey,
        ephemeralPubKey: payload.ephemeralPubKey
    };
}
/**
 * Extracts individual keys from HandshakeResponseContent
 */
export function extractKeysFromHandshakeResponse(content) {
    const decoded = decodeUnifiedPubKeys(content.unifiedPubKeys);
    if (!decoded)
        return null;
    return {
        identityPubKey: decoded.identityPubKey,
        signingPubKey: decoded.signingPubKey,
        ephemeralPubKey: content.ephemeralPubKey
    };
}
/**
 * Parses unified pubKeys from HandshakeLog event
 */
export function parseHandshakeKeys(event) {
    try {
        // Remove '0x' prefix and convert hex to bytes
        const pubKeysBytes = new Uint8Array(Buffer.from(event.pubKeys.slice(2), 'hex'));
        const decoded = decodeUnifiedPubKeys(pubKeysBytes);
        if (!decoded)
            return null;
        return {
            identityPubKey: decoded.identityPubKey,
            signingPubKey: decoded.signingPubKey
        };
    }
    catch (error) {
        console.error('Failed to parse handshake keys:', error);
        return null;
    }
}
