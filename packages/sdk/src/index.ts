export * from './crypto';
export * from './payload';
export * from './send';
export * from './verify';
export * from './types';
export * from './deduplication';
export * from './utils';
export * from './identity';

// Convenience re-exports
export { decryptMessage as decryptLog } from './crypto';

// 🆕 New unified keys specific exports
export {
  encodeUnifiedPubKeys,
  decodeUnifiedPubKeys,
  createHandshakePayload,
  createHandshakeResponseContent,
  extractKeysFromHandshakePayload,
  extractKeysFromHandshakeResponse,
  parseHandshakeKeys,
  migrateLegacyHandshakeLog,
  LegacyHandshakeLog
} from './payload';

export {
  decryptAndExtractHandshakeKeys
} from './crypto';

// 🆕 New derivation proof verification exports
export {
  verifyDerivationProof,
  verifyEOADerivationProof,
  verifySmartAccountDerivationProof
} from './utils';

export {
  verifyAndExtractHandshakeKeys,
  verifyAndExtractHandshakeResponseKeys
} from './verify';

// 🆕 New identity derivation with proof
export {
  deriveIdentityKeyPairWithProof
} from './identity';