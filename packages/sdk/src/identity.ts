import { sha256 } from "@noble/hashes/sha2";
import { hkdf } from "@noble/hashes/hkdf";
import { Signer, concat, hexlify } from "ethers";
import nacl from "tweetnacl";
import { encodeUnifiedPubKeys } from "./payload.js";
import { IdentityProof } from "./types.js";

interface IdentityKeyPair {
  // X25519 keys per encryption/decryption
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  // Ed25519 keys per signing/verification
  signingPublicKey: Uint8Array;
  signingSecretKey: Uint8Array;
}

/**
 * HKDF (RFC 5869) identity key derivation.
 * Returns a proof binding the derived keypair to the wallet address.
 */
export async function deriveIdentityKeyPairWithProof(
  signer: any,
  address: string
): Promise<{
  keyPair: IdentityKeyPair;
  identityProof: {
    message: string;
    signature: string;
    messageRawHex?: `0x${string}`;
  };
}> {
  // 1) Local secret seed (32B CSPRNG), domain-separated by address
  const r = nacl.randomBytes(32);
  const enc = new TextEncoder();
  const addrLower = address.toLowerCase();

  // IKM = HKDF(r || "verbeth/addr:" || address_lower)
  // salt/info are public domain labels
  const seedSalt = enc.encode("verbeth/seed-v1");
  const seedInfo = enc.encode("verbeth/ikm");
  const ikmInput = concat([r, enc.encode("verbeth/addr:" + addrLower)]);
  const ikm = hkdf(sha256, ikmInput, seedSalt, seedInfo, 32);

  // Derive X25519 (encryption)
  const info_x25519 = enc.encode("verbeth-x25519-v1");
  const x25519_sk = hkdf(sha256, ikm, new Uint8Array(0), info_x25519, 32);
  const boxKeyPair = nacl.box.keyPair.fromSecretKey(x25519_sk);

  // Derive Ed25519 (signing)
  const info_ed25519 = enc.encode("verbeth-ed25519-v1");
  const ed25519_seed = hkdf(sha256, ikm, new Uint8Array(0), info_ed25519, 32);
  const signKeyPair = nacl.sign.keyPair.fromSeed(ed25519_seed);

  const pkX25519Hex = hexlify(boxKeyPair.publicKey);
  const pkEd25519Hex = hexlify(signKeyPair.publicKey);

  const keyPair: IdentityKeyPair = {
    publicKey: boxKeyPair.publicKey,
    secretKey: boxKeyPair.secretKey,
    signingPublicKey: signKeyPair.publicKey,
    signingSecretKey: signKeyPair.secretKey,
  };

  // 2) Single signature binding both public keys
  const bindingMsgLines = [
    "VerbEth Key Binding v1",
    `Address: ${addrLower}`,
    `PkEd25519: ${pkEd25519Hex}`,
    `PkX25519: ${pkX25519Hex}`,
    `Context: verbeth`,
    `Version: 1`,
  ];
  const message = bindingMsgLines.join("\n");

  const signature = await signer.signMessage(message);

  const messageRawHex = ("0x" +
    Buffer.from(message, "utf-8").toString("hex")) as `0x${string}`;

  return {
    keyPair,
    identityProof: {
      message,
      signature,
      messageRawHex,
    },
  };
}

export async function deriveIdentityWithUnifiedKeys(
  signer: Signer,
  address: string
): Promise<{
  identityProof: IdentityProof;
  identityPubKey: Uint8Array;
  signingPubKey: Uint8Array;
  unifiedPubKeys: Uint8Array;
}> {
  const result = await deriveIdentityKeyPairWithProof(signer, address);

  const unifiedPubKeys = encodeUnifiedPubKeys(
    result.keyPair.publicKey, // X25519
    result.keyPair.signingPublicKey // Ed25519
  );

  return {
    identityProof: result.identityProof,
    identityPubKey: result.keyPair.publicKey,
    signingPubKey: result.keyPair.signingPublicKey,
    unifiedPubKeys,
  };
}
