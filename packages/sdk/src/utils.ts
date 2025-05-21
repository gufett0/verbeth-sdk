import { 
  getBytes, 
  Transaction, 
  SigningKey, 
  Contract,
  JsonRpcProvider
} from "ethers";
import { convertPublicKeyToX25519 } from './utils/x25519';

/**
 * Generalized EIP-1271 signature verification
 * Checks if a smart contract validates a signature according to EIP-1271
 */
export async function verifyEIP1271Signature(
  contractAddress: string,
  messageHash: string,
  signature: string,
  provider: JsonRpcProvider
): Promise<boolean> {
  try {
    const accountContract = new Contract(
      contractAddress,
      ["function isValidSignature(bytes32, bytes) external view returns (bytes4)"],
      provider
    );

    const result = await accountContract.isValidSignature(messageHash, signature);
    return result === "0x1626ba7e"; 
  } catch (err) {
    console.error("EIP-1271 verification error:", err);
    return false;
  }
}

/**
 * Checks if an address is a smart contract
 * Returns true if the address has deployed code
 */
export async function isSmartContract(
  address: string, 
  provider: JsonRpcProvider
): Promise<boolean> {
  try {
    const code = await provider.getCode(address);
    return code !== "0x";
  } catch (err) {
    console.error("Error checking if address is smart contract:", err);
    return false;
  }
}

/**
 * Verifies that an identity public key matches the signer of a transaction
 * Useful for verifying EOA identity in handshakes/responses
 */
export function verifyEOAIdentity(
  rawTxHex: string,
  expectedIdentityPubKey: Uint8Array
): boolean {
  try {
    if (!rawTxHex || rawTxHex.trim() === "" || rawTxHex === "0x") {
      return false;
    }

    const parsedTx = Transaction.from(rawTxHex);
    const digest = parsedTx.unsignedHash;
    const sig = parsedTx.signature;

    if (!sig) {
      throw new Error("Invalid or missing signature in parsed transaction");
    }

    const secpPubKey = SigningKey.recoverPublicKey(digest, sig);
    if (!secpPubKey || !secpPubKey.startsWith("0x04")) {
      throw new Error("Invalid or missing public key in parsed transaction");
    }

    const pubkeyBytes = getBytes(secpPubKey).slice(1);
    if (pubkeyBytes.length !== 64) {
      throw new Error(
        `Expected 64 bytes after removing prefix, got ${pubkeyBytes.length}`
      );
    }

    const derivedX25519 = convertPublicKeyToX25519(pubkeyBytes);
    
    return Buffer.from(derivedX25519).equals(Buffer.from(expectedIdentityPubKey));
  } catch (err) {
    if (rawTxHex && rawTxHex.trim() !== "" && rawTxHex !== "0x") {
      console.error("verifyEOAIdentity error:", err);
    }
    return false;
  }
}