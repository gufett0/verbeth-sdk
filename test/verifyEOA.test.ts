import { expect } from "chai";
import { ethers, Wallet } from "../utils/ethers"; 
import { verifyHandshakeResponseIdentity } from "../src/verify";
import { convertPublicKeyToX25519 } from "../utils/x25519";
import { LogChain } from "../typechain-types";

describe("verifyHandshakeResponseIdentity (EOA)", function () {
  let logChain: LogChain;

  beforeEach(async () => {
    const factory = await ethers.getContractFactory("LogChain");
    logChain = await factory.deploy();
    await logChain.waitForDeployment();
  });

  it("correctly verifies identity for actual HandshakeResponse tx", async function () {
    // Get the first signer
    const [fundedSigner] = await ethers.getSigners();
    const provider = fundedSigner.provider!;

    // Create a random wallet and connect it to the provider
    const wallet = new Wallet(Wallet.createRandom().privateKey).connect(provider);

    // Send ETH to the wallet
    const fundTx = await fundedSigner.sendTransaction({
      to: wallet.address,
      value: ethers.parseEther("1.0"),
    });
    await fundTx.wait();

    // Verify balance is updated
    const balance = await provider.getBalance(wallet.address);
    expect(BigInt(balance.toString()) > 0n).to.be.true;

    // Derive x25519 key from signature
    const msg = "VerbEth-HSResponse-v1";
    const sig = await wallet.signMessage(msg);
    
    // Get the expanded public key
    const expandedPubKey = ethers.SigningKey.recoverPublicKey(
      ethers.hashMessage(msg),
      sig
    );
    
    // Remove the '0x04' prefix to get the raw 64-byte key
    const rawBytes = ethers.getBytes(expandedPubKey).slice(1);
    const x25519 = convertPublicKeyToX25519(rawBytes);

    // Prepare handshake parameters
    const handshakeId = ethers.keccak256(
      ethers.toUtf8Bytes("ping-alice")
    );
    const ciphertext = ethers.hexlify(ethers.randomBytes(64));

    // Instead of trying to sign and send a raw transaction, 
    // let's directly send the transaction with the wallet
    const tx = await logChain
      .connect(wallet)
      .respondToHandshake(handshakeId, ciphertext);
    
    // Wait for the transaction to be mined
    const receipt = await tx.wait();
    
    // Get the transaction details after it has been mined
    if (!receipt) {
      throw new Error("Transaction receipt is null");
    }
    const minedTx = await provider.getTransaction(receipt.hash);
    if (!minedTx) {
      throw new Error("Transaction not found");
    }
    
    // Convert transaction to serialized form for verification
    const serializedTx = ethers.Transaction.from(minedTx).serialized;
    if (!serializedTx) {
      throw new Error("Serialized transaction not available");
    }
    
    // Verify the sender's identity
    const verified = verifyHandshakeResponseIdentity(serializedTx, x25519);
    expect(verified).to.be.true;
  });
});