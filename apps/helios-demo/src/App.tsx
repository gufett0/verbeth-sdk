import { useEffect, useRef, useState } from "react";

// Declare a custom type for window.ethereum
declare global {
    interface Window {
        ethereum?: any;
    }
}
import nacl from "tweetnacl";
import { Contract, BrowserProvider, JsonRpcSigner, toUtf8Bytes } from "ethers";
import { sendEncryptedMessage } from "@verbeth/sdk";
import { useHelios } from "./helios.js";
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";
// ABI minimale con solo sendMessage
const ABI = [
    "function sendMessage(bytes ciphertext, bytes32 topic, uint256 timestamp, uint256 nonce)"
];
const LOGCHAIN_ADDR = "0xf9fe7E57459CC6c42791670FaD55c1F548AE51E8"; 

export default function App() {
    const readProvider = useHelios();
    const [metaProvider, setMeta] = useState<BrowserProvider | null>(null);
    const [signer, setSigner] = useState<JsonRpcSigner | null>(null);
    const [address, setAddress] = useState<string>("");
    const [ready, setReady] = useState(false);
    const [msg, setMsg] = useState("");
    const logRef = useRef<HTMLTextAreaElement | null>(null);

    // chiavi dimostrative 
    const senderSign = nacl.sign.keyPair();
    const recipient = nacl.box.keyPair();  // fingi sia Bob

    useEffect(() => {
        if (!readProvider) return;

        (async () => {
            const meta = new BrowserProvider(window.ethereum as any);
            // chiede account al wallet
            await meta.send("eth_requestAccounts", []);

            const s = await meta.getSigner();
            const addr = await s.getAddress();

            setMeta(meta);
            setSigner(s);
            setAddress(addr);
            setReady(true);
        })();
    }, [readProvider]);

    async function handleSend() {
        if (!readProvider || !signer) return;

        // // 1. costruisci la tx offline
        // const contractForPop = new Contract(LOGCHAIN_ADDR, ABI, signer);
        // const txReq = await contractForPop.populateTransaction.sendMessage(/* … */);

        // // 2. firma con il wallet
        // const rawTx = await signer.signTransaction(txReq); // deve essere supportato!

        // // 3. trasmetti via Helios (readProvider)
        // const txResp = await readProvider.broadcastTransaction(rawTx);
        // await txResp.wait();

        // senno faccio passare la tx dal RPC di MetaMask
        const contract = new Contract(LOGCHAIN_ADDR, ABI, signer) as unknown as LogChainV1;

        await sendEncryptedMessage({
            contract,
            topic: "0x" + "00".repeat(32),         
            message: msg,
            recipientPubKey: recipient.publicKey,
            senderAddress: await signer.getAddress(),
            senderSignKeyPair: senderSign,
            timestamp: Math.floor(Date.now() / 1000)
        });

        logRef.current!.value += `✓ sent: ${msg}\n`;
        setMsg("");
    }

    return (
        <div className="min-h-screen flex flex-col items-center gap-4 p-6">
            <h1 className="text-2xl font-bold">Helios × VerbEth demo</h1>

            {/* Display connected MetaMask address */}
            <div className="w-full max-w-xl p-3 bg-gray-100 rounded-lg border">
                <div className="text-sm text-gray-600 mb-1">Connected Account:</div>
                {address ? (
                    <div className="font-mono text-sm break-all bg-white p-2 rounded border">
                        {address}
                    </div>
                ) : (
                    <div className="text-gray-400 italic">Not connected</div>
                )}
            </div>

            <textarea
                ref={logRef}
                className="w-full max-w-xl h-48 p-2 bg-white rounded shadow"
                readOnly
            />

            <input
                className="w-full max-w-xl p-2 border rounded"
                placeholder="scrivi un messaggio"
                value={msg}
                onChange={(e) => setMsg(e.target.value)}
            />

            <button
                onClick={handleSend}
                disabled={!ready || !msg}
                className="px-4 py-2 bg-blue-600 text-white rounded disabled:opacity-50"
            >
                {ready ? "Invia cifrato" : "Sync…"}
            </button>
        </div>
    );
}