import { useEffect, useRef, useState } from "react";

// Declare a custom type for window.ethereum
declare global {
    interface Window {
        ethereum?: any;
    }
}
import nacl from "tweetnacl";
import { Contract, BrowserProvider, JsonRpcSigner } from "ethers";
import { sendEncryptedMessage, initiateHandshake } from "@verbeth/sdk";
import { useHelios } from "./helios.js";
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";
// ABI minimale necessario per l'invio di messaggi e handshake
const ABI = [
    "function sendMessage(bytes ciphertext, bytes32 topic, uint256 timestamp, uint256 nonce)",
    "function initiateHandshake(bytes32 recipientHash, bytes identityPubKey, bytes ephemeralPubKey, bytes plaintextPayload)",
    "function respondToHandshake(bytes32 inResponseTo, bytes ciphertext)"
];
const LOGCHAIN_ADDR = "0xf9fe7E57459CC6c42791670FaD55c1F548AE51E8"; 

export default function App() {
    const readProvider = useHelios();
    const [metaProvider, setMeta] = useState<BrowserProvider | null>(null);
    const [signer, setSigner] = useState<JsonRpcSigner | null>(null);
    const [address, setAddress] = useState<string>("");
    const [ready, setReady] = useState(false);
    const [msg, setMsg] = useState("");
    const [mode, setMode] = useState<"send" | "handshake">("send");
    const [recipientPubKeyHex, setRecipientPubKeyHex] = useState("0x");
    const [handshakeAddress, setHandshakeAddress] = useState("");
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

        const contract = new Contract(LOGCHAIN_ADDR, ABI, signer) as unknown as LogChainV1;

        if (mode === "send") {
            const cleanHex = recipientPubKeyHex.trim().replace(/^0x/, "");
            const pubKey = Buffer.from(cleanHex, "hex");
            await sendEncryptedMessage({
                contract,
                topic: "0x" + "00".repeat(32),
                message: msg,
                recipientPubKey: pubKey,
                senderAddress: await signer.getAddress(),
                senderSignKeyPair: senderSign,
                timestamp: Math.floor(Date.now() / 1000)
            });
            logRef.current!.value += `✓ sent: ${msg}\n`;
        } else {
            const identity = nacl.box.keyPair();
            const ephemeral = nacl.box.keyPair();
            await initiateHandshake({
                contract,
                recipientAddress: handshakeAddress.trim(),
                identityPubKey: identity.publicKey,
                ephemeralPubKey: ephemeral.publicKey,
                plaintextPayload: msg
            });
            logRef.current!.value += `✓ handshake: ${msg}\n`;
        }

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

            <select
                className="w-full max-w-xl p-2 border rounded"
                value={mode}
                onChange={(e) => setMode(e.target.value as "send" | "handshake")}
            >
                <option value="send">Invia messaggio cifrato</option>
                <option value="handshake">Inizia handshake</option>
            </select>

            {mode === "send" ? (
                <input
                    className="w-full max-w-xl p-2 border rounded"
                    placeholder="recipient pubkey (hex)"
                    value={recipientPubKeyHex}
                    onChange={(e) => setRecipientPubKeyHex(e.target.value)}
                />
            ) : (
                <input
                    className="w-full max-w-xl p-2 border rounded"
                    placeholder="recipient address"
                    value={handshakeAddress}
                    onChange={(e) => setHandshakeAddress(e.target.value)}
                />
            )}

            <input
                className="w-full max-w-xl p-2 border rounded"
                placeholder="scrivi un messaggio"
                value={msg}
                onChange={(e) => setMsg(e.target.value)}
            />

            <button
                onClick={handleSend}
                disabled={
                    !ready ||
                    !msg ||
                    (mode === "send"
                        ? recipientPubKeyHex.trim().length !== 66
                        : handshakeAddress.trim() === "")
                }
                className="px-4 py-2 bg-blue-600 text-white rounded disabled:opacity-50"
            >
                {mode === "send" ? (ready ? "Invia cifrato" : "Sync…") : (ready ? "Handshake" : "Sync…")}
            </button>
        </div>
    );
}