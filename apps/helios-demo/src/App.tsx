import { useEffect, useRef, useState } from "react";
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount, useWalletClient } from 'wagmi';
import { WalletClient } from 'viem';
import nacl from "tweetnacl";
import { Contract, BrowserProvider } from "ethers";
import { sendEncryptedMessage } from "@verbeth/sdk";
import { useHelios } from "./helios";
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";

// Minimal ABI with only sendMessage
const ABI = [
    "function sendMessage(bytes ciphertext, bytes32 topic, uint256 timestamp, uint256 nonce)"
];
const LOGCHAIN_ADDR = "0xf9fe7E57459CC6c42791670FaD55c1F548AE51E8"; 

export default function App() {
    const readProvider = useHelios();
    const { address, isConnected } = useAccount();
    const { data: walletClient } = useWalletClient();
    const [ready, setReady] = useState(false);
    const [msg, setMsg] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const logRef = useRef<HTMLTextAreaElement | null>(null);

    // Demo cryptographic keys
    const senderSign = nacl.sign.keyPair();
    const recipient = nacl.box.keyPair();

    useEffect(() => {
        setReady(readProvider !== null && isConnected && walletClient !== undefined);
    }, [readProvider, isConnected, walletClient]);

    // Convert viem WalletClient to ethers Signer for compatibility with SDK
    async function getEthersSigner(client: WalletClient) {
        const provider = new BrowserProvider({
            request: async ({ method, params }) => {
                return await client.request({ method: method as any, params });
            }
        });
        return provider.getSigner();
    }

    async function handleSend() {
        if (!readProvider || !walletClient || !address || !msg.trim()) return;

        setIsLoading(true);
        try {
            const signer = await getEthersSigner(walletClient);
            const contract = new Contract(LOGCHAIN_ADDR, ABI, signer) as unknown as LogChainV1;

            await sendEncryptedMessage({
                contract,
                topic: "0x" + "00".repeat(32),         
                message: msg,
                recipientPubKey: recipient.publicKey,
                senderAddress: address,
                senderSignKeyPair: senderSign,
                timestamp: Math.floor(Date.now() / 1000)
            });

            if (logRef.current) {
                const timestamp = new Date().toLocaleTimeString();
                logRef.current.value += `[${timestamp}] ✓ Message sent: "${msg}"\n`;
                logRef.current.scrollTop = logRef.current.scrollHeight;
            }
            setMsg("");
        } catch (error) {
            console.error("Failed to send message:", error);
            if (logRef.current) {
                const timestamp = new Date().toLocaleTimeString();
                logRef.current.value += `[${timestamp}] ✗ Error: ${error}\n`;
                logRef.current.scrollTop = logRef.current.scrollHeight;
            }
        } finally {
            setIsLoading(false);
        }
    }

    const StatusBadge = ({ status, children }: { status: 'success' | 'warning' | 'error', children: React.ReactNode }) => {
        const colors = {
            success: 'bg-green-100 text-green-800 border-green-200',
            warning: 'bg-yellow-100 text-yellow-800 border-yellow-200', 
            error: 'bg-red-100 text-red-800 border-red-200'
        };
        return (
            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${colors[status]}`}>
                {children}
            </span>
        );
    };

    return (
        <div className="min-h-screen bg-gray-50">
            {/* Header */}
            <header className="bg-white border-b border-gray-200">
                <div className="max-w-4xl mx-auto px-4 py-4 flex justify-between items-center">
                    <div className="flex items-center space-x-3">
                        <div className="w-8 h-8 bg-black rounded-lg flex items-center justify-center">
                            <span className="text-white font-bold text-sm">V</span>
                        </div>
                        <h1 className="text-xl font-semibold text-gray-900">VerbEth</h1>
                        <span className="text-sm text-gray-500">Demo</span>
                    </div>
                    <ConnectButton />
                </div>
            </header>

            {/* Main Content */}
            <main className="max-w-4xl mx-auto px-4 py-8">
                <div className="space-y-6">
                    {/* Status Card */}
                    <div className="bg-white rounded-xl border border-gray-200 p-6">
                        <h2 className="text-lg font-semibold text-gray-900 mb-4">Connection Status</h2>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div className="flex flex-col space-y-2">
                                <span className="text-sm font-medium text-gray-500">Helios Client</span>
                                <StatusBadge status={readProvider ? 'success' : 'warning'}>
                                    {readProvider ? 'Synced' : 'Syncing...'}
                                </StatusBadge>
                            </div>
                            <div className="flex flex-col space-y-2">
                                <span className="text-sm font-medium text-gray-500">Wallet</span>
                                <StatusBadge status={isConnected ? 'success' : 'error'}>
                                    {isConnected ? 'Connected' : 'Disconnected'}
                                </StatusBadge>
                            </div>
                            <div className="flex flex-col space-y-2">
                                <span className="text-sm font-medium text-gray-500">Ready</span>
                                <StatusBadge status={ready ? 'success' : 'warning'}>
                                    {ready ? 'Ready' : 'Not Ready'}
                                </StatusBadge>
                            </div>
                        </div>
                        
                        {address && (
                            <div className="mt-6 pt-4 border-t border-gray-100">
                                <span className="text-sm font-medium text-gray-500">Connected Address</span>
                                <p className="mt-1 font-mono text-sm text-gray-900 break-all bg-gray-50 p-2 rounded-lg">
                                    {address}
                                </p>
                            </div>
                        )}
                    </div>

                    {/* Send Message Card */}
                    <div className="bg-white rounded-xl border border-gray-200 p-6">
                        <h2 className="text-lg font-semibold text-gray-900 mb-4">Send Encrypted Message</h2>
                        <div className="space-y-4">
                            <div>
                                <label htmlFor="message" className="block text-sm font-medium text-gray-700 mb-2">
                                    Message
                                </label>
                                <textarea
                                    id="message"
                                    rows={4}
                                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none resize-none"
                                    placeholder="Type your encrypted message here..."
                                    value={msg}
                                    onChange={(e) => setMsg(e.target.value)}
                                    disabled={!ready}
                                />
                            </div>
                            
                            <button
                                onClick={handleSend}
                                disabled={!ready || !msg.trim() || isLoading}
                                className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white font-medium py-3 px-4 rounded-lg transition-colors flex items-center justify-center space-x-2"
                            >
                                {isLoading ? (
                                    <>
                                        <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                                        <span>Sending...</span>
                                    </>
                                ) : (
                                    <span>Send Message</span>
                                )}
                            </button>
                        </div>
                    </div>

                    {/* Activity Log Card */}
                    <div className="bg-white rounded-xl border border-gray-200 p-6">
                        <h2 className="text-lg font-semibold text-gray-900 mb-4">Transaction Log</h2>
                        <div className="relative">
                            <textarea
                                ref={logRef}
                                className="w-full h-48 px-3 py-2 border border-gray-300 rounded-lg bg-gray-50 font-mono text-sm resize-none outline-none"
                                placeholder="Transaction logs will appear here..."
                                readOnly
                            />
                        </div>
                    </div>

                    {/* Info Card */}
                    <div className="bg-blue-50 rounded-xl border border-blue-200 p-4">
                        <div className="flex items-start space-x-3">
                            <div className="flex-shrink-0">
                                <div className="w-5 h-5 bg-blue-600 rounded-full flex items-center justify-center">
                                    <span className="text-white text-xs">i</span>
                                </div>
                            </div>
                            <div className="text-sm text-blue-800">
                                <p className="font-medium mb-1">Demo Information</p>
                                <p>
                                    This demo uses throwaway cryptographic keys for encryption. 
                                    Messages are sent to Base network via Helios light client. 
                                    Production implementations should use proper key management and recipient discovery.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}