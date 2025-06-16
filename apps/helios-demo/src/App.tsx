import { useEffect, useRef, useState } from "react";
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount, useWalletClient } from 'wagmi';
import { WalletClient } from 'viem';
import nacl from "tweetnacl";
import { Contract, BrowserProvider } from "ethers";
import { useHelios } from "./helios";
import { MessageInput } from "./components/MessageInput";
import { ConversationList } from "./components/ConversationList";
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";

import { VerbEthDebugPanel } from './components/VerbEthDebugPanel';


// Wrapper component to handle async contract creation
function MessageInputWrapper({ 
    walletClient, 
    senderAddress, 
    senderSignKeyPair, 
    recipientAddress,
    onMessageSent,
    onError,
    disabled 
}: {
    walletClient: WalletClient;
    senderAddress: string;
    senderSignKeyPair: nacl.SignKeyPair;
    recipientAddress: string;
    onMessageSent: (result: any) => void;
    onError: (error: any) => void;
    disabled: boolean;
}) {
    const [contract, setContract] = useState<LogChainV1 | null>(null);

    useEffect(() => {
        async function createContract() {
            try {
                const provider = new BrowserProvider({
                    request: async ({ method, params }) => {
                        return await walletClient.request({ method: method as any, params });
                    }
                });
                const signer = await provider.getSigner();
                const contractInstance = new Contract(LOGCHAIN_ADDR, ABI, signer) as unknown as LogChainV1;
                setContract(contractInstance);
            } catch (error) {
                onError(error);
            }
        }
        createContract();
    }, [walletClient, onError]);

    if (!contract) {
        return (
            <div className="bg-gray-100 rounded-xl border-2 border-dashed border-gray-300 p-6 text-center">
                <p className="text-gray-600">Loading contract...</p>
            </div>
        );
    }

    return (
        <MessageInput
            contract={contract}
            senderAddress={senderAddress}
            senderSignKeyPair={senderSignKeyPair}
            recipientAddress={recipientAddress}
            onMessageSent={onMessageSent}
            onError={onError}
            disabled={disabled}
        />
    );
}

// Minimal ABI with required functions
const ABI = [
    "function sendMessage(bytes ciphertext, bytes32 topic, uint256 timestamp, uint256 nonce)",
    "function initiateHandshake(bytes32 recipientHash, bytes identityPubKey, bytes ephemeralPubKey, bytes plaintextPayload)",
    "function respondToHandshake(bytes32 inResponseTo, bytes ciphertext)"
];
const LOGCHAIN_ADDR = "0xf9fe7E57459CC6c42791670FaD55c1F548AE51E8"; 

export default function App() {
    const readProvider = useHelios();
    const { address, isConnected } = useAccount();
    const { data: walletClient } = useWalletClient();
    const [ready, setReady] = useState(false);
    const [selectedRecipient, setSelectedRecipient] = useState("");
    const logRef = useRef<HTMLTextAreaElement | null>(null);

    // Demo cryptographic keys (in production, derive from wallet)
    const senderSign = nacl.sign.keyPair();

    useEffect(() => {
        setReady(readProvider !== null && isConnected && walletClient !== undefined);
    }, [readProvider, isConnected, walletClient]);

    const handleMessageSent = (result: any) => {
        if (logRef.current) {
            const timestamp = new Date().toLocaleTimeString();
            const messageType = result.type === 'handshake_initiated' ? 'Handshake initiated' : 'Message sent';
            logRef.current.value += `[${timestamp}] ✓ ${messageType}\n`;
            logRef.current.scrollTop = logRef.current.scrollHeight;
        }
    };

    const handleError = (error: any) => {
        console.error("Failed to send message:", error);
        if (logRef.current) {
            const timestamp = new Date().toLocaleTimeString();
            logRef.current.value += `[${timestamp}] ✗ Error: ${error.message || error}\n`;
            logRef.current.scrollTop = logRef.current.scrollHeight;
        }
    };

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
            {/* HEADER CON LOGO E TITOLO */}
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

            {/* LOG */}
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

{/* DEBUG PANEL */}
{address && <VerbEthDebugPanel userAddress={address} />}

            {/* MAIN: due colonne, sinistra conversazioni + status, destra chat + log */}
            <main className="max-w-4xl mx-auto px-4 py-8">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* LEFT COLUMN */}
                    <div className="space-y-6">
                        {/* STATUS */}
                        <div className="bg-white rounded-xl border border-gray-200 p-6">
                            <h2 className="text-lg font-semibold text-gray-900 mb-4">Connection Status</h2>
                            <div className="grid grid-cols-2 gap-4">
                                <div className="flex flex-col space-y-2">
                                    <span className="text-sm font-medium text-gray-500">Helios Sync</span>
                                    <StatusBadge status={readProvider ? 'success' : 'error'}>
                                        {readProvider ? 'Synced' : 'Not Synced'}
                                    </StatusBadge>
                                </div>
                                <div className="flex flex-col space-y-2">
                                    <span className="text-sm font-medium text-gray-500">Wallet</span>
                                    <StatusBadge status={isConnected ? 'success' : 'error'}>
                                        {isConnected ? 'Connected' : 'Disconnected'}
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

                        {/* CONVERSATION LIST */}
                        <ConversationList
                            selectedRecipient={selectedRecipient}
                            onRecipientSelect={setSelectedRecipient}
                        />
                    </div>

                    {/* RIGHT COLUMN */}
                    <div className="space-y-6">
                        {/* MESSAGING */}
                        {selectedRecipient && ready && address && walletClient ? (
                            <MessageInputWrapper
                                walletClient={walletClient}
                                senderAddress={address}
                                senderSignKeyPair={senderSign}
                                recipientAddress={selectedRecipient}
                                onMessageSent={handleMessageSent}
                                onError={handleError}
                                disabled={!ready}
                            />
                        ) : (
                            <div className="bg-gray-100 rounded-xl border-2 border-dashed border-gray-300 p-6 text-center">
                                <p className="text-gray-600">
                                    {!ready ? "Connect wallet and wait for sync to start messaging" : "Select a recipient to start messaging"}
                                </p>
                            </div>
                        )}

                        {/* LOG */}
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

                        {/* INFO CARD */}
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
                                        This demo handles the full VerbEth conversation flow: handshake initiation, 
                                        response handling, and encrypted messaging. First messages automatically 
                                        trigger handshakes.
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}
