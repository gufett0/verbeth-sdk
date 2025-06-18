import { useEffect, useRef, useState, useCallback } from "react";
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount, useWalletClient } from 'wagmi';
import { WalletClient } from 'viem';
import nacl from "tweetnacl";
import { Contract, BrowserProvider, AbiCoder } from "ethers";
import { useHelios } from "./helios";
import { MessageInput } from "./components/MessageInput";
import { ConversationList } from "./components/ConversationList";
import { ConversationView } from "./components/ConversationView";
import { useMessageListener } from './hooks/useMessageListener';
import { useConversationManager } from './hooks/useConversationManager';
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";
import { deriveIdentityKeyFromAddress } from './utils/keyDerivation';
import {
    encodeHandshakePayload,
    decodeHandshakePayload,
    decryptHandshakeResponse,
    parseHandshakePayload
} from '@verbeth/sdk';

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
            walletClient={walletClient}
            onMessageSent={onMessageSent}
            onError={onError}
            disabled={disabled}
        />
    );
}

// Conversation View Wrapper
function ConversationViewWrapper({
    walletClient,
    senderAddress,
    senderSignKeyPair,
    recipientAddress,
    onClose,
    onError
}: {
    walletClient: WalletClient;
    senderAddress: string;
    senderSignKeyPair: nacl.SignKeyPair;
    recipientAddress: string;
    onClose: () => void;
    onError: (error: any) => void;
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
                <p className="text-gray-600">Loading conversation...</p>
            </div>
        );
    }

    return (
        <ConversationView
            contract={contract}
            senderAddress={senderAddress}
            senderSignKeyPair={senderSignKeyPair}
            recipientAddress={recipientAddress}
            walletClient={walletClient}
            onClose={onClose}
            onError={onError}
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
    const [openConversation, setOpenConversation] = useState<string | null>(null);
    const [pendingHandshakes, setPendingHandshakes] = useState<any[]>([]);
    const logRef = useRef<HTMLTextAreaElement | null>(null);

    // Demo cryptographic keys (in production, derive from wallet)
    const senderSign = nacl.sign.keyPair();

    // Get conversation manager hook
    const { respondToIncomingHandshake, processHandshakeResponse } = useConversationManager();

    useEffect(() => {
        setReady(readProvider !== null && isConnected && walletClient !== undefined);
    }, [readProvider, isConnected, walletClient]);

    // Clean up handshakes when address changes
    useEffect(() => {
        if (address) {
            // Load handshakes for the new address
            try {
                const stored = localStorage.getItem(`verbeth_handshakes_${address.toLowerCase()}`);
                const handshakes = stored ? JSON.parse(stored) : [];

                // Filter out old handshakes (older than 24 hours)
                const now = Date.now();
                const dayInMs = 24 * 60 * 60 * 1000;
                const recentHandshakes = handshakes.filter((h: any) => (now - h.timestamp) < dayInMs);

                setPendingHandshakes(recentHandshakes);

                // Update localStorage if we filtered out old ones
                if (recentHandshakes.length !== handshakes.length) {
                    if (recentHandshakes.length === 0) {
                        localStorage.removeItem(`verbeth_handshakes_${address.toLowerCase()}`);
                    } else {
                        localStorage.setItem(`verbeth_handshakes_${address.toLowerCase()}`, JSON.stringify(recentHandshakes));
                    }
                }
            } catch (error) {
                console.warn('Failed to load handshakes for new address:', error);
                setPendingHandshakes([]);
            }
        } else {
            setPendingHandshakes([]);
        }
    }, [address]);

    // Save handshakes to localStorage when they change
    useEffect(() => {
        if (address && pendingHandshakes.length > 0) {
            try {
                localStorage.setItem(`verbeth_handshakes_${address.toLowerCase()}`, JSON.stringify(pendingHandshakes));
            } catch (error) {
                console.warn('Failed to save handshakes to localStorage:', error);
            }
        }
    }, [pendingHandshakes, address]);

    // Message listener hook with stable callbacks
    const handleIncomingMessage = useCallback((message: any) => {
        console.log('📨 Incoming message:', message);
        if (logRef.current) {
            const timestamp = new Date().toLocaleTimeString();
            logRef.current.value += `[${timestamp}] 📨 Received message from ${message.sender}\n`;
            logRef.current.scrollTop = logRef.current.scrollHeight;
        }
    }, []);

    const handleIncomingHandshake = useCallback((handshake: any) => {
        console.log('🤝 Incoming handshake:', handshake);

        // Check if we already have this handshake to avoid duplicates
        setPendingHandshakes(prev => {
            const exists = prev.some(h => h.transactionHash === handshake.transactionHash);
            if (exists) {
                console.log('🔄 Handshake already processed, skipping...');
                return prev;
            }
            return [...prev, handshake];
        });

        if (logRef.current) {
            const timestamp = new Date().toLocaleTimeString();
            logRef.current.value += `[${timestamp}] 🤝 Received handshake from ${handshake.sender}: "${handshake.plaintextPayload}"\n`;
            logRef.current.scrollTop = logRef.current.scrollHeight;
        }
    }, []);

    const handleIncomingHandshakeResponse = useCallback(async (response: any) => {
        console.log('📧 Incoming handshake response:', response);

        if (!walletClient || !address) {
            console.warn('Wallet not ready for processing handshake response');
            return;
        }

        try {
            const success = await processHandshakeResponse(
                response,
                walletClient,
                address,
                readProvider || undefined // Pass readProvider for verification
            );

            if (success) {
                if (logRef.current) {
                    const timestamp = new Date().toLocaleTimeString();
                    logRef.current.value += `[${timestamp}] ✅ Handshake response processed from ${response.responder}\n`;
                    logRef.current.scrollTop = logRef.current.scrollHeight;
                }
            } else {
                if (logRef.current) {
                    const timestamp = new Date().toLocaleTimeString();
                    logRef.current.value += `[${timestamp}] ❌ Failed to process handshake response from ${response.responder}\n`;
                    logRef.current.scrollTop = logRef.current.scrollHeight;
                }
            }
        } catch (error) {
            console.error('Error processing handshake response:', error);
            if (logRef.current) {
                const timestamp = new Date().toLocaleTimeString();
                logRef.current.value += `[${timestamp}] ❌ Error processing handshake response: ${error instanceof Error ? error.message : String(error)}\n`;
                logRef.current.scrollTop = logRef.current.scrollHeight;
            }
        }
    }, [processHandshakeResponse, walletClient, address, readProvider]);

    useMessageListener({
        readProvider,
        userAddress: address || null,
        onIncomingMessage: handleIncomingMessage,
        onIncomingHandshake: handleIncomingHandshake,
        onIncomingHandshakeResponse: handleIncomingHandshakeResponse // NEW
    });

    // Component for handshake card with custom response
    const HandshakeCard = ({ handshake, onAccept }: { handshake: any, onAccept: (handshake: any, response: string) => Promise<void> }) => {
        const [responseMessage, setResponseMessage] = useState("Hello! Nice to meet you 👋");
        const [isResponding, setIsResponding] = useState(false);

        const handleAccept = async () => {
            setIsResponding(true);
            try {
                await onAccept(handshake, responseMessage);
            } catch (error) {
                console.error('Failed to accept handshake:', error);
            } finally {
                setIsResponding(false);
            }
        };

        return (
            <div className="bg-white rounded-lg p-4 border border-yellow-200">
                <div className="space-y-3">
                    <div>
                        <p className="font-medium text-gray-900">From: {handshake.sender}</p>
                        <p className="text-sm text-gray-600">Message: "{handshake.plaintextPayload}"</p>
                        <p className="text-sm text-gray-500">Block: {handshake.blockNumber}</p>
                    </div>

                    <div>
                        <label htmlFor={`response-${handshake.transactionHash}`} className="block text-sm font-medium text-gray-700 mb-1">
                            Your Response:
                        </label>
                        <textarea
                            id={`response-${handshake.transactionHash}`}
                            rows={2}
                            className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-green-500 focus:border-green-500"
                            placeholder="Type your response message..."
                            value={responseMessage}
                            onChange={(e) => setResponseMessage(e.target.value)}
                            disabled={isResponding}
                        />
                    </div>

                    <div className="flex justify-end space-x-2">
                        <button
                            onClick={handleAccept}
                            disabled={isResponding || !responseMessage.trim()}
                            className="bg-green-600 text-white px-4 py-2 rounded-md text-sm hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
                        >
                            {isResponding && (
                                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                            )}
                            <span>{isResponding ? 'Responding...' : 'Accept & Respond'}</span>
                        </button>
                    </div>
                </div>
            </div>
        );
    };

    // Function to accept handshake with custom response message
    const acceptHandshake = useCallback(async (handshake: any, responseMessage: string) => {
    if (!walletClient || !ready || !address) return;

    try {
        // Check if handshake was verified during initial processing
        if (handshake.verified === false) {
            console.warn('⚠️ Attempting to accept unverified handshake');
            if (logRef.current) {
                const timestamp = new Date().toLocaleTimeString();
                logRef.current.value += `[${timestamp}] ⚠️ Warning: Accepting unverified handshake from ${handshake.sender}\n`;
                logRef.current.scrollTop = logRef.current.scrollHeight;
            }
        } else if (handshake.verified === true) {
            console.log('✅ Processing verified handshake');
        } else {
            console.log('⚠️ Handshake verification status unknown (legacy format)');
        }

        const provider = new BrowserProvider({
            request: async ({ method, params }) => {
                return await walletClient.request({ method: method as any, params });
            }
        });
        const signer = await provider.getSigner();
        const contract = new Contract(LOGCHAIN_ADDR, ABI, signer) as unknown as LogChainV1;

        console.log('Debug handshake object:', {
            handshake,
            hasHandshakeContent: !!handshake.handshakeContent,
            identityPubKey: handshake.identityPubKey,
            identityPubKeyType: typeof handshake.identityPubKey,
            verified: handshake.verified
        });

        // Use handshake data parsed by SDK
        let identityPubKey: Uint8Array;
        
        if (Array.isArray(handshake.identityPubKey)) {
            identityPubKey = new Uint8Array(handshake.identityPubKey);
        } else if (handshake.identityPubKey instanceof Uint8Array) {
            identityPubKey = handshake.identityPubKey;
        } else if (typeof handshake.identityPubKey === 'string') {
            // Handle hex string (most common case)
            const hexString = handshake.identityPubKey.startsWith('0x') 
                ? handshake.identityPubKey.slice(2) 
                : handshake.identityPubKey;
            identityPubKey = new Uint8Array(
                hexString.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []
            );
        } else {
            throw new Error(`Unsupported identityPubKey type: ${typeof handshake.identityPubKey}`);
        }

        // Validate key length
        if (identityPubKey.length !== 32) {
            throw new Error(`Invalid key length: ${identityPubKey.length}, expected 32 bytes`);
        }

        console.log('Accepting handshake with:', {
            sender: handshake.sender,
            identityPubKey: Array.from(identityPubKey),
            length: identityPubKey.length,
            plaintextPayload: handshake.plaintextPayload,
            responseMessage,
            verified: handshake.verified
        });

        await respondToIncomingHandshake({
            contract,
            inResponseTo: handshake.transactionHash,
            initiatorAddress: handshake.sender,
            initiatorPubKey: identityPubKey,
            responseMessage: responseMessage,
            walletClient: walletClient,
            responderAddress: address
        });

        // Remove from pending handshakes and update localStorage
        setPendingHandshakes(prev => {
            const updated = prev.filter(h => h.transactionHash !== handshake.transactionHash);
            // Update localStorage immediately
            if (address) {
                try {
                    if (updated.length === 0) {
                        localStorage.removeItem(`verbeth_handshakes_${address.toLowerCase()}`);
                    } else {
                        localStorage.setItem(`verbeth_handshakes_${address.toLowerCase()}`, JSON.stringify(updated));
                    }
                } catch (error) {
                    console.warn('Failed to update localStorage:', error);
                }
            }
            return updated;
        });

        if (logRef.current) {
            const timestamp = new Date().toLocaleTimeString();
            const verificationStatus = handshake.verified === true ? '✅ (verified)' : 
                                     handshake.verified === false ? '⚠️ (unverified)' : '❓ (unknown)';
            logRef.current.value += `[${timestamp}] ✅ Responded to handshake ${verificationStatus} from ${handshake.sender}: "${responseMessage}"\n`;
            logRef.current.scrollTop = logRef.current.scrollHeight;
        }
    } catch (error) {
        console.error('Failed to accept handshake:', error);
        if (logRef.current) {
            const timestamp = new Date().toLocaleTimeString();
            const errorMessage = error instanceof Error ? error.message : String(error);
            logRef.current.value += `[${timestamp}] ❌ Failed to accept handshake: ${errorMessage}\n`;
            logRef.current.scrollTop = logRef.current.scrollHeight;
        }
    }
}, [walletClient, ready, respondToIncomingHandshake, address]);

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
                <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
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

            {/* MAIN: layout a tre colonne quando una conversazione è aperta */}
            <main className="max-w-7xl mx-auto px-4 py-8">
                <div className={`grid gap-6 ${openConversation ? 'grid-cols-1 lg:grid-cols-3' : 'grid-cols-1 lg:grid-cols-2'}`}>
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

                        {/* PENDING HANDSHAKES SECTION */}
                        {pendingHandshakes.length > 0 && (
                            <div className="bg-yellow-50 rounded-xl border border-yellow-200 p-6">
                                <h2 className="text-lg font-semibold text-yellow-900 mb-4">
                                    🤝 Pending Handshakes ({pendingHandshakes.length})
                                </h2>
                                <div className="space-y-4">
                                    {pendingHandshakes.map((handshake) => (
                                        <HandshakeCard
                                            key={`${handshake.transactionHash}-${handshake.blockNumber}`}
                                            handshake={handshake}
                                            onAccept={acceptHandshake}
                                        />
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* CONVERSATION LIST */}
                        <ConversationList
                            selectedRecipient={selectedRecipient}
                            onRecipientSelect={(recipient) => {
                                setSelectedRecipient(recipient);
                                // Open conversation view if recipient selected
                                if (recipient) {
                                    setOpenConversation(recipient);
                                }
                            }}
                        />
                    </div>

                    {/* MIDDLE COLUMN - Conversation View */}
                    {openConversation && ready && address && walletClient && (
                        <div className="lg:col-span-1">
                            <ConversationViewWrapper
                                senderAddress={address}
                                senderSignKeyPair={senderSign}
                                recipientAddress={openConversation}
                                walletClient={walletClient}
                                onClose={() => setOpenConversation(null)}
                                onError={handleError}
                            />
                        </div>
                    )}

                    {/* RIGHT COLUMN - Legacy messaging + Log */}
                    <div className="space-y-6">
                        {/* LEGACY MESSAGING (solo se non c'è conversazione aperta) */}
                        {!openConversation && (
                            <>
                                {selectedRecipient && ready && address && walletClient ? (
                                    <MessageInputWrapper
                                        senderAddress={address}
                                        senderSignKeyPair={senderSign}
                                        recipientAddress={selectedRecipient}
                                        walletClient={walletClient}
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
                            </>
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
                    </div>
                </div>
            </main>
        </div>
    );
}