import { useEffect, useRef, useState, useCallback } from "react";
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount, useWalletClient } from 'wagmi';
import { WalletClient } from 'viem';
import nacl from "tweetnacl";
import { Contract, BrowserProvider, AbiCoder } from "ethers";
import { useHelios } from "./helios";
import { MessageInput } from "./components/MessageInput";
import { ConversationList } from "./components/ConversationList";
import { useMessageListener } from './hooks/useMessageListener'; 
import { useConversationManager } from './hooks/useConversationManager'; 
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";
import { deriveIdentityKeyFromAddress } from './utils/keyDerivation';
import { encodeHandshakePayload, decodeHandshakePayload } from '@verbeth/sdk';


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
            walletClient={walletClient} 
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
    const [pendingHandshakes, setPendingHandshakes] = useState<any[]>([]); // <-- ADD THIS
    const logRef = useRef<HTMLTextAreaElement | null>(null);

    // Demo cryptographic keys (in production, derive from wallet)
    const senderSign = nacl.sign.keyPair();

    // ADD: Get conversation manager hook
    const { respondToIncomingHandshake } = useConversationManager();

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

    // ADD: Message listener hook with stable callbacks
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
        // Parse the handshake data to extract initiator pubkey
        try {
            const abiCoder = new AbiCoder();
            // Decode the event data: identityPubKey, ephemeralPubKey, plaintextPayload
            const decoded = abiCoder.decode(
                ['bytes', 'bytes', 'bytes'], 
                handshake.data
            );
            
            const [identityPubKeyBytes, ephemeralPubKeyBytes, plaintextPayloadBytes] = decoded;
            
            console.log('Decoded data:', { identityPubKeyBytes, ephemeralPubKeyBytes, plaintextPayloadBytes });
            
            // ethers AbiCoder returns hex strings for bytes, convert them properly
            let identityPubKey, ephemeralPubKey;
            
            if (typeof identityPubKeyBytes === 'string' && identityPubKeyBytes.startsWith('0x')) {
                const hexString = identityPubKeyBytes.slice(2);
                const matchResult = hexString.match(/.{2}/g);
                if (matchResult) {
                    identityPubKey = new Uint8Array(matchResult.map(byte => parseInt(byte, 16)));
                } else {
                    throw new Error("Failed to parse hex string into bytes");
                }
            } else {
                identityPubKey = identityPubKeyBytes instanceof Uint8Array 
                    ? identityPubKeyBytes 
                    : Uint8Array.from(identityPubKeyBytes);
            }
            
            if (typeof ephemeralPubKeyBytes === 'string' && ephemeralPubKeyBytes.startsWith('0x')) {
                const hexString = ephemeralPubKeyBytes.slice(2);
                const matchResult = hexString.match(/.{2}/g);
                if (matchResult) {
                    ephemeralPubKey = new Uint8Array(matchResult.map(byte => parseInt(byte, 16)));
                } else {
                    throw new Error("Failed to parse hex string into bytes");
                }
            } else {
                ephemeralPubKey = ephemeralPubKeyBytes instanceof Uint8Array 
                    ? ephemeralPubKeyBytes 
                    : Uint8Array.from(ephemeralPubKeyBytes);
            }
            
            // Convert bytes to string for plaintext payload
            // For hex strings, we need to remove 0x and convert to bytes properly
            let plaintextPayload;
            if (typeof plaintextPayloadBytes === 'string' && plaintextPayloadBytes.startsWith('0x')) {
                // It's a hex string, convert to bytes then to string
                const hexString = plaintextPayloadBytes.slice(2);
                const matchResult = hexString.match(/.{2}/g);
                if (!matchResult) {
                    throw new Error("Failed to parse hex string into bytes");
                }
                const bytes = new Uint8Array(matchResult.map(byte => parseInt(byte, 16)));
                plaintextPayload = new TextDecoder().decode(bytes);
            } else {
                // It's already bytes
                const plaintextPayloadArray = plaintextPayloadBytes instanceof Uint8Array 
                    ? plaintextPayloadBytes 
                    : Uint8Array.from(plaintextPayloadBytes);
                plaintextPayload = new TextDecoder().decode(plaintextPayloadArray);
            }
            
            console.log('Parsed handshake:', { 
                identityPubKey: Array.from(identityPubKey), 
                ephemeralPubKey: Array.from(ephemeralPubKey), 
                plaintextPayload 
            });
            
            // Clean the sender address by removing leading zeros
            const cleanSenderAddress = handshake.sender.replace(/^0x0+/, '0x');
            
            // Create HandshakePayload using SDK structure
            const handshakePayload = {
                identityPubKey,
                ephemeralPubKey,
                plaintextPayload
            };
            
            // Encode using SDK for consistent serialization
            const encodedPayload = encodeHandshakePayload(handshakePayload);
            
            const handshakeWithParsedData = {
                ...handshake,
                sender: cleanSenderAddress,
                // Store encoded payload for consistent serialization
                encodedPayload,
                // Keep readable fields for UI
                plaintextPayload,
                // Store arrays for immediate use (will be reconstructed from encodedPayload on reload)
                identityPubKey: Array.from(identityPubKey),
                ephemeralPubKey: Array.from(ephemeralPubKey)
            };
            
            // Check if we already have this handshake to avoid duplicates
            setPendingHandshakes(prev => {
                const exists = prev.some(h => h.transactionHash === handshake.transactionHash);
                if (exists) {
                    console.log('🔄 Handshake already processed, skipping...');
                    return prev;
                }
                return [...prev, handshakeWithParsedData];
            });
            
            if (logRef.current) {
                const timestamp = new Date().toLocaleTimeString();
                logRef.current.value += `[${timestamp}] 🤝 Received handshake from ${cleanSenderAddress}: "${plaintextPayload}"\n`;
                logRef.current.scrollTop = logRef.current.scrollHeight;
            }
        } catch (error) {
            console.error('Failed to parse handshake data:', error);
            if (logRef.current) {
                const timestamp = new Date().toLocaleTimeString();
                logRef.current.value += `[${timestamp}] ❌ Failed to parse handshake\n`;
                logRef.current.scrollTop = logRef.current.scrollHeight;
            }
        }
    }, []);

    useMessageListener({
        readProvider,
        userAddress: address || null,
        onIncomingMessage: handleIncomingMessage,
        onIncomingHandshake: handleIncomingHandshake
    });


    // ADD: Component for handshake card with custom response
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
    // ADD: Function to accept handshake with custom response message
    const acceptHandshake = useCallback(async (handshake: any, responseMessage: string) => {
        if (!walletClient || !ready || !address) return;

        try {
            const provider = new BrowserProvider({
                request: async ({ method, params }) => {
                    return await walletClient.request({ method: method as any, params });
                }
            });
            const signer = await provider.getSigner();
            const contract = new Contract(LOGCHAIN_ADDR, ABI, signer) as unknown as LogChainV1;

            console.log('Debug handshake object:', {
                handshake,
                hasEncodedPayload: !!handshake.encodedPayload,
                identityPubKey: handshake.identityPubKey,
                identityPubKeyType: typeof handshake.identityPubKey
            });

            // Use SDK to decode the handshake payload if available
            let identityPubKey: Uint8Array;
            
            if (handshake.encodedPayload) {
                // Decode using SDK function
                const decodedPayload = decodeHandshakePayload(handshake.encodedPayload);
                identityPubKey = decodedPayload.identityPubKey;
                console.log('Decoded handshake using SDK:', {
                    plaintextPayload: decodedPayload.plaintextPayload,
                    identityPubKey: Array.from(decodedPayload.identityPubKey),
                    ephemeralPubKey: Array.from(decodedPayload.ephemeralPubKey)
                });
            } else {
                // Fallback to manual parsing for backwards compatibility
                if (typeof handshake.identityPubKey === 'string' && handshake.identityPubKey.startsWith('0x')) {
                    const hexString = handshake.identityPubKey.slice(2);
                    identityPubKey = new Uint8Array(hexString.match(/.{2}/g)!.map((byte: string) => parseInt(byte, 16)));
                } else if (Array.isArray(handshake.identityPubKey)) {
                    identityPubKey = new Uint8Array(handshake.identityPubKey);
                } else if (handshake.identityPubKey instanceof Uint8Array) {
                    identityPubKey = handshake.identityPubKey;
                } else if (handshake.identityPubKey && typeof handshake.identityPubKey === 'object') {
                    const keys = Object.keys(handshake.identityPubKey);
                    if (keys.length === 32 && keys.every(k => !isNaN(parseInt(k)))) {
                        const array = new Array(32);
                        for (let i = 0; i < 32; i++) {
                            array[i] = handshake.identityPubKey[i];
                        }
                        identityPubKey = new Uint8Array(array);
                    } else {
                        throw new Error(`Unsupported identityPubKey object structure. Keys: ${JSON.stringify(keys.slice(0, 5))}`);
                    }
                } else {
                    throw new Error(`Unsupported identityPubKey type: ${typeof handshake.identityPubKey}, value: ${JSON.stringify(handshake.identityPubKey)}`);
                }
            }

            // Validate key length
            if (identityPubKey.length !== 32) {
                throw new Error(`Invalid key length: ${identityPubKey.length}, expected 32 bytes`);
            }

            // Derive deterministic identity key for this address
            const responderIdentityPubKey = await deriveIdentityKeyFromAddress(walletClient, address);

            console.log('Accepting handshake with:', {
                sender: handshake.sender,
                identityPubKey: Array.from(identityPubKey),
                length: identityPubKey.length,
                plaintextPayload: handshake.plaintextPayload,
                responseMessage,
                responderIdentityPubKey: Array.from(responderIdentityPubKey)
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
                logRef.current.value += `[${timestamp}] ✅ Responded to handshake from ${handshake.sender}: "${responseMessage}"\n`;
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
    }, [walletClient, ready, respondToIncomingHandshake, address, deriveIdentityKeyFromAddress]);

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

                        {/* ADD: PENDING HANDSHAKES SECTION */}
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
                            onRecipientSelect={setSelectedRecipient}
                        />
                    </div>

                    {/* RIGHT COLUMN */}
                    <div className="space-y-6">
                        {/* MESSAGING */}
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
                    </div>
                </div>
            </main>
        </div>
    );
}