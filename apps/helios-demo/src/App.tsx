import { useEffect, useRef, useState } from "react";
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount, useWalletClient } from 'wagmi';
import { WalletClient } from 'viem';
import { hashMessage } from 'viem';
import nacl from "tweetnacl";
import { Contract, BrowserProvider, keccak256, toUtf8Bytes, hexlify, SigningKey, getBytes } from "ethers";
import { useHelios } from "./helios";
import { deriveIdentityKeyFromAddress } from './utils/keyDerivation';
import { 
  sendEncryptedMessage, 
  decryptMessage,
  getNextNonce
} from '@verbeth/sdk';
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";

// Contract configuration
const ABI = [
  "function sendMessage(bytes ciphertext, bytes32 topic, uint256 timestamp, uint256 nonce)",
  "event MessageSent(address indexed sender, bytes ciphertext, uint256 timestamp, bytes32 indexed topic, uint256 nonce)"
];
const LOGCHAIN_ADDR = "0xf9fe7E57459CC6c42791670FaD55c1F548AE51E8";
const MESSAGE_SENT_SIGNATURE = keccak256(toUtf8Bytes("MessageSent(address,bytes,uint256,bytes32,uint256)"));

interface Message {
  id: string;
  sender: string;
  content: string;
  timestamp: number;
  blockNumber: number;
  transactionHash: string;
}

export default function App() {
  const readProvider = useHelios();
  const { address, isConnected } = useAccount();
  const { data: walletClient } = useWalletClient();
  
  // UI State
  const [ready, setReady] = useState(false);
  const [filterAddress, setFilterAddress] = useState("");
  const [filterTopic, setFilterTopic] = useState("");
  const [recipientPubKey, setRecipientPubKey] = useState("");
  const [senderPubKey, setSenderPubKey] = useState("");
  const [messageText, setMessageText] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [isListening, setIsListening] = useState(false);
  const [isSending, setIsSending] = useState(false);
  
  // User's derived identity
  const [userIdentityPubKey, setUserIdentityPubKey] = useState<Uint8Array | null>(null);
  const [recoveredPubKey, setRecoveredPubKey] = useState<string | null>(null);
  const [isDerivingKey, setIsDerivingKey] = useState(false);
  
  const logRef = useRef<HTMLTextAreaElement | null>(null);
  const lastBlockRef = useRef<number>(0);
  
  // Demo cryptographic keys - we'll derive these from wallet when connected
  const [senderSignKeyPair, setSenderSignKeyPair] = useState<nacl.SignKeyPair | null>(null);

  useEffect(() => {
    const newReady = readProvider !== null && isConnected && walletClient !== undefined && userIdentityPubKey !== null && senderSignKeyPair !== null;
    setReady(newReady);
    addLog(`🎯 Ready state updated to: ${newReady}`);
    
    if (!newReady) {
      setTimeout(() => debugReadyState(), 100); // Small delay to ensure state is updated
    }
  }, [readProvider, isConnected, walletClient, userIdentityPubKey, senderSignKeyPair]);

  // Load or derive identity key when wallet connects
  useEffect(() => {
    const loadOrDeriveUserIdentity = async () => {
      if (!walletClient || !address || !isConnected) {
        setUserIdentityPubKey(null);
        setRecoveredPubKey(null);
        setSenderSignKeyPair(null);
        return;
      }

      // Check localStorage first
      const storageKey = `verbeth_identity_${address.toLowerCase()}`;
      try {
        const stored = localStorage.getItem(storageKey);
        if (stored) {
          const { identityPubKey, recoveredPubKey: storedRecoveredPubKey } = JSON.parse(stored);
          const identityPubKeyBytes = new Uint8Array(identityPubKey);
          
          addLog(`📦 Loading from cache...`);
          setUserIdentityPubKey(identityPubKeyBytes);
          setRecoveredPubKey(storedRecoveredPubKey || null);
          
          // Create deterministic signing keypair from cached key
          const seed = new Uint8Array(32);
          seed.set(identityPubKeyBytes);
          const signingKeyPair = nacl.sign.keyPair.fromSeed(seed);
          setSenderSignKeyPair(signingKeyPair);
          
          addLog(`✅ Identity key loaded from cache for ${address}`);
          addLog(`🔑 userIdentityPubKey set: ${!!identityPubKeyBytes}`);
          addLog(`🔑 senderSignKeyPair set: ${!!signingKeyPair}`);
          if (storedRecoveredPubKey) {
            addLog(`🔑 Cached Recovered PubKey: ${storedRecoveredPubKey}`);
          }
          addLog(`🔑 Cached VerbEth Identity: ${Array.from(identityPubKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('')}`);
          return;
        }
      } catch (error) {
        console.warn('Failed to load cached identity key:', error);
      }

      // If not cached, derive new key
      setIsDerivingKey(true);
      addLog(`🔑 Deriving identity key for ${address}...`);

      try {
        // Create the same message as in deriveIdentityKeyFromAddress
        const message = `VerbEth Identity Key for ${address.toLowerCase()}`;
        
        // Sign the message with the wallet
        const signature = await walletClient.signMessage({
            account: address as `0x${string}`,
            message: message
        });

        // Recover the public key from the signature
        const messageHash = hashMessage(message);
        const recoveredPubKey = SigningKey.recoverPublicKey(messageHash, signature);
        
        if (!recoveredPubKey || !recoveredPubKey.startsWith("0x04")) {
            throw new Error("Invalid recovered public key");
        }

        // Convert from secp256k1 to X25519 (same logic as keyDerivation.ts)
        const pubkeyBytes = getBytes(recoveredPubKey).slice(1); // Remove 0x04 prefix
        if (pubkeyBytes.length !== 64) {
            throw new Error(`Expected 64 bytes, got ${pubkeyBytes.length}`);
        }

        // Hash the pubkey to get X25519 compatible key (simplified approach)
        const identityPubKey = nacl.hash(pubkeyBytes).slice(0, 32);
        
        addLog(`🔑 Setting derived keys...`);
        setUserIdentityPubKey(identityPubKey);
        setRecoveredPubKey(recoveredPubKey);
        
        // Cache the derived keys
        localStorage.setItem(storageKey, JSON.stringify({
          identityPubKey: Array.from(identityPubKey),
          recoveredPubKey: recoveredPubKey,
          timestamp: Date.now()
        }));
        
        // For signing, we'll create a deterministic nacl signing keypair
        const seed = new Uint8Array(32);
        seed.set(identityPubKey);
        const signingKeyPair = nacl.sign.keyPair.fromSeed(seed);
        setSenderSignKeyPair(signingKeyPair);

        addLog(`✅ Identity key derived and cached for ${address}`);
        addLog(`🔑 userIdentityPubKey set: ${!!identityPubKey}`);
        addLog(`🔑 senderSignKeyPair set: ${!!signingKeyPair}`);
        addLog(`🔑 Recovered PubKey: ${recoveredPubKey}`);
        addLog(`🔑 VerbEth Identity: ${Array.from(identityPubKey).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
      } catch (error) {
        addLog(`❌ Failed to derive identity key: ${error instanceof Error ? error.message : String(error)}`);
        setUserIdentityPubKey(null);
        setRecoveredPubKey(null);
        setSenderSignKeyPair(null);
      } finally {
        setIsDerivingKey(false);
      }
    };

    loadOrDeriveUserIdentity();
  }, [walletClient, address, isConnected]);

  // Function to add log entry
  const addLog = (message: string) => {
    console.log(message); // Also log to console for debugging
    if (logRef.current) {
      const timestamp = new Date().toLocaleTimeString();
      logRef.current.value += `[${timestamp}] ${message}\n`;
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  };

  // Debug function to check ready state
  const debugReadyState = () => {
    const conditions = {
      readProvider: !!readProvider,
      isConnected,
      walletClient: !!walletClient,
      userIdentityPubKey: !!userIdentityPubKey,
      senderSignKeyPair: !!senderSignKeyPair
    };
    console.log('Ready state conditions:', conditions);
    addLog(`🔍 Ready check: ${JSON.stringify(conditions)}`);
    return Object.values(conditions).every(Boolean);
  };

  // Function to start listening for messages
  const startListening = async () => {
    if (!readProvider || !filterAddress || !filterTopic) {
      addLog("❌ Missing read provider, address, or topic");
      return;
    }

    setIsListening(true);
    setMessages([]);
    addLog(`🔍 Starting to listen for messages from ${filterAddress} on topic ${filterTopic}`);

    try {
      // Get current block number
      const currentBlock = await readProvider.getBlockNumber();
      lastBlockRef.current = currentBlock;
      
      // Create topic filter
      const topicHash = keccak256(toUtf8Bytes(filterTopic));
      
      // Pad the address to 32 bytes for indexed topic filtering
      const paddedSenderAddress = "0x" + "0".repeat(24) + filterAddress.slice(2).toLowerCase();
      addLog(`🔍 Using padded sender address: ${paddedSenderAddress}`);
      
      // Get historical messages first
      addLog(`📚 Fetching historical messages from block 0 to ${currentBlock}...`);
      addLog(`🔍 Filter topics: [MessageSent, ${paddedSenderAddress}, ${topicHash}]`);
      
      const historicalLogs = await readProvider.getLogs({
        address: LOGCHAIN_ADDR,
        topics: [
          MESSAGE_SENT_SIGNATURE,
          paddedSenderAddress, // indexed sender (padded to 32 bytes)
          topicHash // indexed topic
        ],
        fromBlock: 31700000,
        toBlock: currentBlock
      });

      addLog(`📜 Found ${historicalLogs.length} historical messages`);
      
      // Process historical messages
      for (const log of historicalLogs) {
        await processMessageLog(log);
      }

      // Set up polling for new messages
      const pollInterval = setInterval(async () => {
        try {
          const latestBlock = await readProvider.getBlockNumber();
          if (latestBlock > lastBlockRef.current) {
            const newLogs = await readProvider.getLogs({
              address: LOGCHAIN_ADDR,
              topics: [
                MESSAGE_SENT_SIGNATURE,
                paddedSenderAddress,
                topicHash
              ],
              fromBlock: lastBlockRef.current + 1,
              toBlock: latestBlock
            });

            if (newLogs.length > 0) {
              addLog(`📨 Received ${newLogs.length} new messages`);
              for (const log of newLogs) {
                await processMessageLog(log);
              }
            }

            lastBlockRef.current = latestBlock;
          }
        } catch (error) {
          addLog(`❌ Error polling for new messages: ${error instanceof Error ? error.message : String(error)}`);
        }
      }, 3000); // Poll every 3 seconds

      // Store interval ID for cleanup
      (window as any).verbethPollInterval = pollInterval;

    } catch (error) {
      addLog(`❌ Error starting listener: ${error instanceof Error ? error.message : String(error)}`);
      setIsListening(false);
    }
  };

  // Function to stop listening
  const stopListening = () => {
    setIsListening(false);
    if ((window as any).verbethPollInterval) {
      clearInterval((window as any).verbethPollInterval);
      (window as any).verbethPollInterval = null;
    }
    addLog("⏹️ Stopped listening for messages");
  };

  // Function to process a message log
  const processMessageLog = async (log: any) => {
    try {
      // Decode the log data
      const iface = new Contract(LOGCHAIN_ADDR, ABI).interface;
      const decoded = iface.parseLog({
        topics: log.topics,
        data: log.data
      });

      if (!decoded) return;

      const { sender, ciphertext, timestamp, nonce } = decoded.args;
      
      // Try to decrypt if we have the sender's public key
      if (senderPubKey) {
        try {
          // Convert hex string to bytes
          const ciphertextBytes = new TextDecoder().decode(ciphertext);
          
          // Create ephemeral key pair for decryption (this is just for demo)
          const recipientKeyPair = nacl.box.keyPair();
          
          // Convert sender public key from hex
          const senderPubKeyBytes = new Uint8Array(
            senderPubKey.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []
          );
          
          const decrypted = decryptMessage(
            ciphertextBytes,
            recipientKeyPair.secretKey,
            senderPubKeyBytes
          );
          
          if (decrypted) {
            const message: Message = {
              id: `${log.transactionHash}-${log.logIndex}`,
              sender,
              content: decrypted,
              timestamp: Number(timestamp),
              blockNumber: log.blockNumber,
              transactionHash: log.transactionHash
            };
            
            setMessages(prev => [...prev, message]);
            addLog(`✅ Decrypted message: "${decrypted}"`);
          } else {
            addLog(`🔒 Could not decrypt message from ${sender}`);
          }
        } catch (decryptError) {
          addLog(`❌ Decryption error: ${decryptError instanceof Error ? decryptError.message : String(decryptError)}`);
        }
      } else {
        addLog(`📩 Received encrypted message from ${sender} (no decryption key provided)`);
      }
      
    } catch (error) {
      addLog(`❌ Error processing log: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  // Function to send a message
  const sendMessage = async () => {
    if (!walletClient || !ready || !address || !recipientPubKey || !messageText || !filterTopic || !senderSignKeyPair) {
      addLog("❌ Missing wallet, recipient public key, message, topic, or identity key");
      return;
    }

    setIsSending(true);
    
    try {
      // Create contract instance
      const provider = new BrowserProvider({
        request: async ({ method, params }) => {
          return await walletClient.request({ method: method as any, params });
        }
      });
      const signer = await provider.getSigner();
      const contract = new Contract(LOGCHAIN_ADDR, ABI, signer) as unknown as LogChainV1;

      // Convert recipient public key from hex
      const recipientPubKeyBytes = new Uint8Array(
        recipientPubKey.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []
      );

      // Send encrypted message
      const topicHash = keccak256(toUtf8Bytes(filterTopic));
      const timestamp = Math.floor(Date.now() / 1000);

      await sendEncryptedMessage({
        contract,
        topic: topicHash,
        message: messageText,
        recipientPubKey: recipientPubKeyBytes,
        senderAddress: address,
        senderSignKeyPair: senderSignKeyPair,
        timestamp
      });

      addLog(`✅ Message sent: "${messageText}"`);
      setMessageText("");
      
    } catch (error) {
      addLog(`❌ Error sending message: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setIsSending(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* HEADER */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-black rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-sm">V</span>
            </div>
            <h1 className="text-xl font-semibold text-gray-900">VerbEth</h1>
            <span className="text-sm text-gray-500">Simplified Demo</span>
          </div>
          <ConnectButton />
        </div>
      </header>

      {/* MAIN */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        <div className="grid gap-6 lg:grid-cols-2">
          
          {/* LEFT COLUMN - Configuration & Controls */}
          <div className="space-y-6">
            
            {/* Connection Status */}
            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Connection Status</h2>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">Helios Sync:</span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    readProvider ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                  }`}>
                    {readProvider ? 'Synced' : 'Not Synced'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">Wallet:</span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    isConnected ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                  }`}>
                    {isConnected ? 'Connected' : 'Disconnected'}
                  </span>
                </div>
                {address && (
                  <div className="pt-2 border-t border-gray-100">
                    <span className="text-sm text-gray-600">Address:</span>
                    <p className="text-xs font-mono text-gray-900 mt-1 break-all">{address}</p>
                  </div>
                )}
              </div>
            </div>

            {/* Message Filter Configuration */}
            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Message Filter</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Sender Address
                  </label>
                  <input
                    type="text"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    placeholder="0x..."
                    value={filterAddress}
                    onChange={(e) => setFilterAddress(e.target.value)}
                    disabled={isListening}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Topic
                  </label>
                  <input
                    type="text"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    placeholder="chat:demo"
                    value={filterTopic}
                    onChange={(e) => setFilterTopic(e.target.value)}
                    disabled={isListening}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Sender Public Key (for decryption)
                  </label>
                  <input
                    type="text"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    placeholder="32-byte hex string..."
                    value={senderPubKey}
                    onChange={(e) => setSenderPubKey(e.target.value)}
                    disabled={isListening}
                  />
                </div>
                <button
                  onClick={isListening ? stopListening : startListening}
                  disabled={!ready || (!isListening && (!filterAddress || !filterTopic))}
                  className={`w-full px-4 py-2 rounded-md text-sm font-medium ${
                    isListening 
                      ? 'bg-red-600 text-white hover:bg-red-700'
                      : 'bg-blue-600 text-white hover:bg-blue-700'
                  } disabled:opacity-50 disabled:cursor-not-allowed`}
                >
                  {isListening ? 'Stop Listening' : 'Start Listening'}
                </button>
              </div>
            </div>

            {/* Send Message */}
            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Send Message</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Topic
                  </label>
                  <input
                    type="text"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    placeholder="chat:demo"
                    value={filterTopic}
                    onChange={(e) => setFilterTopic(e.target.value)}
                    disabled={isSending}
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Topic/channel for this message
                  </p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Recipient Public Key
                  </label>
                  <input
                    type="text"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    placeholder="32-byte hex string..."
                    value={recipientPubKey}
                    onChange={(e) => setRecipientPubKey(e.target.value)}
                    disabled={isSending}
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Recipient's VerbEth Identity Key (32 bytes hex)
                  </p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Message
                  </label>
                  <textarea
                    rows={3}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Type your message..."
                    value={messageText}
                    onChange={(e) => setMessageText(e.target.value)}
                    disabled={isSending}
                  />
                </div>
                <button
                  onClick={sendMessage}
                  disabled={!ready || !recipientPubKey || !messageText || !filterTopic || isSending}
                  className="w-full px-4 py-2 bg-green-600 text-white rounded-md text-sm font-medium hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
                >
                  {isSending && (
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  )}
                  <span>{isSending ? 'Sending...' : 'Send Message'}</span>
                </button>
                <button
                  onClick={debugReadyState}
                  className="w-full px-4 py-2 bg-gray-600 text-white rounded-md text-xs font-medium hover:bg-gray-700 mt-2"
                >
                  Debug: Check Send Button State
                </button>
              </div>
            </div>
          </div>

          {/* RIGHT COLUMN - Messages & Log */}
          <div className="space-y-6">
            
            {/* Messages */}
            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">
                Messages ({messages.length})
              </h2>
              <div className="space-y-3 max-h-64 overflow-y-auto">
                {messages.length === 0 ? (
                  <p className="text-sm text-gray-500 italic">No messages yet...</p>
                ) : (
                  messages.map((message) => (
                    <div key={message.id} className="border border-gray-200 rounded-lg p-3">
                      <div className="text-xs text-gray-500 mb-1">
                        From: {message.sender.slice(0, 8)}...{message.sender.slice(-6)} 
                        • Block: {message.blockNumber}
                      </div>
                      <div className="text-sm text-gray-900">{message.content}</div>
                      <div className="text-xs text-gray-400 mt-1">
                        {new Date(message.timestamp * 1000).toLocaleString()}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Activity Log */}
            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Activity Log</h2>
              <textarea
                ref={logRef}
                className="w-full h-48 px-3 py-2 border border-gray-300 rounded-lg bg-gray-50 font-mono text-sm resize-none outline-none"
                placeholder="Activity logs will appear here..."
                readOnly
              />
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}