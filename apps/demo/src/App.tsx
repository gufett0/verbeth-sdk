import { useEffect, useRef, useState, useCallback } from "react";
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount, useWalletClient } from 'wagmi';
import { useRpcProvider } from './rpc.js';
import { BrowserProvider, keccak256, toUtf8Bytes } from "ethers";
import {
  LogChainV1__factory,
  type LogChainV1,
} from "@verbeth/contracts/typechain-types/index.js";
import nacl from "tweetnacl";
import {
  sendEncryptedMessage,
  initiateHandshake,
  respondToHandshake,
  IExecutor,
  ExecutorFactory,
  deriveIdentityKeyPairWithProof,
  IdentityKeyPair,
  DerivationProof
} from '@verbeth/sdk';
import { useMessageListener } from './hooks/useMessageListener.js';
import { useMessageProcessor } from './hooks/useMessageProcessor.js';
import { dbService } from './services/DbService.js';
import {
  LOGCHAIN_SINGLETON_ADDR,
  CONTRACT_CREATION_BLOCK,
  Contact,
  StoredIdentity
} from './types.js';

export default function App() {
  const readProvider = useRpcProvider();
  const { address, isConnected } = useAccount();
  const { data: walletClient } = useWalletClient();

  // State
  const [ready, setReady] = useState(false);
  const [recipientAddress, setRecipientAddress] = useState("");
  const [message, setMessage] = useState("");
  const [selectedContact, setSelectedContact] = useState<Contact | null>(null);
  const [loading, setLoading] = useState(false);
  const [currentAccount, setCurrentAccount] = useState<string | null>(null);

  const [identityKeyPair, setIdentityKeyPair] = useState<IdentityKeyPair | null>(null);
  const [derivationProof, setDerivationProof] = useState<DerivationProof | null>(null);
  const [executor, setExecutor] = useState<IExecutor | null>(null);
  const [contract, setContract] = useState<LogChainV1 | null>(null);
  const [signer, setSigner] = useState<any>(null);

  // Refs for logging - moved to top
  const logRef = useRef<HTMLTextAreaElement>(null);

  const addLog = useCallback((message: string) => {
    if (logRef.current) {
      const timestamp = new Date().toLocaleTimeString();
      logRef.current.value += `[${timestamp}] ${message}\n`;
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, []);

  // ✅ FIXED: Always call hooks in the same order - don't conditionally call them
  const {
    messages,
    pendingHandshakes,
    contacts,
    addMessage,
    removePendingHandshake,
    updateContact,
    processEvents
  } = useMessageProcessor({
    readProvider,
    address,
    identityKeyPair,
    onLog: addLog
  });

  const {
    isInitialLoading,
    isLoadingMore,
    canLoadMore,
    syncProgress,
    loadMoreHistory,
  } = useMessageListener({
    readProvider,
    address,
    onLog: addLog,
    onEventsProcessed: processEvents
  });

  useEffect(() => {
    setReady(readProvider !== null && isConnected && walletClient !== undefined);
  }, [readProvider, isConnected, walletClient]);

  // ✅ FIXED: Remove debouncing timeout to avoid hook order issues
  useEffect(() => {
    handleInitialization();
  }, [ready, readProvider, walletClient, address]);

  const handleInitialization = useCallback(async () => {
    try {
      // Reset everything if not ready
      if (!ready || !readProvider || !walletClient || !address) {
        setCurrentAccount(null);
        setIdentityKeyPair(null);
        setDerivationProof(null);
        setSelectedContact(null);
        setSigner(null);
        setContract(null);
        setExecutor(null);
        return;
      }

      // Step 1: Initialize contract and signer FIRST
      addLog(`🔄 Initializing for account: ${address.slice(0, 8)}...`);
      
      const ethersProvider = new BrowserProvider(walletClient.transport);
      const ethersSigner = await ethersProvider.getSigner();
      
      // Verify signer matches the current address
      const signerAddress = await ethersSigner.getAddress();
      if (signerAddress.toLowerCase() !== address.toLowerCase()) {
        addLog(`❌ Signer mismatch: expected ${address.slice(0, 8)}, got ${signerAddress.slice(0, 8)}`);
        return;
      }

      const contractInstance = LogChainV1__factory.connect(LOGCHAIN_SINGLETON_ADDR, ethersSigner as any);
      const executorInstance = ExecutorFactory.createEOA(contractInstance);

      // Set contract and signer
      setContract(contractInstance);
      setSigner(ethersSigner);
      setExecutor(executorInstance);

      // Step 2: Handle account change if needed
      if (address !== currentAccount) {
        addLog(`🔄 Account ${currentAccount ? 'changed' : 'connected'}: ${address.slice(0, 8)}...`);
        
        // Clear current state
        setIdentityKeyPair(null);
        setDerivationProof(null);
        setSelectedContact(null);
        
        // Switch account in database service
        await dbService.switchAccount(address);
        
        // Update current account
        setCurrentAccount(address);
      }

      // Step 3: Initialize or load identity
      addLog(`🔑 Loading identity for ${address.slice(0, 8)}...`);
      
      // Check database first
      const storedIdentity = await dbService.getIdentity(address);
      
      if (storedIdentity) {
        setIdentityKeyPair(storedIdentity.keyPair);
        setDerivationProof(storedIdentity.proof ?? null);
        addLog(`✅ Identity keys restored from database: ${Buffer.from(storedIdentity.keyPair.publicKey).toString('hex').slice(0, 16)}...`);
      } else {
        // Derive new identity
        addLog("🔑 Deriving new identity key from wallet...");
        const result = await deriveIdentityKeyPairWithProof(ethersSigner, address);
        
        setIdentityKeyPair(result.keyPair);
        setDerivationProof(result.derivationProof);

        // Save to database
        const identityToStore: StoredIdentity = {
          address,
          keyPair: result.keyPair,
          derivedAt: Date.now(),
          proof: result.derivationProof
        };
        
        await dbService.saveIdentity(identityToStore);

        addLog(`✅ New identity key derived and saved: ${Buffer.from(result.keyPair.publicKey).toString('hex').slice(0, 16)}...`);
      }

      addLog("✅ Initialization complete");

    } catch (error) {
      console.error("Failed to initialize:", error);
      addLog(`❌ Failed to initialize: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }, [ready, readProvider, walletClient, address, currentAccount, addLog]);

  // Send handshake
  const sendHandshake = async () => {
    if (!executor || !address || !recipientAddress || !message || !identityKeyPair || !derivationProof || !signer) {
      addLog("❌ Missing required data for handshake");
      return;
    }

    setLoading(true);
    try {
      const ephemeralKeyPair = nacl.box.keyPair();

      const tx = await initiateHandshake({
        executor,
        recipientAddress,
        identityKeyPair,
        ephemeralPubKey: ephemeralKeyPair.publicKey,
        plaintextPayload: message,
        derivationProof,
        signer
      });

      const newContact: Contact = {
        address: recipientAddress,
        ownerAddress: address,
        status: 'handshake_sent',
        ephemeralKey: ephemeralKeyPair.secretKey,
        topic: tx.hash,
        lastMessage: message,
        lastTimestamp: Date.now()
      };

      // Save to database
      await updateContact(newContact);

      addLog(`📤 Handshake sent to ${recipientAddress.slice(0, 8)}...: "${message}" (tx: ${tx.hash})`);
      setMessage("");
    } catch (error) {
      console.error("Failed to send handshake:", error);
      addLog(`❌ Failed to send handshake: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setLoading(false);
    }
  };

  // Accept handshake
  const acceptHandshake = async (handshake: any, responseMessage: string) => {
    if (!executor || !address || !identityKeyPair || !derivationProof || !signer) {
      addLog("❌ Missing required data for handshake response");
      return;
    }

    try {
      const tx = await respondToHandshake({
        executor,
        inResponseTo: handshake.id,
        initiatorPubKey: handshake.ephemeralPubKey,
        responderIdentityKeyPair: identityKeyPair,
        note: responseMessage,
        derivationProof,
        signer
      });

      const newContact: Contact = {
        address: handshake.sender,
        ownerAddress: address,
        status: 'established',
        identityPubKey: handshake.identityPubKey,
        signingPubKey: handshake.signingPubKey,
        lastMessage: responseMessage,
        lastTimestamp: Date.now()
      };

      // Save to database
      await updateContact(newContact);
      await removePendingHandshake(handshake.id);

      addLog(`✅ Handshake accepted from ${handshake.sender.slice(0, 8)}...: "${responseMessage}"`);
    } catch (error) {
      console.error("Failed to accept handshake:", error);
      addLog(`❌ Failed to accept handshake: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  // Send message to established contact
  const sendMessageToContact = async (contact: Contact, messageText: string) => {
    if (!executor || !address || !contact.identityPubKey) {
      addLog("❌ Contact not established or missing data");
      return;
    }

    setLoading(true);
    try {
      const topic = keccak256(toUtf8Bytes(`chat:${contact.address}`));
      const timestamp = Math.floor(Date.now() / 1000);

      if (!identityKeyPair) {
        addLog("❌ Identity key pair is missing");
        setLoading(false);
        return;
      }

      const identityAsSigningKey = {
        publicKey: identityKeyPair.signingPublicKey,
        secretKey: identityKeyPair.signingSecretKey
      };

      await sendEncryptedMessage({
        executor,
        topic,
        message: messageText,
        recipientPubKey: contact.identityPubKey,
        senderAddress: address,
        senderSignKeyPair: identityAsSigningKey,
        timestamp
      });

      const newMessage = {
        id: `${Date.now()}-${Math.random()}`,
        topic,
        sender: address,
        recipient: contact.address,
        ciphertext: '', // Will be filled by actual encryption
        timestamp: Date.now(),
        blockTimestamp: Date.now(),
        blockNumber: 0, // Will be updated when confirmed
        direction: 'outgoing' as const,
        decrypted: messageText,
        read: true,
        nonce: 0, // Will be updated
        dedupKey: `${address}:${topic}:${Date.now()}`,
        type: 'text' as const,
        ownerAddress: address
      };

      addMessage(newMessage);

      addLog(`📤 Message sent to ${contact.address.slice(0, 8)}...: "${messageText}"`);
    } catch (error) {
      console.error("Failed to send message:", error);
      addLog(`❌ Failed to send message: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-white p-4">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-8 border-b border-gray-800 pb-4">
          <h1 className="text-2xl font-bold">VerbEth Demo</h1>
          <ConnectButton />
        </div>

        {!ready ? (
          <div className="text-center py-16">
            <p className="text-gray-400 text-lg">
              {!isConnected ? "Please connect your wallet" : "Initializing..."}
            </p>
            {isInitialLoading && (
              <div className="mt-4 flex items-center justify-center gap-2">
                <div className="animate-spin w-6 h-6 border-2 border-blue-400 border-t-transparent rounded-full"></div>
                <span className="text-blue-400">Loading recent messages...</span>
                {syncProgress && (
                  <span className="text-sm">({syncProgress.current}/{syncProgress.total})</span>
                )}
              </div>
            )}
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left Panel - Handshake */}
            <div className="space-y-6">
              <div className="border border-gray-800 rounded-lg p-4">
                <h2 className="text-lg font-semibold mb-4">Start Handshake</h2>
                <div className="space-y-3">
                  <input
                    type="text"
                    placeholder="Recipient address (0x...)"
                    value={recipientAddress}
                    onChange={(e) => setRecipientAddress(e.target.value)}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-white"
                  />
                  <input
                    type="text"
                    placeholder="Message"
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-white"
                  />
                  <button
                    onClick={sendHandshake}
                    disabled={loading || !recipientAddress || !message}
                    className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed rounded font-medium"
                  >
                    {loading ? "Sending..." : "Send Handshake"}
                  </button>
                </div>
              </div>

              {/* Pending Handshakes */}
              {pendingHandshakes.length > 0 && (
                <div className="border border-gray-800 rounded-lg p-4">
                  <h2 className="text-lg font-semibold mb-4">Pending Handshakes</h2>
                  <div className="space-y-3">
                    {pendingHandshakes.map((handshake) => (
                      <div key={handshake.id} className="bg-gray-900 p-3 rounded">
                        <div className="flex justify-between items-start mb-2">
                          <span className="text-sm text-gray-400">
                            From: {handshake.sender.slice(0, 8)}...
                          </span>
                          <span className="text-xs">
                            {handshake.verified ? '✅' : '⚠️'}
                          </span>
                        </div>
                        <p className="text-sm mb-2">"{handshake.message}"</p>
                        <div className="flex gap-2">
                          <input
                            type="text"
                            placeholder="Response message"
                            className="flex-1 px-2 py-1 bg-gray-800 border border-gray-600 rounded text-xs"
                            id={`response-${handshake.id}`}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') {
                                const target = e.target as HTMLInputElement;
                                acceptHandshake(handshake, target.value);
                                target.value = '';
                              }
                            }}
                          />
                          <button
                            onClick={() => {
                              const input = document.getElementById(`response-${handshake.id}`) as HTMLInputElement;
                              if (input?.value) {
                                acceptHandshake(handshake, input.value);
                                input.value = '';
                              }
                            }}
                            className="px-3 py-1 bg-green-600 hover:bg-green-700 rounded text-xs"
                          >
                            Accept
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Middle Panel - Contacts */}
            <div className="border border-gray-800 rounded-lg p-4">
              <h2 className="text-lg font-semibold mb-4">Contacts</h2>
              <div className="space-y-2">
                {contacts.map((contact) => (
                  <div
                    key={contact.address}
                    onClick={() => setSelectedContact(contact)}
                    className={`p-3 rounded cursor-pointer transition-colors ${selectedContact?.address === contact.address
                      ? 'bg-blue-900'
                      : 'bg-gray-900 hover:bg-gray-800'
                      }`}
                  >
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-medium">
                        {contact.address.slice(0, 8)}...
                      </span>
                      <span className={`text-xs px-2 py-1 rounded ${contact.status === 'established'
                        ? 'bg-green-800 text-green-200'
                        : contact.status === 'handshake_sent'
                          ? 'bg-yellow-800 text-yellow-200'
                          : 'bg-gray-700 text-gray-300'
                        }`}>
                        {contact.status.replace('_', ' ')}
                      </span>
                    </div>
                    {contact.lastMessage && (
                      <p className="text-xs text-gray-400 mt-1">
                        "{contact.lastMessage.slice(0, 30)}..."
                      </p>
                    )}
                  </div>
                ))}
                {contacts.length === 0 && (
                  <p className="text-gray-400 text-sm text-center py-4">
                    No contacts yet. Start a handshake to add contacts.
                  </p>
                )}
              </div>
            </div>

            {/* Right Panel - Conversation */}
            <div className="border border-gray-800 rounded-lg p-4 flex flex-col h-96">
              <h2 className="text-lg font-semibold mb-4">
                {selectedContact ? `Chat with ${selectedContact.address.slice(0, 8)}...` : 'Select a contact'}
              </h2>

              {selectedContact ? (
                <>
                  {/* Load More History Button */}
                  {canLoadMore && (
                    <div className="text-center mb-2">
                      <button
                        onClick={loadMoreHistory}
                        disabled={isLoadingMore}
                        className="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:cursor-not-allowed rounded"
                      >
                        {isLoadingMore ? (
                          <div className="flex items-center gap-2">
                            <div className="animate-spin w-3 h-3 border border-gray-400 border-t-transparent rounded-full"></div>
                            <span>Loading...</span>
                            {syncProgress && <span>({syncProgress.current}/{syncProgress.total})</span>}
                          </div>
                        ) : (
                          "Load More History"
                        )}
                      </button>
                    </div>
                  )}

                  {/* Messages */}
                  <div className="flex-1 overflow-y-auto space-y-2 mb-4">
                    {messages
                      .filter(m =>
                        m.sender.toLowerCase() === selectedContact.address.toLowerCase() ||
                        (m.direction === 'outgoing' && selectedContact)
                      )
                      .map((msg) => (
                        <div
                          key={msg.id}
                          className={`p-2 rounded max-w-xs ${msg.direction === 'outgoing'
                            ? 'bg-blue-600 ml-auto'
                            : msg.type === 'system'
                              ? 'bg-gray-700 mx-auto text-center text-xs'
                              : 'bg-gray-700'
                            }`}
                        >
                          <p className="text-sm">{msg.decrypted || msg.ciphertext}</p>
                          <span className="text-xs text-gray-300">
                            {new Date(msg.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      ))}
                    {messages.filter(m =>
                      m.sender.toLowerCase() === selectedContact.address.toLowerCase() ||
                      (m.direction === 'outgoing' && selectedContact)
                    ).length === 0 && (
                        <p className="text-gray-400 text-sm text-center py-8">
                          No messages yet. {selectedContact.status === 'established' ? 'Start the conversation!' : 'Complete the handshake first.'}
                        </p>
                      )}
                  </div>

                  {/* Message Input */}
                  {selectedContact.status === 'established' && selectedContact.identityPubKey && (
                    <div className="flex gap-2">
                      <input
                        type="text"
                        placeholder="Type a message..."
                        className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded text-white"
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' && e.currentTarget.value.trim()) {
                            sendMessageToContact(selectedContact, e.currentTarget.value.trim());
                            e.currentTarget.value = '';
                          }
                        }}
                      />
                      <button
                        onClick={() => {
                          const input = document.querySelector('input[placeholder="Type a message..."]') as HTMLInputElement;
                          if (input?.value.trim()) {
                            sendMessageToContact(selectedContact, input.value.trim());
                            input.value = '';
                          }
                        }}
                        disabled={loading}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 rounded"
                      >
                        Send
                      </button>
                    </div>
                  )}

                  {selectedContact.status !== 'established' && (
                    <div className="text-center py-4 text-gray-400 text-sm">
                      Handshake required before sending messages
                    </div>
                  )}
                </>
              ) : (
                <div className="flex-1 flex items-center justify-center text-gray-400">
                  Select a contact to start messaging
                </div>
              )}
            </div>
          </div>
        )}

        {/* Activity Log */}
        <div className="mt-8 border border-gray-800 rounded-lg p-4">
          <div className="flex justify-between items-center mb-4">
            <div className="flex items-center gap-4">
              <h2 className="text-lg font-semibold">Activity Log</h2>
              {canLoadMore && ready && (
                <button
                  onClick={loadMoreHistory}
                  disabled={isLoadingMore}
                  className="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:cursor-not-allowed rounded flex items-center gap-2"
                >
                  {isLoadingMore ? (
                    <>
                      <div className="animate-spin w-3 h-3 border border-gray-400 border-t-transparent rounded-full"></div>
                      <span>Loading blocks...</span>
                    </>
                  ) : (
                    <>
                      <span>📂</span>
                      <span>Load More History</span>
                    </>
                  )}
                </button>
              )}
            </div>
            {(isInitialLoading || isLoadingMore) && (
              <div className="flex items-center gap-2 text-sm text-blue-400">
                <div className="animate-spin w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full"></div>
                <span>{isInitialLoading ? 'Initial sync...' : 'Loading more...'}</span>
                {syncProgress && (
                  <span>({syncProgress.current}/{syncProgress.total})</span>
                )}
              </div>
            )}
          </div>
          <textarea
            ref={logRef}
            readOnly
            className="w-full h-32 bg-gray-900 border border-gray-700 rounded p-2 text-sm font-mono text-gray-300 resize-none"
            placeholder="Activity will appear here..."
          />
        </div>

        {/* Debug Info */}
        <div className="mt-4 text-xs text-gray-500 space-y-1">
          <p>Contract: {LOGCHAIN_SINGLETON_ADDR}</p>
          <p>Network: Base</p>
          <p>Contract creation block: {CONTRACT_CREATION_BLOCK}</p>
          <p>Status: {ready ? '🟢 Ready' : '🔴 Not Ready'} {(isInitialLoading || isLoadingMore) ? '⏳ Loading' : ''}</p>
          {/* Debug info for development */}
          <p>Current Account: {currentAccount?.slice(0, 8) || 'None'}...</p>
          <p>Connected Address: {address?.slice(0, 8) || 'None'}...</p>
          <p>Signer Available: {signer ? '✅' : '❌'}</p>
          <p>Identity Available: {identityKeyPair ? '✅' : '❌'}</p>
        </div>
      </div>
    </div>
  );
}