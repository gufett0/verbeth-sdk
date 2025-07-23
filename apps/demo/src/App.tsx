import { useEffect, useRef, useState, useCallback } from "react";
import { CheckIcon, XIcon } from "lucide-react";
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount, useWalletClient } from 'wagmi';
import { useRpcProvider } from './rpc.js';
import { BrowserProvider } from "ethers";
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
  DerivationProof,
  getNextNonce
} from '@verbeth/sdk';
import { useMessageListener } from './hooks/useMessageListener.js';
import { useMessageProcessor } from './hooks/useMessageProcessor.js';
import { dbService } from './services/DbService.js';
import {
  LOGCHAIN_SINGLETON_ADDR,
  CONTRACT_CREATION_BLOCK,
  Contact,
  StoredIdentity,
  generateConversationTopic, generateTempMessageId
} from './types.js';
import { InitialForm } from './components/InitialForm.js';
//import { createBaseAccountSDK } from "@base-org/account";


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
  const [showHandshakeForm, setShowHandshakeForm] = useState(true);

  const [identityKeyPair, setIdentityKeyPair] = useState<IdentityKeyPair | null>(null);
  const [derivationProof, setDerivationProof] = useState<DerivationProof | null>(null);
  const [executor, setExecutor] = useState<IExecutor | null>(null);
  const [contract, setContract] = useState<LogChainV1 | null>(null);
  const [signer, setSigner] = useState<any>(null);
  const [isActivityLogOpen, setIsActivityLogOpen] = useState(false);

  // Refs for logging
  const logRef = useRef<HTMLTextAreaElement>(null);
  //const sdk = useRef<ReturnType<typeof createBaseAccountSDK>>();

  const addLog = useCallback((message: string) => {
    if (logRef.current) {
      const timestamp = new Date().toLocaleTimeString();
      logRef.current.value += `[${timestamp}] ${message}\n`;
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, []);

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

  useEffect(() => {
    handleInitialization();
  }, [ready, readProvider, walletClient, address]);

  // hide handshake form when we have contacts
  useEffect(() => {
    setShowHandshakeForm(contacts.length === 0);
  }, [contacts.length]);

  const handleInitialization = useCallback(async () => {
    try {
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

      console.log(`...Initializing for account: ${address.slice(0, 8)}...`);

      // get current provider from wagmi
      const ethersProvider = new BrowserProvider(walletClient.transport);
      const ethersSigner = await ethersProvider.getSigner();

      let isBaseSmartAccount = false;
      let publicIdentity = address;
      let executorInstance: IExecutor;
      const paymasterUrl = import.meta.env.VITE_PAYMASTER_AND_BUNDLER_ENDPOINT;

      try {
        // test if wallet smart account features
        const capabilities = await walletClient.transport.request({
          method: 'wallet_getCapabilities',
          params: [address]
        }).catch(() => null);

        const hasSmartAccountFeatures = capabilities &&
          Object.values(capabilities).some((chainCaps: any) =>
            chainCaps?.paymasterService || chainCaps?.atomicBatch
          );

        if (hasSmartAccountFeatures) {
          isBaseSmartAccount = true;
          executorInstance = ExecutorFactory.createBaseSmartAccount(
            walletClient.transport,
            LOGCHAIN_SINGLETON_ADDR,
            8453,
            paymasterUrl 
          );
          
          if (paymasterUrl) {
            console.log(`Smart Account with gas sponsorship detected: ${address.slice(0, 8)}...`);
          } else {
            console.log(`Smart Account detected: ${address.slice(0, 8)}...`);
          }
        } else {
          // fallback to EOA
          const contractInstance = LogChainV1__factory.connect(LOGCHAIN_SINGLETON_ADDR, ethersSigner as any);
          executorInstance = ExecutorFactory.createEOA(contractInstance);
          setContract(contractInstance);
          console.log(`Using EOA mode: ${address.slice(0, 8)}...`);
        }
      } catch (error) {
        const contractInstance = LogChainV1__factory.connect(LOGCHAIN_SINGLETON_ADDR, ethersSigner as any);
        executorInstance = ExecutorFactory.createEOA(contractInstance);
        setContract(contractInstance);
        console.log(`Capability check failed, using EOA mode: ${address.slice(0, 8)}...`);
      }

      setSigner(ethersSigner);
      setExecutor(executorInstance);

      if (publicIdentity !== currentAccount) {
        console.log(`Account ${currentAccount ? 'changed' : 'connected'}: ${publicIdentity.slice(0, 8)}...${isBaseSmartAccount ? ' (Smart Account)' : ' (EOA)'}`);

        setIdentityKeyPair(null);
        setDerivationProof(null);
        setSelectedContact(null);

        await dbService.switchAccount(publicIdentity);
        setCurrentAccount(publicIdentity);
      }

      console.log(`Loading identity for ${publicIdentity.slice(0, 8)}...`);

      const storedIdentity = await dbService.getIdentity(publicIdentity);

      if (storedIdentity) {
        setIdentityKeyPair(storedIdentity.keyPair);
        setDerivationProof(storedIdentity.proof ?? null);
        console.log(`Identity keys restored from database`);
      } else {
        try {
          console.log("Deriving new identity key...");

          const result = await deriveIdentityKeyPairWithProof(ethersSigner, address);

          setIdentityKeyPair(result.keyPair);
          setDerivationProof(result.derivationProof);

          const identityToStore: StoredIdentity = {
            address: publicIdentity,
            keyPair: result.keyPair,
            derivedAt: Date.now(),
            proof: result.derivationProof
          };

          await dbService.saveIdentity(identityToStore);
          console.log(`New identity key derived and saved`);

        } catch (signError: any) {
          if (signError.code === 4001) {
            console.log("User rejected signing request.");
            return;
          } else {
            console.log(`✗ Failed to derive identity: ${signError.message}`);
            return;
          }
        }
      }

      const sponsorshipStatus = isBaseSmartAccount && paymasterUrl ? ' with gas sponsorship' : '';
      console.log(`Initialization complete - Mode: ${isBaseSmartAccount ? 'Smart Account' : 'EOA'}${sponsorshipStatus}`);

    } catch (error) {
      console.error("Failed to initialize:", error);
      console.log(`✗ Failed to initialize: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }, [ready, readProvider, walletClient, address, currentAccount, addLog]);

  // Send handshake
  const sendHandshake = async () => {
    if (!executor || !address || !recipientAddress || !message || !identityKeyPair || !derivationProof || !signer) {
      addLog("✗ Missing required data for handshake");
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

      // Auto-select the new contact and add handshake message to chat
      setSelectedContact(newContact);

      // Add handshake message as system message in chat
      const handshakeMessage = {
        id: generateTempMessageId(),
        topic: generateConversationTopic(address, recipientAddress),
        sender: address,
        recipient: recipientAddress,
        ciphertext: '',
        timestamp: Date.now(),
        blockTimestamp: Date.now(),
        blockNumber: 0,
        direction: 'outgoing' as const,
        decrypted: `Handshake sent: "${message}"`,
        read: true,
        nonce: 0,
        dedupKey: `handshake-${tx.hash}`,
        type: 'system' as const,
        ownerAddress: address,
        status: 'pending' as const
      };

      await addMessage(handshakeMessage);

      addLog(`Handshake sent to ${recipientAddress.slice(0, 8)}...: "${message}" (tx: ${tx.hash})`);
      setMessage("");
      setRecipientAddress("");
    } catch (error) {
      console.error("Failed to send handshake:", error);
      addLog(`✗ Failed to send handshake: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setLoading(false);
    }
  };

  // Accept handshake
  const acceptHandshake = async (handshake: any, responseMessage: string) => {
    if (!executor || !address || !identityKeyPair || !derivationProof || !signer) {
      addLog("✗ Missing required data for handshake response");
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

      // Auto-select the new contact
      setSelectedContact(newContact);

      addLog(`✅ Handshake accepted from ${handshake.sender.slice(0, 8)}...: "${responseMessage}"`);
    } catch (error) {
      console.error("Failed to accept handshake:", error);
      addLog(`✗ Failed to accept handshake: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  // Send message to established contact
  const sendMessageToContact = async (contact: Contact, messageText: string) => {
    if (!executor || !address || !contact.identityPubKey || !identityKeyPair) {
      addLog("✗ Contact not established or missing data");
      return;
    }

    setLoading(true);
    try {
      // Generate consistent topic for this conversation
      const topic = generateConversationTopic(address, contact.address);
      const timestamp = Math.floor(Date.now() / 1000);
      const identityAsSigningKey = {
        publicKey: identityKeyPair.signingPublicKey,
        secretKey: identityKeyPair.signingSecretKey
      };

      const expectedNonce = Number(getNextNonce(address, topic)) + 1;

      // Create and save the pending message BEFORE sending
      const pendingMessage = {
        id: generateTempMessageId(),
        topic,
        sender: address,
        recipient: contact.address,
        ciphertext: '',
        timestamp: timestamp * 1000,
        blockTimestamp: Date.now(),
        blockNumber: 0,
        direction: 'outgoing' as const,
        decrypted: messageText,
        read: true,
        nonce: expectedNonce,
        dedupKey: `${address}:${topic}:${expectedNonce}`,
        type: 'text' as const,
        ownerAddress: address,
        status: 'pending' as const
      };

      // Save to database immediately with pending status
      await addMessage(pendingMessage);

      // Send the actual transaction
      await sendEncryptedMessage({
        executor,
        topic,
        message: messageText,
        recipientPubKey: contact.identityPubKey,
        senderAddress: address,
        senderSignKeyPair: identityAsSigningKey,
        timestamp
      });

      // Update contact's lastMessage and lastTimestamp
      const updatedContact: Contact = {
        ...contact,
        lastMessage: messageText,
        lastTimestamp: Date.now()
      };
      await updateContact(updatedContact);

      addLog(`Message sent to ${contact.address.slice(0, 8)}...: "${messageText}"`);
    } catch (error) {
      console.error("Failed to send message:", error);
      addLog(`✗ Failed to send message: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Header full width */}
      <div className="w-full border-b border-gray-800 bg-black">
        <div className="flex justify-between items-center px-4 py-4">
          <h1 className="text-2xl font-bold">Verbeth Chat</h1>
          <ConnectButton />
        </div>
      </div>

      {/* Main content with max-width */}
      <div className="max-w-6xl mx-auto p-4 flex flex-col min-h-[80vh]">
        <div className="flex-1 flex flex-col">

          {/* Notification Banner for Pending Handshakes */}
          {pendingHandshakes.length > 0 && (
            <div className="mb-6">
              {pendingHandshakes.map((handshake) => (
                <div key={handshake.id} className="bg-blue-900/20 border border-blue-700 rounded-lg p-4 mb-2">
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-medium">Handshake from {handshake.sender.slice(0, 8)}...</span>
                        <span className="text-xs">{handshake.verified ? '✅ Verified' : '⚠️ Unverified'}</span>
                      </div>
                      <p className="text-sm text-gray-300 mb-3">"{handshake.message}"</p>
                      <div className="flex gap-2 items-center">
                        <input
                          type="text"
                          placeholder="Your response..."
                          className="flex-1 px-3 py-1 bg-gray-800 border border-gray-600 rounded text-sm"
                          id={`response-${handshake.id}`}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') {
                              const target = e.target as HTMLInputElement;
                              if (target.value.trim()) {
                                acceptHandshake(handshake, target.value.trim());
                                target.value = '';
                              }
                            }
                          }}
                        />
                        <button
                          onClick={() => {
                            const input = document.getElementById(`response-${handshake.id}`) as HTMLInputElement;
                            if (input?.value.trim()) {
                              acceptHandshake(handshake, input.value.trim());
                              input.value = '';
                            }
                          }}
                          className="px-3 py-1 bg-green-600 hover:bg-green-700 rounded text-sm flex items-center gap-1"
                        >
                          <CheckIcon size={14} />
                          Accept
                        </button>
                        <button
                          onClick={() => removePendingHandshake(handshake.id)}
                          className="px-3 py-1 bg-red-600 hover:bg-red-700 rounded text-sm flex items-center gap-1"
                        >
                          <XIcon size={14} />
                          Reject
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {showHandshakeForm ? (
            <InitialForm
              isConnected={isConnected}
              loading={loading}
              recipientAddress={recipientAddress}
              setRecipientAddress={setRecipientAddress}
              message={message}
              setMessage={setMessage}
              onSendHandshake={sendHandshake}
              contactsLength={contacts.length}
              onBackToChats={() => setShowHandshakeForm(false)}
            />
          ) : (
            /* Main Chat Layout */
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left Panel - Contacts */}
              <div className="border border-gray-800 rounded-lg p-4">
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-lg font-semibold">Contacts</h2>
                  <button
                    onClick={() => setShowHandshakeForm(true)}
                    className="text-sm px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded"
                  >
                    + New
                  </button>
                </div>
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
                </div>
              </div>

              {/* Right Panel - Conversation (spans 2 columns) */}
              <div className="lg:col-span-2 border border-gray-800 rounded-lg p-4 flex flex-col h-96">
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
                        .filter(m => {
                          const conversationTopic = generateConversationTopic(address as string, selectedContact.address);
                          return (
                            m.sender.toLowerCase() === selectedContact.address.toLowerCase() ||
                            (m.direction === 'outgoing' && m.recipient?.toLowerCase() === selectedContact.address.toLowerCase()) ||
                            m.topic === conversationTopic
                          );
                        })
                        .sort((a, b) => a.timestamp - b.timestamp)
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
                            <div className="flex justify-between items-center mt-1">
                              <span className="text-xs text-gray-300">
                                {new Date(msg.timestamp).toLocaleTimeString()}
                              </span>
                              {msg.direction === 'outgoing' && (
                                <span className="text-xs" title={`Status: ${msg.status}`}>
                                  {msg.status === 'confirmed' ? '✓✓' :
                                    msg.status === 'failed' ? '✗' :
                                      msg.status === 'pending' ? '✓' : '?'}
                                </span>
                              )}
                            </div>
                          </div>
                        ))}
                      {messages.filter(m => {
                        const conversationTopic = generateConversationTopic(address as string, selectedContact.address);
                        return (
                          m.sender.toLowerCase() === selectedContact.address.toLowerCase() ||
                          (m.direction === 'outgoing' && m.recipient?.toLowerCase() === selectedContact.address.toLowerCase()) ||
                          m.topic === conversationTopic
                        );
                      }).length === 0 && (
                          <p className="text-gray-400 text-sm text-center py-8">
                            No messages yet. {selectedContact.status === 'established' ? 'Start the conversation!' : 'Waiting for handshake completion.'}
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
                        Handshake in progress... waiting for response
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
          {ready && (
            <div className="mt-8 border border-gray-800 rounded-lg">
              <div
                className="flex justify-between items-center p-4 cursor-pointer hover:bg-gray-900/50 transition-colors"
                onClick={() => setIsActivityLogOpen(!isActivityLogOpen)}
              >
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2">
                    <h2 className="text-lg font-semibold">Activity Log</h2>
                    <span className="text-gray-400 text-sm">
                      {isActivityLogOpen ? '▼' : '▶'}
                    </span>
                  </div>
                  {canLoadMore && ready && isActivityLogOpen && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        loadMoreHistory();
                      }}
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
                {(isInitialLoading || isLoadingMore) && isActivityLogOpen && (
                  <div className="flex items-center gap-2 text-sm text-blue-400">
                    <div className="animate-spin w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full"></div>
                    <span>{isInitialLoading ? 'Initial sync...' : 'Loading more...'}</span>
                    {syncProgress && (
                      <span>({syncProgress.current}/{syncProgress.total})</span>
                    )}
                  </div>
                )}
              </div>

              {isActivityLogOpen && (
                <div className="p-4 pt-0">
                  <textarea
                    ref={logRef}
                    readOnly
                    className="w-full h-32 bg-gray-900 border border-gray-700 rounded p-2 text-sm font-mono text-gray-300 resize-none"
                    placeholder="Activity will appear here..."
                  />
                </div>
              )}
            </div>
          )}

        </div>

        {/* Debug Info */}
        <div className="mt-4 text-xs text-gray-500 space-y-1">
          <p>Contract: {LOGCHAIN_SINGLETON_ADDR}</p>
          <p>Network: Base</p>
          <p>Contract creation block: {CONTRACT_CREATION_BLOCK}</p>
          <p>Status: {ready ? '🟢 Ready' : '🔴 Not Ready'} {(isInitialLoading || isLoadingMore) ? '⏳ Loading' : ''}</p>
        </div>
      </div>
    </div>
  );
}