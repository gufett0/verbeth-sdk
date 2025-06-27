import React, { useEffect, useRef, useState, useCallback } from "react";
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount, useWalletClient } from 'wagmi';
import { useRpcProvider } from './rpc';
import { Contract, BrowserProvider, keccak256, toUtf8Bytes, hexlify } from "ethers";
import nacl from "tweetnacl";
import {
  sendEncryptedMessage,
  encryptStructuredPayload,
  initiateHandshake,
  HandshakeResponseContent
} from '@verbeth/sdk';
import { useMessageListener } from './hooks/useMessageListener';
import { deriveIdentityKeyPair } from './utils/identityKeys';


// Constants
const LOGCHAIN_ABI = [
  "event MessageSent(address indexed sender, bytes ciphertext, uint256 timestamp, bytes32 indexed topic, uint256 nonce)",
  "event Handshake(bytes32 indexed recipientHash, address indexed sender, bytes identityPubKey, bytes ephemeralPubKey, bytes plaintextPayload)",
  "event HandshakeResponse(bytes32 indexed inResponseTo, address indexed responder, bytes ciphertext)",
  "function sendMessage(bytes calldata ciphertext, bytes32 topic, uint256 timestamp, uint256 nonce)",
  "function initiateHandshake(bytes32 recipientHash, bytes identityPubKey, bytes ephemeralPubKey, bytes plaintextPayload)",
  "function respondToHandshake(bytes32 inResponseTo, bytes ciphertext)"
];

const LOGCHAIN_ADDR = "0xf9fe7E57459CC6c42791670FaD55c1F548AE51E8";
const CONTRACT_CREATION_BLOCK = 30568313;

interface Contact {
  address: string;
  signingPubKey?: Uint8Array;
  pubKey?: Uint8Array;
  ephemeralKey?: Uint8Array;
  topic?: string;
  status: 'none' | 'handshake_sent' | 'established';
  lastMessage?: string;
  lastTimestamp?: number;
}

export default function App() {
  const readProvider = useRpcProvider();
  const { address, isConnected } = useAccount();
  const { data: walletClient } = useWalletClient();
  const [signer, setSigner] = useState<any>(null);


  // State
  const [ready, setReady] = useState(false);
  const [contract, setContract] = useState<Contract | null>(null);
  const [recipientAddress, setRecipientAddress] = useState("");
  const [identityKeyPair, setIdentityKeyPair] = useState<{ publicKey: Uint8Array, secretKey: Uint8Array } | null>(null);
  const [message, setMessage] = useState("");
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [selectedContact, setSelectedContact] = useState<Contact | null>(null);
  const [loading, setLoading] = useState(false);



  // Refs
  const logRef = useRef<HTMLTextAreaElement>(null);

  // Demo keys - in production, derive from wallet
  const senderSignKeyPair = useRef(nacl.sign.keyPair());

  useEffect(() => {
    setReady(readProvider !== null && isConnected && walletClient !== undefined);
  }, [readProvider, isConnected, walletClient]);


  useEffect(() => {
    const initializeIdentityKey = async () => {
      if (address && signer) {
        try {
          addLog("🔑 Deriving identity key from wallet...");
          const keyPair = await deriveIdentityKeyPair(signer, address);
          setIdentityKeyPair(keyPair);
          addLog(`✅ Identity key derived: ${Buffer.from(keyPair.publicKey).toString('hex').slice(0, 16)}...`);
        } catch (error) {
          console.error("Failed to derive identity key:", error);
          addLog(`❌ Failed to derive identity key: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }
    };

    initializeIdentityKey();
  }, [address, signer]);

  // Helper functions
  const addLog = (message: string) => {
    if (logRef.current) {
      const timestamp = new Date().toLocaleTimeString();
      logRef.current.value += `[${timestamp}] ${message}\n`;
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  };

  // Message listener hook - FIXED: Pass all required props
  const {
    messages,
    pendingHandshakes,
    isInitialLoading,
    isLoadingMore,
    canLoadMore,
    syncProgress,
    loadMoreHistory,
    addMessage,
    removePendingHandshake
  } = useMessageListener({
    readProvider,
    address,
    contacts,
    identityKeyPair: identityKeyPair,
    senderSignKeyPair: senderSignKeyPair.current,
    onContactsUpdate: (newContacts) => setContacts(newContacts),
    onLog: addLog
  });

  // Initialize contract and identity key
  useEffect(() => {
  if (!ready || !readProvider || !walletClient || !address) return;

  const initContract = async () => {
    try {
      const ethersProvider = new BrowserProvider(walletClient.transport);
      const ethersSigner = await ethersProvider.getSigner();  
      const contractInstance = new Contract(LOGCHAIN_ADDR, LOGCHAIN_ABI, ethersSigner);
      
      setContract(contractInstance);
      setSigner(ethersSigner); 

      addLog("✅ Contract initialized and ready");
    } catch (error) {
      console.error("Failed to initialize contract:", error);
      addLog("❌ Failed to initialize contract");
    }
  };

  initContract();
}, [ready, readProvider, walletClient, address]);

  // Load contacts from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem('verbeth_contacts');
      if (stored) {
        const parsed = JSON.parse(stored);
        setContacts(parsed.map((c: any) => ({
          ...c,
          pubKey: c.pubKey ? new Uint8Array(c.pubKey) : undefined,
          ephemeralKey: c.ephemeralKey ? new Uint8Array(c.ephemeralKey) : undefined
        })));
      }
    } catch (error) {
      console.error("Failed to load contacts:", error);
    }
  }, []);

  // Save contacts to localStorage
  const saveContacts = useCallback((newContacts: Contact[]) => {
    try {
      const serializable = newContacts.map(c => ({
        ...c,
        pubKey: c.pubKey ? Array.from(c.pubKey) : undefined,
        ephemeralKey: c.ephemeralKey ? Array.from(c.ephemeralKey) : undefined
      }));
      localStorage.setItem('verbeth_contacts', JSON.stringify(serializable));
      setContacts(newContacts);
    } catch (error) {
      console.error("Failed to save contacts:", error);
    }
  }, []);

  // Use correct SDK initiateHandshake function signature
  const sendHandshake = async () => {
    if (!contract || !address || !recipientAddress || !message || !identityKeyPair) {
      addLog("❌ Missing required data for handshake");
      return;
    }

    setLoading(true);
    try {
      // Generate ephemeral keypair for this handshake
      const ephemeralKeyPair = nacl.box.keyPair();

      // FIX: Ora l'SDK ritorna la transaction
      const tx = await initiateHandshake({
        contract: contract as any,
        recipientAddress,
        identityPubKey: identityKeyPair.publicKey,
        ephemeralPubKey: ephemeralKeyPair.publicKey,
        plaintextPayload: message
      });

      // Add to contacts
      const newContact: Contact = {
        address: recipientAddress,
        status: 'handshake_sent',
        ephemeralKey: ephemeralKeyPair.secretKey,
        topic: tx.hash,
        lastMessage: message,
        lastTimestamp: Date.now()
      };

      const updatedContacts = [...contacts.filter(c => c.address !== recipientAddress), newContact];
      saveContacts(updatedContacts);

      addLog(`📤 Handshake sent to ${recipientAddress.slice(0, 8)}...: "${message}" (tx: ${tx.hash})`);
      setMessage("");
    } catch (error) {
      console.error("Failed to send handshake:", error);
      addLog(`❌ Failed to send handshake: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setLoading(false);
    }
  };

  // Use SDK encryptStructuredPayload function
  const acceptHandshake = async (handshake: any, responseMessage: string) => {
    if (!contract || !address || !identityKeyPair) {
      addLog("❌ Missing required data for handshake response");
      return;
    }

    try {
      const responderEphemeralKeyPair = nacl.box.keyPair();

      const responseContent: HandshakeResponseContent = {
        identityPubKey: identityKeyPair.publicKey, 
        ephemeralPubKey: responderEphemeralKeyPair.publicKey,
        note: responseMessage
      };

      // Use SDK function for encrypting response
      const encryptedResponse = encryptStructuredPayload(
        responseContent,
        handshake.ephemeralPubKey,
        responderEphemeralKeyPair.secretKey,
        responderEphemeralKeyPair.publicKey
      );

      const tx = await contract.respondToHandshake(
        handshake.id,
        toUtf8Bytes(encryptedResponse)
      );

        addLog(`🔍 Accepting handshake - signingKey: ${handshake.signingPubKey ? 'YES' : 'NO'}`);
  if (handshake.signingPubKey) {
    addLog(`🔍 Signing key: ${Buffer.from(handshake.signingPubKey).toString('hex').slice(0, 16)}...`);
  }


      // Add to contacts
      const newContact: Contact = {
        address: handshake.sender,
        status: 'established',
        pubKey: handshake.identityPubKey,
        signingPubKey: handshake.signingPubKey, 
        lastMessage: responseMessage,
        lastTimestamp: Date.now()
      };

      const updatedContacts = [...contacts.filter(c => c.address !== handshake.sender), newContact];
      saveContacts(updatedContacts);

      // Remove from pending
      removePendingHandshake(handshake.id);

      addLog(`✅ Handshake accepted from ${handshake.sender.slice(0, 8)}...: "${responseMessage}"`);
    } catch (error) {
      console.error("Failed to accept handshake:", error);
      addLog(`❌ Failed to accept handshake: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  // Send message to established contact - FIXED: Use addMessage from hook
  const sendMessageToContact = async (contact: Contact, messageText: string) => {
    if (!contract || !address || !contact.pubKey) {
      addLog("❌ Contact not established or missing data");
      return;
    }

    setLoading(true);
    try {
      const topic = keccak256(toUtf8Bytes(`chat:${contact.address}`));
      const timestamp = Math.floor(Date.now() / 1000);

      await sendEncryptedMessage({
        contract: contract as any,
        topic,
        message: messageText,
        recipientPubKey: contact.pubKey,
        senderAddress: address,
        senderSignKeyPair: senderSignKeyPair.current,
        timestamp
      });

      // Add to messages using hook function
      const newMessage = {
        id: `${Date.now()}-${Math.random()}`,
        content: messageText,
        sender: address,
        timestamp: Date.now(),
        type: 'outgoing' as const
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
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') {
                                acceptHandshake(handshake, e.currentTarget.value);
                                e.currentTarget.value = '';
                              }
                            }}
                          />
                          <button
                            onClick={() => {
                              const input = document.querySelector(`input[placeholder="Response message"]`) as HTMLInputElement;
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
                        (m.type === 'outgoing' && selectedContact)
                      )
                      .map((msg) => (
                        <div
                          key={msg.id}
                          className={`p-2 rounded max-w-xs ${msg.type === 'outgoing'
                            ? 'bg-blue-600 ml-auto'
                            : msg.type === 'system'
                              ? 'bg-gray-700 mx-auto text-center text-xs'
                              : 'bg-gray-700'
                            }`}
                        >
                          <p className="text-sm">{msg.content}</p>
                          <span className="text-xs text-gray-300">
                            {new Date(msg.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      ))}
                    {messages.filter(m =>
                      m.sender.toLowerCase() === selectedContact.address.toLowerCase() ||
                      (m.type === 'outgoing' && selectedContact)
                    ).length === 0 && (
                        <p className="text-gray-400 text-sm text-center py-8">
                          No messages yet. {selectedContact.status === 'established' ? 'Start the conversation!' : 'Complete the handshake first.'}
                        </p>
                      )}
                  </div>

                  {/* Message Input */}
                  {selectedContact.status === 'established' && (
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
              {/* Global Load More History Button */}
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
          <p>Contract: {LOGCHAIN_ADDR}</p>
          <p>Network: Base</p>
          <p>Contract creation block: {CONTRACT_CREATION_BLOCK}</p>
          <p>Status: {ready ? '🟢 Ready' : '🔴 Not Ready'} {(isInitialLoading || isLoadingMore) ? '⏳ Loading' : ''}</p>
        </div>
      </div>
    </div>
  );
}