// Enhanced useConversationManager with handshake response verification
import { useState, useCallback, useEffect } from 'react';
import nacl from 'tweetnacl';
import { 
  initiateHandshake, 
  respondToHandshake, 
  sendEncryptedMessage,
  decryptHandshakeResponse,
  verifyHandshakeResponseIdentity
} from '@verbeth/sdk';
import type { LogChainV1 } from '@verbeth/contracts/typechain-types';
import { WalletClient } from 'viem';
import { BrowserProvider } from 'ethers';
import { deriveIdentityKeyFromAddress } from '../utils/keyDerivation';

interface ConversationMessage {
  id: string;
  content: string;
  timestamp: number;
  sender: string;
  type: 'outgoing' | 'incoming' | 'handshake' | 'system';
  status?: 'sending' | 'sent' | 'failed';
}

interface ConversationState {
  recipientAddress: string;
  recipientPubKey?: Uint8Array;
  status: 'none' | 'initiated' | 'established';
  lastMessageTime?: number;
  messages: ConversationMessage[];
  // Store ephemeral keys for decryption
  ephemeralKeys?: {
    ourEphemeralPrivateKey?: Uint8Array;
    theirEphemeralPublicKey?: Uint8Array;
  };
}

interface MessageOptions {
  contract: LogChainV1;
  recipientAddress: string;
  message: string;
  senderAddress: string;
  senderSignKeyPair: nacl.SignKeyPair;
  walletClient: WalletClient; 
  topic?: string;
}

// localStorage keys
const STORAGE_KEYS = {
  RECIPIENTS: 'verbeth_recipients',
  CONVERSATIONS: 'verbeth_conversations_v2', // Bumped version for new format
  PENDING_HANDSHAKES: 'verbeth_pending_handshakes'
} as const;

// Helper functions for localStorage operations
const loadRecipientsFromStorage = (): string[] => {
  try {
    const stored = localStorage.getItem(STORAGE_KEYS.RECIPIENTS);
    return stored ? JSON.parse(stored) : [];
  } catch {
    return [];
  }
};

const saveRecipientsToStorage = (recipients: string[]) => {
  try {
    localStorage.setItem(STORAGE_KEYS.RECIPIENTS, JSON.stringify(recipients));
  } catch (error) {
    console.error('Failed to save recipients to localStorage:', error);
  }
};

const addRecipientToStorage = (recipient: string) => {
  const recipients = loadRecipientsFromStorage();
  const normalizedRecipient = recipient.toLowerCase();
  
  if (!recipients.includes(normalizedRecipient)) {
    recipients.push(normalizedRecipient);
    saveRecipientsToStorage(recipients);
  }
};

const defaultTopic = '0x' + '01'.repeat(32); // Topic for regular messages

export function useConversationManager() {
  const [conversations, setConversations] = useState<Map<string, ConversationState>>(new Map());
  const [isLoaded, setIsLoaded] = useState(false);
  // Load conversations from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEYS.CONVERSATIONS);
      if (stored) {
        const parsed = JSON.parse(stored);
        const conversationMap = new Map<string, ConversationState>();
        
        Object.entries(parsed).forEach(([address, conv]: [string, any]) => {
          try {
            const conversation: ConversationState = {
              ...conv,
              recipientPubKey: conv.recipientPubKey ? new Uint8Array(conv.recipientPubKey) : undefined,
              ephemeralKeys: conv.ephemeralKeys ? {
                ourEphemeralPrivateKey: conv.ephemeralKeys.ourEphemeralPrivateKey ? 
                  new Uint8Array(conv.ephemeralKeys.ourEphemeralPrivateKey) : undefined,
                theirEphemeralPublicKey: conv.ephemeralKeys.theirEphemeralPublicKey ? 
                  new Uint8Array(conv.ephemeralKeys.theirEphemeralPublicKey) : undefined,
              } : undefined
            };
            conversationMap.set(address, conversation);
          } catch (convError) {
            console.error(`Error processing conversation for ${address}:`, convError);
          }
        });
        
        setConversations(conversationMap);
      }
      setIsLoaded(true);
    } catch (error) {
      console.error('Failed to load conversations from localStorage:', error);
      setIsLoaded(true);
    }
  }, []);

  // Save conversations to localStorage whenever conversations change (but only after initial load)
  useEffect(() => {
    if (!isLoaded) return;
    
    try {
      const conversationObj: Record<string, any> = {};
      conversations.forEach((conv, address) => {
        conversationObj[address] = {
          ...conv,
          recipientPubKey: conv.recipientPubKey ? Array.from(conv.recipientPubKey) : undefined,
          ephemeralKeys: conv.ephemeralKeys ? {
            ourEphemeralPrivateKey: conv.ephemeralKeys.ourEphemeralPrivateKey ? 
              Array.from(conv.ephemeralKeys.ourEphemeralPrivateKey) : undefined,
            theirEphemeralPublicKey: conv.ephemeralKeys.theirEphemeralPublicKey ? 
              Array.from(conv.ephemeralKeys.theirEphemeralPublicKey) : undefined,
          } : undefined
        };
      });
      
      localStorage.setItem(STORAGE_KEYS.CONVERSATIONS, JSON.stringify(conversationObj));
    } catch (error) {
      console.error('Failed to save conversations to localStorage:', error);
    }
  }, [conversations, isLoaded]);

  const addRecipient = useCallback((address: string): string => {
    if (!address || typeof address !== 'string') {
      throw new Error('Invalid address');
    }
    
    const trimmed = address.trim();
    if (!trimmed.match(/^0x[a-fA-F0-9]{40}$/)) {
      throw new Error('Invalid Ethereum address format');
    }
    
    const normalizedAddress = trimmed.toLowerCase();
    addRecipientToStorage(normalizedAddress);
    
    return normalizedAddress;
  }, []);

  const removeRecipient = useCallback((address: string) => {
    const normalizedAddress = address.toLowerCase();
    const recipients = loadRecipientsFromStorage();
    const updated = recipients.filter(r => r !== normalizedAddress);
    saveRecipientsToStorage(updated);
    
    // Also remove from conversations
    setConversations(prev => {
      const newMap = new Map(prev);
      newMap.delete(normalizedAddress);
      return newMap;
    });
  }, []);

  const clearAllRecipients = useCallback(() => {
    localStorage.removeItem(STORAGE_KEYS.RECIPIENTS);
    localStorage.removeItem(STORAGE_KEYS.CONVERSATIONS);
    setConversations(new Map());
  }, []);

  const getStoredRecipients = useCallback(() => {
    return loadRecipientsFromStorage();
  }, []);

  const getConversation = useCallback((recipientAddress: string): ConversationState => {
    const normalizedAddress = recipientAddress.toLowerCase();
    return conversations.get(normalizedAddress) || {
      recipientAddress: normalizedAddress,
      status: 'none',
      messages: []
    };
  }, [conversations]);

  const updateConversation = useCallback((recipientAddress: string, updates: Partial<ConversationState>) => {
    const normalizedAddress = recipientAddress.toLowerCase();
    
    // Add to recipients list in localStorage
    addRecipientToStorage(normalizedAddress);
    
    setConversations(prev => {
      const newMap = new Map(prev);
      const existing = newMap.get(normalizedAddress) || { 
        recipientAddress: normalizedAddress, 
        status: 'none' as const,
        messages: [] 
      };
      newMap.set(normalizedAddress, { ...existing, ...updates });
      return newMap;
    });
  }, []);

  const addMessage = useCallback((recipientAddress: string, message: ConversationMessage) => {
    const normalizedAddress = recipientAddress.toLowerCase();
    
    setConversations(prev => {
      const newMap = new Map(prev);
      const existing = newMap.get(normalizedAddress) || {
        recipientAddress: normalizedAddress,
        status: 'none' as const,
        messages: []
      };
      
      const updatedMessages = [...existing.messages, message];
      
      newMap.set(normalizedAddress, {
        ...existing,
        messages: updatedMessages,
        lastMessageTime: message.timestamp
      });
      
      return newMap;
    });
  }, []);

  const updateMessageStatus = useCallback((recipientAddress: string, messageId: string, status: 'sending' | 'sent' | 'failed') => {
    const normalizedAddress = recipientAddress.toLowerCase();
    
    setConversations(prev => {
      const newMap = new Map(prev);
      const existing = newMap.get(normalizedAddress);
      
      if (existing) {
        const updatedMessages = existing.messages.map(msg => 
          msg.id === messageId ? { ...msg, status } : msg
        );
        
        newMap.set(normalizedAddress, {
          ...existing,
          messages: updatedMessages
        });
      }
      
      return newMap;
    });
  }, []);

  const sendMessage = useCallback(async (options: MessageOptions) => {
    const { 
      contract, 
      recipientAddress, 
      message, 
      senderAddress, 
      senderSignKeyPair, 
      walletClient, 
      topic = defaultTopic 
    } = options;

    const conversation = getConversation(recipientAddress);
    const timestamp = Math.floor(Date.now() / 1000);
    const messageId = `msg_${timestamp}_${Math.random().toString(36).substr(2, 9)}`;

    // Add message to conversation immediately with 'sending' status
    const newMessage: ConversationMessage = {
      id: messageId,
      content: message,
      timestamp,
      sender: senderAddress,
      type: 'outgoing',
      status: 'sending'
    };

    addMessage(recipientAddress, newMessage);

    try {
      switch (conversation.status) {
        case 'none':
          // First message - initiate handshake
          const identityPubKey = await deriveIdentityKeyFromAddress(walletClient, senderAddress);
          const ephemeralKeyPair = nacl.box.keyPair();
          
          await initiateHandshake({
            contract,
            recipientAddress,
            identityPubKey,
            ephemeralPubKey: ephemeralKeyPair.publicKey,
            plaintextPayload: message
          });

          updateConversation(recipientAddress, { 
            status: 'initiated',
            lastMessageTime: timestamp,
            ephemeralKeys: {
              ourEphemeralPrivateKey: ephemeralKeyPair.secretKey
            }
          });

          // Update message type to handshake
          setConversations(prev => {
            const newMap = new Map(prev);
            const existing = newMap.get(recipientAddress.toLowerCase());
            if (existing) {
              const updatedMessages = existing.messages.map(msg =>
                msg.id === messageId ? { ...msg, type: 'handshake' as const, status: 'sent' as const } : msg
              );
              newMap.set(recipientAddress.toLowerCase(), { ...existing, messages: updatedMessages });
            }
            return newMap;
          });
          
          return { type: 'handshake_initiated', success: true };

        case 'established':
          // Ongoing conversation - use regular encrypted message
          if (!conversation.recipientPubKey) {
            throw new Error('Recipient public key not available');
          }

          await sendEncryptedMessage({
            contract,
            topic: defaultTopic,
            message,
            recipientPubKey: conversation.recipientPubKey,
            senderAddress,
            senderSignKeyPair,
            timestamp
          });

          updateConversation(recipientAddress, { 
            lastMessageTime: timestamp
          });

          updateMessageStatus(recipientAddress, messageId, 'sent');

          return { type: 'message_sent', success: true };

        case 'initiated':
          // Waiting for handshake response - could resend or wait
          updateMessageStatus(recipientAddress, messageId, 'failed');
          throw new Error('Handshake pending. Wait for recipient response before sending more messages.');

        default:
          updateMessageStatus(recipientAddress, messageId, 'failed');
          throw new Error('Unknown conversation status');
      }
    } catch (error) {
      console.error('Failed to send message:', error);
      updateMessageStatus(recipientAddress, messageId, 'failed');
      throw error;
    }
  }, [getConversation, updateConversation, addMessage, updateMessageStatus]);

  const handleHandshakeResponse = useCallback(async (
    recipientAddress: string,
    recipientPubKey: Uint8Array,
    responseMessage?: string
  ) => {
    const timestamp = Math.floor(Date.now() / 1000);
    
    updateConversation(recipientAddress, {
      status: 'established',
      recipientPubKey,
      lastMessageTime: timestamp
    });

    // Add system message about connection establishment
    if (responseMessage) {
      const systemMessage: ConversationMessage = {
        id: `sys_${timestamp}_${Math.random().toString(36).substr(2, 9)}`,
        content: `Connection established. Response: "${responseMessage}"`,
        timestamp,
        sender: 'system',
        type: 'system'
      };
      addMessage(recipientAddress, systemMessage);
    }
  }, [updateConversation, addMessage]);

  const processHandshakeResponse = useCallback(async (
    responseData: any,
    walletClient: WalletClient,
    userAddress: string,
    readProvider?: BrowserProvider
  ) => {
    try {
      // Find the conversation that initiated the handshake
      const conversations_array = Array.from(conversations.values());
      const initiatedConversation = conversations_array.find(conv => 
        conv.status === 'initiated' && 
        conv.ephemeralKeys?.ourEphemeralPrivateKey &&
        conv.recipientAddress.toLowerCase() === responseData.responder.toLowerCase()
      );

      if (!initiatedConversation || !initiatedConversation.ephemeralKeys?.ourEphemeralPrivateKey) {
        console.warn('No matching initiated conversation found for handshake response from:', responseData.responder);
        return false;
      }

      // Decrypt the handshake response using SDK
      const decryptedResponse = decryptHandshakeResponse(
        responseData.ciphertextJson,
        initiatedConversation.ephemeralKeys.ourEphemeralPrivateKey
      );

      if (!decryptedResponse) {
        console.error('Failed to decrypt handshake response');
        return false;
      }

      // Verify handshake response identity if we have transaction data and provider
      if (responseData.rawTxHex && readProvider) {
        const responseEvent = {
          inResponseTo: responseData.inResponseTo,
          responder: responseData.responder,
          ciphertext: responseData.rawData.ciphertextBytes
        };

        const isVerified = await verifyHandshakeResponseIdentity(
          responseData.rawTxHex,
          responseEvent,
          decryptedResponse.identityPubKey,
          initiatedConversation.ephemeralKeys.ourEphemeralPrivateKey,
          readProvider
        );

        if (!isVerified) {
          console.warn('⚠️ Handshake response verification failed');
          return false;
        }
      }

      // Update conversation with recipient's public key
      await handleHandshakeResponse(
        responseData.responder,
        decryptedResponse.identityPubKey,
        decryptedResponse.note
      );

      return true;
    } catch (error) {
      console.error('Failed to process handshake response:', error);
      return false;
    }
  }, [conversations, handleHandshakeResponse]);

  const respondToIncomingHandshake = useCallback(async (options: {
    contract: LogChainV1;
    inResponseTo: string;
    initiatorAddress: string;
    initiatorPubKey: Uint8Array;
    responseMessage?: string;
    walletClient: WalletClient; 
    responderAddress: string; 
  }) => {
    const { 
      contract, 
      inResponseTo, 
      initiatorAddress, 
      initiatorPubKey, 
      responseMessage,
      walletClient,
      responderAddress
    } = options;

    try {
      const responderIdentityPubKey = await deriveIdentityKeyFromAddress(walletClient, responderAddress); 
      const responderEphemeralKeyPair = nacl.box.keyPair();

      await respondToHandshake({
        contract,
        inResponseTo,
        initiatorPubKey,
        responderIdentityPubKey,
        responderEphemeralKeyPair,
        note: responseMessage
      });

      // Update conversation state
      const timestamp = Math.floor(Date.now() / 1000);
      updateConversation(initiatorAddress, {
        status: 'established',
        recipientPubKey: initiatorPubKey,
        lastMessageTime: timestamp
      });

      // Add system message about accepting handshake
      const systemMessage: ConversationMessage = {
        id: `sys_${timestamp}_${Math.random().toString(36).substr(2, 9)}`,
        content: `Handshake accepted. Response: "${responseMessage || 'Connection established'}"`,
        timestamp,
        sender: 'system',
        type: 'system'
      };
      addMessage(initiatorAddress, systemMessage);

      return { success: true };
    } catch (error) {
      console.error('Failed to respond to handshake:', error);
      throw error;
    }
  }, [updateConversation, addMessage]);

  return {
    conversations: Array.from(conversations.values()),
    getConversation,
    addRecipient,
    removeRecipient,
    clearAllRecipients,
    getStoredRecipients,
    sendMessage,
    handleHandshakeResponse,
    respondToIncomingHandshake,
    addMessage,
    updateMessageStatus,
    processHandshakeResponse
  };
}