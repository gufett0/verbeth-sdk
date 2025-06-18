// Enhanced useConversationManager with persistent conversation state and message history
import { useState, useCallback, useEffect } from 'react';
import nacl from 'tweetnacl';
import { 
  initiateHandshake, 
  respondToHandshake, 
  sendEncryptedMessage,
  decryptHandshakeResponse 
} from '@verbeth/sdk';
import type { LogChainV1 } from '@verbeth/contracts/typechain-types';
import { WalletClient } from 'viem';
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
  } catch (error) {
    console.warn('Failed to load recipients from localStorage:', error);
    return [];
  }
};

const saveRecipientsToStorage = (recipients: string[]): void => {
  try {
    localStorage.setItem(STORAGE_KEYS.RECIPIENTS, JSON.stringify(recipients));
  } catch (error) {
    console.warn('Failed to save recipients to localStorage:', error);
  }
};

const loadConversationsFromStorage = (): Map<string, ConversationState> => {
  try {
    const stored = localStorage.getItem(STORAGE_KEYS.CONVERSATIONS);
    if (stored) {
      const conversationsData = JSON.parse(stored);
      const conversationsMap = new Map<string, ConversationState>();
      
      // Reconstruct conversations with message history
      Object.entries(conversationsData).forEach(([address, state]: [string, any]) => {
        conversationsMap.set(address, {
          recipientAddress: address,
          status: state.status || 'none',
          lastMessageTime: state.lastMessageTime,
          messages: state.messages || [],
          // Don't restore ephemeral keys for security
          // Don't restore recipientPubKey as it's a Uint8Array and needs fresh exchange
        });
      });
      
      return conversationsMap;
    }
  } catch (error) {
    console.warn('Failed to load conversations from localStorage:', error);
  }
  return new Map();
};

const saveConversationsToStorage = (conversations: Map<string, ConversationState>): void => {
  try {
    const conversationsData: Record<string, any> = {};
    conversations.forEach((state, address) => {
      // Store conversation data with message history
      conversationsData[address] = {
        recipientAddress: state.recipientAddress,
        status: state.status,
        lastMessageTime: state.lastMessageTime,
        messages: state.messages,
        // Note: recipientPubKey and ephemeralKeys intentionally excluded for security
      };
    });
    localStorage.setItem(STORAGE_KEYS.CONVERSATIONS, JSON.stringify(conversationsData));
  } catch (error) {
    console.warn('Failed to save conversations to localStorage:', error);
  }
};

const addRecipientToStorage = (recipientAddress: string): void => {
  const recipients = loadRecipientsFromStorage();
  const normalizedAddress = recipientAddress.toLowerCase();
  
  if (!recipients.includes(normalizedAddress)) {
    recipients.push(normalizedAddress);
    saveRecipientsToStorage(recipients);
  }
};

export function useConversationManager() {
  const [conversations, setConversations] = useState<Map<string, ConversationState>>(() => {
    // Initialize from localStorage on mount
    return loadConversationsFromStorage();
  });

  // Load recipients from localStorage and ensure all stored recipients have conversation entries
  useEffect(() => {
    const storedRecipients = loadRecipientsFromStorage();
    if (storedRecipients.length > 0) {
      setConversations(prev => {
        const newMap = new Map(prev);
        storedRecipients.forEach(address => {
          if (!newMap.has(address)) {
            newMap.set(address, {
              recipientAddress: address,
              status: 'none',
              messages: []
            });
          }
        });
        return newMap;
      });
    }
  }, []);

  // Save conversations to localStorage whenever they change
  useEffect(() => {
    saveConversationsToStorage(conversations);
  }, [conversations]);
  
  const getConversation = useCallback((recipientAddress: string): ConversationState => {
    const normalizedAddress = recipientAddress.toLowerCase();
    const existing = conversations.get(normalizedAddress);
    return existing || {
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

  const addRecipient = useCallback((recipientAddress: string) => {
    const normalizedAddress = recipientAddress.toLowerCase();
    
    // Validate Ethereum address format
    if (!/^0x[a-fA-F0-9]{40}$/.test(recipientAddress)) {
      throw new Error('Invalid Ethereum address format');
    }
    
    // Add to localStorage
    addRecipientToStorage(normalizedAddress);
    
    // Add to conversations if not already present
    setConversations(prev => {
      const newMap = new Map(prev);
      if (!newMap.has(normalizedAddress)) {
        newMap.set(normalizedAddress, {
          recipientAddress: normalizedAddress,
          status: 'none',
          messages: []
        });
      }
      return newMap;
    });
    
    return normalizedAddress;
  }, []);

  const removeRecipient = useCallback((recipientAddress: string) => {
    const normalizedAddress = recipientAddress.toLowerCase();
    
    // Remove from localStorage
    const recipients = loadRecipientsFromStorage();
    const filteredRecipients = recipients.filter(addr => addr !== normalizedAddress);
    saveRecipientsToStorage(filteredRecipients);
    
    // Remove from conversations
    setConversations(prev => {
      const newMap = new Map(prev);
      newMap.delete(normalizedAddress);
      return newMap;
    });
  }, []);

  const clearAllRecipients = useCallback(() => {
    // Clear localStorage
    try {
      localStorage.removeItem(STORAGE_KEYS.RECIPIENTS);
      localStorage.removeItem(STORAGE_KEYS.CONVERSATIONS);
    } catch (error) {
      console.warn('Failed to clear recipients from localStorage:', error);
    }
    
    // Clear state
    setConversations(new Map());
  }, []);

  const getStoredRecipients = useCallback((): string[] => {
    return loadRecipientsFromStorage();
  }, []);

  const sendMessage = useCallback(async (options: MessageOptions) => {
    const { contract, recipientAddress, message, senderAddress, senderSignKeyPair, walletClient, topic } = options;
    const conversation = getConversation(recipientAddress);
    const timestamp = Math.floor(Date.now() / 1000);
    const defaultTopic = topic || "0x" + "00".repeat(32);
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
    userAddress: string
  ) => {
    try {
      // Find the conversation that initiated the handshake
      const conversations_array = Array.from(conversations.values());
      const initiatedConversation = conversations_array.find(conv => 
        conv.status === 'initiated' && conv.ephemeralKeys?.ourEphemeralPrivateKey
      );

      if (!initiatedConversation || !initiatedConversation.ephemeralKeys?.ourEphemeralPrivateKey) {
        console.warn('No matching initiated conversation found for handshake response');
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

      console.log('Successfully decrypted handshake response:', decryptedResponse);

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