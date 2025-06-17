// apps/helios-demo/src/hooks/useConversationManager.ts
import { useState, useCallback, useEffect } from 'react';
import { Contract } from 'ethers';
import nacl from 'tweetnacl';
import { 
  initiateHandshake, 
  respondToHandshake, 
  sendEncryptedMessage 
} from '@verbeth/sdk';
import type { LogChainV1 } from '@verbeth/contracts/typechain-types';

interface ConversationState {
  recipientAddress: string;
  recipientPubKey?: Uint8Array;
  status: 'none' | 'initiated' | 'established';
  lastMessageTime?: number;
}

interface MessageOptions {
  contract: LogChainV1;
  recipientAddress: string;
  message: string;
  senderAddress: string;
  senderSignKeyPair: nacl.SignKeyPair;
  topic?: string;
}

// localStorage keys
const STORAGE_KEYS = {
  RECIPIENTS: 'verbeth_recipients',
  CONVERSATIONS: 'verbeth_conversations'
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
      
      // Reconstruct conversations but reset ephemeral data (recipientPubKey)
      // since it cannot be safely serialized/deserialized
      Object.entries(conversationsData).forEach(([address, state]: [string, any]) => {
        conversationsMap.set(address, {
          recipientAddress: address,
          status: state.status === 'established' ? 'none' : state.status, // Reset established connections
          lastMessageTime: state.lastMessageTime,
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
      // Store minimal conversation data (exclude recipientPubKey)
      conversationsData[address] = {
        recipientAddress: state.recipientAddress,
        status: state.status,
        lastMessageTime: state.lastMessageTime,
        // Note: recipientPubKey intentionally excluded as it needs fresh exchange
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
              status: 'none'
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
      status: 'none'
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
        status: 'none' as const 
      };
      newMap.set(normalizedAddress, { ...existing, ...updates });
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
          status: 'none'
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
    const { contract, recipientAddress, message, senderAddress, senderSignKeyPair, topic } = options;
    const conversation = getConversation(recipientAddress);
    const timestamp = Math.floor(Date.now() / 1000);
    const defaultTopic = topic || "0x" + "00".repeat(32);

    try {
      switch (conversation.status) {
        case 'none':
          // First message - initiate handshake
          const identityPubKey = nacl.box.keyPair().publicKey; // TODO: derive from Ethereum address
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
            lastMessageTime: timestamp
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

          return { type: 'message_sent', success: true };

        case 'initiated':
          // Waiting for handshake response - could resend or wait
          throw new Error('Handshake pending. Wait for recipient response before sending more messages.');

        default:
          throw new Error('Unknown conversation status');
      }
    } catch (error) {
      console.error('Failed to send message:', error);
      throw error;
    }
  }, [getConversation, updateConversation]);

  const handleHandshakeResponse = useCallback(async (
    recipientAddress: string,
    recipientPubKey: Uint8Array
  ) => {
    updateConversation(recipientAddress, {
      status: 'established',
      recipientPubKey
    });
  }, [updateConversation]);

  const respondToIncomingHandshake = useCallback(async (options: {
    contract: LogChainV1;
    inResponseTo: string;
    initiatorAddress: string;
    initiatorPubKey: Uint8Array;
    responseMessage?: string;
    senderSignKeyPair: nacl.SignKeyPair;
  }) => {
    const { 
      contract, 
      inResponseTo, 
      initiatorAddress, 
      initiatorPubKey, 
      responseMessage,
      senderSignKeyPair 
    } = options;

    try {
      const responderIdentityPubKey = nacl.box.keyPair().publicKey; // TODO: derive from Ethereum address
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
      updateConversation(initiatorAddress, {
        status: 'established',
        recipientPubKey: initiatorPubKey,
        lastMessageTime: Math.floor(Date.now() / 1000)
      });

      return { success: true };
    } catch (error) {
      console.error('Failed to respond to handshake:', error);
      throw error;
    }
  }, [updateConversation]);

  return {
    conversations: Array.from(conversations.values()),
    getConversation,
    addRecipient,
    removeRecipient,
    clearAllRecipients,
    getStoredRecipients,
    sendMessage,
    handleHandshakeResponse,
    respondToIncomingHandshake
  };
}