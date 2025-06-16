// apps/helios-demo/src/hooks/useConversationManager.ts
import { useState, useCallback } from 'react';
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

export function useConversationManager() {
  const [conversations, setConversations] = useState<Map<string, ConversationState>>(new Map());
  
  const getConversation = useCallback((recipientAddress: string): ConversationState => {
    const existing = conversations.get(recipientAddress.toLowerCase());
    return existing || {
      recipientAddress: recipientAddress.toLowerCase(),
      status: 'none'
    };
  }, [conversations]);

  const updateConversation = useCallback((recipientAddress: string, updates: Partial<ConversationState>) => {
    setConversations(prev => {
      const newMap = new Map(prev);
      const existing = newMap.get(recipientAddress.toLowerCase()) || { 
        recipientAddress: recipientAddress.toLowerCase(), 
        status: 'none' as const 
      };
      newMap.set(recipientAddress.toLowerCase(), { ...existing, ...updates });
      return newMap;
    });
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
    sendMessage,
    handleHandshakeResponse,
    respondToIncomingHandshake
  };
}