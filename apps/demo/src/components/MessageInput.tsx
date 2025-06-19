// apps/helios-demo/src/components/MessageInput.tsx
import { useState } from 'react';
import { WalletClient } from 'viem';
import nacl from 'tweetnacl';
import { useConversationManager } from '../hooks/useConversationManager';
import type { LogChainV1 } from '@verbeth/contracts/typechain-types';

interface MessageInputProps {
  contract: LogChainV1;
  senderAddress: string;
  senderSignKeyPair: nacl.SignKeyPair;
  recipientAddress: string;
  walletClient: WalletClient; 
  onMessageSent?: (result: any) => void;
  onError?: (error: any) => void;
  disabled?: boolean;
}

export function MessageInput({
  contract,
  senderAddress,
  senderSignKeyPair,
  recipientAddress,
  walletClient, 
  onMessageSent,
  onError,
  disabled = false
}: MessageInputProps) {
  const [message, setMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { sendMessage, getConversation } = useConversationManager();

  const handleSend = async () => {
    if (!message.trim() || isLoading || disabled) return;

    setIsLoading(true);
    try {
      const result = await sendMessage({
        contract,
        recipientAddress,
        message: message.trim(),
        senderAddress,
        senderSignKeyPair,
        walletClient 
      });

      setMessage('');
      onMessageSent?.(result);
    } catch (error) {
      onError?.(error);
    } finally {
      setIsLoading(false);
    }
  };

  const conversation = getConversation(recipientAddress);
  const getPlaceholderText = () => {
    switch (conversation.status) {
      case 'none':
        return 'Start a new conversation (will initiate handshake)...';
      case 'initiated':
        return 'Handshake pending - wait for response...';
      case 'established':
        return 'Type your encrypted message...';
      default:
        return 'Type your message...';
    }
  };

  const getButtonText = () => {
    if (isLoading) return 'Sending...';
    switch (conversation.status) {
      case 'none':
        return 'Start Conversation';
      case 'initiated':
        return 'Handshake Pending';
      case 'established':
        return 'Send Message';
      default:
        return 'Send';
    }
  };

  const isButtonDisabled = disabled || !message.trim() || isLoading || conversation.status === 'initiated';

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-gray-900">Send Message</h2>
        {conversation.status !== 'none' && (
          <div className={`px-2 py-1 text-xs rounded-full ${
            conversation.status === 'established' 
              ? 'bg-green-100 text-green-800' 
              : 'bg-yellow-100 text-yellow-800'
          }`}>
            {conversation.status === 'established' ? 'Secure' : 'Pending'}
          </div>
        )}
      </div>
      
      <div className="space-y-4">
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder={getPlaceholderText()}
          className="w-full p-3 border border-gray-300 rounded-lg resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          rows={3}
          disabled={disabled || isLoading || conversation.status === 'initiated'}
        />
        
        <button
          onClick={handleSend}
          disabled={isButtonDisabled}
          className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {getButtonText()}
        </button>
      </div>
    </div>
  );
}