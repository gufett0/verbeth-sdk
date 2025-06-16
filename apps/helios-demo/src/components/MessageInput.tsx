// apps/helios-demo/src/components/MessageInput.tsx
import { useState } from 'react';
import { Contract } from 'ethers';
import nacl from 'tweetnacl';
import { useConversationManager } from '../hooks/useConversationManager';
import type { LogChainV1 } from '@verbeth/contracts/typechain-types';

interface MessageInputProps {
  contract: LogChainV1;
  senderAddress: string;
  senderSignKeyPair: nacl.SignKeyPair;
  recipientAddress: string;
  onMessageSent?: (result: any) => void;
  onError?: (error: any) => void;
  disabled?: boolean;
}

export function MessageInput({
  contract,
  senderAddress,
  senderSignKeyPair,
  recipientAddress,
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
        senderSignKeyPair
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
            {conversation.status === 'established' ? 'Connected' : 'Connecting'}
          </div>
        )}
      </div>

      <div className="space-y-4">
        <div>
          <label htmlFor="message" className="block text-sm font-medium text-gray-700 mb-2">
            Message
          </label>
          <textarea
            id="message"
            rows={4}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none resize-none"
            placeholder={getPlaceholderText()}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            disabled={disabled || conversation.status === 'initiated'}
          />
        </div>
        
        <button
          onClick={handleSend}
          disabled={isButtonDisabled}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white font-medium py-3 px-4 rounded-lg transition-colors flex items-center justify-center space-x-2"
        >
          {isLoading && (
            <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
          )}
          <span>{getButtonText()}</span>
        </button>
      </div>
    </div>
  );
}