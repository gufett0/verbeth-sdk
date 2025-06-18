// apps/helios-demo/src/components/ConversationView.tsx
import { useState, useRef, useEffect } from 'react';
import { WalletClient } from 'viem';
import nacl from 'tweetnacl';
import { useConversationManager } from '../hooks/useConversationManager';
import type { LogChainV1 } from '@verbeth/contracts/typechain-types';

interface ConversationViewProps {
  contract: LogChainV1;
  senderAddress: string;
  senderSignKeyPair: nacl.SignKeyPair;
  recipientAddress: string;
  walletClient: WalletClient;
  onClose: () => void;
  onError?: (error: any) => void;
}

interface ConversationMessage {
  id: string;
  content: string;
  timestamp: number;
  sender: string;
  type: 'outgoing' | 'incoming' | 'handshake' | 'system';
  status?: 'sending' | 'sent' | 'failed';
}

export function ConversationView({
  contract,
  senderAddress,
  senderSignKeyPair,
  recipientAddress,
  walletClient,
  onClose,
  onError
}: ConversationViewProps) {
  const [message, setMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const { sendMessage, getConversation } = useConversationManager();

  const conversation = getConversation(recipientAddress);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [conversation.messages]);

  const handleSend = async () => {
    if (!message.trim() || isLoading) return;

    setIsLoading(true);
    try {
      await sendMessage({
        contract,
        recipientAddress,
        message: message.trim(),
        senderAddress,
        senderSignKeyPair,
        walletClient
      });

      setMessage('');
    } catch (error) {
      onError?.(error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const formatTime = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleTimeString([], { 
      hour: '2-digit', 
      minute: '2-digit' 
    });
  };

  const formatAddress = (address: string) => {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  };

  const getStatusIcon = (status?: string) => {
    switch (status) {
      case 'sending':
        return <span className="text-gray-400">⏳</span>;
      case 'sent':
        return <span className="text-blue-500">✓</span>;
      case 'failed':
        return <span className="text-red-500">❌</span>;
      default:
        return null;
    }
  };

  const getConnectionStatusColor = (status: string) => {
    switch (status) {
      case 'established':
        return 'text-green-600';
      case 'initiated':
        return 'text-yellow-600';
      default:
        return 'text-gray-600';
    }
  };

  const getConnectionStatusText = (status: string) => {
    switch (status) {
      case 'established':
        return 'End-to-end encrypted';
      case 'initiated':
        return 'Handshake pending';
      default:
        return 'Not connected';
    }
  };

  const isInputDisabled = conversation.status === 'initiated' || isLoading;

  return (
    <div className="flex flex-col h-full bg-white rounded-xl border border-gray-200 overflow-hidden">
      {/* Header */}
      <div className="bg-gray-50 border-b border-gray-200 p-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <button
            onClick={onClose}
            className="p-1 hover:bg-gray-200 rounded-lg transition-colors"
            title="Close conversation"
          >
            <svg className="w-5 h-5 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </button>
          <div>
            <h3 className="font-medium text-gray-900 font-mono">
              {formatAddress(recipientAddress)}
            </h3>
            <p className={`text-xs ${getConnectionStatusColor(conversation.status)}`}>
              {getConnectionStatusText(conversation.status)}
            </p>
          </div>
        </div>
        
        <div className="flex items-center space-x-2">
          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
            conversation.status === 'established' 
              ? 'bg-green-100 text-green-800' 
              : conversation.status === 'initiated'
              ? 'bg-yellow-100 text-yellow-800'
              : 'bg-gray-100 text-gray-800'
          }`}>
            {conversation.status === 'established' ? 'Connected' : 
             conversation.status === 'initiated' ? 'Pending' : 'New'}
          </span>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {conversation.messages.length === 0 && (
          <div className="text-center py-8">
            <div className="text-gray-400 mb-2">
              <svg className="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
              </svg>
            </div>
            <p className="text-gray-500 text-sm">
              Start your conversation
            </p>
          </div>
        )}

        {conversation.messages.map((msg: ConversationMessage) => {
          const isOutgoing = msg.type === 'outgoing' || msg.type === 'handshake';
          const isSystem = msg.type === 'system';
          
          if (isSystem) {
            return (
              <div key={msg.id} className="flex justify-center">
                <div className="bg-gray-100 text-gray-600 text-xs px-3 py-1 rounded-full">
                  {msg.content}
                </div>
              </div>
            );
          }

          return (
            <div key={msg.id} className={`flex ${isOutgoing ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-xs lg:max-w-md px-4 py-2 rounded-2xl ${
                isOutgoing 
                  ? 'bg-blue-500 text-white' 
                  : 'bg-gray-100 text-gray-900'
              }`}>
                {msg.type === 'handshake' && (
                  <div className="text-xs opacity-75 mb-1">
                    🤝 Handshake
                  </div>
                )}
                <p className="text-sm break-words">{msg.content}</p>
                <div className={`text-xs mt-1 flex items-center justify-between ${
                  isOutgoing ? 'text-blue-100' : 'text-gray-500'
                }`}>
                  <span>{formatTime(msg.timestamp)}</span>
                  {isOutgoing && getStatusIcon(msg.status)}
                </div>
              </div>
            </div>
          );
        })}
        <div ref={messagesEndRef} />
      </div>

      {/* Message Input */}
      <div className="border-t border-gray-200 p-4">
        {conversation.status === 'initiated' && (
          <div className="mb-3 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
            <p className="text-sm text-yellow-800">
              ⏳ Waiting for handshake response. You can't send more messages until the recipient responds.
            </p>
          </div>
        )}
        
        <div className="flex items-end space-x-2">
          <div className="flex-1">
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder={
                conversation.status === 'none' 
                  ? 'Start a new conversation (will initiate handshake)...'
                  : conversation.status === 'initiated'
                  ? 'Handshake pending - wait for response...'
                  : 'Type your encrypted message...'
              }
              className="w-full p-3 border border-gray-300 rounded-lg resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent max-h-24"
              rows={1}
              disabled={isInputDisabled}
            />
          </div>
          <button
            onClick={handleSend}
            disabled={!message.trim() || isInputDisabled}
            className="p-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
            title="Send message"
          >
            {isLoading ? (
              <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
            ) : (
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
              </svg>
            )}
          </button>
        </div>
        
        <div className="flex justify-between items-center mt-2 text-xs text-gray-500">
          <span>Press Enter to send, Shift+Enter for new line</span>
          {message.length > 0 && (
            <span>{message.length} characters</span>
          )}
        </div>
      </div>
    </div>
  );
}