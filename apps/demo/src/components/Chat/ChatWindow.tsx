// apps/demo/src/components/Chat/ChatWindow.tsx
import React, { useState, useRef, useEffect } from 'react';
import { ContactDisplay, MessageDisplay } from '../../types/index.js';
import { MessageList } from './MessageList.js';
import { MessageInput } from './MessageInput.js';

interface ChatWindowProps {
  selectedContact: ContactDisplay | null;
  messages: MessageDisplay[];
  isLoadingMessages: boolean;
  canLoadMore: boolean;
  onLoadMore: () => void;
  onSendMessage: (content: string) => Promise<void>;
  onMarkAsRead: (contactAddress: string) => void;
  className?: string;
}

export function ChatWindow({
  selectedContact,
  messages,
  isLoadingMessages,
  canLoadMore,
  onLoadMore,
  onSendMessage,
  onMarkAsRead,
  className = ''
}: ChatWindowProps) {
  const [isSending, setIsSending] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Mark messages as read when contact is selected
  useEffect(() => {
    if (selectedContact && selectedContact.unreadCount > 0) {
      onMarkAsRead(selectedContact.address);
    }
  }, [selectedContact, onMarkAsRead]);

  const handleSendMessage = async (content: string) => {
    if (!selectedContact || isSending) return;

    setIsSending(true);
    try {
      await onSendMessage(content);
    } catch (error) {
      console.error('Failed to send message:', error);
    } finally {
      setIsSending(false);
    }
  };

  if (!selectedContact) {
    return (
      <div className={`flex flex-col h-96 ${className}`}>
        <div className="border border-gray-800 rounded-lg p-4 flex-1 flex items-center justify-center">
          <div className="text-center text-gray-400">
            <div className="text-6xl mb-4">💬</div>
            <h3 className="text-lg font-semibold mb-2">Select a contact</h3>
            <p className="text-sm">Choose a contact to start messaging</p>
          </div>
        </div>
      </div>
    );
  }

  const isEstablished = selectedContact.status === 'established';
  const contactMessages = messages.filter(msg => 
    msg.sender.toLowerCase() === selectedContact.address.toLowerCase() ||
    (msg.direction === 'outgoing' && selectedContact)
  );

  return (
    <div className={`flex flex-col h-96 ${className}`}>
      <div className="border border-gray-800 rounded-lg flex flex-col h-full">
        
        {/* Chat Header */}
        <div className="border-b border-gray-800 p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center text-white font-semibold">
                {selectedContact.address.slice(2, 4).toUpperCase()}
              </div>
              <div>
                <h3 className="font-semibold text-white">
                  {selectedContact.name || `${selectedContact.address.slice(0, 8)}...`}
                </h3>
                <div className="flex items-center space-x-2 text-xs">
                  <span className={`px-2 py-1 rounded ${
                    selectedContact.status === 'established'
                      ? 'bg-green-800 text-green-200'
                      : selectedContact.status === 'handshake_sent'
                        ? 'bg-yellow-800 text-yellow-200'
                        : 'bg-gray-700 text-gray-300'
                  }`}>
                    {selectedContact.status.replace('_', ' ')}
                  </span>
                  {selectedContact.unreadCount > 0 && (
                    <span className="bg-blue-600 text-white px-2 py-1 rounded-full text-xs">
                      {selectedContact.unreadCount}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Messages Area */}
        <div className="flex-1 flex flex-col min-h-0">
          {isEstablished ? (
            <>
              <MessageList
                messages={contactMessages}
                isLoading={isLoadingMessages}
                canLoadMore={canLoadMore}
                onLoadMore={onLoadMore}
                className="flex-1"
              />
              <div ref={messagesEndRef} />
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center p-8">
              <div className="text-center text-gray-400">
                <div className="text-4xl mb-4">🤝</div>
                <h4 className="font-semibold mb-2">Handshake Required</h4>
                <p className="text-sm">
                  {selectedContact.status === 'handshake_sent' 
                    ? 'Waiting for contact to accept handshake...'
                    : 'Complete the handshake before sending messages'
                  }
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Message Input */}
        {isEstablished && (
          <div className="border-t border-gray-800 p-4">
            <MessageInput
              onSendMessage={handleSendMessage}
              disabled={isSending}
              placeholder="Type a message..."
            />
          </div>
        )}
      </div>
    </div>
  );
}