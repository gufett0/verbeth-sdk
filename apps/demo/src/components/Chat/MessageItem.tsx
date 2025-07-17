// apps/demo/src/components/Chat/MessageItem.tsx
import React from 'react';
import { MessageDisplay } from '../../types/index.js';

interface MessageItemProps {
  message: MessageDisplay;
  className?: string;
}

export function MessageItem({ message, className = '' }: MessageItemProps) {
  const isOutgoing = message.direction === 'outgoing';
  const isSystem = message.direction === 'system';

  if (isSystem) {
    return (
      <div className={`flex justify-center ${className}`}>
        <div className="bg-gray-700 text-gray-300 text-xs px-3 py-1 rounded-full max-w-xs text-center">
          {message.content}
        </div>
      </div>
    );
  }

  return (
    <div className={`flex ${isOutgoing ? 'justify-end' : 'justify-start'} ${className}`}>
      <div
        className={`max-w-xs lg:max-w-md px-4 py-2 rounded-2xl ${
          isOutgoing
            ? 'bg-blue-600 text-white rounded-br-sm'
            : 'bg-gray-700 text-white rounded-bl-sm'
        }`}
      >
        
        {/* Message Content */}
        <div className="break-words">
          {message.encrypted && !message.content ? (
            <div className="flex items-center space-x-2 text-gray-300">
              <span className="text-sm">🔒</span>
              <span className="text-sm italic">Encrypted message</span>
            </div>
          ) : (
            <p className="text-sm">{message.content}</p>
          )}
        </div>

        {/* Message Metadata */}
        <div className={`flex items-center justify-between mt-1 text-xs ${
          isOutgoing ? 'text-blue-100' : 'text-gray-400'
        }`}>
          <span>
            {new Date(message.timestamp).toLocaleTimeString([], { 
              hour: '2-digit', 
              minute: '2-digit' 
            })}
          </span>
          
          <div className="flex items-center space-x-1 ml-2">
            {/* Verification Status */}
            {message.verified && (
              <span title="Identity verified">✅</span>
            )}
            
            {/* Read Status for outgoing messages */}
            {isOutgoing && (
              <span title={message.read ? 'Read' : 'Sent'}>
                {message.read ? '✓✓' : '✓'}
              </span>
            )}
            
            {/* Message Status */}
            {message.status === 'pending' && (
              <span className="animate-pulse" title="Sending...">⏳</span>
            )}
            {message.status === 'failed' && (
              <span title="Failed to send">❌</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}