// apps/demo/src/components/Chat/MessageList.tsx
import React from 'react';
import { MessageDisplay } from '../../types/index.js';
import { MessageItem } from './MessageItem.js';

interface MessageListProps {
  messages: MessageDisplay[];
  isLoading: boolean;
  canLoadMore: boolean;
  onLoadMore: () => void;
  className?: string;
}

export function MessageList({
  messages,
  isLoading,
  canLoadMore,
  onLoadMore,
  className = ''
}: MessageListProps) {

  return (
    <div className={`flex flex-col ${className}`}>
      
      {/* Load More History Button */}
      {canLoadMore && (
        <div className="text-center py-2 border-b border-gray-800">
          <button
            onClick={onLoadMore}
            disabled={isLoading}
            className="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:cursor-not-allowed rounded transition-colors"
          >
            {isLoading ? (
              <div className="flex items-center space-x-2">
                <div className="animate-spin w-3 h-3 border border-gray-400 border-t-transparent rounded-full"></div>
                <span>Loading...</span>
              </div>
            ) : (
              '📂 Load More History'
            )}
          </button>
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {messages.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            <div className="text-4xl mb-4">💭</div>
            <p className="text-sm">No messages yet</p>
            <p className="text-xs mt-1">Start the conversation!</p>
          </div>
        ) : (
          messages.map((message, index) => {
            // Check if this message is from a different day than the previous one
            const showDateSeparator = index === 0 || 
              new Date(message.timestamp).toDateString() !== 
              new Date(messages[index - 1].timestamp).toDateString();

            return (
              <React.Fragment key={message.id}>
                {showDateSeparator && (
                  <div className="flex justify-center py-2">
                    <span className="text-xs text-gray-500 bg-gray-800 px-3 py-1 rounded-full">
                      {new Date(message.timestamp).toLocaleDateString()}
                    </span>
                  </div>
                )}
                <MessageItem message={message} />
              </React.Fragment>
            );
          })
        )}
      </div>
    </div>
  );
}