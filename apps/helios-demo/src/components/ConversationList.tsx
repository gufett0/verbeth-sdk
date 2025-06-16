// apps/helios-demo/src/components/ConversationList.tsx
import { useState } from 'react';
import { useConversationManager } from '../hooks/useConversationManager';

interface ConversationListProps {
  selectedRecipient: string;
  onRecipientSelect: (recipient: string) => void;
}

export function ConversationList({ selectedRecipient, onRecipientSelect }: ConversationListProps) {
  const [newRecipient, setNewRecipient] = useState('');
  const { conversations } = useConversationManager();

  const handleAddRecipient = () => {
    if (!newRecipient.trim()) return;
    
    // Basic validation for Ethereum address
    if (!/^0x[a-fA-F0-9]{40}$/.test(newRecipient.trim())) {
      alert('Please enter a valid Ethereum address');
      return;
    }

    onRecipientSelect(newRecipient.trim());
    setNewRecipient('');
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'established':
        return 'bg-green-100 text-green-800';
      case 'initiated':
        return 'bg-yellow-100 text-yellow-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusText = (status: string) => {
    switch (status) {
      case 'established':
        return 'Connected';
      case 'initiated':
        return 'Pending';
      default:
        return 'New';
    }
  };

  const formatAddress = (address: string) => {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  };

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6">
      <h2 className="text-lg font-semibold text-gray-900 mb-4">Conversations</h2>
      
      {/* Add new recipient */}
      <div className="mb-4 space-y-2">
        <input
          type="text"
          placeholder="Enter recipient address (0x...)"
          value={newRecipient}
          onChange={(e) => setNewRecipient(e.target.value)}
          className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none font-mono text-sm"
        />
        <button
          onClick={handleAddRecipient}
          disabled={!newRecipient.trim()}
          className="w-full bg-gray-600 hover:bg-gray-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white font-medium py-2 px-4 rounded-lg transition-colors text-sm"
        >
          Add Recipient
        </button>
      </div>

      {/* Conversations list */}
      <div className="space-y-2">
        {conversations.length === 0 && !selectedRecipient && (
          <p className="text-gray-500 text-sm text-center py-4">
            No conversations yet. Add a recipient to start messaging.
          </p>
        )}

        {/* Show selected recipient even if not in conversations yet */}
        {selectedRecipient && !conversations.find(c => c.recipientAddress === selectedRecipient.toLowerCase()) && (
          <div className="flex items-center justify-between p-3 bg-blue-50 border border-blue-200 rounded-lg">
            <div className="flex-1 min-w-0">
              <p className="font-mono text-sm text-blue-900 truncate">
                {formatAddress(selectedRecipient)}
              </p>
            </div>
            <span className="ml-2 px-2 py-1 text-xs rounded-full bg-blue-100 text-blue-800">
              Selected
            </span>
          </div>
        )}

        {conversations.map((conversation) => (
          <div
            key={conversation.recipientAddress}
            onClick={() => onRecipientSelect(conversation.recipientAddress)}
            className={`flex items-center justify-between p-3 rounded-lg cursor-pointer transition-colors ${
              selectedRecipient.toLowerCase() === conversation.recipientAddress
                ? 'bg-blue-50 border border-blue-200'
                : 'hover:bg-gray-50 border border-gray-200'
            }`}
          >
            <div className="flex-1 min-w-0">
              <p className={`font-mono text-sm truncate ${
                selectedRecipient.toLowerCase() === conversation.recipientAddress
                  ? 'text-blue-900'
                  : 'text-gray-900'
              }`}>
                {formatAddress(conversation.recipientAddress)}
              </p>
              {conversation.lastMessageTime && (
                <p className="text-xs text-gray-500 mt-1">
                  Last: {new Date(conversation.lastMessageTime * 1000).toLocaleTimeString()}
                </p>
              )}
            </div>
            <div className="ml-2 flex items-center space-x-2">
              <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(conversation.status)}`}>
                {getStatusText(conversation.status)}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}