// apps/helios-demo/src/components/ConversationList.tsx
import { useState } from 'react';
import { useConversationManager } from '../hooks/useConversationManager';

interface ConversationListProps {
  selectedRecipient: string;
  onRecipientSelect: (recipient: string) => void;
}

export function ConversationList({ selectedRecipient, onRecipientSelect }: ConversationListProps) {
  const [newRecipient, setNewRecipient] = useState('');
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const { 
    conversations, 
    addRecipient, 
    removeRecipient, 
    clearAllRecipients,
    getStoredRecipients 
  } = useConversationManager();

  const handleAddRecipient = () => {
    if (!newRecipient.trim()) return;
    
    try {
      const normalizedAddress = addRecipient(newRecipient.trim());
      onRecipientSelect(normalizedAddress);
      setNewRecipient('');
    } catch (error) {
      alert(error instanceof Error ? error.message : 'Please enter a valid Ethereum address');
    }
  };

  const handleRemoveRecipient = (recipientAddress: string, event: React.MouseEvent) => {
    event.stopPropagation(); // Prevent selecting the conversation
    
    if (confirm(`Remove ${formatAddress(recipientAddress)} from your contacts?`)) {
      removeRecipient(recipientAddress);
      
      // If this was the selected recipient, clear selection
      if (selectedRecipient === recipientAddress) {
        onRecipientSelect('');
      }
    }
  };

  const handleClearAll = () => {
    if (showClearConfirm) {
      clearAllRecipients();
      onRecipientSelect('');
      setShowClearConfirm(false);
    } else {
      setShowClearConfirm(true);
      // Auto-hide confirmation after 3 seconds
      setTimeout(() => setShowClearConfirm(false), 3000);
    }
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

  const storedRecipients = getStoredRecipients();

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-gray-900">Conversations</h2>
        {conversations.length > 0 && (
          <button
            onClick={handleClearAll}
            className={`text-xs px-2 py-1 rounded transition-colors ${
              showClearConfirm 
                ? 'bg-red-100 text-red-800 hover:bg-red-200' 
                : 'text-gray-500 hover:text-red-600'
            }`}
            title={showClearConfirm ? 'Click again to confirm' : 'Clear all contacts'}
          >
            {showClearConfirm ? 'Confirm Clear All' : 'Clear All'}
          </button>
        )}
      </div>
      
      {/* Add new recipient */}
      <div className="mb-4 space-y-2">
        <div className="relative">
          <input
            type="text"
            placeholder="Enter recipient address (0x...)"
            value={newRecipient}
            onChange={(e) => setNewRecipient(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleAddRecipient()}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none font-mono text-sm"
          />
          {newRecipient && (
            <button
              onClick={() => setNewRecipient('')}
              className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
              title="Clear input"
            >
              ✕
            </button>
          )}
        </div>
        <button
          onClick={handleAddRecipient}
          disabled={!newRecipient.trim()}
          className="w-full bg-gray-600 hover:bg-gray-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white font-medium py-2 px-4 rounded-lg transition-colors text-sm"
        >
          Add Recipient
        </button>
      </div>

      {/* Storage status indicator */}
      {storedRecipients.length > 0 && (
        <div className="mb-3 text-xs text-gray-500 flex items-center gap-1">
          <span className="w-2 h-2 bg-green-400 rounded-full"></span>
          {storedRecipients.length} recipient{storedRecipients.length !== 1 ? 's' : ''} saved locally
        </div>
      )}

      {/* Conversations list */}
      <div className="space-y-2">
        {conversations.length === 0 && (
          <div className="text-center py-8">
            <div className="text-gray-400 mb-2">
              <svg className="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
              </svg>
            </div>
            <p className="text-gray-500 text-sm">
              No conversations yet.<br />
              Add a recipient to start messaging.
            </p>
          </div>
        )}
        
        {conversations.map((conversation: any) => (
          <div
            key={conversation.recipientAddress}
            onClick={() => onRecipientSelect(conversation.recipientAddress)}
            className={`
              relative group p-3 border rounded-lg cursor-pointer transition-all duration-200
              hover:border-gray-300 hover:shadow-sm
              ${selectedRecipient === conversation.recipientAddress 
                ? 'border-blue-500 bg-blue-50 shadow-sm' 
                : 'border-gray-200 hover:bg-gray-50'
              }
            `}
          >
            <div className="flex items-center justify-between">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-sm font-medium text-gray-900 truncate">
                    {formatAddress(conversation.recipientAddress)}
                  </span>
                  <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getStatusColor(conversation.status)}`}>
                    {getStatusText(conversation.status)}
                  </span>
                </div>
                {conversation.lastMessageTime && (
                  <p className="text-xs text-gray-500">
                    Last activity: {new Date(conversation.lastMessageTime * 1000).toLocaleString()}
                  </p>
                )}
              </div>
              
              {/* Remove button */}
              <button
                onClick={(e) => handleRemoveRecipient(conversation.recipientAddress, e)}
                className="opacity-0 group-hover:opacity-100 ml-2 p-1 text-gray-400 hover:text-red-600 transition-all duration-200"
                title="Remove recipient"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Quick stats */}
      {conversations.length > 0 && (
        <div className="mt-4 pt-3 border-t border-gray-100">
          <div className="flex items-center justify-between text-xs text-gray-500">
            <span>Total: {conversations.length}</span>
            <div className="flex gap-3">
              <span>Connected: {conversations.filter(c => c.status === 'established').length}</span>
              <span>Pending: {conversations.filter(c => c.status === 'initiated').length}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}