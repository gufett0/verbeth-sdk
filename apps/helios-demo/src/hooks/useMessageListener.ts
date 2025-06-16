// apps/helios-demo/src/hooks/useMessageListener.ts
import { useEffect, useCallback } from 'react';
import { BrowserProvider } from 'ethers';
import { useConversationManager } from './useConversationManager';

interface MessageListenerProps {
  readProvider: BrowserProvider | null;
  userAddress: string | null;
  onIncomingMessage?: (message: any) => void;
  onIncomingHandshake?: (handshake: any) => void;
}

export function useMessageListener({
  readProvider,
  userAddress,
  onIncomingMessage,
  onIncomingHandshake
}: MessageListenerProps) {
  const { handleHandshakeResponse } = useConversationManager();

  const handleNewLog = useCallback(async (log: any) => {
    try {
      // Handle different event types based on the log structure
      const topics = log.topics;
      
      if (!topics || topics.length === 0) return;

      // Check event signature (first topic)
      const eventSignature = topics[0];
      
      // MessageSent event signature: keccak256("MessageSent(address,bytes,uint256,bytes32,uint256)")
      if (eventSignature === '0x...') { // TODO: Replace with actual signature
        onIncomingMessage?.({
          type: 'message',
          sender: log.address,
          data: log.data,
          timestamp: Date.now()
        });
      }
      
      // Handshake event signature: keccak256("Handshake(bytes32,address,bytes,bytes,bytes)")
      else if (eventSignature === '0x...') { // TODO: Replace with actual signature
        // Check if this handshake is for the current user
        const recipientHash = topics[1]; // recipientHash is indexed
        const expectedHash = `0x...`; // TODO: Calculate keccak256("contact:" + userAddress.toLowerCase())
        
        if (recipientHash === expectedHash) {
          onIncomingHandshake?.({
            type: 'handshake',
            sender: log.address,
            data: log.data,
            timestamp: Date.now()
          });
        }
      }
      
      // HandshakeResponse event signature: keccak256("HandshakeResponse(bytes32,address,bytes)")
      else if (eventSignature === '0x...') { // TODO: Replace with actual signature
        // This might be a response to our handshake
        const inResponseTo = topics[1];
        // TODO: Check if inResponseTo matches any of our pending handshakes
        // and call handleHandshakeResponse with the recipient's public key
      }
      
    } catch (error) {
      console.error('Error processing incoming log:', error);
    }
  }, [onIncomingMessage, onIncomingHandshake, handleHandshakeResponse, userAddress]);

  useEffect(() => {
    if (!readProvider || !userAddress) return;

    let isListening = true;

    const startListening = async () => {
      try {
        // Listen for new blocks and filter relevant logs
        readProvider.on('block', async (blockNumber: number) => {
          if (!isListening) return;
          
          try {
            // Get logs for this block from the LogChain contract
            const filter = {
              address: '0xf9fe7E57459CC6c42791670FaD55c1F548AE51E8', // LOGCHAIN_ADDR
              fromBlock: blockNumber,
              toBlock: blockNumber
            };
            
            const logs = await readProvider.getLogs(filter);
            
            for (const log of logs) {
              await handleNewLog(log);
            }
          } catch (error) {
            console.error('Error fetching logs for block:', blockNumber, error);
          }
        });
        
        console.log('Started listening for VerbEth messages');
      } catch (error) {
        console.error('Failed to start message listener:', error);
      }
    };

    startListening();

    return () => {
      isListening = false;
      readProvider.removeAllListeners('block');
      console.log('Stopped listening for VerbEth messages');
    };
  }, [readProvider, userAddress, handleNewLog]);
}

// Helper function to calculate recipient hash
export function calculateRecipientHash(address: string): string {
  // TODO: Implement using ethers.js keccak256 and toUtf8Bytes
  // return keccak256(toUtf8Bytes('contact:' + address.toLowerCase()));
  return '0x...'; // Placeholder
}