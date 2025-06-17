// Enhanced useMessageListener with improved error handling
import { useEffect, useCallback, useRef } from 'react';
import { BrowserProvider, keccak256, toUtf8Bytes } from 'ethers';
import { useConversationManager } from './useConversationManager';

interface MessageListenerProps {
  readProvider: BrowserProvider | null;
  userAddress: string | null;
  onIncomingMessage?: (message: any) => void;
  onIncomingHandshake?: (handshake: any) => void;
}

const EVENT_SIGNATURES = {
  MessageSent: keccak256(toUtf8Bytes("MessageSent(address,bytes,uint256,bytes32,uint256)")),
  Handshake: keccak256(toUtf8Bytes("Handshake(bytes32,address,bytes,bytes,bytes)")),
  HandshakeResponse: keccak256(toUtf8Bytes("HandshakeResponse(bytes32,address,bytes)"))
};

const LOGCHAIN_ADDR = '0xf9fe7E57459CC6c42791670FaD55c1F548AE51E8';

export function useMessageListener({
  readProvider,
  userAddress,
  onIncomingMessage,
  onIncomingHandshake
}: MessageListenerProps) {
  const { handleHandshakeResponse } = useConversationManager();
  const processedLogs = useRef(new Set<string>());
  const lastScannedBlock = useRef<number>(0);

  const handleNewLog = useCallback(async (log: any) => {
    try {
      // Prevent duplicate processing
      const logKey = `${log.transactionHash}-${log.logIndex}`;
      if (processedLogs.current.has(logKey)) return;
      processedLogs.current.add(logKey);

      const topics = log.topics;
      if (!topics || topics.length === 0) return;

      const eventSignature = topics[0];
      
      if (eventSignature === EVENT_SIGNATURES.MessageSent) {
        console.log('📨 MessageSent detected:', log);
        onIncomingMessage?.({
          type: 'message',
          sender: log.address,
          data: log.data,
          timestamp: Date.now(),
          blockNumber: log.blockNumber
        });
      }
      
      else if (eventSignature === EVENT_SIGNATURES.Handshake) {
        if (!userAddress) return;
        
        const recipientHash = topics[1];
        const expectedHash = calculateRecipientHash(userAddress);
        
        console.log('🤝 Handshake detected:', {
          recipientHash,
          expectedHash,
          isForMe: recipientHash === expectedHash,
          sender: topics[2],
          block: log.blockNumber
        });
        
        if (recipientHash === expectedHash) {
          onIncomingHandshake?.({
            type: 'handshake',
            sender: topics[2],
            data: log.data,
            timestamp: Date.now(),
            recipientHash,
            blockNumber: log.blockNumber,
            transactionHash: log.transactionHash
          });
        }
      }
      
      else if (eventSignature === EVENT_SIGNATURES.HandshakeResponse) {
        console.log('🔄 HandshakeResponse detected:', log);
        const inResponseTo = topics[1];
        // Handle response logic here
      }
      
    } catch (error) {
      console.error('Error processing log:', error);
    }
  }, [onIncomingMessage, onIncomingHandshake, handleHandshakeResponse, userAddress]);

  // Scan historical logs with improved error handling
  const scanHistoricalLogs = useCallback(async () => {
    if (!readProvider || !userAddress) return;

    try {
      const currentBlock = await readProvider.getBlockNumber();
      let fromBlock = Math.max(currentBlock - 100, 0);
      
      console.log(`🔍 Scanning historical logs from block ${fromBlock} to ${currentBlock}`);
      
      // Try with full range first
      try {
        const filter = {
          address: LOGCHAIN_ADDR,
          fromBlock,
          toBlock: currentBlock,
          topics: [
            [EVENT_SIGNATURES.MessageSent, EVENT_SIGNATURES.Handshake, EVENT_SIGNATURES.HandshakeResponse]
          ]
        };
        
        const historicalLogs = await readProvider.getLogs(filter);
        console.log(`📜 Found ${historicalLogs.length} historical logs`);
        
        for (const log of historicalLogs) {
          await handleNewLog(log);
        }
        
        lastScannedBlock.current = currentBlock;
      } catch (receiptError) {
        console.warn('⚠️ Full range scan failed, trying smaller chunks...', receiptError);
        
        // Fallback: scan in smaller chunks
        const chunkSize = 20;
        let scannedLogs = 0;
        
        for (let start = fromBlock; start <= currentBlock; start += chunkSize) {
          try {
            const end = Math.min(start + chunkSize - 1, currentBlock);
            const filter = {
              address: LOGCHAIN_ADDR,
              fromBlock: start,
              toBlock: end,
              topics: [
                [EVENT_SIGNATURES.MessageSent, EVENT_SIGNATURES.Handshake, EVENT_SIGNATURES.HandshakeResponse]
              ]
            };
            
            const chunkLogs = await readProvider.getLogs(filter);
            
            for (const log of chunkLogs) {
              await handleNewLog(log);
            }
            
            scannedLogs += chunkLogs.length;
          } catch (chunkError) {
            console.warn(`⚠️ Failed to scan chunk ${start}-${Math.min(start + chunkSize - 1, currentBlock)}:`, chunkError);
            // Continue with next chunk
          }
        }
        
        console.log(`📜 Fallback scan completed: ${scannedLogs} logs found`);
        lastScannedBlock.current = currentBlock;
      }
      
    } catch (error) {
      console.error('Error scanning historical logs:', error);
      // Set a conservative last scanned block to avoid infinite retries
      if (!lastScannedBlock.current) {
        try {
          const currentBlock = await readProvider.getBlockNumber();
          lastScannedBlock.current = currentBlock;
        } catch (blockError) {
          console.error('Failed to get current block number:', blockError);
        }
      }
    }
  }, [readProvider, userAddress, handleNewLog]);

  useEffect(() => {
    if (!readProvider || !userAddress) return;

    let isListening = true;

    const startListening = async () => {
      try {
        // First scan historical logs
        await scanHistoricalLogs();

        // Then listen for new blocks
        readProvider.on('block', async (blockNumber: number) => {
          if (!isListening) return;
          
          try {
            // Only scan blocks we haven't seen yet
            if (blockNumber <= lastScannedBlock.current) return;
            
            const filter = {
              address: LOGCHAIN_ADDR,
              fromBlock: blockNumber,
              toBlock: blockNumber
            };
            
            const logs = await readProvider.getLogs(filter);
            
            if (logs.length > 0) {
              console.log(`🆕 Found ${logs.length} new logs in block ${blockNumber}`);
            }
            
            for (const log of logs) {
              await handleNewLog(log);
            }
            
            lastScannedBlock.current = blockNumber;
          } catch (error) {
            console.error('Error fetching logs for block:', blockNumber, error);
            // Don't fail completely, just log and continue
          }
        });
        
        console.log('✅ Started listening for VerbEth messages');
      } catch (error) {
        console.error('❌ Failed to start message listener:', error);
      }
    };

    startListening();

    return () => {
      isListening = false;
      readProvider.removeAllListeners('block');
      processedLogs.current.clear();
      console.log('🛑 Stopped listening for VerbEth messages');
    };
  }, [readProvider, userAddress, handleNewLog, scanHistoricalLogs]);
}

export function calculateRecipientHash(address: string): string {
  return keccak256(toUtf8Bytes('contact:' + address.toLowerCase()));
}