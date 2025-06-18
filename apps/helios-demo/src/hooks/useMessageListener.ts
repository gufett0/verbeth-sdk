// Enhanced useMessageListener with improved error handling and HandshakeResponse support
import { useEffect, useCallback, useRef } from 'react';
import { BrowserProvider, keccak256, toUtf8Bytes, AbiCoder } from 'ethers';
import { useConversationManager } from './useConversationManager';
import { 
  decodeHandshakePayload, 
  decryptHandshakeResponse,
  decryptMessage,
  parseHandshakePayload 
} from '@verbeth/sdk';

interface MessageListenerProps {
  readProvider: BrowserProvider | null;
  userAddress: string | null;
  onIncomingMessage?: (message: any) => void;
  onIncomingHandshake?: (handshake: any) => void;
  onIncomingHandshakeResponse?: (response: any) => void;
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
  onIncomingHandshake,
  onIncomingHandshakeResponse
}: MessageListenerProps) {
  const { handleHandshakeResponse, updateConversation } = useConversationManager();
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
          try {
            // Use SDK functions to decode handshake
            const abiCoder = new AbiCoder();
            const decoded = abiCoder.decode(['bytes', 'bytes', 'bytes'], log.data);
            const [identityPubKeyBytes, ephemeralPubKeyBytes, plaintextPayloadBytes] = decoded;
            
            // Convert hex to Uint8Array
            const identityPubKey = hexToUint8Array(identityPubKeyBytes);
            const ephemeralPubKey = hexToUint8Array(ephemeralPubKeyBytes);
            const plaintextPayloadStr = hexToString(plaintextPayloadBytes);
            
            // Parse using SDK function
            const handshakeContent = parseHandshakePayload(plaintextPayloadStr);
            
            // Clean sender address
            const cleanSenderAddress = topics[2].replace(/^0x0+/, '0x');
            
            const handshakeWithParsedData = {
              ...log,
              type: 'handshake',
              sender: cleanSenderAddress,
              timestamp: Date.now(),
              blockNumber: log.blockNumber,
              transactionHash: log.transactionHash,
              // Store structured data using SDK format
              identityPubKey: Array.from(identityPubKey),
              ephemeralPubKey: Array.from(ephemeralPubKey),
              plaintextPayload: handshakeContent.plaintextPayload,
              handshakeContent, // Full parsed content including identityProof if present
              // Store raw data for reconstruction
              rawData: {
                identityPubKeyBytes,
                ephemeralPubKeyBytes,
                plaintextPayloadBytes
              }
            };
            
            onIncomingHandshake?.(handshakeWithParsedData);
          } catch (error) {
            console.error('Failed to parse handshake using SDK:', error);
          }
        }
      }
      
      else if (eventSignature === EVENT_SIGNATURES.HandshakeResponse) {
        if (!userAddress) return;
        
        console.log('🔄 HandshakeResponse detected:', log);
        
        try {
          const abiCoder = new AbiCoder();
          const decoded = abiCoder.decode(['bytes'], log.data);
          const [ciphertextBytes] = decoded;
          
          // Convert to string for SDK decryption
          const ciphertextJson = hexToString(ciphertextBytes);
          const inResponseTo = topics[1]; // Transaction hash this responds to
          const responderAddress = topics[2].replace(/^0x0+/, '0x');
          
          console.log('HandshakeResponse details:', {
            inResponseTo,
            responderAddress,
            ciphertextLength: ciphertextJson.length
          });
          
          const handshakeResponseData = {
            type: 'handshake_response',
            inResponseTo,
            responder: responderAddress,
            ciphertextJson,
            timestamp: Date.now(),
            blockNumber: log.blockNumber,
            transactionHash: log.transactionHash,
            rawData: {
              ciphertextBytes
            }
          };
          
          // Update conversation state to established if this response is for us
          // Note: We need to check if the original handshake was sent by us
          updateConversation(responderAddress, {
            status: 'established',
            lastMessageTime: Math.floor(Date.now() / 1000)
          });
          
          onIncomingHandshakeResponse?.(handshakeResponseData);
        } catch (error) {
          console.error('Failed to parse handshake response:', error);
        }
      }
      
    } catch (error) {
      console.error('Error processing log:', error);
    }
  }, [onIncomingMessage, onIncomingHandshake, onIncomingHandshakeResponse, handleHandshakeResponse, userAddress, updateConversation]);

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

// Helper functions to convert hex to proper types using SDK patterns
function hexToUint8Array(hexValue: string): Uint8Array {
  if (typeof hexValue === 'string' && hexValue.startsWith('0x')) {
    const hexString = hexValue.slice(2);
    const matchResult = hexString.match(/.{2}/g);
    if (!matchResult) {
      throw new Error("Failed to parse hex string into bytes");
    }
    return new Uint8Array(matchResult.map(byte => parseInt(byte, 16)));
  } else {
    throw new Error(`Expected hex string, got: ${typeof hexValue}`);
  }
}

function hexToString(hexValue: string): string {
  if (typeof hexValue === 'string' && hexValue.startsWith('0x')) {
    const hexString = hexValue.slice(2);
    const matchResult = hexString.match(/.{2}/g);
    if (!matchResult) {
      throw new Error("Failed to parse hex string into bytes");
    }
    const bytes = new Uint8Array(matchResult.map(byte => parseInt(byte, 16)));
    return new TextDecoder().decode(bytes);
  } else {
    throw new Error(`Expected hex string, got: ${typeof hexValue}`);
  }
}