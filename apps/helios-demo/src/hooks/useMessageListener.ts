// Enhanced useMessageListener with verification using SDK functions
import { useEffect, useCallback, useRef } from 'react';
import { BrowserProvider, keccak256, toUtf8Bytes, AbiCoder, Transaction } from 'ethers';
import { useConversationManager } from './useConversationManager';
import { 
  decodeHandshakePayload, 
  decryptHandshakeResponse,
  decryptMessage,
  parseHandshakePayload,
  verifyHandshakeIdentity
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

// Helper function to serialize transaction for verification
function serializeTransaction(tx: any): string {
  try {
    if (typeof tx === 'string') {
      return tx; // Already serialized
    }
    
    console.log('🔧 Serializing transaction:', {
      type: tx.type,
      to: tx.to,
      value: tx.value?.toString(),
      data: tx.data,
      gasLimit: tx.gasLimit?.toString(),
      nonce: tx.nonce,
      chainId: tx.chainId,
      hasSignature: !!tx.signature
    });
    
    // For EIP-1559 transactions (type 2)
    if (tx.type === 2) {
      const cleanTx = {
        type: 2,
        to: tx.to,
        value: tx.value || 0n,
        data: tx.data || '0x',
        gasLimit: tx.gasLimit,
        maxFeePerGas: tx.maxFeePerGas,
        maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
        nonce: tx.nonce,
        chainId: tx.chainId,
        accessList: tx.accessList || []
      };
      
      // Create transaction without signature first
      const unsignedTx = Transaction.from(cleanTx);
      
      // Add signature if available
      if (tx.signature) {
        unsignedTx.signature = tx.signature;
      }
      
      return unsignedTx.serialized;
    }
    
    // For legacy transactions (type 0)
    else {
      const cleanTx = {
        type: 0,
        to: tx.to,
        value: tx.value || 0n,
        data: tx.data || '0x',
        gasLimit: tx.gasLimit,
        gasPrice: tx.gasPrice,
        nonce: tx.nonce,
        chainId: tx.chainId
      };
      
      // Create transaction without signature first
      const unsignedTx = Transaction.from(cleanTx);
      
      // Add signature if available
      if (tx.signature) {
        unsignedTx.signature = tx.signature;
      }
      
      return unsignedTx.serialized;
    }
  } catch (error) {
    console.error('❌ Failed to serialize transaction:', error, {
      type: typeof tx,
      txType: tx.type,
      hasSignature: !!tx.signature,
      signature: tx.signature
    });
    return '';
  }
}

// Helper function to convert hex string to regular string
function hexToString(hexString: string): string {
  try {
    const bytes = new Uint8Array(
      hexString.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []
    );
    return new TextDecoder().decode(bytes);
  } catch {
    return hexString;
  }
}

export function useMessageListener({
  readProvider,
  userAddress,
  onIncomingMessage,
  onIncomingHandshake,
  onIncomingHandshakeResponse
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
      
      // Fetch transaction data for verification with retry
      let rawTxHex: string | null = null;
      try {
        console.log('🔍 Fetching transaction:', log.transactionHash);
        
        // First attempt
        let transaction = await readProvider?.getTransaction(log.transactionHash);
        
        // If not found, wait and retry (Helios might need time to sync)
        if (!transaction) {
          console.log('🔄 Transaction not found, retrying in 6 seconds...');
          await new Promise(resolve => setTimeout(resolve, 6000));
          transaction = await readProvider?.getTransaction(log.transactionHash);
        }
        
        // If still not found, try one more time with longer delay
        if (!transaction) {
          console.log('🔄 Transaction still not found, retrying in 15 seconds...');
          await new Promise(resolve => setTimeout(resolve, 15000));
          transaction = await readProvider?.getTransaction(log.transactionHash);
        }
        
        if (transaction) {
          console.log('📄 Transaction fetched:', {
            hash: transaction.hash,
            type: transaction.type,
            hasSignature: !!transaction.signature,
            to: transaction.to,
            from: transaction.from
          });
          rawTxHex = serializeTransaction(transaction);
          console.log('📦 Serialized transaction length:', rawTxHex?.length || 0);
        } else {
          console.warn('⚠️ Transaction not found after retries (Helios limitation):', log.transactionHash);
        }
      } catch (error) {
        console.warn('⚠️ Could not fetch transaction for verification:', error);
        // Continue processing but note that verification will be skipped
      }

      if (eventSignature === EVENT_SIGNATURES.MessageSent) {
        console.log('📨 MessageSent detected:', log);
        onIncomingMessage?.(log);
      }
      
      else if (eventSignature === EVENT_SIGNATURES.Handshake) {
        if (!userAddress) return;
        
        console.log('🤝 Handshake detected:', log);
        
        try {
          const recipientHash = topics[1];
          const senderAddress = topics[2].replace(/^0x0+/, '0x');
          
          // ⚠️ IMPORTANT: Only process handshakes NOT sent by current user
          if (senderAddress.toLowerCase() === userAddress.toLowerCase()) {
            console.log('📤 Skipping handshake sent by current user:', senderAddress);
            return;
          }
          
          // Check if this handshake is intended for current user
          const expectedRecipientHash = keccak256(toUtf8Bytes(`contact:${userAddress.toLowerCase()}`));
          if (recipientHash.toLowerCase() !== expectedRecipientHash.toLowerCase()) {
            console.log('📭 Handshake not intended for current user, skipping');
            return;
          }
          
          console.log('📨 Processing incoming handshake from:', senderAddress, 'to:', userAddress);
          
          const abiCoder = new AbiCoder();
          const [identityPubKeyBytes, ephemeralPubKeyBytes, plaintextPayloadBytes] = abiCoder.decode(
            ['bytes', 'bytes', 'bytes'], 
            log.data
          );

          // Create handshake event object for verification
          const handshakeEvent = {
            recipientHash,
            sender: senderAddress,
            identityPubKey: identityPubKeyBytes,
            ephemeralPubKey: ephemeralPubKeyBytes,
            plaintextPayload: hexToString(plaintextPayloadBytes)
          };

          // Verify handshake identity if we have transaction data
          if (rawTxHex && readProvider) {
            console.log('🔐 Verifying handshake identity...');
            const isVerified = await verifyHandshakeIdentity(
              handshakeEvent,
              rawTxHex,
              readProvider
            );

            if (!isVerified) {
              console.warn('⚠️ Handshake verification failed, rejecting handshake from:', senderAddress);
              return; // Don't process unverified handshake
            }
            console.log('✅ Handshake verification successful');
          } else {
            console.warn('⚠️ Skipping handshake verification - Helios light client limitation (cannot fetch transaction data)');
            console.log('ℹ️ For production, consider using a full node or implementing alternative verification');
          }

          // Parse the handshake payload using SDK
          const parsedPayload = parseHandshakePayload(handshakeEvent.plaintextPayload);
          
          const handshakeWithParsedData = {
            type: 'handshake',
            recipientHash,
            sender: senderAddress,
            identityPubKey: identityPubKeyBytes,
            ephemeralPubKey: ephemeralPubKeyBytes,
            plaintextPayload: handshakeEvent.plaintextPayload,
            parsedPayload,
            timestamp: Date.now(),
            blockNumber: log.blockNumber,
            transactionHash: log.transactionHash,
            rawTxHex, // Include for downstream verification if needed
            verified: !!rawTxHex // Mark if verification was performed
          };

          onIncomingHandshake?.(handshakeWithParsedData);
        } catch (error) {
          console.error('Failed to parse handshake using SDK:', error);
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
            rawTxHex, // Include for verification
            rawData: {
              ciphertextBytes
            }
          };
          
          // Notify about the response - let the parent component handle conversation updates
          onIncomingHandshakeResponse?.(handshakeResponseData);
          
          // Process with conversation manager (will handle verification internally)
          // Note: processHandshakeResponse needs walletClient and userAddress, 
          // but we don't have them in this hook. The actual processing should be 
          // called from the component level where these are available.
          // For now, we just notify about the response.
          // await handleHandshakeResponse(handshakeResponseData);
        } catch (error) {
          console.error('Failed to parse handshake response:', error);
        }
      }
      
    } catch (error) {
      console.error('Error processing log:', error);
    }
  }, [onIncomingMessage, onIncomingHandshake, onIncomingHandshakeResponse, handleHandshakeResponse, userAddress, readProvider]);

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
            // Scan new logs since last scanned block
            const fromBlock = Math.max(lastScannedBlock.current + 1, blockNumber - 5);
            
            if (fromBlock <= blockNumber) {
              const filter = {
                address: LOGCHAIN_ADDR,
                fromBlock,
                toBlock: blockNumber,
                topics: [
                  [EVENT_SIGNATURES.MessageSent, EVENT_SIGNATURES.Handshake, EVENT_SIGNATURES.HandshakeResponse]
                ]
              };
              
              const newLogs = await readProvider.getLogs(filter);
              
              for (const log of newLogs) {
                await handleNewLog(log);
              }
              
              lastScannedBlock.current = blockNumber;
            }
          } catch (error) {
            console.error('Error processing new block logs:', error);
          }
        });

        console.log('👂 Started listening for new events...');
      } catch (error) {
        console.error('Error starting event listener:', error);
      }
    };

    startListening();

    return () => {
      isListening = false;
      try {
        readProvider.removeAllListeners('block');
        console.log('🛑 Stopped listening for events');
      } catch (error) {
        console.error('Error cleaning up event listeners:', error);
      }
    };
  }, [readProvider, userAddress, scanHistoricalLogs, handleNewLog]);

  return null;
}