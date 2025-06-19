// Stable useMessageListener with SDK functions and identity verification
import { useEffect, useRef } from 'react';
import { JsonRpcProvider, keccak256, toUtf8Bytes, AbiCoder } from 'ethers';
import { 
  parseHandshakePayload,
  verifyHandshakeIdentity 
} from '@verbeth/sdk';

interface MessageListenerProps {
  readProvider: JsonRpcProvider | null;
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
const CONTRACT_CREATION_BLOCK = 30568313;
const BLOCK_CHUNK_SIZE = 20;
const HISTORICAL_BLOCKS = 50;

export function useMessageListener({
  readProvider,
  userAddress,
  onIncomingMessage,
  onIncomingHandshake,
  onIncomingHandshakeResponse
}: MessageListenerProps) {
  const processedLogs = useRef(new Set<string>());
  const lastScannedBlock = useRef<number>(CONTRACT_CREATION_BLOCK);

  useEffect(() => {
    if (!readProvider || !userAddress) return;

    let isListening = true;

    // Calculate user's recipient hash
    const userRecipientHash = calculateRecipientHash(userAddress);

    // Helper functions
    const getStoredContacts = (): string[] => {
      try {
        const stored = localStorage.getItem('verbeth_recipients');
        return stored ? JSON.parse(stored) : [];
      } catch {
        return [];
      }
    };

    const getPendingHandshakes = (): string[] => {
      try {
        const stored = localStorage.getItem(`verbeth_handshakes_${userAddress.toLowerCase()}`);
        const handshakes = stored ? JSON.parse(stored) : [];
        return handshakes.map((h: any) => h.transactionHash);
      } catch {
        return [];
      }
    };

    // Process single log entry
    const processLog = async (log: any) => {
      const logKey = `${log.transactionHash}-${log.logIndex}`;
      if (processedLogs.current.has(logKey)) return;
      processedLogs.current.add(logKey);

      const eventSignature = log.topics[0];

      try {
        if (eventSignature === EVENT_SIGNATURES.Handshake) {
          // Process handshake - use raw data directly and prepare for verification
          const abiCoder = new AbiCoder();
          const decoded = abiCoder.decode(['bytes', 'bytes', 'bytes'], log.data);
          const [identityPubKeyBytes, ephemeralPubKeyBytes, plaintextPayloadBytes] = decoded;
          
          // Convert directly from raw bytes
          const identityPubKey = hexToUint8Array(identityPubKeyBytes);
          const ephemeralPubKey = hexToUint8Array(ephemeralPubKeyBytes);
          const plaintextPayload = new TextDecoder().decode(hexToUint8Array(plaintextPayloadBytes));
          
          // Use SDK function for parsing the plaintext payload
          const handshakeContent = parseHandshakePayload(plaintextPayload);
          
          const cleanSenderAddress = log.topics[2].replace(/^0x0+/, '0x');
          const recipientHash = log.topics[1];
          
          // Prepare handshake event in SDK format for verification
          const handshakeEvent = {
            recipientHash,
            sender: cleanSenderAddress,
            identityPubKey: identityPubKeyBytes, // Keep as hex for SDK verification
            ephemeralPubKey: ephemeralPubKeyBytes, // Keep as hex for SDK verification
            plaintextPayload: handshakeContent.plaintextPayload
          };
          
          // Try to verify handshake identity using SDK
          let isVerified = false;
          try {
            // Get the raw transaction for verification
            const tx = await readProvider.getTransaction(log.transactionHash);
            if (tx) {
              // Reconstruct raw transaction hex
              const rawTx = tx.serialized;
              isVerified = await verifyHandshakeIdentity(handshakeEvent, rawTx);
              console.log(`🔐 Handshake identity verification: ${isVerified ? 'VERIFIED' : 'FAILED'}`);
            }
          } catch (verifyError) {
            console.warn('Failed to verify handshake identity:', verifyError);
            // Continue processing even if verification fails
          }
          
          const handshakeData = {
            ...log,
            type: 'handshake',
            sender: cleanSenderAddress,
            timestamp: Date.now(),
            blockNumber: log.blockNumber,
            transactionHash: log.transactionHash,
            identityPubKey: Array.from(identityPubKey), // 32 bytes for app usage
            ephemeralPubKey: Array.from(ephemeralPubKey), // 32 bytes for app usage
            plaintextPayload: handshakeContent.plaintextPayload,
            handshakeContent,
            isVerified, // Include verification result
            handshakeEvent, // Include formatted event for re-verification if needed
            rawData: {
              identityPubKeyBytes,
              ephemeralPubKeyBytes,
              plaintextPayloadBytes
            }
          };
          
          console.log('🤝 Processing handshake (with verification):', {
            sender: cleanSenderAddress,
            payload: handshakeContent.plaintextPayload,
            identityKeyLength: identityPubKey.length,
            ephemeralKeyLength: ephemeralPubKey.length,
            verified: isVerified
          });
          
          onIncomingHandshake?.(handshakeData);
          
        } else if (eventSignature === EVENT_SIGNATURES.HandshakeResponse) {
          // Process handshake response - prepare for SDK verification
          const abiCoder = new AbiCoder();
          const decoded = abiCoder.decode(['bytes'], log.data);
          const [ciphertextBytes] = decoded;
          
          const ciphertextJson = new TextDecoder().decode(hexToUint8Array(ciphertextBytes));
          const inResponseTo = log.topics[1];
          const responderAddress = log.topics[2].replace(/^0x0+/, '0x');
          
          // Prepare response event in SDK format for verification
          const responseEvent = {
            inResponseTo,
            responder: responderAddress,
            ciphertext: ciphertextBytes // Keep as hex for SDK verification
          };
          
          // Get raw transaction for potential verification
          let rawTx = null;
          try {
            const tx = await readProvider.getTransaction(log.transactionHash);
            if (tx) {
              rawTx = tx.serialized;
            }
          } catch (txError) {
            console.warn('Failed to get transaction for handshake response:', txError);
          }
          
          const responseData = {
            type: 'handshake_response',
            inResponseTo,
            responder: responderAddress,
            ciphertextJson, // For decryption
            timestamp: Date.now(),
            blockNumber: log.blockNumber,
            transactionHash: log.transactionHash,
            responseEvent, // Formatted for SDK verification
            rawTx, // Include for verification if needed
            rawData: { ciphertextBytes }
          };
          
          console.log('📧 Processing handshake response (prepared for verification):', { 
            responder: responderAddress,
            hasRawTx: !!rawTx
          });
          
          onIncomingHandshakeResponse?.(responseData);
          
        } else if (eventSignature === EVENT_SIGNATURES.MessageSent) {
          // Process message
          const abiCoder = new AbiCoder();
          const decoded = abiCoder.decode(['bytes', 'uint256', 'bytes32', 'uint256'], log.data);
          const [ciphertextBytes, timestamp, topic, nonce] = decoded;
          
          const sender = log.topics[1].replace(/^0x0+/, '0x');
          const ciphertextJson = new TextDecoder().decode(hexToUint8Array(ciphertextBytes));
          
          const messageData = {
            type: 'message',
            sender,
            topic,
            timestamp: Number(timestamp),
            nonce: Number(nonce),
            ciphertextJson,
            blockNumber: log.blockNumber,
            transactionHash: log.transactionHash,
            rawData: { ciphertextBytes }
          };
          
          console.log('📨 Processing message:', { sender, topic });
          onIncomingMessage?.(messageData);
        }
      } catch (error) {
        console.error('Error processing log:', error);
      }
    };

    // Scan logs with filtering
    const scanLogs = async (fromBlock: number, toBlock: number) => {
      try {
        const contacts = getStoredContacts();
        const pendingHandshakes = getPendingHandshakes();

        // 1. Handshakes for me
        try {
          const handshakeFilter = {
            address: LOGCHAIN_ADDR,
            fromBlock,
            toBlock,
            topics: [EVENT_SIGNATURES.Handshake, userRecipientHash]
          };
          
          const handshakeLogs = await readProvider.getLogs(handshakeFilter);
          for (const log of handshakeLogs) {
            await processLog(log);
          }
        } catch (error) {
          console.warn('Failed to scan handshakes:', error);
        }

        // 2. Handshake responses to my handshakes
        if (pendingHandshakes.length > 0) {
          try {
            const responseFilter = {
              address: LOGCHAIN_ADDR,
              fromBlock,
              toBlock,
              topics: [EVENT_SIGNATURES.HandshakeResponse]
            };
            
            const responseLogs = await readProvider.getLogs(responseFilter);
            const myResponses = responseLogs.filter(log => 
              pendingHandshakes.includes(log.topics[1])
            );
            
            for (const log of myResponses) {
              await processLog(log);
            }
          } catch (error) {
            console.warn('Failed to scan responses:', error);
          }
        }

        // 3. Messages from contacts
        if (contacts.length > 0) {
          try {
            const senderTopics = contacts.map(address => 
              '0x' + address.replace('0x', '').toLowerCase().padStart(64, '0')
            );
            
            const messageFilter = {
              address: LOGCHAIN_ADDR,
              fromBlock,
              toBlock,
              topics: [EVENT_SIGNATURES.MessageSent, senderTopics]
            };
            
            const messageLogs = await readProvider.getLogs(messageFilter);
            for (const log of messageLogs) {
              await processLog(log);
            }
          } catch (error) {
            console.warn('Failed to scan messages:', error);
          }
        }
      } catch (error) {
        console.error('Error scanning logs:', error);
      }
    };

    const startListening = async () => {
      try {
        // Initialize lastScannedBlock
        if (lastScannedBlock.current < CONTRACT_CREATION_BLOCK) {
          lastScannedBlock.current = CONTRACT_CREATION_BLOCK;
        }

        // Scan historical logs
        const currentBlock = await readProvider.getBlockNumber();
        const fromBlock = Math.max(currentBlock - HISTORICAL_BLOCKS, CONTRACT_CREATION_BLOCK);
        
        console.log(`🔍 Scanning from block ${fromBlock} to ${currentBlock}`);
        
        for (let start = fromBlock; start <= currentBlock; start += BLOCK_CHUNK_SIZE) {
          if (!isListening) break;
          
          const end = Math.min(start + BLOCK_CHUNK_SIZE - 1, currentBlock);
          await scanLogs(start, end);
          await new Promise(resolve => setTimeout(resolve, 100));
        }
        
        lastScannedBlock.current = currentBlock;

        // Listen for new blocks
        readProvider.on('block', async (blockNumber: number) => {
          if (!isListening || blockNumber <= lastScannedBlock.current) return;
          
          try {
            const fromBlock = lastScannedBlock.current + 1;
            await scanLogs(fromBlock, blockNumber);
            lastScannedBlock.current = blockNumber;
          } catch (error) {
            console.error(`Error processing block ${blockNumber}:`, error);
          }
        });
        
        console.log('✅ Started listening with optimized filtering');
      } catch (error) {
        console.error('❌ Failed to start listener:', error);
      }
    };

    startListening();

    return () => {
      isListening = false;
      readProvider.removeAllListeners('block');
      processedLogs.current.clear();
      console.log('🛑 Stopped listening');
    };
  }, [readProvider, userAddress, onIncomingMessage, onIncomingHandshake, onIncomingHandshakeResponse]);
}

// Helper functions
export function calculateRecipientHash(address: string): string {
  return keccak256(toUtf8Bytes('contact:' + address.toLowerCase()));
}

function hexToUint8Array(hexValue: string): Uint8Array {
  if (typeof hexValue === 'string' && hexValue.startsWith('0x')) {
    const hexString = hexValue.slice(2);
    const matchResult = hexString.match(/.{2}/g);
    if (!matchResult) {
      throw new Error("Failed to parse hex string");
    }
    return new Uint8Array(matchResult.map(byte => parseInt(byte, 16)));
  } else {
    throw new Error(`Expected hex string, got: ${typeof hexValue}`);
  }
}