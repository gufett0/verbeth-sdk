import { useState, useEffect, useRef, useCallback } from 'react';
import { AbiCoder, keccak256, toUtf8Bytes } from 'ethers';
import nacl from 'tweetnacl';
import { 
  decryptMessage,
  decryptHandshakeResponse,
  parseHandshakePayload,
  verifyHandshakeIdentity,
  verifyHandshakeResponseIdentity
} from '@verbeth/sdk';

// Constants
const LOGCHAIN_ADDR = "0xf9fe7E57459CC6c42791670FaD55c1F548AE51E8";
const CONTRACT_CREATION_BLOCK = 30568313;
const INITIAL_SCAN_BLOCKS = 10000; // Ultimi 10k blocchi per caricamento iniziale
const EVENTS_PER_CHUNK = 20; // Target eventi per chunk in lazy pagination
const CONCURRENCY = 3;
const MAX_RETRIES = 3;

const EVENT_SIGNATURES = {
  MessageSent: keccak256(toUtf8Bytes("MessageSent(address,bytes,uint256,bytes32,uint256)")),
  Handshake: keccak256(toUtf8Bytes("Handshake(bytes32,address,bytes,bytes,bytes)")),
  HandshakeResponse: keccak256(toUtf8Bytes("HandshakeResponse(bytes32,address,bytes)"))
};

interface Contact {
  address: string;
  pubKey?: Uint8Array;
  ephemeralKey?: Uint8Array;
  topic?: string;
  status: 'none' | 'handshake_sent' | 'established';
  lastMessage?: string;
  lastTimestamp?: number;
}

interface PendingHandshake {
  id: string;
  sender: string;
  message: string;
  identityPubKey: Uint8Array;
  ephemeralPubKey: Uint8Array;
  timestamp: number;
  verified: boolean;
}

interface Message {
  id: string;
  content: string;
  sender: string;
  timestamp: number;
  type: 'incoming' | 'outgoing' | 'system';
}

interface ScanChunk {
  fromBlock: number;
  toBlock: number;
  loaded: boolean;
  events: any[];
}

interface UseMessageListenerProps {
  readProvider: any;
  address: string | undefined;
  contacts: Contact[];
  myIdentityKey: Uint8Array | null;
  senderSignKeyPair: nacl.SignKeyPair;
  onContactsUpdate: (contacts: Contact[]) => void;
  onLog: (message: string) => void;
}

export const useMessageListener = ({
  readProvider,
  address,
  contacts,
  myIdentityKey,
  senderSignKeyPair,
  onContactsUpdate,
  onLog
}: UseMessageListenerProps) => {
  // State
  const [messages, setMessages] = useState<Message[]>([]);
  const [pendingHandshakes, setPendingHandshakes] = useState<PendingHandshake[]>([]);
  const [isInitialLoading, setIsInitialLoading] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [canLoadMore, setCanLoadMore] = useState(true);
  const [syncProgress, setSyncProgress] = useState<{current: number, total: number} | null>(null);

  // Refs
  const processedLogs = useRef(new Set<string>());
  const scanChunks = useRef<ScanChunk[]>([]);
  const lastKnownBlock = useRef<number | null>(null);
  const oldestScannedBlock = useRef<number | null>(null);

  // Helper functions
  const calculateRecipientHash = (recipientAddr: string) => {
    return keccak256(toUtf8Bytes(`contact:${recipientAddr.toLowerCase()}`));
  };

  const hexToUint8Array = (hex: string): Uint8Array => {
    const cleanHex = hex.replace('0x', '');
    return new Uint8Array(cleanHex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []);
  };

  // RPC helper with retry logic
  const safeGetLogs = async (filter: any, fromBlock: number, toBlock: number, retries = MAX_RETRIES): Promise<any[]> => {
    let attempt = 0;
    let delay = 500;
    
    while (attempt < retries) {
      try {
        return await readProvider.getLogs({
          ...filter,
          fromBlock,
          toBlock
        });
      } catch (error: any) {
        attempt++;
        
        if (error.code === 429 || error.message?.includes('rate') || error.message?.includes('limit')) {
          if (attempt < retries) {
            onLog(`⏳ Rate limited, retrying in ${delay}ms... (attempt ${attempt}/${retries})`);
            await new Promise(resolve => setTimeout(resolve, delay));
            delay *= 2;
            continue;
          }
        }
        
        if (error.message?.includes('exceed') || error.message?.includes('range')) {
          onLog(`❌ Block range error: ${error.message}`);
          throw new Error('Block range exceeded');
        }
        
        throw error;
      }
    }
    
    throw new Error(`Failed after ${retries} retries`);
  };

  // Binary search to find first event in range
  const findFirstEventInRange = async (startBlock: number, endBlock: number, filter: any): Promise<number | null> => {
    if (startBlock > endBlock) return null;
    
    let left = startBlock;
    let right = endBlock;
    let firstEventBlock: number | null = null;
    
    while (left <= right) {
      const mid = Math.floor((left + right) / 2);
      
      try {
        const logs = await safeGetLogs(filter, mid, mid);
        
        if (logs.length > 0) {
          firstEventBlock = mid;
          right = mid - 1; // Look for earlier events
        } else {
          left = mid + 1; // Look for later events
        }
      } catch (error) {
        onLog(`⚠️ Binary search error at block ${mid}: ${error}`);
        break;
      }
    }
    
    return firstEventBlock;
  };

  // Smart chunking: find optimal ranges with events
  const findEventRanges = async (fromBlock: number, toBlock: number): Promise<[number, number][]> => {
    const ranges: [number, number][] = [];
    const userRecipientHash = calculateRecipientHash(address!);
    
    // Prepare all possible filters for user events
    const filters = [
      // Handshakes to me
      {
        address: LOGCHAIN_ADDR,
        topics: [EVENT_SIGNATURES.Handshake, userRecipientHash]
      },
      // Handshake responses (need to check all and filter)
      {
        address: LOGCHAIN_ADDR,
        topics: [EVENT_SIGNATURES.HandshakeResponse]
      },
      // Messages from established contacts
      {
        address: LOGCHAIN_ADDR,
        topics: [EVENT_SIGNATURES.MessageSent]
      }
    ];

    let currentBlock = toBlock;
    let eventsFound = 0;
    
    while (currentBlock >= fromBlock && eventsFound < EVENTS_PER_CHUNK) {
      // Use binary search to find next event
      const eventBlock = await findFirstEventInRange(fromBlock, currentBlock, filters[0]); // Start with handshakes
      
      if (eventBlock === null) {
        // No more events found
        break;
      }
      
      // Create a range around the found event (scan some blocks before/after)
      const rangeStart = Math.max(eventBlock - 50, fromBlock);
      const rangeEnd = Math.min(eventBlock + 50, currentBlock);
      
      ranges.unshift([rangeStart, rangeEnd]); // Add to beginning for chronological order
      eventsFound += 5; // Estimate - we'll count actual events later
      
      currentBlock = rangeStart - 1;
    }
    
    return ranges;
  };

  // Batch scanning with controlled concurrency
  const batchScanRanges = async (ranges: [number, number][]): Promise<any[]> => {
    if (ranges.length > 1) {
      setSyncProgress({ current: 0, total: ranges.length });
    }
    
    let results: any[] = [];
    let completedRanges = 0;
    const pendingRanges = [...ranges];
    
    const worker = async (): Promise<void> => {
      while (pendingRanges.length > 0) {
        const range = pendingRanges.shift();
        if (!range) break;
        
        const [start, end] = range;
        try {
          const chunkResults = await scanBlockRange(start, end);
          results = results.concat(chunkResults);
          completedRanges++;
          
          if (pendingRanges.length > 0) {
            setSyncProgress({ current: completedRanges, total: completedRanges + pendingRanges.length });
          }
        } catch (error) {
          onLog(`❌ Failed to scan range ${start}-${end}: ${error}`);
        }
      }
    };
    
    await Promise.all(
      Array(Math.min(CONCURRENCY, ranges.length))
        .fill(null)
        .map(() => worker())
    );
    
    setSyncProgress(null);
    return results;
  };

  // Scan specific block range for all user events
  const scanBlockRange = async (fromBlock: number, toBlock: number): Promise<any[]> => {
    if (!address) return [];
    
    const userRecipientHash = calculateRecipientHash(address);
    const allEvents: any[] = [];
    
    try {
      // 1. Handshakes to me
      const handshakeFilter = {
        address: LOGCHAIN_ADDR,
        topics: [EVENT_SIGNATURES.Handshake, userRecipientHash]
      };
      const handshakeLogs = await safeGetLogs(handshakeFilter, fromBlock, toBlock);
      allEvents.push(...handshakeLogs.map(log => ({ ...log, eventType: 'handshake' })));

      // 2. Handshake responses to my handshakes
      const pendingTxHashes = contacts
        .filter(c => c.status === 'handshake_sent')
        .map(c => c.topic)
        .filter(Boolean);

      if (pendingTxHashes.length > 0) {
        const responseFilter = {
          address: LOGCHAIN_ADDR,
          topics: [EVENT_SIGNATURES.HandshakeResponse]
        };
        const responseLogs = await safeGetLogs(responseFilter, fromBlock, toBlock);
        const myResponses = responseLogs.filter(log => 
          pendingTxHashes.includes(log.topics[1])
        );
        allEvents.push(...myResponses.map(log => ({ ...log, eventType: 'handshake_response' })));
      }

      // 3. Messages from established contacts
      const establishedContacts = contacts.filter(c => c.status === 'established');
      if (establishedContacts.length > 0) {
        const senderTopics = establishedContacts.map(c => 
          '0x' + c.address.replace('0x', '').toLowerCase().padStart(64, '0')
        );
        
        const messageFilter = {
          address: LOGCHAIN_ADDR,
          topics: [EVENT_SIGNATURES.MessageSent, senderTopics]
        };
        const messageLogs = await safeGetLogs(messageFilter, fromBlock, toBlock);
        allEvents.push(...messageLogs.map(log => ({ ...log, eventType: 'message' })));
      }

    } catch (error) {
      onLog(`⚠️ Error scanning block range ${fromBlock}-${toBlock}: ${error}`);
    }

    return allEvents;
  };

  // Process events based on type
  const processEvent = async (event: any) => {
    const logKey = `${event.transactionHash}-${event.logIndex}`;
    if (processedLogs.current.has(logKey)) return;
    processedLogs.current.add(logKey);

    switch (event.eventType) {
      case 'handshake':
        await processHandshakeLog(event);
        break;
      case 'handshake_response':
        await processHandshakeResponseLog(event);
        break;
      case 'message':
        await processMessageLog(event);
        break;
    }
  };

  // Process handshake log (unchanged from original)
  const processHandshakeLog = async (log: any) => {
    try {
      const abiCoder = new AbiCoder();
      const decoded = abiCoder.decode(['bytes', 'bytes', 'bytes'], log.data);
      const [identityPubKeyBytes, ephemeralPubKeyBytes, plaintextPayloadBytes] = decoded;
      
      const identityPubKey = hexToUint8Array(identityPubKeyBytes);
      const ephemeralPubKey = hexToUint8Array(ephemeralPubKeyBytes);
      const plaintextPayload = new TextDecoder().decode(hexToUint8Array(plaintextPayloadBytes));
      
      const cleanSenderAddress = log.topics[2].replace(/^0x0+/, '0x');
      const recipientHash = log.topics[1];
      
      const handshakeContent = parseHandshakePayload(plaintextPayload);
      
      const handshakeEvent = {
        recipientHash,
        sender: cleanSenderAddress,
        identityPubKey: identityPubKeyBytes,
        ephemeralPubKey: ephemeralPubKeyBytes,
        plaintextPayload: handshakeContent.plaintextPayload
      };
      
      let isVerified = false;
      try {
        const tx = await readProvider.getTransaction(log.transactionHash);
        if (tx?.serialized) {
          isVerified = await verifyHandshakeIdentity(handshakeEvent, tx.serialized);
        }
      } catch (error) {
        console.warn("Failed to verify handshake identity:", error);
      }
      
      const pendingHandshake: PendingHandshake = {
        id: log.transactionHash,
        sender: cleanSenderAddress,
        message: handshakeContent.plaintextPayload,
        identityPubKey,
        ephemeralPubKey,
        timestamp: Date.now(),
        verified: isVerified
      };
      
      setPendingHandshakes(prev => {
        const existing = prev.find(h => h.id === pendingHandshake.id);
        if (existing) return prev;
        return [...prev, pendingHandshake];
      });
      
      onLog(`📨 Handshake received from ${cleanSenderAddress.slice(0, 8)}... ${isVerified ? '✅' : '⚠️'}: "${handshakeContent.plaintextPayload}"`);
    } catch (error) {
      console.error("Failed to process handshake log:", error);
    }
  };

  // Process handshake response log (unchanged from original)
  const processHandshakeResponseLog = async (log: any) => {
    try {
      const abiCoder = new AbiCoder();
      const [ciphertextBytes] = abiCoder.decode(['bytes'], log.data);
      const ciphertextJson = new TextDecoder().decode(hexToUint8Array(ciphertextBytes));
      
      const responder = log.topics[2].replace(/^0x0+/, '0x');
      const inResponseTo = log.topics[1];
      
      const contact = contacts.find(c => 
        c.address.toLowerCase() === responder.toLowerCase() && 
        c.status === 'handshake_sent'
      );
      
      if (!contact || !contact.ephemeralKey) {
        onLog(`❓ Received handshake response from unknown contact: ${responder.slice(0, 8)}...`);
        return;
      }
      
      const decryptedResponse = decryptHandshakeResponse(ciphertextJson, contact.ephemeralKey);
      
      if (!decryptedResponse) {
        onLog(`❌ Failed to decrypt handshake response from ${responder.slice(0, 8)}...`);
        return;
      }
      
      let isVerified = false;
      try {
        const tx = await readProvider.getTransaction(log.transactionHash);
        if (tx?.serialized) {
          const responseEvent = {
            inResponseTo,
            responder,
            ciphertext: ciphertextBytes
          };
          
          isVerified = await verifyHandshakeResponseIdentity(
            tx.serialized,
            responseEvent,
            decryptedResponse.identityPubKey,
            contact.ephemeralKey
          );
        }
      } catch (error) {
        console.warn("Failed to verify handshake response identity:", error);
      }
      
      const updatedContacts = contacts.map(c => 
        c.address.toLowerCase() === responder.toLowerCase() 
          ? { 
              ...c, 
              status: 'established' as const, 
              pubKey: decryptedResponse.identityPubKey,
              lastMessage: decryptedResponse.note,
              lastTimestamp: Date.now()
            }
          : c
      );
      onContactsUpdate(updatedContacts);
      
      onLog(`🤝 Handshake completed with ${responder.slice(0, 8)}... ${isVerified ? '✅' : '⚠️'}: "${decryptedResponse.note}"`);
    } catch (error) {
      console.error("Failed to process handshake response log:", error);
    }
  };

  // Process message log (unchanged from original)
  const processMessageLog = async (log: any) => {
    try {
      const abiCoder = new AbiCoder();
      const [ciphertextBytes] = abiCoder.decode(['bytes'], log.data);
      const sender = log.topics[1].replace(/^0x0+/, '0x');
      
      const contact = contacts.find(c => 
        c.address.toLowerCase() === sender.toLowerCase() && 
        c.status === 'established'
      );
      
      if (!contact || !contact.pubKey) {
        onLog(`❓ Received message from unknown contact: ${sender.slice(0, 8)}...`);
        return;
      }
      
      const ciphertextJson = new TextDecoder().decode(hexToUint8Array(ciphertextBytes));
      const decryptedMessage = decryptMessage(ciphertextJson, nacl.box.keyPair().secretKey, contact.pubKey);
      
      if (decryptedMessage) {
        const newMessage: Message = {
          id: log.transactionHash,
          content: decryptedMessage,
          sender,
          timestamp: Date.now(),
          type: 'incoming'
        };
        
        setMessages(prev => {
          const existing = prev.find(m => m.id === newMessage.id);
          if (existing) return prev;
          return [...prev, newMessage];
        });
        
        onLog(`💬 Message from ${sender.slice(0, 8)}...: "${decryptedMessage}"`);
      } else {
        onLog(`❌ Failed to decrypt message from ${sender.slice(0, 8)}...`);
      }
    } catch (error) {
      console.error("Failed to process message log:", error);
    }
  };

  // Initial backward scan (ultimi 10k blocchi)
  const performInitialScan = useCallback(async () => {
    if (!readProvider || !address || isInitialLoading) return;
    
    setIsInitialLoading(true);
    onLog(`🚀 Starting initial scan of last ${INITIAL_SCAN_BLOCKS} blocks...`);
    
    try {
      const currentBlock = await readProvider.getBlockNumber();
      const startBlock = Math.max(currentBlock - INITIAL_SCAN_BLOCKS, CONTRACT_CREATION_BLOCK);
      
      lastKnownBlock.current = currentBlock;
      oldestScannedBlock.current = startBlock;
      
      // Scan backward from tip
      const events = await scanBlockRange(startBlock, currentBlock);
      
      // Process all events
      for (const event of events) {
        await processEvent(event);
      }
      
      // Store chunk info
      scanChunks.current = [{
        fromBlock: startBlock,
        toBlock: currentBlock,
        loaded: true,
        events
      }];
      
      // Check if we can load more (not reached contract creation)
      setCanLoadMore(startBlock > CONTRACT_CREATION_BLOCK);
      
      onLog(`✅ Initial scan complete: ${events.length} events found in blocks ${startBlock}-${currentBlock}`);
      
    } catch (error) {
      onLog(`❌ Initial scan failed: ${error}`);
    } finally {
      setIsInitialLoading(false);
    }
  }, [readProvider, address, isInitialLoading, onLog]);

  // Lazy load more history
  const loadMoreHistory = useCallback(async () => {
    if (!readProvider || !address || isLoadingMore || !canLoadMore || !oldestScannedBlock.current) {
      return;
    }
    
    setIsLoadingMore(true);
    onLog(`📂 Loading more history...`);
    
    try {
      const endBlock = oldestScannedBlock.current - 1;
      const startBlock = Math.max(endBlock - INITIAL_SCAN_BLOCKS, CONTRACT_CREATION_BLOCK);
      
      // Use smart chunking to find optimal ranges
      const ranges = await findEventRanges(startBlock, endBlock);
      
      if (ranges.length === 0) {
        onLog(`📄 No more events found before block ${endBlock}`);
        setCanLoadMore(false);
        return;
      }
      
      // Scan the identified ranges
      const events = await batchScanRanges(ranges);
      
      // Process all events
      for (const event of events) {
        await processEvent(event);
      }
      
      // Update chunk tracking
      scanChunks.current.push({
        fromBlock: startBlock,
        toBlock: endBlock,
        loaded: true,
        events
      });
      
      oldestScannedBlock.current = startBlock;
      
      // Check if we can continue loading
      setCanLoadMore(startBlock > CONTRACT_CREATION_BLOCK);
      
      onLog(`✅ Loaded ${events.length} more events from blocks ${startBlock}-${endBlock}`);
      
    } catch (error) {
      onLog(`❌ Failed to load more history: ${error}`);
    } finally {
      setIsLoadingMore(false);
    }
  }, [readProvider, address, isLoadingMore, canLoadMore, onLog]);

  // Real-time scanning for new blocks
  useEffect(() => {
    if (!readProvider || !address || !lastKnownBlock.current) return;
    
    const interval = setInterval(async () => {
      try {
        const currentBlock = await readProvider.getBlockNumber();
        
        if (currentBlock > lastKnownBlock.current!) {
          const events = await scanBlockRange(lastKnownBlock.current! + 1, currentBlock);
          
          for (const event of events) {
            await processEvent(event);
          }
          
          lastKnownBlock.current = currentBlock;
          
          if (events.length > 0) {
            onLog(`🔄 Found ${events.length} new events in blocks ${lastKnownBlock.current! + 1}-${currentBlock}`);
          }
        }
      } catch (error) {
        onLog(`⚠️ Real-time scan error: ${error}`);
      }
    }, 5000);
    
    return () => clearInterval(interval);
  }, [readProvider, address, onLog]);

  // Initialize
  useEffect(() => {
    if (readProvider && address && !isInitialLoading && scanChunks.current.length === 0) {
      performInitialScan();
    }
  }, [readProvider, address, performInitialScan]);

  return {
    messages,
    pendingHandshakes,
    isInitialLoading,
    isLoadingMore,
    canLoadMore,
    syncProgress,
    loadMoreHistory,
    // Helper to add messages from UI
    addMessage: (message: Message) => {
      setMessages(prev => [...prev, message]);
    },
    // Helper to remove pending handshakes
    removePendingHandshake: (id: string) => {
      setPendingHandshakes(prev => prev.filter(h => h.id !== id));
    }
  };
};