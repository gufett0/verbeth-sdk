import { useState, useEffect, useRef, useCallback } from "react";
import { AbiCoder, keccak256, toUtf8Bytes } from "ethers";
import nacl from "tweetnacl";
import {
  decryptMessage,
  decryptHandshakeResponse,
  parseHandshakePayload,
  verifyHandshakeIdentity,
  verifyHandshakeResponseIdentity,
  IdentityKeyPair,
} from "@verbeth/sdk";

// Constants
const LOGCHAIN_ADDR = "0xf9fe7E57459CC6c42791670FaD55c1F548AE51E8";
const CONTRACT_CREATION_BLOCK = 30568313;
const INITIAL_SCAN_BLOCKS = 10000; // Ultimi 10k blocchi per caricamento iniziale
const MAX_RETRIES = 3;
const MAX_RANGE_PROVIDER = 2000; // Range massimo per provider RPC
const CHUNK_SIZE = 2000; // Dimensione chunk per smart chunking ( se == a MAX_RANGE_PROVIDER allora 1 chunk == 1 chiamata RPC)
const REAL_TIME_BUFFER = 3; // Buffer

const EVENT_SIGNATURES = {
  MessageSent: keccak256(
    toUtf8Bytes("MessageSent(address,bytes,uint256,bytes32,uint256)")
  ),
  Handshake: keccak256(
    toUtf8Bytes("Handshake(bytes32,address,bytes,bytes,bytes)")
  ),
  HandshakeResponse: keccak256(
    toUtf8Bytes("HandshakeResponse(bytes32,address,bytes)")
  ),
};

interface Contact {
  address: string;
  pubKey?: Uint8Array;
  ephemeralKey?: Uint8Array;
  topic?: string;
  status: "none" | "handshake_sent" | "established";
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
  type: "incoming" | "outgoing" | "system";
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
<<<<<<< Updated upstream
  identityKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array } | null;
=======
  identityKeyPair: IdentityKeyPair | null; 
  senderSignKeyPair: nacl.SignKeyPair;
>>>>>>> Stashed changes
  onContactsUpdate: (contacts: Contact[]) => void;
  onLog: (message: string) => void;
}

export const useMessageListener = ({
  readProvider,
  address,
  contacts,
  identityKeyPair,
  onContactsUpdate,
  onLog,
}: UseMessageListenerProps) => {
  // State
  const [messages, setMessages] = useState<Message[]>([]);
  const [pendingHandshakes, setPendingHandshakes] = useState<
    PendingHandshake[]
  >([]);
  const [isInitialLoading, setIsInitialLoading] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [canLoadMore, setCanLoadMore] = useState(true);
  const [syncProgress, setSyncProgress] = useState<{
    current: number;
    total: number;
  } | null>(null);

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
    const cleanHex = hex.replace("0x", "");
    return new Uint8Array(
      cleanHex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );
  };

  // RPC helper with retry logic
  const safeGetLogs = async (
    filter: any,
    fromBlock: number,
    toBlock: number,
    retries = MAX_RETRIES
  ): Promise<any[]> => {
    let attempt = 0;
    let delay = 1000; // FIX: Delay iniziale più lungo

    while (attempt < retries) {
      try {
        // FIX: Valida che il range non sia troppo piccolo o invalido
        if (fromBlock > toBlock) {
          onLog(`⚠️ Invalid block range: ${fromBlock} > ${toBlock}`);
          return [];
        }

        // FIX: Limita range massimo per evitare errori provider
        if (toBlock - fromBlock > MAX_RANGE_PROVIDER) {
          //onLog(`⚠️ Range too large (${toBlock - fromBlock}), splitting...`);
          const mid = fromBlock + Math.floor((toBlock - fromBlock) / 2);
          const firstHalf = await safeGetLogs(filter, fromBlock, mid, retries);
          const secondHalf = await safeGetLogs(
            filter,
            mid + 1,
            toBlock,
            retries
          );
          return [...firstHalf, ...secondHalf];
        }

        return await readProvider.getLogs({
          ...filter,
          fromBlock,
          toBlock,
        });
      } catch (error: any) {
        attempt++;

        if (
          error.code === 429 ||
          error.message?.includes("rate") ||
          error.message?.includes("limit") ||
          error.message?.includes("invalid block range")
        ) {
          if (attempt < retries) {
            onLog(
              `⏳ RPC error, retrying in ${delay}ms... (attempt ${attempt}/${retries})`
            );
            onLog(`Error details: ${error.message}`);
            await new Promise((resolve) => setTimeout(resolve, delay));
            delay *= 1.5; // FIX: Incremento più graduale
            continue;
          }
        }

        if (
          error.message?.includes("exceed") ||
          error.message?.includes("range")
        ) {
          onLog(`❌ Block range error, skipping range ${fromBlock}-${toBlock}`);
          return []; // FIX: Return empty instead of throwing
        }

        onLog(
          `❌ RPC error on range ${fromBlock}-${toBlock}: ${error.message}`
        );
        return []; // FIX: Return empty instead of throwing
      }
    }

    onLog(
      `❌ Failed after ${retries} retries for range ${fromBlock}-${toBlock}`
    );
    return [];
  };

  // Smart chunking: find optimal ranges with events
  const findEventRanges = async (
    fromBlock: number,
    toBlock: number
  ): Promise<[number, number][]> => {
    const ranges: [number, number][] = [];

    let currentBlock = toBlock;

    while (currentBlock >= fromBlock) {
      const rangeStart = Math.max(currentBlock - CHUNK_SIZE, fromBlock);
      const rangeEnd = currentBlock;

      ranges.unshift([rangeStart, rangeEnd]); // Add to beginning for chronological order
      currentBlock = rangeStart - 1;

      // Limit to reasonable number of ranges to avoid overwhelming the RPC
      if (ranges.length >= 5) break;
    }

    return ranges;
  };

  const batchScanRanges = async (
    ranges: [number, number][]
  ): Promise<any[]> => {
    if (ranges.length > 1) {
      setSyncProgress({ current: 0, total: ranges.length });
    }

    let results: any[] = [];
    let completedRanges = 0;

    // FIX: Riduci concorrenza e aggiungi delay per evitare rate limiting
    for (const range of ranges) {
      const [start, end] = range;
      try {
        const chunkResults = await scanBlockRange(start, end);
        results = results.concat(chunkResults);
        completedRanges++;

        setSyncProgress({ current: completedRanges, total: ranges.length });

        // FIX: Aggiungi delay tra le richieste per provider pubblico
        if (completedRanges < ranges.length) {
          await new Promise((resolve) => setTimeout(resolve, 200));
        }
      } catch (error) {
        onLog(`❌ Failed to scan range ${start}-${end}: ${error}`);
        // FIX: Continue instead of breaking on single range failure
      }
    }

    setSyncProgress(null);
    return results;
  };

  // Scan specific block range for all user events
  const scanBlockRange = async (
    fromBlock: number,
    toBlock: number
  ): Promise<any[]> => {
    if (!address) return [];

    const userRecipientHash = calculateRecipientHash(address);
    const allEvents: any[] = [];

    try {
      // 1. Handshakes to me
      const handshakeFilter = {
        address: LOGCHAIN_ADDR,
        topics: [EVENT_SIGNATURES.Handshake, userRecipientHash],
      };
      const handshakeLogs = await safeGetLogs(
        handshakeFilter,
        fromBlock,
        toBlock
      );
      allEvents.push(
        ...handshakeLogs.map((log) => ({ ...log, eventType: "handshake" }))
      );

      // 2. Handshake responses to my handshakes
      const pendingTxHashes = contacts
        .filter((c) => c.status === "handshake_sent")
        .map((c) => c.topic)
        .filter(Boolean);

      if (pendingTxHashes.length > 0) {
        const responseFilter = {
          address: LOGCHAIN_ADDR,
          topics: [EVENT_SIGNATURES.HandshakeResponse],
        };
        const responseLogs = await safeGetLogs(
          responseFilter,
          fromBlock,
          toBlock
        );
        const myResponses = responseLogs.filter((log) =>
          pendingTxHashes.includes(log.topics[1])
        );
        allEvents.push(
          ...myResponses.map((log) => ({
            ...log,
            eventType: "handshake_response",
          }))
        );
      }

      // 3. Messages from established contacts
      const establishedContacts = contacts.filter(
        (c) => c.status === "established"
      );
      if (establishedContacts.length > 0) {
        const senderTopics = establishedContacts.map(
          (c) =>
            "0x" + c.address.replace("0x", "").toLowerCase().padStart(64, "0")
        );

        const messageFilter = {
          address: LOGCHAIN_ADDR,
          topics: [EVENT_SIGNATURES.MessageSent, senderTopics],
        };
        const messageLogs = await safeGetLogs(
          messageFilter,
          fromBlock,
          toBlock
        );
        allEvents.push(
          ...messageLogs.map((log) => ({ ...log, eventType: "message" }))
        );
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
      case "handshake":
        await processHandshakeLog(event);
        break;
      case "handshake_response":
        await processHandshakeResponseLog(event);
        break;
      case "message":
        await processMessageLog(event);
        break;
    }
  };

  // Process handshake log 
  const processHandshakeLog = async (log: any) => {
    try {
      const abiCoder = new AbiCoder();
      const decoded = abiCoder.decode(["bytes", "bytes", "bytes"], log.data);
      const [identityPubKeyBytes, ephemeralPubKeyBytes, plaintextPayloadBytes] =
        decoded;

      const identityPubKey = hexToUint8Array(identityPubKeyBytes);
      const ephemeralPubKey = hexToUint8Array(ephemeralPubKeyBytes);
      const plaintextPayload = new TextDecoder().decode(
        hexToUint8Array(plaintextPayloadBytes)
      );

      const cleanSenderAddress = log.topics[2].replace(/^0x0+/, "0x");
      const recipientHash = log.topics[1];

      // FIXED: Usa SDK function per parsare handshake payload
      const handshakeContent = parseHandshakePayload(plaintextPayload);

      const handshakeEvent = {
        recipientHash,
        sender: cleanSenderAddress,
        identityPubKey: identityPubKeyBytes,
        ephemeralPubKey: ephemeralPubKeyBytes,
        plaintextPayload: handshakeContent.plaintextPayload,
      };

      let isVerified = false;
      try {
        const tx = await readProvider.getTransaction(log.transactionHash);
        if (tx?.serialized && identityKeyPair) {
          isVerified = await verifyHandshakeIdentity(
            handshakeEvent,
            tx.serialized
          );
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
        verified: isVerified,
      };

      setPendingHandshakes((prev) => {
        const existing = prev.find((h) => h.id === pendingHandshake.id);
        if (existing) return prev;
        return [...prev, pendingHandshake];
      });

      onLog(
        `📨 Handshake received from ${cleanSenderAddress.slice(0, 8)}... ${
          isVerified ? "✅" : "⚠️"
        }: "${handshakeContent.plaintextPayload}"`
      );
    } catch (error) {
      console.error("Failed to process handshake log:", error);
    }
  };

  // Process handshake response log - FIXED: usa chiavi corrette e SDK
  const processHandshakeResponseLog = async (log: any) => {
    try {
      const abiCoder = new AbiCoder();
      const [ciphertextBytes] = abiCoder.decode(["bytes"], log.data);
      const ciphertextJson = new TextDecoder().decode(
        hexToUint8Array(ciphertextBytes)
      );

      const responder = log.topics[2].replace(/^0x0+/, "0x");
      const inResponseTo = log.topics[1];

      const contact = contacts.find(
        (c) =>
          c.address.toLowerCase() === responder.toLowerCase() &&
          c.status === "handshake_sent"
      );

      if (!contact || !contact.ephemeralKey) {
        onLog(
          `❓ Received handshake response from unknown contact: ${responder.slice(
            0,
            8
          )}...`
        );
        return;
      }

      // FIXED: Usa SDK function per decryptare handshake response
      const decryptedResponse = decryptHandshakeResponse(
        ciphertextJson,
        contact.ephemeralKey
      );

      if (!decryptedResponse) {
        onLog(
          `❌ Failed to decrypt handshake response from ${responder.slice(
            0,
            8
          )}...`
        );
        return;
      }

      let isVerified = false;
      try {
        const tx = await readProvider.getTransaction(log.transactionHash);
        if (tx?.serialized) {
          const responseEvent = {
            inResponseTo,
            responder,
            ciphertext: ciphertextBytes,
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

      const updatedContacts = contacts.map((c) =>
        c.address.toLowerCase() === responder.toLowerCase()
          ? {
              ...c,
              status: "established" as const,
              pubKey: decryptedResponse.identityPubKey,
              lastMessage: decryptedResponse.note,
              lastTimestamp: Date.now(),
            }
          : c
      );
      onContactsUpdate(updatedContacts);

      onLog(
        `🤝 Handshake completed with ${responder.slice(0, 8)}... ${
          isVerified ? "✅" : "⚠️"
        }: "${decryptedResponse.note}"`
      );
    } catch (error) {
      console.error("Failed to process handshake response log:", error);
    }
  };

  // Process message log - FIXED: usa chiavi derivate dal wallet
  const processMessageLog = async (log: any) => {
    try {
      const abiCoder = new AbiCoder();
      const [ciphertextBytes] = abiCoder.decode(["bytes"], log.data);
      const sender = log.topics[1].replace(/^0x0+/, "0x");

      const contact = contacts.find(
        (c) =>
          c.address.toLowerCase() === sender.toLowerCase() &&
          c.status === "established"
      );

      if (!contact || !contact.pubKey) {
        onLog(
          `❓ Received message from unknown contact: ${sender.slice(0, 8)}...`
        );
        return;
      }

      // ✅ USA identityKeyPair invece di myIdentityKey
      if (!identityKeyPair) {
          onLog(`⏳ Identity key not ready yet, skipping message from ${sender.slice(0, 8)}...`);
          return;
        }

      const ciphertextJson = new TextDecoder().decode(
        hexToUint8Array(ciphertextBytes)
      );

      // ✅ USA la chiave privata dell'identità per decifrare MessageSent
      const decryptedMessage = decryptMessage(
        ciphertextJson,
        identityKeyPair.secretKey, 
        contact.pubKey 
        //undefined                     // ⭐ IGNORA firma per ora, fino a che non scambiamo signing keys
      );

      if (decryptedMessage) {
        const newMessage: Message = {
          id: log.transactionHash,
          content: decryptedMessage,
          sender,
          timestamp: Date.now(),
          type: "incoming",
        };

        setMessages((prev) => {
          const existing = prev.find((m) => m.id === newMessage.id);
          if (existing) return prev;
          return [...prev, newMessage];
        });

        onLog(
          `💬 Message from ${sender.slice(0, 8)}...: "${decryptedMessage}"`
        );
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
      const startBlock = Math.max(
        currentBlock - INITIAL_SCAN_BLOCKS,
        CONTRACT_CREATION_BLOCK
      );

      lastKnownBlock.current = currentBlock;
      oldestScannedBlock.current = startBlock;

      // Scan backward from tip
      const events = await scanBlockRange(startBlock, currentBlock);

      // Process all events
      for (const event of events) {
        await processEvent(event);
      }

      // Store chunk info
      scanChunks.current = [
        {
          fromBlock: startBlock,
          toBlock: currentBlock,
          loaded: true,
          events,
        },
      ];

      // Check if we can load more (not reached contract creation)
      setCanLoadMore(startBlock > CONTRACT_CREATION_BLOCK);

      onLog(
        `✅ Initial scan complete: ${events.length} events found in blocks ${startBlock}-${currentBlock}`
      );
    } catch (error) {
      onLog(`❌ Initial scan failed: ${error}`);
    } finally {
      setIsInitialLoading(false);
    }
  }, [readProvider, address, isInitialLoading, onLog]);

  // Lazy load more history
  const loadMoreHistory = useCallback(async () => {
    if (
      !readProvider ||
      !address ||
      isLoadingMore ||
      !canLoadMore ||
      !oldestScannedBlock.current
    ) {
      return;
    }

    setIsLoadingMore(true);
    onLog(`📂 Loading more history...`);

    try {
      const endBlock = oldestScannedBlock.current - 1;
      const startBlock = Math.max(
        endBlock - INITIAL_SCAN_BLOCKS,
        CONTRACT_CREATION_BLOCK
      );

      // ----------- INIZIO FIX -----------
      // Trova l'effettivo blocco più recente davvero indicizzato in questo range
      let maxIndexedBlock = endBlock;
      for (let b = endBlock; b >= startBlock; b--) {
        const blk = await readProvider.getBlock(b);
        if (blk) {
          maxIndexedBlock = b;
          break;
        }
      }
      // Se nessun blocco nel range è indicizzato, esci e riprova più tardi
      if (maxIndexedBlock < startBlock) {
        onLog(
          `⚠️ Nessun blocco indicizzato trovato tra ${startBlock} e ${endBlock}. Riproverò più tardi.`
        );
        setIsLoadingMore(false);
        return;
      }
      // Aggiorna startBlock in base all'ultimo blocco effettivamente disponibile
      const safeStartBlock = Math.max(startBlock, CONTRACT_CREATION_BLOCK);
      const safeEndBlock = maxIndexedBlock;
      // ----------- FINE FIX -----------

      // Usa smart chunking per trovare range ottimali
      const ranges = await findEventRanges(safeStartBlock, safeEndBlock);

      if (ranges.length === 0) {
        onLog(`📄 No more events found before block ${safeEndBlock}`);
        setCanLoadMore(false);
        setIsLoadingMore(false);
        return;
      }

      // Scansiona solo i blocchi effettivamente disponibili!
      const events = await batchScanRanges(ranges);

      for (const event of events) {
        await processEvent(event);
      }

      // Aggiorna i chunk tracciati
      scanChunks.current.push({
        fromBlock: safeStartBlock,
        toBlock: safeEndBlock,
        loaded: true,
        events,
      });

      oldestScannedBlock.current = safeStartBlock;

      // Continua solo se ci sono ancora blocchi più vecchi
      setCanLoadMore(safeStartBlock > CONTRACT_CREATION_BLOCK);

      onLog(
        `✅ Loaded ${events.length} more events from blocks ${safeStartBlock}-${safeEndBlock}`
      );
    } catch (error) {
      onLog(`❌ Failed to load more history: ${error}`);
    } finally {
      setIsLoadingMore(false);
    }
  }, [readProvider, address, isLoadingMore, canLoadMore, onLog]);

  // Real-time scanning for new blocks with safety buffer
  useEffect(() => {
    if (!readProvider || !address || !lastKnownBlock.current) return;

    const interval = setInterval(async () => {
      try {
        const currentBlock = await readProvider.getBlockNumber();
        const maxSafeBlock = currentBlock - REAL_TIME_BUFFER; // Buffer per evitare blocchi non indicizzati

        if (maxSafeBlock > lastKnownBlock.current!) {
          // Scansiona solo blocchi "sicuri" (non troppo freschi)
          const startScanBlock = lastKnownBlock.current! + 1;
          const events = await scanBlockRange(startScanBlock, maxSafeBlock);

          for (const event of events) {
            await processEvent(event);
          }

          lastKnownBlock.current = maxSafeBlock;

          console.log(
            `🔄 Real-time scan updated to block ${maxSafeBlock} (last known: ${startScanBlock})`
          );
          console.log(`Processed ${events.length} new events`);

          if (events.length > 0) {
            onLog(
              `🔄 Found ${events.length} new events in blocks ${startScanBlock}-${maxSafeBlock}`
            );
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
    if (
      readProvider &&
      address &&
      identityKeyPair && 
      !isInitialLoading &&
      scanChunks.current.length === 0
    ) {
      performInitialScan();
    }
  }, [readProvider, address, identityKeyPair, performInitialScan]); 

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
      setMessages((prev) => [...prev, message]);
    },
    // Helper to remove pending handshakes
    removePendingHandshake: (id: string) => {
      setPendingHandshakes((prev) => prev.filter((h) => h.id !== id));
    },
  };
};
