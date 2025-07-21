// apps/demo/src/hooks/useMessageListener.ts

import { useState, useEffect, useRef, useCallback } from "react";
import { keccak256, toUtf8Bytes } from "ethers";
import { dbService } from "../services/DbService.js";
import {
  LOGCHAIN_SINGLETON_ADDR,
  CONTRACT_CREATION_BLOCK,
  INITIAL_SCAN_BLOCKS,
  MAX_RETRIES,
  MAX_RANGE_PROVIDER,
  CHUNK_SIZE,
  REAL_TIME_BUFFER,
  EVENT_SIGNATURES,
  Contact,
  ScanProgress,
  ScanChunk,
  ProcessedEvent,
  MessageListenerResult,
} from "../types.js";

interface UseMessageListenerProps {
  readProvider: any;
  address: string | undefined;
  onLog: (message: string) => void;
  onEventsProcessed: (events: ProcessedEvent[]) => void;
}

export const useMessageListener = ({
  readProvider,
  address,
  onLog,
  onEventsProcessed,
}: UseMessageListenerProps): MessageListenerResult => {
  // State
  const [isInitialLoading, setIsInitialLoading] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [canLoadMore, setCanLoadMore] = useState(true);
  const [syncProgress, setSyncProgress] = useState<ScanProgress | null>(null);
  const [lastKnownBlock, setLastKnownBlock] = useState<number | null>(null);
  const [oldestScannedBlock, setOldestScannedBlock] = useState<number | null>(
    null
  );

  // Refs
  const processedLogs = useRef(new Set<string>());
  const scanChunks = useRef<ScanChunk[]>([]);

  // Helper functions
  const calculateRecipientHash = (recipientAddr: string) => {
    return keccak256(toUtf8Bytes(`contact:${recipientAddr.toLowerCase()}`));
  };

  // Load contacts directly from database when needed
  const getCurrentContacts = useCallback(async (): Promise<Contact[]> => {
    if (!address) return [];
    try {
      return await dbService.getAllContacts(address);
    } catch (error) {
      onLog(`✗ Failed to load contacts: ${error}`);
      return [];
    }
  }, [address, onLog]);

  // RPC helper with retry logic (unchanged)
  const safeGetLogs = async (
    filter: any,
    fromBlock: number,
    toBlock: number,
    retries = MAX_RETRIES
  ): Promise<any[]> => {
    let attempt = 0;
    let delay = 1000;

    while (attempt < retries) {
      try {
        if (fromBlock > toBlock) {
          onLog(`⚠️ Invalid block range: ${fromBlock} > ${toBlock}`);
          return [];
        }

        if (toBlock - fromBlock > MAX_RANGE_PROVIDER) {
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
              `! RPC error, retrying in ${delay}ms... (attempt ${attempt}/${retries})`
            );
            await new Promise((resolve) => setTimeout(resolve, delay));
            delay *= 1.5;
            continue;
          }
        }

        if (
          error.message?.includes("exceed") ||
          error.message?.includes("range")
        ) {
          onLog(`✗ Block range error, skipping range ${fromBlock}-${toBlock}`);
          return [];
        }

        onLog(
          `✗ RPC error on range ${fromBlock}-${toBlock}: ${error.message}`
        );
        return [];
      }
    }

    onLog(
      `✗ Failed after ${retries} retries for range ${fromBlock}-${toBlock}`
    );
    return [];
  };

  // Smart chunking (unchanged)
  const findEventRanges = async (
    fromBlock: number,
    toBlock: number
  ): Promise<[number, number][]> => {
    const ranges: [number, number][] = [];
    let currentBlock = toBlock;

    while (currentBlock >= fromBlock) {
      const rangeStart = Math.max(currentBlock - CHUNK_SIZE, fromBlock);
      const rangeEnd = currentBlock;

      ranges.unshift([rangeStart, rangeEnd]);
      currentBlock = rangeStart - 1;

      if (ranges.length >= 5) break;
    }

    return ranges;
  };

  const batchScanRanges = async (
    ranges: [number, number][]
  ): Promise<ProcessedEvent[]> => {
    if (ranges.length > 1) {
      setSyncProgress({ current: 0, total: ranges.length });
    }

    let results: ProcessedEvent[] = [];
    let completedRanges = 0;

    for (const range of ranges) {
      const [start, end] = range;
      try {
        const chunkResults = await scanBlockRange(start, end);
        results = results.concat(chunkResults);
        completedRanges++;

        setSyncProgress({ current: completedRanges, total: ranges.length });

        if (completedRanges < ranges.length) {
          await new Promise((resolve) => setTimeout(resolve, 200));
        }
      } catch (error) {
        onLog(`✗ Failed to scan range ${start}-${end}: ${error}`);
      }
    }

    setSyncProgress(null);
    return results;
  };

  // ✅ FIXED: Scan specific block range - load contacts from DB when needed
  const scanBlockRange = async (
    fromBlock: number,
    toBlock: number
  ): Promise<ProcessedEvent[]> => {
    if (!address) return [];

    // ✅ Load fresh contacts from database
    const contacts = await getCurrentContacts();

    const userRecipientHash = calculateRecipientHash(address);
    const allEvents: ProcessedEvent[] = [];

    try {
      // 1. Handshakes to me
      const handshakeFilter = {
        address: LOGCHAIN_SINGLETON_ADDR,
        topics: [EVENT_SIGNATURES.Handshake, userRecipientHash],
      };
      const handshakeLogs = await safeGetLogs(
        handshakeFilter,
        fromBlock,
        toBlock
      );

      for (const log of handshakeLogs) {
        const logKey = `${log.transactionHash}-${log.logIndex}`;
        if (!processedLogs.current.has(logKey)) {
          processedLogs.current.add(logKey);
          allEvents.push({
            logKey,
            eventType: "handshake",
            rawLog: log,
            blockNumber: log.blockNumber,
            timestamp: Date.now(),
          });
        }
      }

      // 2. Load pending handshakes from fresh contacts
      const pendingTxHashes = contacts
        .filter((c) => c.status === "handshake_sent")
        .map((c) => c.topic)
        .filter(Boolean);

      //onLog(`Debug: Found ${pendingTxHashes.length} pending handshakes in blocks ${fromBlock}-${toBlock}`);
      pendingTxHashes.forEach((hash, i) => {
        onLog(`🔍 Pending[${i}]: ${hash}`);
      });

      if (pendingTxHashes.length > 0) {
        const responseFilter = {
          address: LOGCHAIN_SINGLETON_ADDR,
          topics: [EVENT_SIGNATURES.HandshakeResponse],
        };
        const responseLogs = await safeGetLogs(
          responseFilter,
          fromBlock,
          toBlock
        );

        onLog(
          `🔍 Found ${responseLogs.length} total handshake responses in blocks ${fromBlock}-${toBlock}`
        );
        responseLogs.forEach((log, i) => {
          onLog(`Response[${i}] inResponseTo: ${log.topics[1]}`);
        });

        const myResponses = responseLogs.filter((log) =>
          pendingTxHashes.includes(log.topics[1])
        );

        onLog(`Filtered to ${myResponses.length} responses for me`);

        for (const log of myResponses) {
          const logKey = `${log.transactionHash}-${log.logIndex}`;
          if (!processedLogs.current.has(logKey)) {
            processedLogs.current.add(logKey);
            allEvents.push({
              logKey,
              eventType: "handshake_response",
              rawLog: log,
              blockNumber: log.blockNumber,
              timestamp: Date.now(),
            });
          }
        }
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

        // 👉 aggiungi il tuo indirizzo così il listener vede i tuoi messaggi in uscita
        if (address) {
          const myTopic =
            "0x" + address.replace("0x", "").toLowerCase().padStart(64, "0");
          if (!senderTopics.includes(myTopic)) senderTopics.push(myTopic);
        }

        const messageFilter = {
          address: LOGCHAIN_SINGLETON_ADDR,
          topics: [EVENT_SIGNATURES.MessageSent, senderTopics],
        };
        const messageLogs = await safeGetLogs(
          messageFilter,
          fromBlock,
          toBlock
        );

        for (const log of messageLogs) {
          const logKey = `${log.transactionHash}-${log.logIndex}`;
          if (!processedLogs.current.has(logKey)) {
            processedLogs.current.add(logKey);
            allEvents.push({
              logKey,
              eventType: "message",
              rawLog: log,
              blockNumber: log.blockNumber,
              timestamp: Date.now(),
            });
          }
        }
      }
    } catch (error) {
      onLog(`Error scanning block range ${fromBlock}-${toBlock}: ${error}`);
    }

    return allEvents;
  };

  // Initial backward scan (unchanged)
  const performInitialScan = useCallback(async () => {
    if (!readProvider || !address || isInitialLoading) return;

    // Check if initial scan already completed for this address
    const initialScanComplete = await dbService.getInitialScanComplete(address);
    if (initialScanComplete) {
      onLog(`✅ Initial scan already completed for ${address.slice(0, 8)}...`);

      // Load from database
      const savedLastBlock = await dbService.getLastKnownBlock();
      const savedOldestBlock = await dbService.getOldestScannedBlock();

      if (savedLastBlock) setLastKnownBlock(savedLastBlock);
      if (savedOldestBlock) setOldestScannedBlock(savedOldestBlock);

      setCanLoadMore(
        savedOldestBlock ? savedOldestBlock > CONTRACT_CREATION_BLOCK : true
      );
      return;
    }

    setIsInitialLoading(true);
    onLog(`...Starting initial scan of last ${INITIAL_SCAN_BLOCKS} blocks...`);

    try {
      const currentBlock = await readProvider.getBlockNumber();
      const startBlock = Math.max(
        currentBlock - INITIAL_SCAN_BLOCKS,
        CONTRACT_CREATION_BLOCK
      );

      const events = await scanBlockRange(startBlock, currentBlock);

      // Process events
      onEventsProcessed(events);

      // Store chunk info
      scanChunks.current = [
        {
          fromBlock: startBlock,
          toBlock: currentBlock,
          loaded: true,
          events: events.map((e) => e.rawLog),
        },
      ];

      // Update state and database
      setLastKnownBlock(currentBlock);
      setOldestScannedBlock(startBlock);
      setCanLoadMore(startBlock > CONTRACT_CREATION_BLOCK);

      await dbService.setLastKnownBlock(currentBlock);
      await dbService.setOldestScannedBlock(startBlock);
      await dbService.setInitialScanComplete(address, true);

      onLog(
        `✅ Initial scan complete: ${events.length} events found in blocks ${startBlock}-${currentBlock}`
      );
    } catch (error) {
      onLog(`✗ Initial scan failed: ${error}`);
    } finally {
      setIsInitialLoading(false);
    }
  }, [
    readProvider,
    address,
    isInitialLoading,
    onLog,
    onEventsProcessed,
    getCurrentContacts,
  ]);

  // Lazy load more history (unchanged)
  const loadMoreHistory = useCallback(async () => {
    if (
      !readProvider ||
      !address ||
      isLoadingMore ||
      !canLoadMore ||
      !oldestScannedBlock
    ) {
      return;
    }

    setIsLoadingMore(true);
    onLog(`...Loading more history...`);

    try {
      const endBlock = oldestScannedBlock - 1;
      const startBlock = Math.max(
        endBlock - INITIAL_SCAN_BLOCKS,
        CONTRACT_CREATION_BLOCK
      );

      // Check if blocks are available
      let maxIndexedBlock = endBlock;
      for (let b = endBlock; b >= startBlock; b--) {
        const blk = await readProvider.getBlock(b);
        if (blk) {
          maxIndexedBlock = b;
          break;
        }
      }

      if (maxIndexedBlock < startBlock) {
        onLog(
          `⚠️ No indexed blocks found between ${startBlock} and ${endBlock}. Retrying later.`
        );
        setIsLoadingMore(false);
        return;
      }

      const safeStartBlock = Math.max(startBlock, CONTRACT_CREATION_BLOCK);
      const safeEndBlock = maxIndexedBlock;

      const ranges = await findEventRanges(safeStartBlock, safeEndBlock);

      if (ranges.length === 0) {
        onLog(`No more events found before block ${safeEndBlock}`);
        setCanLoadMore(false);
        setIsLoadingMore(false);
        return;
      }

      const events = await batchScanRanges(ranges);

      // Process events
      onEventsProcessed(events);

      // Update chunks
      scanChunks.current.push({
        fromBlock: safeStartBlock,
        toBlock: safeEndBlock,
        loaded: true,
        events: events.map((e) => e.rawLog),
      });

      // Update state and database
      setOldestScannedBlock(safeStartBlock);
      setCanLoadMore(safeStartBlock > CONTRACT_CREATION_BLOCK);
      await dbService.setOldestScannedBlock(safeStartBlock);

      onLog(
        `✅ Loaded ${events.length} more events from blocks ${safeStartBlock}-${safeEndBlock}`
      );
    } catch (error) {
      onLog(`✗ Failed to load more history: ${error}`);
    } finally {
      setIsLoadingMore(false);
    }
  }, [
    readProvider,
    address,
    isLoadingMore,
    canLoadMore,
    oldestScannedBlock,
    onLog,
    onEventsProcessed,
  ]);

  // Real-time scanning for new blocks (unchanged)
  useEffect(() => {
    if (!readProvider || !address || !lastKnownBlock) return;

    const interval = setInterval(async () => {
      try {
        const currentBlock = await readProvider.getBlockNumber();
        const maxSafeBlock = currentBlock - REAL_TIME_BUFFER;

        if (maxSafeBlock > lastKnownBlock) {
          const startScanBlock = lastKnownBlock + 1;
          const events = await scanBlockRange(startScanBlock, maxSafeBlock);

          if (events.length > 0) {
            onEventsProcessed(events);
            onLog(
              `Found ${events.length} new events in blocks ${startScanBlock}-${maxSafeBlock}`
            );
          }

          setLastKnownBlock(maxSafeBlock);
          await dbService.setLastKnownBlock(maxSafeBlock);
        }
      } catch (error) {
        onLog(`⚠️ Real-time scan error: ${error}`);
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [readProvider, address, lastKnownBlock, onLog, onEventsProcessed]);

  // Clear state when address changes
  useEffect(() => {
    if (address) {
      setIsInitialLoading(false);
      setIsLoadingMore(false);
      setCanLoadMore(true);
      setSyncProgress(null);
      setLastKnownBlock(null);
      setOldestScannedBlock(null);
      processedLogs.current.clear();
      scanChunks.current = [];
    }
  }, [address]);

  // Initialize
  useEffect(() => {
    if (
      readProvider &&
      address &&
      !isInitialLoading &&
      scanChunks.current.length === 0
    ) {
      performInitialScan();
    }
  }, [readProvider, address, performInitialScan]);

  return {
    isInitialLoading,
    isLoadingMore,
    canLoadMore,
    syncProgress,
    loadMoreHistory,
    lastKnownBlock,
    oldestScannedBlock,
  };
};
