import React, { useEffect, useRef, useState, useCallback } from "react";
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount, useWalletClient } from 'wagmi';
import { hashMessage } from 'viem';
import nacl from "tweetnacl";
import {
  BrowserProvider,
  Contract,
  keccak256,
  SigningKey,
  toUtf8Bytes,
  getBytes
} from "ethers";
import { useHelios } from "./helios";
import {
  sendEncryptedMessage,
  decryptMessage
} from '@verbeth/sdk';
import type { LogChainV1 } from "@verbeth/contracts/typechain-types";

/**
 * ---------------------------------------------------------------------------
 * LogChain / VerbEth demo – App.tsx
 * ---------------------------------------------------------------------------
 *
 *       Helios currently cannot prove receipts for ranges larger than 4 096
 *       blocks (see `MAX_SUPPORTED_BLOCKS_TO_PROVE_FOR_LOGS` in Helios core).
 *       The helper below therefore caps each request to 4 000 blocks and will
 *       recursively split failing windows until they succeed or reach a single
 *       block.  This allows us to keep the UI snappy while still scanning the
 *       full history.
 * ------------------------------------------------------------------------- */

const ABI = [
  "function sendMessage(bytes ciphertext, bytes32 topic, uint256 timestamp, uint256 nonce)",
  "event MessageSent(address indexed sender, bytes ciphertext, uint256 timestamp, bytes32 indexed topic, uint256 nonce)"
];
const LOGCHAIN_ADDR = "0xf9fe7E57459CC6c42791670FaD55c1F548AE51E8";
const MESSAGE_SENT_SIGNATURE = keccak256(toUtf8Bytes("MessageSent(address,bytes,uint256,bytes32,uint256)"));

// Helios reliably proves ~4 096 blocks; 
const MAX_WINDOW = 4000;

interface Message {
  id: string;
  sender: string;
  content: string;
  timestamp: number;
  blockNumber: number;
  transactionHash: string;
}

export default function App() {
  // ────────────────────────────────────────────────────────────────────────────
  // React state & refs
  // ────────────────────────────────────────────────────────────────────────────
  const readProvider = useHelios();
  const { address, isConnected } = useAccount();
  const { data: walletClient } = useWalletClient();

  const [ready, setReady]               = useState(false);
  const [filterAddress, setFilterAddress] = useState("");
  const [filterTopic,   setFilterTopic]   = useState("");
  const [recipientPubKey, setRecipientPubKey] = useState("");
  const [senderPubKey,    setSenderPubKey]    = useState("");
  const [messageText,     setMessageText]     = useState("");
  const [messages,        setMessages]        = useState<Message[]>([]);
  const [isListening,     setIsListening]     = useState(false);
  const [isSending,       setIsSending]       = useState(false);

  const [userIdentityPubKey, setUserIdentityPubKey] = useState<Uint8Array | null>(null);
  const [recoveredPubKey,    setRecoveredPubKey]    = useState<string | null>(null);
  const [isDerivingKey,      setIsDerivingKey]      = useState(false);
  const [senderSignKeyPair,  setSenderSignKeyPair]  = useState<nacl.SignKeyPair | null>(null);

  const logRef        = useRef<HTMLTextAreaElement | null>(null);
  const lastBlockRef  = useRef<number>(0);

  // ────────────────────────────────────────────────────────────────────────────
  // Helpers
  // ────────────────────────────────────────────────────────────────────────────
  const addLog = (msg: string) => {
    console.log(msg);
    if (logRef.current) {
      const ts = new Date().toLocaleTimeString();
      logRef.current.value += `[${ts}] ${msg}\n`;
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  };

  /** Recursively fetches logs, making sure that each request stays below
   *  `maxWindow`.  When a window fails it will be split in half and retried.
   */
  const fetchLogsRange = useCallback(async (
  address: string,
  topics: (string | string[])[],
  fromBlock: number,
  toBlock: number,
  maxWindow: number,
  reverseOrder: boolean = false // NUOVO PARAMETRO
): Promise<any[]> => {
  const span = toBlock - fromBlock + 1;
  if (span <= 0) return [];

  // If the range is too large split it up front
  if (span > maxWindow) {
    const mid = fromBlock + Math.floor(span / 2);
    
    if (reverseOrder) {
      // CAMBIAMENTO: Per ordine inverso, processa prima la parte destra (più recente)
      const right = await fetchLogsRange(address, topics, mid, toBlock, maxWindow, reverseOrder);
      const left  = await fetchLogsRange(address, topics, fromBlock, mid - 1, maxWindow, reverseOrder);
      return [...right, ...left];
    } else {
      // Ordine normale
      const left  = await fetchLogsRange(address, topics, fromBlock, mid - 1, maxWindow, reverseOrder);
      const right = await fetchLogsRange(address, topics, mid, toBlock, maxWindow, reverseOrder);
      return [...left, ...right];
    }
  }

  // Attempt the query – if it fails, split and retry (until single‑block)
  try {
    addLog(`📚 Fetching logs ${fromBlock}-${toBlock} …`);
    const logs = await readProvider!.getLogs({ address, topics, fromBlock, toBlock });
    addLog(`   ↳ ${logs.length} logs`);
    
    // CAMBIAMENTO: Se reverseOrder è true, inverti i logs prima di restituirli
    return reverseOrder ? logs.reverse() : logs;
  } catch (err: any) {
    addLog(`⚠️  Error fetching ${fromBlock}-${toBlock}: ${err.message || err}`);
    if (span === 1) return []; // can't split further
    const mid = fromBlock + Math.floor(span / 2);
    
    if (reverseOrder) {
      // CAMBIAMENTO: Per ordine inverso, processa prima la parte destra (più recente)
      const right = await fetchLogsRange(address, topics, mid, toBlock, maxWindow, reverseOrder);
      const left  = await fetchLogsRange(address, topics, fromBlock, mid - 1, maxWindow, reverseOrder);
      return [...right, ...left];
    } else {
      // Ordine normale
      const left  = await fetchLogsRange(address, topics, fromBlock, mid - 1, maxWindow, reverseOrder);
      const right = await fetchLogsRange(address, topics, mid, toBlock, maxWindow, reverseOrder);
      return [...left, ...right];
    }
  }
}, [readProvider]);

  // Debug helper to inspect readiness
  const debugReadyState = () => {
    const state = {
      readProvider: !!readProvider,
      isConnected,
      walletClient: !!walletClient,
      userIdentityPubKey: !!userIdentityPubKey,
      senderSignKeyPair: !!senderSignKeyPair
    };
    addLog(`🔍 Ready check: ${JSON.stringify(state)}`);
    return Object.values(state).every(Boolean);
  };

  // ────────────────────────────────────────────────────────────────────────────
  // Sync ‘ready’ flag whenever dependencies change
  // ────────────────────────────────────────────────────────────────────────────
  useEffect(() => {
    setReady(debugReadyState());
  }, [readProvider, isConnected, walletClient, userIdentityPubKey, senderSignKeyPair]);

  // ────────────────────────────────────────────────────────────────────────────
  // Identity key derivation (unchanged)
  // ────────────────────────────────────────────────────────────────────────────
  useEffect(() => {
    const derive = async () => {
      if (!walletClient || !address || !isConnected) {
        setUserIdentityPubKey(null);
        setRecoveredPubKey(null);
        setSenderSignKeyPair(null);
        return;
      }

      const storageKey = `verbeth_identity_${address.toLowerCase()}`;
      try {
        const cached = localStorage.getItem(storageKey);
        if (cached) {
          const { identityPubKey, recoveredPubKey } = JSON.parse(cached);
          const idBytes = new Uint8Array(identityPubKey);
          const seed = new Uint8Array(32);
          seed.set(idBytes);
          setUserIdentityPubKey(idBytes);
          setRecoveredPubKey(recoveredPubKey || null);
          setSenderSignKeyPair(nacl.sign.keyPair.fromSeed(seed));
          addLog('✅ Loaded identity from cache');
          return;
        }
      } catch {/* ignore */}

      setIsDerivingKey(true);
      try {
        const msg       = `VerbEth Identity Key for ${address.toLowerCase()}`;
        const signature = await walletClient.signMessage({ account: address as `0x${string}`, message: msg });
        const pk        = SigningKey.recoverPublicKey(hashMessage(msg), signature);
        if (!pk?.startsWith('0x04')) throw new Error('Recovered pk invalid');
        const idBytes   = nacl.hash(getBytes(pk).slice(1)).slice(0, 32);
        const seed      = new Uint8Array(32);
        seed.set(idBytes);
        const signPair  = nacl.sign.keyPair.fromSeed(seed);
        setUserIdentityPubKey(idBytes);
        setRecoveredPubKey(pk);
        setSenderSignKeyPair(signPair);
        localStorage.setItem(storageKey, JSON.stringify({ identityPubKey: Array.from(idBytes), recoveredPubKey: pk, timestamp: Date.now() }));
        addLog('✅ Derived and cached identity');
      } catch (e: any) {
        addLog(`❌ Identity derivation failed: ${e.message || e}`);
      } finally {
        setIsDerivingKey(false);
      }
    };

    derive();
  }, [walletClient, address, isConnected]);

  // ────────────────────────────────────────────────────────────────────────────
  // Event‑processing helpers
  // ────────────────────────────────────────────────────────────────────────────
  const processMessageLog = async (log: any) => {
    try {
      const iface   = new Contract(LOGCHAIN_ADDR, ABI).interface;
      const decoded = iface.parseLog({ topics: log.topics, data: log.data });
      if (!decoded) return;

      const { sender, ciphertext, timestamp } = decoded.args;
      if (!senderPubKey) {
        addLog(`📩 Encrypted message from ${sender} (no decryption key set)`);
        return;
      }

      const cipherBytes = new TextDecoder().decode(ciphertext);
      const recKeyPair  = nacl.box.keyPair(); // demo only – proper identity key should be used
      const senderBytes = new Uint8Array(senderPubKey.match(/.{1,2}/g)?.map(b => parseInt(b, 16)) || []);
      const decrypted   = decryptMessage(cipherBytes, recKeyPair.secretKey, senderBytes);
      if (!decrypted) throw new Error('decrypt failed');

      setMessages(prev => [...prev, {
        id: `${log.transactionHash}-${log.logIndex}`,
        sender,
        content: decrypted,
        timestamp: Number(timestamp),
        blockNumber: log.blockNumber,
        transactionHash: log.transactionHash
      }]);
      addLog(`✅ Decrypted: “${decrypted}”`);
    } catch (err: any) {
      addLog(`❌ Process log error: ${err.message || err}`);
    }
  };

  // ────────────────────────────────────────────────────────────────────────────
  // Start / stop listening
  // ────────────────────────────────────────────────────────────────────────────
  const startListening = async () => {
    if (!readProvider || !filterAddress || !filterTopic) {
      addLog('❌ Missing provider / address / topic');
      return;
    }

    setIsListening(true);
    setMessages([]);
    addLog(`🔍 Listening for ${filterAddress} on “${filterTopic}”`);

    try {
      const currentBlock       = await readProvider.getBlockNumber();
      lastBlockRef.current      = currentBlock;
      const topicHash          = keccak256(toUtf8Bytes(filterTopic));
      const paddedSender       = '0x' + '0'.repeat(24) + filterAddress.slice(2).toLowerCase();
      const topics: (string | string[])[] = [MESSAGE_SENT_SIGNATURE, paddedSender, topicHash];

      // Historical scan -------------------------------------------------------
      const historicalLogs = await fetchLogsRange(LOGCHAIN_ADDR, topics, 30568313, currentBlock, MAX_WINDOW, true);
      addLog(`📜 History complete (${historicalLogs.length} logs)`);
      for (const l of historicalLogs) await processMessageLog(l);

      // Live polling ----------------------------------------------------------
      const id = setInterval(async () => {
        try {
          const latest = await readProvider.getBlockNumber();
          if (latest <= lastBlockRef.current) return;
          const newLogs = await fetchLogsRange(LOGCHAIN_ADDR, topics, lastBlockRef.current + 1, latest, MAX_WINDOW, false);
          for (const l of newLogs) await processMessageLog(l);
          lastBlockRef.current = latest;
        } catch (e: any) {
          addLog(`⚠️  Poll error: ${e.message || e}`);
        }
      }, 3_000);
      (window as any).verbethPollInterval = id;
    } catch (e: any) {
      addLog(`❌ Listener error: ${e.message || e}`);
      setIsListening(false);
    }
  };

  const stopListening = () => {
    setIsListening(false);
    const id = (window as any).verbethPollInterval;
    if (id) clearInterval(id);
    addLog('🛑 Listener stopped');
  };

  // ────────────────────────────────────────────────────────────────────────────
  // Send message
  // ────────────────────────────────────────────────────────────────────────────
  const sendMessage = async () => {
    if (!walletClient || !ready || !address || !recipientPubKey || !messageText || !filterTopic || !senderSignKeyPair) {
      addLog('❌ Missing fields – cannot send');
      return;
    }

    setIsSending(true);
    try {
      const provider = new BrowserProvider({ request: ({ method, params }) => walletClient.request({ method: method as any, params }) });
      const signer   = await provider.getSigner();
      const contract = new Contract(LOGCHAIN_ADDR, ABI, signer) as unknown as LogChainV1;

      const recipientBytes = new Uint8Array(recipientPubKey.match(/.{1,2}/g)?.map(b => parseInt(b, 16)) || []);
      const topicHash      = keccak256(toUtf8Bytes(filterTopic));
      const timestamp      = Math.floor(Date.now() / 1000);

      await sendEncryptedMessage({
        contract,
        topic: topicHash,
        message: messageText,
        recipientPubKey: recipientBytes,
        senderAddress: address,
        senderSignKeyPair,
        timestamp
      });
      addLog(`✅ Sent: “${messageText}”`);
      setMessageText('');
    } catch (e: any) {
      addLog(`❌ Send failed: ${e.message || e}`);
    } finally {
      setIsSending(false);
    }
  };

  // ────────────────────────────────────────────────────────────────────────────
  // JSX 
  // ────────────────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-black rounded-lg flex items-center justify-center"><span className="text-white font-bold text-sm">V</span></div>
            <h1 className="text-xl font-semibold text-gray-900">VerbEth</h1>
            <span className="text-sm text-gray-500">Simplified Demo</span>
          </div>
          <ConnectButton />
        </div>
      </header>

      {/* Main */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Left column – config */}
          <div className="space-y-6">
            {/* Connection status */}
            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Connection Status</h2>
              <div className="space-y-3">
                <StatusRow label="Helios Sync" ok={!!readProvider} />
                <StatusRow label="Wallet" ok={isConnected} />
                {address && <AddrRow address={address} />}
              </div>
            </div>

            {/* Filters */}
            <FilterCard
              filterAddress={filterAddress}
              setFilterAddress={setFilterAddress}
              filterTopic={filterTopic}
              setFilterTopic={setFilterTopic}
              senderPubKey={senderPubKey}
              setSenderPubKey={setSenderPubKey}
              isListening={isListening}
              ready={ready}
              startListening={startListening}
              stopListening={stopListening}
            />

            {/* Send */}
            <SendCard
              filterTopic={filterTopic}
              setFilterTopic={setFilterTopic}
              recipientPubKey={recipientPubKey}
              setRecipientPubKey={setRecipientPubKey}
              messageText={messageText}
              setMessageText={setMessageText}
              sendMessage={sendMessage}
              ready={ready}
              isSending={isSending}
            />
          </div>

          {/* Right column – messages + log */}
          <div className="space-y-6">
            <MessageList messages={messages} />
            <LogArea ref={logRef} />
          </div>
        </div>
      </main>
    </div>
  );
}

/* ------------------------------------------------------------------------- */
/* Reusable components              */
/* ------------------------------------------------------------------------- */
function StatusRow({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="flex items-center justify-between"><span className="text-sm text-gray-600">{label}:</span><span className={`px-2 py-1 rounded text-xs font-medium ${ok ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>{ok ? 'OK' : 'N/A'}</span></div>
  );
}
function AddrRow({ address }: { address: string }) {
  return (
    <div className="pt-2 border-t border-gray-100"><span className="text-sm text-gray-600">Address:</span><p className="text-xs font-mono text-gray-900 mt-1 break-all">{address}</p></div>
  );
}
function FilterCard({
  filterAddress,
  setFilterAddress,
  filterTopic,
  setFilterTopic,
  senderPubKey,
  setSenderPubKey,
  isListening,
  ready,
  startListening,
  stopListening
}: {
  filterAddress: string;
  setFilterAddress: (v: string) => void;
  filterTopic: string;
  setFilterTopic: (v: string) => void;
  senderPubKey: string;
  setSenderPubKey: (v: string) => void;
  isListening: boolean;
  ready: boolean;
  startListening: () => void;
  stopListening: () => void;
}) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6">
      <h2 className="text-lg font-semibold text-gray-900 mb-4">Message Filter</h2>
      <div className="space-y-4">
        <InputField
          label="Sender Address"
          value={filterAddress}
          onChange={e => setFilterAddress(e.target.value)}
          placeholder="0x…"
          disabled={isListening}
        />
        <InputField
          label="Topic"
          value={filterTopic}
          onChange={e => setFilterTopic(e.target.value)}
          placeholder="chat:demo"
          disabled={isListening}
        />
        <InputField
          label="Sender Public Key (for decryption)"
          value={senderPubKey}
          onChange={e => setSenderPubKey(e.target.value)}
          placeholder="32‑byte hex string…"
          disabled={isListening}
        />
        <button
          onClick={isListening ? stopListening : startListening}
          disabled={!ready || (!isListening && (!filterAddress || !filterTopic))}
          className={`w-full px-4 py-2 rounded-md text-sm font-medium ${isListening ? 'bg-red-600 hover:bg-red-700' : 'bg-blue-600 hover:bg-blue-700'} text-white disabled:opacity-50`}
        >
          {isListening ? 'Stop Listening' : 'Start Listening'}
        </button>
      </div>
    </div>
  );
}

function SendCard({
  filterTopic,
  setFilterTopic,
  recipientPubKey,
  setRecipientPubKey,
  messageText,
  setMessageText,
  sendMessage,
  ready,
  isSending
}: {
  filterTopic: string;
  setFilterTopic: (v: string) => void;
  recipientPubKey: string;
  setRecipientPubKey: (v: string) => void;
  messageText: string;
  setMessageText: (v: string) => void;
  sendMessage: () => void;
  ready: boolean;
  isSending: boolean;
}) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6">
      <h2 className="text-lg font-semibold text-gray-900 mb-4">Send Message</h2>
      <div className="space-y-4">
        <InputField
          label="Topic"
          value={filterTopic}
          onChange={e => setFilterTopic(e.target.value)}
          placeholder="chat:demo"
          disabled={isSending}
        />
        <InputField
          label="Recipient Public Key"
          value={recipientPubKey}
          onChange={e => setRecipientPubKey(e.target.value)}
          placeholder="32‑byte hex string…"
          disabled={isSending}
        />
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Message</label>
          <textarea
            rows={3}
            className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            placeholder="Type your message…"
            value={messageText}
            onChange={e => setMessageText(e.target.value)}
            disabled={isSending}
          />
        </div>
        <button
          onClick={sendMessage}
          disabled={!ready || !recipientPubKey || !messageText || !filterTopic || isSending}
          className="w-full px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-md text-sm font-medium disabled:opacity-50 flex items-center justify-center space-x-2"
        >
          {isSending && <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
          <span>{isSending ? 'Sending…' : 'Send Message'}</span>
        </button>
      </div>
    </div>
  );
}

function MessageList({ messages }: { messages: Message[] }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6">
      <h2 className="text-lg font-semibold text-gray-900 mb-4">Messages ({messages.length})</h2>
      <div className="space-y-3 max-h-64 overflow-y-auto">
        {messages.length === 0 ? (
          <p className="text-sm text-gray-500 italic">No messages yet…</p>
        ) : (
          messages.map(m => (
            <div key={m.id} className="border border-gray-200 rounded-lg p-3">
              <div className="text-xs text-gray-500 mb-1">
                From: {m.sender.slice(0, 8)}…{m.sender.slice(-6)} • Block: {m.blockNumber}
              </div>
              <div className="text-sm text-gray-900 break-words whitespace-pre-wrap">{m.content}</div>
              <div className="text-xs text-gray-400 mt-1">
                {new Date(m.timestamp * 1000).toLocaleString()}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function InputField({ label, ...rest }: { label: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-1">{label}</label>
      <input
        className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 disabled:opacity-50"
        {...rest}
      />
    </div>
  );
}


const LogArea = React.forwardRef<HTMLTextAreaElement>((_props, ref) => (
  <div className="bg-white rounded-xl border border-gray-200 p-6"><h2 className="text-lg font-semibold text-gray-900 mb-4">Activity Log</h2><textarea ref={ref} className="w-full h-48 px-3 py-2 border border-gray-300 rounded-lg bg-gray-50 font-mono text-sm resize-none outline-none" readOnly placeholder="Activity logs will appear here…"/></div>
));
