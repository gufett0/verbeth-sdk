// Debug component to add to your app
import React, { useState, useEffect } from 'react';
import { useHelios } from '../helios.js';
import { keccak256, toUtf8Bytes } from 'ethers';

const LOGCHAIN_ADDR = '0xf9fe7E57459CC6c42791670FaD55c1F548AE51E8';

export function VerbEthDebugPanel({ userAddress }: { userAddress: string | null }) {
  const readProvider = useHelios();
  const [debugInfo, setDebugInfo] = useState<any>({});
  const [isScanning, setIsScanning] = useState(false);

  const runDiagnostics = async () => {
    if (!readProvider || !userAddress) return;
    
    setIsScanning(true);
    const results: any = {};

    try {
      // Test 1: Check provider connection
      results.providerConnected = true;
      results.currentBlock = await readProvider.getBlockNumber();
      
      // Test 2: Check contract existence
      const code = await readProvider.getCode(LOGCHAIN_ADDR);
      results.contractExists = code !== '0x';
      
      // Test 3: Calculate recipient hash
      results.userAddress = userAddress;
      results.recipientHash = keccak256(toUtf8Bytes('contact:' + userAddress.toLowerCase()));
      
      // Test 4: Scan for any events from the contract
      const filter = {
        address: LOGCHAIN_ADDR,
        fromBlock: Math.max(results.currentBlock - 50, 0),
        toBlock: results.currentBlock
      };
      
      const allLogs = await readProvider.getLogs(filter);
      results.totalLogsFound = allLogs.length;
      results.recentLogs = allLogs.slice(-5).map(log => ({
        blockNumber: log.blockNumber,
        topics: log.topics,
        data: log.data,
        transactionHash: log.transactionHash
      }));
      
      // Test 5: Check for handshakes directed to this user
      const handshakeFilter = {
        address: LOGCHAIN_ADDR,
        fromBlock: Math.max(results.currentBlock - 100, 0),
        toBlock: results.currentBlock,
        topics: [
          keccak256(toUtf8Bytes("Handshake(bytes32,address,bytes,bytes,bytes)")),
          results.recipientHash // Filter by recipient
        ]
      };
      
      const userHandshakes = await readProvider.getLogs(handshakeFilter);
      results.handshakesForUser = userHandshakes.length;
      
    } catch (error) {
      results.error = error.message;
    }
    
    setDebugInfo(results);
    setIsScanning(false);
  };

  useEffect(() => {
    if (readProvider && userAddress) {
      runDiagnostics();
    }
  }, [readProvider, userAddress]);

  if (!readProvider || !userAddress) {
    return <div className="text-yellow-600">⚠️ Waiting for provider and user address...</div>;
  }

  return (
    <div className="bg-gray-100 p-4 rounded-lg">
      <h3 className="text-lg font-semibold mb-3">🔧 VerbEth Debug Panel</h3>
      
      <button 
        onClick={runDiagnostics}
        disabled={isScanning}
        className="mb-4 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50"
      >
        {isScanning ? 'Scanning...' : 'Run Diagnostics'}
      </button>

      <div className="space-y-2 text-sm">
        <div className={`p-2 rounded ${debugInfo.providerConnected ? 'bg-green-100' : 'bg-red-100'}`}>
          <strong>Provider:</strong> {debugInfo.providerConnected ? '✅ Connected' : '❌ Disconnected'}
          {debugInfo.currentBlock && <span> (Block: {debugInfo.currentBlock})</span>}
        </div>

        <div className={`p-2 rounded ${debugInfo.contractExists ? 'bg-green-100' : 'bg-red-100'}`}>
          <strong>Contract:</strong> {debugInfo.contractExists ? '✅ Found' : '❌ Not found'} at {LOGCHAIN_ADDR}
        </div>

        <div className="p-2 rounded bg-blue-100">
          <strong>User:</strong> {debugInfo.userAddress}<br/>
          <strong>Recipient Hash:</strong> <code className="text-xs">{debugInfo.recipientHash}</code>
        </div>

        <div className="p-2 rounded bg-yellow-100">
          <strong>Recent Activity:</strong> {debugInfo.totalLogsFound || 0} logs found in last 50 blocks<br/>
          <strong>Handshakes for you:</strong> {debugInfo.handshakesForUser || 0}
        </div>

        {debugInfo.recentLogs && debugInfo.recentLogs.length > 0 && (
          <div className="p-2 rounded bg-gray-200">
            <strong>Recent Logs:</strong>
            <pre className="text-xs mt-1 overflow-x-auto">
              {JSON.stringify(debugInfo.recentLogs, null, 2)}
            </pre>
          </div>
        )}

        {debugInfo.error && (
          <div className="p-2 rounded bg-red-100">
            <strong>Error:</strong> {debugInfo.error}
          </div>
        )}
      </div>
    </div>
  );
}