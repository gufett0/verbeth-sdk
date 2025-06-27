import { createContext, useContext, useEffect, useState } from "react";
import { JsonRpcProvider } from "ethers";

const RpcCtx = createContext<JsonRpcProvider | null>(null);

export function RpcProvider({ children }: { children: React.ReactNode }) {
  const [readProvider, setReadProvider] = useState<JsonRpcProvider | null>(null);
  const [isConnecting, setIsConnecting] = useState(true);
  const [connectionError, setConnectionError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    const connectToRpc = async () => {
      try {
        setIsConnecting(true);
        setConnectionError(null);
        
        console.log("🔗 Connecting to RPC...");
        
        // Enable built-in polling for event listening
        const provider = new JsonRpcProvider("https://base-rpc.publicnode.com", undefined, {
          polling: true,
          pollingInterval: 3000 // 3 seconds
        });
        
        // Test the connection by getting network info
        const network = await provider.getNetwork();
        const blockNumber = await provider.getBlockNumber();
        
        console.log("✅ Connected to RPC:", {
          chainId: network.chainId.toString(),
          name: network.name,
          currentBlock: blockNumber
        });
        
        if (isMounted) {
          setReadProvider(provider);
          setIsConnecting(false);
        }
      } catch (error) {
        console.error("❌ Failed to connect to RPC provider:", error);
        if (isMounted) {
          setConnectionError(error instanceof Error ? error.message : 'Connection failed');
          setIsConnecting(false);
        }
      }
    };

    connectToRpc();

    return () => {
      isMounted = false;
    };
  }, []);

  return (
    <RpcCtx.Provider value={readProvider}>
      {children}
    </RpcCtx.Provider>
  );
}

export function useRpcProvider() {
  return useContext(RpcCtx);
}

export function useRpcStatus() {
  const provider = useContext(RpcCtx);
  return {
    isConnected: provider !== null,
    provider
  };
}