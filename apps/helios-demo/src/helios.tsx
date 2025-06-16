import { createContext, useContext, useEffect, useState } from "react";
import { HeliosProvider as RawHelios, init as initHelios, Network } from "helios";
import { BrowserProvider } from "ethers";

const HeliosCtx = createContext<BrowserProvider | null>(null);

export function HeliosProvider({ children }: { children: React.ReactNode }) {
  const [readProvider, setReadProvider] = useState<BrowserProvider | null>(null);

  useEffect(() => {
    (async () => {
      await initHelios();

      const helios = new RawHelios(
        {
          executionRpc:   "https://base-rpc.publicnode.com",
          executionVerifiableApi: "https://base-rpc.publicnode.com",
          //consensusRpc:   "http://localhost:5174/consensus", // stesso origin, niente CORS
          //consensusRpc: "https://base.operationsolarstorm.org",
          // non serve consensusRpc: viene risolto da helios-opstack,
          dbType:         "localstorage",
          network:       "base" as Network,
        },
        "opstack"
      );
      await helios.sync();
      await helios.waitSynced(); 

      setReadProvider(new BrowserProvider(helios as any));
    })();
  }, []);

  return (
    <HeliosCtx.Provider value={readProvider}>{children}</HeliosCtx.Provider>
  );
}

export function useHelios() {
  return useContext(HeliosCtx);
}
